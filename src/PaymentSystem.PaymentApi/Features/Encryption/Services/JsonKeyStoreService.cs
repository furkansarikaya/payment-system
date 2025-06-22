using System.Text.Json;
using Microsoft.Extensions.Options;
using PaymentSystem.PaymentApi.Features.Encryption.Models;

namespace PaymentSystem.PaymentApi.Features.Encryption.Services;

public class JsonKeyStoreService(ILogger<JsonKeyStoreService> logger, IOptions<JsonKeyStoreOptions> options)
    : IJsonKeyStoreService
{
    private readonly JsonKeyStoreOptions _options = options.Value;
    private readonly SemaphoreSlim _refreshLock = new(1, 1);

    private JsonKeyStore? _keyStore;
    private DateTime _lastRefresh = DateTime.MinValue;

    /// <summary>
    /// Environment için encryption configuration getir
    /// </summary>
    public async Task<EncryptionConfiguration> GetEncryptionConfigurationAsync(string environment)
    {
        try
        {
            // Key store'u yükle/refresh et
            await EnsureKeyStoreLoadedAsync();

            if (_keyStore?.Environments == null || !_keyStore.Environments.TryGetValue(environment, out var envKeys))
            {
                throw new InvalidOperationException($"Environment not found in key store: {environment}");
            }

            if (envKeys.CurrentKey == null)
            {
                throw new InvalidOperationException($"No current key found for environment: {environment}");
            }

            if (!envKeys.CurrentKey.IsActive)
            {
                logger.LogWarning("Current key is not active for environment: {Environment}", environment);
            }

            var config = new EncryptionConfiguration
            {
                PublicKey = envKeys.CurrentKey.PublicKey,
                PrivateKey = envKeys.CurrentKey.PrivateKey,
                RequestTimeoutMinutes = _options.RequestTimeoutMinutes,
                KeyId = envKeys.CurrentKey.KeyId,
                Environment = environment,
                KeySize = envKeys.CurrentKey.KeySize,
                CreatedAt = envKeys.CurrentKey.CreatedAt,
                ExpiresAt = envKeys.CurrentKey.ExpiresAt
            };

            logger.LogDebug("Encryption configuration loaded for environment: {Environment}, KeyId: {KeyId}",
                environment, config.KeyId);

            return config;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to get encryption configuration for environment: {Environment}", environment);
            throw;
        }
    }

    /// <summary>
    /// Key store'u yeniden yükle
    /// </summary>
    public async Task<bool> RefreshKeyStoreAsync()
    {
        await _refreshLock.WaitAsync();
        try
        {
            logger.LogInformation("Refreshing key store from: {FilePath}", _options.KeyStoreFilePath);

            if (!File.Exists(_options.KeyStoreFilePath))
            {
                logger.LogError("Key store file not found: {FilePath}", _options.KeyStoreFilePath);
                return false;
            }

            var jsonContent = await File.ReadAllTextAsync(_options.KeyStoreFilePath);
            var keyStore = JsonSerializer.Deserialize<JsonKeyStore>(jsonContent, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

            if (keyStore == null)
            {
                logger.LogError("Failed to deserialize key store");
                return false;
            }

            _keyStore = keyStore;
            _lastRefresh = DateTime.UtcNow;

            logger.LogInformation("Key store refreshed successfully. Environments: {Count}, Last refresh: {RefreshTime}",
                _keyStore.Environments?.Count ?? 0, _lastRefresh);

            return true;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to refresh key store");
            return false;
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    /// <summary>
    /// Key store bilgilerini getir
    /// </summary>
    public async Task<KeyStoreInfo> GetKeyStoreInfoAsync()
    {
        await EnsureKeyStoreLoadedAsync();

        var info = new KeyStoreInfo
        {
            Version = _keyStore?.Version ?? "Unknown",
            GeneratedAt = _keyStore?.GeneratedAt ?? DateTime.MinValue,
            LastRefresh = _lastRefresh,
            FilePath = _options.KeyStoreFilePath,
            EnvironmentCount = _keyStore?.Environments?.Count ?? 0
        };

        if (_keyStore?.Environments == null) 
            return info;
        foreach (var envInfo in _keyStore.Environments.Select(env => new EnvironmentKeyInfo
                 {
                     Environment = env.Key,
                     CurrentKeyId = env.Value.CurrentKey?.KeyId,
                     KeySize = env.Value.CurrentKey?.KeySize ?? 0,
                     IsActive = env.Value.CurrentKey?.IsActive ?? false,
                     ExpiresAt = env.Value.CurrentKey?.ExpiresAt,
                     HasNextKey = env.Value.NextKey != null,
                     BackupKeyCount = env.Value.BackupKeys?.Count ?? 0
                 }))
        {
            info.Environments.Add(envInfo);
        }

        return info;
    }

    /// <summary>
    /// Key rotation gerekli mi kontrol et
    /// </summary>
    public async Task<bool> IsKeyRotationNeededAsync(string environment)
    {
        await EnsureKeyStoreLoadedAsync();

        if (_keyStore?.Environments == null || !_keyStore.Environments.TryGetValue(environment, out var envKeys))
        {
            return false;
        }

        if (envKeys.CurrentKey == null || envKeys.RotationPolicy == null)
        {
            return false;
        }

        var daysToExpiry = (envKeys.CurrentKey.ExpiresAt - DateTime.UtcNow).TotalDays;
        var rotationNeeded = daysToExpiry <= envKeys.RotationPolicy.WarningDays;

        if (rotationNeeded)
        {
            logger.LogWarning("Key rotation needed for environment: {Environment}, Days to expiry: {Days}",
                environment, (int)daysToExpiry);
        }

        return rotationNeeded;
    }

    /// <summary>
    /// Key store'un yüklü olduğundan emin ol
    /// </summary>
    private async Task EnsureKeyStoreLoadedAsync()
    {
        if (_keyStore == null || ShouldRefresh())
        {
            var refreshed = await RefreshKeyStoreAsync();
            if (!refreshed)
            {
                throw new InvalidOperationException("Failed to load key store");
            }
        }
    }

    /// <summary>
    /// Refresh gerekli mi kontrol et
    /// </summary>
    private bool ShouldRefresh()
    {
        return DateTime.UtcNow - _lastRefresh > TimeSpan.FromMinutes(_options.RefreshIntervalMinutes);
    }
}