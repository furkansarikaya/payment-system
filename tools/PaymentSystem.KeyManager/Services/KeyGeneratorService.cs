using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using PaymentSystem.KeyManager.Models;

namespace PaymentSystem.KeyManager.Services;

public class KeyGeneratorService(ILogger<KeyGeneratorService> logger) : IKeyGeneratorService
{
    /// <summary>
    /// Secure RSA key pair generation
    /// </summary>
    public RsaKeyPair GenerateKeyPair(string environment, string purpose, int keySize = 2048)
    {
        try
        {
            logger.LogInformation("RSA key pair üretiliyor: Environment={Environment}, Purpose={Purpose}, KeySize={KeySize}",
                environment, purpose, keySize);

            using var rsa = RSA.Create(keySize);

            var keyId = GenerateKeyId(environment, purpose);
            var now = DateTime.UtcNow;

            var keyPair = new RsaKeyPair
            {
                KeyId = keyId,
                PublicKey = rsa.ExportRSAPublicKeyPem(),
                PrivateKey = rsa.ExportRSAPrivateKeyPem(),
                KeySize = keySize,
                Environment = environment,
                Purpose = purpose,
                CreatedAt = now,
                ExpiresAt = now.AddDays(90), // 90 gün geçerli
                IsActive = true,
                Version = 1,
                Metadata = new Dictionary<string, object>
                {
                    ["generatedBy"] = Environment.MachineName,
                    ["generatedAt"] = now.ToString("O"),
                    ["rsaParameters"] = new
                    {
                        KeySize = keySize,
                        MaxDirectEncryptionSize = (keySize / 8) - 66, // OAEP padding overhead
                        RecommendedUsage = "Hybrid encryption with AES"
                    }
                }
            };

            logger.LogInformation("Key pair başarıyla üretildi: {KeyId}", keyId);
            return keyPair;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Key pair üretimi başarısız: Environment={Environment}, Purpose={Purpose}",
                environment, purpose);
            throw;
        }
    }

    /// <summary>
    /// Multiple environment için complete key store generation
    /// </summary>
    public async Task<RsaKeyStore> GenerateKeyStoreAsync(KeyGenerationRequest request)
    {
        try
        {
            logger.LogInformation("Key store üretiliyor: {RequestName}", request.Name);

            var keyStore = new RsaKeyStore
            {
                GeneratedAt = DateTime.UtcNow,
                Description = request.Description
            };

            foreach (var envConfig in request.Environments)
            {
                logger.LogInformation("Environment key'leri üretiliyor: {Environment}", envConfig.Name);

                var environmentKeys = new EnvironmentKeys
                {
                    Environment = envConfig.Name,
                    Description = envConfig.Description,
                    RotationPolicy = new KeyRotationPolicy
                    {
                        RotationIntervalDays = envConfig.RotationIntervalDays,
                        WarningDays = envConfig.WarningDays,
                        AutoRotationEnabled = envConfig.AutoRotationEnabled
                    },
                    // Current key üret
                    CurrentKey = GenerateKeyPair(envConfig.Name, "payment-encryption", envConfig.KeySize)
                };

                // Next key üret (rotation için hazır)
                if (envConfig.GenerateNextKey)
                {
                    environmentKeys.NextKey = GenerateKeyPair(envConfig.Name, "payment-encryption-next", envConfig.KeySize);
                    environmentKeys.NextKey.IsActive = false; // Henüz aktif değil
                }

                // Backup key'ler üret
                for (var i = 0; i < envConfig.BackupKeyCount; i++)
                {
                    var backupKey = GenerateKeyPair(envConfig.Name, $"payment-encryption-backup-{i + 1}", envConfig.KeySize);
                    backupKey.IsActive = false;
                    environmentKeys.BackupKeys.Add(backupKey);
                }

                keyStore.Environments[envConfig.Name] = environmentKeys;

                // CPU'yu rahatlatmak için küçük delay
                await Task.Delay(100);
            }

            logger.LogInformation("Key store başarıyla üretildi. Toplam environment: {Count}",
                keyStore.Environments.Count);

            return keyStore;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Key store üretimi başarısız");
            throw;
        }
    }

    /// <summary>
    /// Key pair validation - güvenlik kontrolü
    /// </summary>
    public async Task<bool> ValidateKeyPairAsync(RsaKeyPair keyPair)
    {
        try
        {
            await Task.Run(() =>
            {
                // 1. Key format kontrolü
                using var publicRsa = RSA.Create();
                using var privateRsa = RSA.Create();

                publicRsa.ImportFromPem(keyPair.PublicKey);
                privateRsa.ImportFromPem(keyPair.PrivateKey);

                // 2. Key size kontrolü
                if (publicRsa.KeySize != keyPair.KeySize || privateRsa.KeySize != keyPair.KeySize)
                {
                    throw new InvalidOperationException("Key size mismatch");
                }

                // 3. Encryption/decryption test
                const string testData = "key-validation-test-data";
                var testBytes = System.Text.Encoding.UTF8.GetBytes(testData);

                var encrypted = publicRsa.Encrypt(testBytes, RSAEncryptionPadding.OaepSHA256);
                var decrypted = privateRsa.Decrypt(encrypted, RSAEncryptionPadding.OaepSHA256);
                var decryptedText = System.Text.Encoding.UTF8.GetString(decrypted);

                if (decryptedText != testData)
                {
                    throw new InvalidOperationException("Encryption/decryption validation failed");
                }
            });

            logger.LogDebug("Key pair validation başarılı: {KeyId}", keyPair.KeyId);
            return true;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Key pair validation başarısız: {KeyId}", keyPair.KeyId);
            return false;
        }
    }

    /// <summary>
    /// Key rotation - security best practice
    /// </summary>
    public Task<RsaKeyStore> RotateKeysAsync(RsaKeyStore keyStore, string environment)
    {
        try
        {
            logger.LogInformation("Key rotation başlatılıyor: Environment={Environment}", environment);

            if (!keyStore.Environments.TryGetValue(environment, out var envKeys))
            {
                throw new ArgumentException($"Environment not found: {environment}");
            }

            // Mevcut key'i backup'a taşı
            if (envKeys.CurrentKey != null)
            {
                envKeys.CurrentKey.IsActive = false;
                envKeys.BackupKeys.Insert(0, envKeys.CurrentKey);

                // Archive old key
                keyStore.ArchivedKeys.Add(envKeys.CurrentKey);
            }

            // Next key'i current yap
            if (envKeys.NextKey != null)
            {
                envKeys.NextKey.IsActive = true;
                envKeys.CurrentKey = envKeys.NextKey;
            }
            else
            {
                // Next key yoksa yeni üret
                envKeys.CurrentKey = GenerateKeyPair(environment, "payment-encryption", 2048);
            }

            // Yeni next key üret
            envKeys.NextKey = GenerateKeyPair(environment, "payment-encryption-next", 2048);
            envKeys.NextKey.IsActive = false;

            // Rotation policy güncelle
            envKeys.RotationPolicy.LastRotation = DateTime.UtcNow;
            envKeys.RotationPolicy.NextRotation = DateTime.UtcNow.AddDays(envKeys.RotationPolicy.RotationIntervalDays);

            // Eski backup key'leri temizle (max 5 backup)
            if (envKeys.BackupKeys.Count > 5)
            {
                var toRemove = envKeys.BackupKeys.Skip(5).ToList();
                foreach (var oldKey in toRemove)
                {
                    keyStore.ArchivedKeys.Add(oldKey);
                }

                envKeys.BackupKeys = envKeys.BackupKeys.Take(5).ToList();
            }

            logger.LogInformation("Key rotation tamamlandı: Environment={Environment}, NewKeyId={KeyId}",
                environment, envKeys.CurrentKey?.KeyId);

            return Task.FromResult(keyStore);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Key rotation başarısız: Environment={Environment}", environment);
            throw;
        }
    }

    private static string GenerateKeyId(string environment, string purpose)
    {
        var timestamp = DateTime.UtcNow.ToString("yyyyMMddHHmmss");
        var randomPart = Guid.NewGuid().ToString("N")[..8];
        return $"{environment}_{purpose}_{timestamp}_{randomPart}".ToUpper();
    }
}