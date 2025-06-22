using System.Text.Json;
using Microsoft.Extensions.Logging;
using PaymentSystem.KeyManager.Models;

namespace PaymentSystem.KeyManager.Services;

/// <summary>
/// Key Store Management Service Implementation
/// JSON dosya işlemleri için concrete implementation
/// </summary>
public class KeyStoreService(ILogger<KeyStoreService> logger) : IKeyStoreService
{
    private readonly JsonSerializerOptions _jsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    /// <summary>
    /// Key store'u güvenli şekilde JSON dosyasına kaydet
    /// </summary>
    public async Task SaveKeyStoreAsync(RsaKeyStore keyStore, string filePath)
    {
        try
        {
            logger.LogInformation("Key store kaydediliyor: {FilePath}", filePath);

            // Backup oluştur (eğer dosya mevcutsa)
            if (File.Exists(filePath))
            {
                var backupPath = $"{filePath}.backup.{DateTime.UtcNow:yyyyMMddHHmmss}";
                File.Copy(filePath, backupPath);
                logger.LogDebug("Backup oluşturuldu: {BackupPath}", backupPath);
            }

            // Directory'yi oluştur
            var directory = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            // JSON'a serialize et
            var jsonContent = JsonSerializer.Serialize(keyStore, _jsonOptions);

            // Temporary dosyaya yaz, sonra atomic move
            var tempPath = $"{filePath}.tmp";
            await File.WriteAllTextAsync(tempPath, jsonContent);

            // Atomic move
            if (File.Exists(filePath))
            {
                File.Delete(filePath);
            }

            File.Move(tempPath, filePath);

            // Dosya izinlerini ayarla (sadece owner okuyabilsin)
            if (OperatingSystem.IsLinux() || OperatingSystem.IsMacOS())
            {
                File.SetUnixFileMode(filePath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            logger.LogInformation("Key store başarıyla kaydedildi: {FilePath}, Size: {Size} bytes",
                filePath, new FileInfo(filePath).Length);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Key store kaydedilemedi: {FilePath}", filePath);
            throw;
        }
    }

    /// <summary>
    /// JSON dosyasından key store'u yükle
    /// </summary>
    public async Task<RsaKeyStore> LoadKeyStoreAsync(string filePath)
    {
        try
        {
            logger.LogDebug("Key store yükleniyor: {FilePath}", filePath);

            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException($"Key store dosyası bulunamadı: {filePath}");
            }

            var jsonContent = await File.ReadAllTextAsync(filePath);

            if (string.IsNullOrWhiteSpace(jsonContent))
            {
                throw new InvalidOperationException("Key store dosyası boş");
            }

            var keyStore = JsonSerializer.Deserialize<RsaKeyStore>(jsonContent, _jsonOptions);

            if (keyStore == null)
            {
                throw new InvalidOperationException("Key store deserialize edilemedi");
            }

            logger.LogInformation("Key store başarıyla yüklendi: {FilePath}, Environments: {Count}",
                filePath, keyStore.Environments.Count);

            return keyStore;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Key store yüklenemedi: {FilePath}", filePath);
            throw;
        }
    }

    /// <summary>
    /// Key store backup'ını oluştur
    /// </summary>
    public async Task<bool> BackupKeyStoreAsync(string sourceFile, string backupDirectory)
    {
        try
        {
            if (!File.Exists(sourceFile))
            {
                logger.LogWarning("Backup için source dosya bulunamadı: {SourceFile}", sourceFile);
                return false;
            }

            if (!Directory.Exists(backupDirectory))
            {
                Directory.CreateDirectory(backupDirectory);
            }

            var fileName = Path.GetFileNameWithoutExtension(sourceFile);
            var extension = Path.GetExtension(sourceFile);
            var timestamp = DateTime.UtcNow.ToString("yyyyMMdd_HHmmss");
            var backupFileName = $"{fileName}_backup_{timestamp}{extension}";
            var backupPath = Path.Combine(backupDirectory, backupFileName);

            await Task.Run(() => File.Copy(sourceFile, backupPath));

            logger.LogInformation("Backup oluşturuldu: {BackupPath}", backupPath);

            // Eski backup'ları temizle (30 günden eski)
            var oldBackups = Directory.GetFiles(backupDirectory, $"{fileName}_backup_*{extension}")
                .Where(f => File.GetCreationTime(f) < DateTime.Now.AddDays(-30))
                .ToList();

            foreach (var oldBackup in oldBackups)
            {
                File.Delete(oldBackup);
                logger.LogDebug("Eski backup silindi: {OldBackup}", oldBackup);
            }

            return true;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Backup oluşturulamadı: {SourceFile}", sourceFile);
            return false;
        }
    }

    /// <summary>
    /// Multiple key store'ları birleştir
    /// </summary>
    public async Task<RsaKeyStore> MergeKeyStoresAsync(params string[] filePaths)
    {
        try
        {
            logger.LogInformation("Key store'lar birleştiriliyor: {Count} dosya", filePaths.Length);

            var mergedStore = new RsaKeyStore
            {
                GeneratedAt = DateTime.UtcNow,
                Description = "Merged key store from multiple sources"
            };

            foreach (var filePath in filePaths)
            {
                var keyStore = await LoadKeyStoreAsync(filePath);

                // Environment'ları birleştir
                foreach (var kvp in keyStore.Environments)
                {
                    if (!mergedStore.Environments.ContainsKey(kvp.Key))
                    {
                        mergedStore.Environments[kvp.Key] = kvp.Value;
                    }
                    else
                    {
                        logger.LogWarning("Duplicate environment: {Environment}, skipping from {FilePath}",
                            kvp.Key, filePath);
                    }
                }

                // Archived key'leri birleştir
                mergedStore.ArchivedKeys.AddRange(keyStore.ArchivedKeys);
            }

            logger.LogInformation("Key store merge tamamlandı. Toplam environment: {Count}",
                mergedStore.Environments.Count);

            return mergedStore;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Key store merge başarısız");
            throw;
        }
    }

    /// <summary>
    /// Key store health check ve validation
    /// </summary>
    public async Task<KeyStoreHealthReport> ValidateKeyStoreAsync(string filePath)
    {
        var report = new KeyStoreHealthReport { FilePath = filePath };

        try
        {
            var keyStore = await LoadKeyStoreAsync(filePath);
            report.IsValid = true;
            report.EnvironmentCount = keyStore.Environments.Count;

            foreach (var env in keyStore.Environments)
            {
                var envHealth = new EnvironmentHealth
                {
                    Environment = env.Key,
                    HasCurrentKey = env.Value.CurrentKey != null,
                    HasNextKey = env.Value.NextKey != null,
                    BackupKeyCount = env.Value.BackupKeys.Count
                };

                // Key expiration kontrolü
                if (env.Value.CurrentKey != null)
                {
                    var daysToExpiry = (env.Value.CurrentKey.ExpiresAt - DateTime.UtcNow).TotalDays;
                    envHealth.DaysToExpiry = (int)daysToExpiry;
                    envHealth.ExpirationWarning = daysToExpiry <= env.Value.RotationPolicy.WarningDays;
                }

                report.Environments.Add(envHealth);
            }

            logger.LogInformation("Key store validation tamamlandı: {FilePath}, Valid: {IsValid}",
                filePath, report.IsValid);
        }
        catch (Exception ex)
        {
            report.IsValid = false;
            report.ValidationError = ex.Message;
            logger.LogError(ex, "Key store validation başarısız: {FilePath}", filePath);
        }

        return report;
    }
}