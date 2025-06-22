using PaymentSystem.KeyManager.Models;

namespace PaymentSystem.KeyManager.Services;

/// <summary>
/// Key Store Management Service Interface
/// JSON dosya yönetimi için contract
/// </summary>
public interface IKeyStoreService
{
    /// <summary>
    /// Key store'u JSON dosyasına kaydet
    /// </summary>
    Task SaveKeyStoreAsync(RsaKeyStore keyStore, string filePath);

    /// <summary>
    /// JSON dosyasından key store'u yükle
    /// </summary>
    Task<RsaKeyStore> LoadKeyStoreAsync(string filePath);

    /// <summary>
    /// Key store backup'ını oluştur
    /// </summary>
    Task<bool> BackupKeyStoreAsync(string sourceFile, string backupDirectory);

    /// <summary>
    /// Multiple key store'ları birleştir
    /// </summary>
    Task<RsaKeyStore> MergeKeyStoresAsync(params string[] filePaths);

    /// <summary>
    /// Key store health check ve validation
    /// </summary>
    Task<KeyStoreHealthReport> ValidateKeyStoreAsync(string filePath);
}