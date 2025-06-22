using PaymentSystem.PaymentApi.Features.Encryption.Models;

namespace PaymentSystem.PaymentApi.Features.Encryption.Services;

/// <summary>
/// JSON-based Key Store Service for Payment API
/// JSON key store'dan environment-specific key'leri yükler
/// </summary>
public interface IJsonKeyStoreService
{
    Task<EncryptionConfiguration> GetEncryptionConfigurationAsync(string environment);
    Task<bool> RefreshKeyStoreAsync();
    Task<KeyStoreInfo> GetKeyStoreInfoAsync();
    Task<bool> IsKeyRotationNeededAsync(string environment);
}