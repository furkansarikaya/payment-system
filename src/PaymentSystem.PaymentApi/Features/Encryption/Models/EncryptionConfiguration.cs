namespace PaymentSystem.PaymentApi.Features.Encryption.Models;

/// <summary>
/// RSA anahtar çiftimiz için konfigürasyon sınıfı
/// </summary>
public class EncryptionConfiguration
{
    public string PublicKey { get; set; } = string.Empty;
    public string PrivateKey { get; set; } = string.Empty;
    public int RequestTimeoutMinutes { get; set; } = 5;
        
    // JSON key store metadata
    public string KeyId { get; set; } = string.Empty;
    public string Environment { get; set; } = string.Empty;
    public int KeySize { get; set; } = 2048;
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
        
    // Computed properties
    public bool IsExpired => DateTime.UtcNow > ExpiresAt;
    public int DaysToExpiry => (int)(ExpiresAt - DateTime.UtcNow).TotalDays;
    public bool ExpirationWarning => DaysToExpiry <= 7;
}