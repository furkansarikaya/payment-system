namespace PaymentSystem.PaymentApi.Features.Encryption.Models;

/// <summary>
/// Hybrid encryption result container
/// </summary>
public class HybridEncryptionResult
{
    public string EncryptedData { get; set; } = string.Empty;      // AES ile şifrelenmiş asıl veri
    public string EncryptedKey { get; set; } = string.Empty;       // RSA ile şifrelenmiş AES key+IV
    public string Algorithm { get; set; } = string.Empty;          // Kullanılan algoritma bilgisi
    public int KeySize { get; set; }                               // RSA key boyutu
    public DateTime Timestamp { get; set; }                       // Şifreleme zamanı
}