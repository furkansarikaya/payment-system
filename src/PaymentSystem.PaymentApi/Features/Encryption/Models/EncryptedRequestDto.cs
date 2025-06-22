namespace PaymentSystem.PaymentApi.Features.Encryption.Models;

public class EncryptedRequestDto
{
    public string EncryptedData { get; set; } = string.Empty; // Şifrelenmiş veri
    public string RequestId { get; set; } = string.Empty;    // Request ID
    public DateTime Timestamp { get; set; }                   // Şifreleme zamanı
}