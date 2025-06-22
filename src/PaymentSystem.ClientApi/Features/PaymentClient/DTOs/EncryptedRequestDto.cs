namespace PaymentSystem.ClientApi.Features.PaymentClient.DTOs;

/// <summary>
/// Payment API'ye gönderilecek şifrelenmiş istek DTO'su
/// Bu Payment API'deki EncryptedRequest modeli ile aynı yapıda olmalı
/// </summary>
public class EncryptedRequestDto
{
    public string EncryptedData { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
    public string RequestId { get; set; } = string.Empty;
}