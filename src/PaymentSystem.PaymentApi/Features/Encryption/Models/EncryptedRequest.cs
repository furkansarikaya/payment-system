namespace PaymentSystem.PaymentApi.Features.Encryption.Models;

/// <summary>
/// Şifrelenmiş istek modelimiz. İstemcilerden gelen tüm hassas veriler bu formatta gelecek.
/// </summary>
public class EncryptedRequest
{
    /// <summary>
    /// RSA ile şifrelenmiş veri (Base64 formatında)
    /// </summary>
    public string EncryptedData { get; set; } = string.Empty;
        
    /// <summary>
    /// İstek zaman damgası - replay attack'lara karşı koruma için
    /// </summary>
    public DateTime Timestamp { get; set; }
        
    /// <summary>
    /// İstek kimliği - her istek için benzersiz olmalı
    /// </summary>
    public string RequestId { get; set; } = string.Empty;
}