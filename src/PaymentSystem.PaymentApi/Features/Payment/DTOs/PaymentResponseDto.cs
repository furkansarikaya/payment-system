namespace PaymentSystem.PaymentApi.Features.Payment.DTOs;

/// <summary>
/// Ödeme işlemi sonucu. Bu bilgiler Client API'ye döndürülecek.
/// Hassas bilgi içermediği için şifrelenmiş olarak gönderilmeyecek.
/// </summary>
public class PaymentResponseDto
{
    /// <summary>
    /// İşlem başarılı mı?
    /// </summary>
    public bool IsSuccessful { get; set; }
        
    /// <summary>
    /// İşlem kimliği - başarılı işlemler için benzersiz ID
    /// </summary>
    public string TransactionId { get; set; } = string.Empty;
        
    /// <summary>
    /// İşlem mesajı (başarı/hata durumu açıklaması)
    /// </summary>
    public string Message { get; set; } = string.Empty;
        
    /// <summary>
    /// İşlem tarihi
    /// </summary>
    public DateTime ProcessedAt { get; set; }
        
    /// <summary>
    /// İşlenen tutar (doğrulama için)
    /// </summary>
    public decimal ProcessedAmount { get; set; }
        
    /// <summary>
    /// Para birimi
    /// </summary>
    public string Currency { get; set; } = string.Empty;
        
    /// <summary>
    /// Hata kodu (başarısız işlemler için)
    /// </summary>
    public string? ErrorCode { get; set; }
}