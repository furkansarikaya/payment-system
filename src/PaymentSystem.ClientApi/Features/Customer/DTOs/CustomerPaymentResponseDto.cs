namespace PaymentSystem.ClientApi.Features.Customer.DTOs;

/// <summary>
/// Müşteriye döndürülen ödeme sonucu. Bu DTO hassas bilgi içermez
/// ve güvenle frontend'e gönderilebilir.
/// </summary>
public class CustomerPaymentResponseDto
{
    /// <summary>
    /// İşlem başarılı mı?
    /// </summary>
    public bool IsSuccessful { get; set; }
        
    /// <summary>
    /// Müşteriye gösterilecek mesaj
    /// </summary>
    public string Message { get; set; } = string.Empty;
        
    /// <summary>
    /// İşlem numarası (başarılı işlemler için)
    /// </summary>
    public string? TransactionId { get; set; }
        
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
    /// Hata kategorisi (teknik detay vermeden)
    /// </summary>
    public string? ErrorCategory { get; set; }
}