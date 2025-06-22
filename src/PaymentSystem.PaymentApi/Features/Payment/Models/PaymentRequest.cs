namespace PaymentSystem.PaymentApi.Features.Payment.Models;

/// <summary>
/// Ödeme talebinin içeriği. Bu model şifrelenmiş veri çözüldükten sonra oluşturulacak.
/// </summary>
public class PaymentRequest
{
    /// <summary>
    /// Kredi kartı bilgileri
    /// </summary>
    public CreditCard CreditCard { get; set; } = new();
        
    /// <summary>
    /// Ödenecek tutar
    /// </summary>
    public decimal Amount { get; set; }
        
    /// <summary>
    /// Para birimi (TRY, USD, EUR vb.)
    /// </summary>
    public string Currency { get; set; } = "TRY";
        
    /// <summary>
    /// İşlem açıklaması
    /// </summary>
    public string Description { get; set; } = string.Empty;
        
    /// <summary>
    /// Müşteri referans numarası
    /// </summary>
    public string CustomerReference { get; set; } = string.Empty;
}