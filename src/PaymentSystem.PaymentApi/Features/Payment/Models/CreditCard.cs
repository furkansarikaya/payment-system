namespace PaymentSystem.PaymentApi.Features.Payment.Models;

/// <summary>
/// Kredi kartı bilgileri modeli. Bu hassas veri her zaman şifrelenmiş olarak gelecek.
/// </summary>
public class CreditCard
{
    /// <summary>
    /// Kredi kartı numarası (16 haneli)
    /// </summary>
    public string CardNumber { get; set; } = string.Empty;
        
    /// <summary>
    /// Kart üzerindeki isim
    /// </summary>
    public string CardHolderName { get; set; } = string.Empty;
        
    /// <summary>
    /// Son kullanma tarihi (MM/YY formatında)
    /// </summary>
    public string ExpiryDate { get; set; } = string.Empty;
        
    /// <summary>
    /// CVV güvenlik kodu (3 haneli)
    /// </summary>
    public string CVV { get; set; } = string.Empty;
}
