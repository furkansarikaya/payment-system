namespace PaymentSystem.ClientApi.Features.Customer.DTOs;

/// <summary>
/// Müşteriden gelen ödeme talebi. Bu DTO web arayüzü veya mobil 
/// uygulamadan gelen form verilerini temsil eder.
/// </summary>
public class CustomerPaymentRequestDto
{
    /// <summary>
    /// Kredi kartı bilgileri - hassas veri
    /// </summary>
    public CustomerCreditCardDto CreditCard { get; set; } = new();
        
    /// <summary>
    /// Ödenecek tutar
    /// </summary>
    public decimal Amount { get; set; }
        
    /// <summary>
    /// Para birimi (TRY, USD, EUR vb.)
    /// </summary>
    public string Currency { get; set; } = "TRY";
        
    /// <summary>
    /// İşlem açıklaması (ürün adı, hizmet tanımı vb.)
    /// </summary>
    public string Description { get; set; } = string.Empty;
        
    /// <summary>
    /// Müşteri e-posta adresi (bilgilendirme için)
    /// </summary>
    public string CustomerEmail { get; set; } = string.Empty;
        
    /// <summary>
    /// Sipariş numarası veya benzersiz referans
    /// </summary>
    public string OrderReference { get; set; } = string.Empty;
}

/// <summary>
/// Müşteri tarafından girilen kredi kartı bilgileri
/// </summary>
public class CustomerCreditCardDto
{
    public string CardNumber { get; set; } = string.Empty;
    public string CardHolderName { get; set; } = string.Empty;
    public string ExpiryDate { get; set; } = string.Empty;
    public string CVV { get; set; } = string.Empty;
}