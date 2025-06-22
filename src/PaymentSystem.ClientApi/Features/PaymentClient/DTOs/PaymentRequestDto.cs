namespace PaymentSystem.ClientApi.Features.PaymentClient.DTOs;

/// <summary>
/// Client API'de kullanılan ödeme talebi DTO'su. Bu model müşterilerden
/// gelen verileri temsil eder ve Payment API'ye gönderilmek üzere şifrelenecektir.
/// </summary>
public class PaymentRequestDto
{
    /// <summary>
    /// Kredi kartı bilgileri
    /// </summary>
    public CreditCardDto CreditCard { get; set; } = new();
        
    /// <summary>
    /// Ödenecek tutar
    /// </summary>
    public decimal Amount { get; set; }
        
    /// <summary>
    /// Para birimi
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

/// <summary>
/// Client API tarafında kullanılan kredi kartı DTO'su
/// </summary>
public class CreditCardDto
{
    public string CardNumber { get; set; } = string.Empty;
    public string CardHolderName { get; set; } = string.Empty;
    public string ExpiryDate { get; set; } = string.Empty;
    public string CVV { get; set; } = string.Empty;
}