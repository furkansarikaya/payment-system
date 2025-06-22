using System.Text.RegularExpressions;
using PaymentSystem.ClientApi.Features.Customer.DTOs;
using PaymentSystem.ClientApi.Features.PaymentClient.DTOs;
using PaymentSystem.ClientApi.Features.PaymentClient.Services;

namespace PaymentSystem.ClientApi.Features.Customer.Services;

/// <summary>
/// Müşteri işlemlerini yöneten servis. Bu sınıf customer-facing business logic'i
/// içerir ve PaymentClientService ile Payment API arasındaki köprü görevi görür.
/// 
/// Sorumlulukları:
/// 1. Müşteri verilerini validate etmek
/// 2. DTO'ları dönüştürmek (Customer -> PaymentClient)
/// 3. Hata mesajlarını müşteri dostu hale getirmek
/// 4. Audit log'lama yapmak
/// </summary>
public class CustomerService(
    IPaymentClientService paymentClientService,
    ILogger<CustomerService> logger)
    : ICustomerService
{
    /// <summary>
    /// Müşteri ödeme talebini işler. Bu metod müşteri deneyimini optimize etmek
    /// için hata mesajlarını kullanıcı dostu hale getirir ve teknik detayları gizler.
    /// </summary>
    public async Task<CustomerPaymentResponseDto> ProcessCustomerPaymentAsync(CustomerPaymentRequestDto request)
    {
        try
        {
            // 1. Müşteri verilerini validate et
            var (isValid, errors) = ValidateCustomerRequest(request);
            if (!isValid)
            {
                logger.LogWarning("Müşteri isteği geçersiz: {Errors}, Email: {Email}",
                    string.Join(", ", errors), request.CustomerEmail);

                return new CustomerPaymentResponseDto
                {
                    IsSuccessful = false,
                    Message = "Lütfen form bilgilerini kontrol ediniz: " + string.Join(", ", errors),
                    ErrorCategory = "VALIDATION_ERROR",
                    ProcessedAt = DateTime.UtcNow
                };
            }

            // 2. Customer DTO'yu PaymentClient DTO'ya çevir
            var paymentRequest = MapToPaymentRequest(request);

            // 3. Payment API'ye gönder
            logger.LogInformation("Müşteri ödemesi işleniyor: {Email}, Tutar: {Amount} {Currency}",
                request.CustomerEmail, request.Amount, request.Currency);

            var paymentResponse = await paymentClientService.ProcessPaymentAsync(paymentRequest);

            // 4. Payment API yanıtını customer response'a çevir
            var customerResponse = MapToCustomerResponse(paymentResponse, request);

            // 5. Sonucu logla (hassas bilgi olmadan)
            if (customerResponse.IsSuccessful)
            {
                logger.LogInformation("Müşteri ödemesi başarılı: {Email}, TransactionId: {TransactionId}",
                    request.CustomerEmail, customerResponse.TransactionId);
            }
            else
            {
                logger.LogWarning("Müşteri ödemesi başarısız: {Email}, Category: {Category}",
                    request.CustomerEmail, customerResponse.ErrorCategory);
            }

            return customerResponse;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Müşteri ödeme işlemi sırasında beklenmeyen hata: {Email}", request.CustomerEmail);

            return new CustomerPaymentResponseDto
            {
                IsSuccessful = false,
                Message = "İşlem sırasında teknik bir sorun oluştu. Lütfen daha sonra tekrar deneyiniz.",
                ErrorCategory = "SYSTEM_ERROR",
                ProcessedAt = DateTime.UtcNow
            };
        }
    }

    /// <summary>
    /// Müşteri verilerinin kapsamlı validasyonunu yapar. Bu metod hem güvenlik
    /// hem de kullanıcı deneyimi açısından kritik öneme sahiptir.
    /// </summary>
    public (bool IsValid, List<string> Errors) ValidateCustomerRequest(CustomerPaymentRequestDto request)
    {
        var errors = new List<string>();

        switch (request.Amount)
        {
            // Tutar kontrolü
            case <= 0:
                errors.Add("Geçerli bir tutar giriniz");
                break;
            // İş kuralı: maksimum işlem limiti
            case > 50000:
                errors.Add("Maksimum işlem tutarı 50.000 TL'dir");
                break;
        }

        // Para birimi kontrolü
        var validCurrencies = new[] { "TRY", "USD", "EUR" };
        if (!validCurrencies.Contains(request.Currency?.ToUpperInvariant()))
        {
            errors.Add("Geçersiz para birimi");
        }

        // E-posta kontrolü
        if (string.IsNullOrWhiteSpace(request.CustomerEmail) ||
            !IsValidEmail(request.CustomerEmail))
        {
            errors.Add("Geçerli bir e-posta adresi giriniz");
        }

        // Kredi kartı validasyonu
        var cardErrors = ValidateCreditCard(request.CreditCard);
        errors.AddRange(cardErrors);

        // Açıklama kontrolü (iş kuralı)
        if (string.IsNullOrWhiteSpace(request.Description))
        {
            errors.Add("İşlem açıklaması giriniz");
        }

        return (errors.Count == 0, errors);
    }

    /// <summary>
    /// Kredi kartı bilgilerinin detaylı validasyonunu yapar
    /// </summary>
    private List<string> ValidateCreditCard(CustomerCreditCardDto creditCard)
    {
        var errors = new List<string>();

        // Kart numarası kontrolü
        if (string.IsNullOrWhiteSpace(creditCard.CardNumber))
        {
            errors.Add("Kart numarası giriniz");
        }
        else
        {
            var cleanCardNumber = creditCard.CardNumber.Replace(" ", "").Replace("-", "");
            if (!Regex.IsMatch(cleanCardNumber, @"^\d{16}$", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(5)))
            {
                errors.Add("Kart numarası 16 haneli olmalıdır");
            }
        }

        // Kart sahibi adı kontrolü
        if (string.IsNullOrWhiteSpace(creditCard.CardHolderName))
        {
            errors.Add("Kart sahibi adı giriniz");
        }
        else if (creditCard.CardHolderName.Length < 3)
        {
            errors.Add("Kart sahibi adı çok kısa");
        }

        // Son kullanma tarihi kontrolü
        if (string.IsNullOrWhiteSpace(creditCard.ExpiryDate))
        {
            errors.Add("Son kullanma tarihi giriniz");
        }
        else if (!IsValidExpiryDate(creditCard.ExpiryDate))
        {
            errors.Add("Geçerli bir son kullanma tarihi giriniz (AA/YY)");
        }

        // CVV kontrolü
        if (string.IsNullOrWhiteSpace(creditCard.CVV))
        {
            errors.Add("CVV kodu giriniz");
        }
        else if (!Regex.IsMatch(creditCard.CVV, @"^\d{3}$", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(5)))
        {
            errors.Add("CVV kodu 3 haneli olmalıdır");
        }

        return errors;
    }

    /// <summary>
    /// E-posta format kontrolü
    /// </summary>
    private static bool IsValidEmail(string email)
    {
        return Regex.IsMatch(email, @"^[^\s@]+@[^\s@]+\.[^\s@]+$",
            RegexOptions.IgnoreCase, TimeSpan.FromSeconds(5));
    }

    /// <summary>
    /// Son kullanma tarihi geçerlilik kontrolü
    /// </summary>
    private static bool IsValidExpiryDate(string expiryDate)
    {
        if (!Regex.IsMatch(expiryDate, @"^\d{2}/\d{2}$", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(5)))
            return false;

        var parts = expiryDate.Split('/');
        if (!int.TryParse(parts[0], out var month) || !int.TryParse(parts[1], out var year))
            return false;

        if (month is < 1 or > 12)
            return false;

        year += 2000;
        var expiryDateTime = new DateTime(year, month, 1).AddMonths(1).AddDays(-1);
        return expiryDateTime >= DateTime.Now.Date;
    }

    /// <summary>
    /// Customer DTO'yu PaymentClient DTO'ya dönüştürür
    /// </summary>
    private static PaymentRequestDto MapToPaymentRequest(CustomerPaymentRequestDto request)
    {
        return new PaymentRequestDto
        {
            CreditCard = new CreditCardDto
            {
                CardNumber = request.CreditCard.CardNumber,
                CardHolderName = request.CreditCard.CardHolderName,
                ExpiryDate = request.CreditCard.ExpiryDate,
                CVV = request.CreditCard.CVV
            },
            Amount = request.Amount,
            Currency = request.Currency,
            Description = request.Description,
            CustomerReference = $"{request.CustomerEmail}_{request.OrderReference}"
        };
    }

    /// <summary>
    /// Payment API yanıtını customer-friendly response'a çevirir
    /// </summary>
    private CustomerPaymentResponseDto MapToCustomerResponse(PaymentResponseDto paymentResponse, CustomerPaymentRequestDto originalRequest)
    {
        // Hata kodlarını müşteri dostu kategorilere çevir
        var errorCategory = paymentResponse.ErrorCode switch
        {
            "INVALID_CARD" => "CARD_ERROR",
            "INVALID_AMOUNT" => "AMOUNT_ERROR",
            "TECHNICAL_ERROR" or "SYSTEM_ERROR" => "SYSTEM_ERROR",
            "KEY_UNAVAILABLE" or "DECRYPTION_FAILED" => "SYSTEM_ERROR",
            _ => null
        };

        // Müşteri dostu mesajlar
        var message = paymentResponse.IsSuccessful
            ? "Ödemeniz başarıyla tamamlanmıştır."
            : GetCustomerFriendlyMessage(paymentResponse.ErrorCode);

        return new CustomerPaymentResponseDto
        {
            IsSuccessful = paymentResponse.IsSuccessful,
            Message = message,
            TransactionId = paymentResponse.TransactionId,
            ProcessedAt = paymentResponse.ProcessedAt,
            ProcessedAmount = originalRequest.Amount,
            Currency = originalRequest.Currency,
            ErrorCategory = errorCategory
        };
    }

    /// <summary>
    /// Teknik hata kodlarını müşteri dostu mesajlara çevirir
    /// </summary>
    private static string GetCustomerFriendlyMessage(string? errorCode)
    {
        return errorCode switch
        {
            "INVALID_CARD" => "Kredi kartı bilgileri geçersiz. Lütfen kontrol ediniz.",
            "INVALID_AMOUNT" => "İşlem tutarı geçersiz.",
            "TECHNICAL_ERROR" or "SYSTEM_ERROR" => "Sistem hatası oluştu. Lütfen daha sonra tekrar deneyiniz.",
            "KEY_UNAVAILABLE" => "Sistem geçici olarak hizmet verememektedir. Lütfen daha sonra tekrar deneyiniz.",
            _ => "İşlem tamamlanamadı. Lütfen daha sonra tekrar deneyiniz."
        };
    }
}