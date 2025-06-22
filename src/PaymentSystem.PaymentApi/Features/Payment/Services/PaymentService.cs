using System.Text.RegularExpressions;
using PaymentSystem.PaymentApi.Features.Payment.DTOs;
using PaymentSystem.PaymentApi.Features.Payment.Models;

namespace PaymentSystem.PaymentApi.Features.Payment.Services;

/// <summary>
/// Ödeme işlemlerini yöneten ana servis sınıfımız. Bu sınıf gerçek hayatta
/// bir payment gateway (Stripe, PayPal, İyzico vb.) ile entegre olur.
/// Şu an demo amaçlı basit bir implementasyon yapıyoruz.
/// </summary>
public class PaymentService(ILogger<PaymentService> logger) : IPaymentService
{
    /// <summary>
    /// Kredi kartı ile ödeme işlemini gerçekleştirir. Gerçek hayatta bu metod
    /// bir payment gateway'e istek atacak ve sonucu bekleyecektir.
    /// </summary>
    public async Task<PaymentResponseDto> ProcessPaymentAsync(PaymentRequest paymentRequest)
    {
        try
        {
            // Öncelikle kredi kartının geçerliliğini kontrol ediyoruz
            if (!ValidateCreditCard(paymentRequest.CreditCard))
            {
                logger.LogWarning("Geçersiz kredi kartı ile ödeme denemesi: {CustomerRef}",
                    paymentRequest.CustomerReference);

                return new PaymentResponseDto
                {
                    IsSuccessful = false,
                    Message = "Geçersiz kredi kartı bilgileri",
                    ErrorCode = "INVALID_CARD",
                    ProcessedAt = DateTime.UtcNow
                };
            }

            // Tutar kontrolü - negatif veya sıfır olamaz
            if (paymentRequest.Amount <= 0)
            {
                return new PaymentResponseDto
                {
                    IsSuccessful = false,
                    Message = "Geçersiz tutar",
                    ErrorCode = "INVALID_AMOUNT",
                    ProcessedAt = DateTime.UtcNow
                };
            }

            // Gerçek hayatta burada payment gateway'e istek atılır
            // Şimdilik demo amaçlı başarılı sonuç döndürüyoruz
            await SimulatePaymentGatewayCall();

            // Başarılı işlem için benzersiz transaction ID oluştur
            var transactionId = GenerateTransactionId();

            logger.LogInformation("Ödeme işlemi başarılı: {TransactionId}, Tutar: {Amount} {Currency}",
                transactionId, paymentRequest.Amount, paymentRequest.Currency);

            return new PaymentResponseDto
            {
                IsSuccessful = true,
                TransactionId = transactionId,
                Message = "Ödeme başarıyla tamamlandı",
                ProcessedAt = DateTime.UtcNow,
                ProcessedAmount = paymentRequest.Amount,
                Currency = paymentRequest.Currency
            };
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Ödeme işlemi sırasında hata oluştu: {CustomerRef}",
                paymentRequest.CustomerReference);

            return new PaymentResponseDto
            {
                IsSuccessful = false,
                Message = "Ödeme işlemi sırasında teknik hata oluştu",
                ErrorCode = "TECHNICAL_ERROR",
                ProcessedAt = DateTime.UtcNow
            };
        }
    }

    /// <summary>
    /// Kredi kartı bilgilerinin format ve geçerlilik kontrolünü yapar.
    /// Bu metod Luhn algoritması gibi gelişmiş kontroller de içerebilir.
    /// </summary>
    public bool ValidateCreditCard(CreditCard creditCard)
    {
        // Kart numarası kontrolü - 16 haneli sayı olmalı
        if (string.IsNullOrWhiteSpace(creditCard.CardNumber) ||
            !Regex.IsMatch(creditCard.CardNumber.Replace(" ", ""), @"^\d{16}$", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(5)))
        {
            return false;
        }

        // Kart sahibi ismi kontrolü - boş olamaz
        if (string.IsNullOrWhiteSpace(creditCard.CardHolderName))
        {
            return false;
        }

        // Son kullanma tarihi kontrolü - MM/YY formatında olmalı ve gelecekte olmalı
        if (!IsValidExpiryDate(creditCard.ExpiryDate))
        {
            return false;
        }

        // CVV kontrolü - 3 haneli sayı olmalı
        return !string.IsNullOrWhiteSpace(creditCard.CVV) &&
               Regex.IsMatch(creditCard.CVV, @"^\d{3}$", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(5));
        // Tüm kontroller başarılı
    }

    /// <summary>
    /// Son kullanma tarihinin geçerliliğini kontrol eder
    /// </summary>
    private static bool IsValidExpiryDate(string expiryDate)
    {
        if (string.IsNullOrWhiteSpace(expiryDate) ||
            !Regex.IsMatch(expiryDate, @"^\d{2}/\d{2}$", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(5)))
        {
            return false;
        }

        var parts = expiryDate.Split('/');
        if (!int.TryParse(parts[0], out var month) ||
            !int.TryParse(parts[1], out var year))
        {
            return false;
        }

        // Ay 1-12 arasında olmalı
        if (month is < 1 or > 12)
        {
            return false;
        }

        // Yıl kontrolü - 2000'li yıllara çeviriyoruz (YY -> 20YY)
        year += 2000;
        var expiryDateTime = new DateTime(year, month, 1).AddMonths(1).AddDays(-1);

        // Kartın süresi dolmuş mu?
        return expiryDateTime >= DateTime.Now.Date;
    }

    /// <summary>
    /// Payment gateway çağrısını simüle eder. Gerçek hayatta bu metod
    /// HTTP client ile dış servise istek atacaktır.
    /// </summary>
    private static async Task SimulatePaymentGatewayCall()
    {
        // Gerçekçi bir işlem süresi simüle ediyoruz
        await Task.Delay(Random.Shared.Next(500, 2000));

        // Gerçek hayatta burada başarısız işlemler de olabilir
        // Demo için %95 başarı oranı simüle edebiliriz
        if (Random.Shared.Next(1, 101) <= 5) // %5 başarısızlık
        {
            throw new InvalidOperationException("Payment gateway hatası");
        }
    }

    /// <summary>
    /// Benzersiz transaction ID oluşturur
    /// </summary>
    private static string GenerateTransactionId()
    {
        return $"TXN_{DateTime.UtcNow:yyyyMMddHHmmss}_{Guid.NewGuid():N}"[..24];
    }
}