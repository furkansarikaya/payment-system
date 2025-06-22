using PaymentSystem.PaymentApi.Features.Payment.DTOs;
using PaymentSystem.PaymentApi.Features.Payment.Models;

namespace PaymentSystem.PaymentApi.Features.Payment.Services;

/// <summary>
/// Ödeme işlemleri için servis arayüzü. Bu arayüz business logic'imizi tanımlar.
/// </summary>
public interface IPaymentService
{
    /// <summary>
    /// Kredi kartı ile ödeme işlemi gerçekleştirir
    /// </summary>
    /// <param name="paymentRequest">Ödeme talebi bilgileri</param>
    /// <returns>İşlem sonucu</returns>
    Task<PaymentResponseDto> ProcessPaymentAsync(PaymentRequest paymentRequest);
        
    /// <summary>
    /// Kredi kartı bilgilerinin geçerliliğini kontrol eder
    /// </summary>
    /// <param name="creditCard">Kontrol edilecek kredi kartı</param>
    /// <returns>Kart geçerli mi?</returns>
    bool ValidateCreditCard(CreditCard creditCard);
}