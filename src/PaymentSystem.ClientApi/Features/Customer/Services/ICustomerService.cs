using PaymentSystem.ClientApi.Features.Customer.DTOs;

namespace PaymentSystem.ClientApi.Features.Customer.Services;

/// <summary>
/// Müşteri işlemleri için servis arayüzü. Bu servis customer-facing
/// business logic'i yönetir.
/// </summary>
public interface ICustomerService
{
    /// <summary>
    /// Müşteri ödeme talebini işler ve Payment API'ye yönlendirir
    /// </summary>
    /// <param name="request">Müşteri ödeme talebi</param>
    /// <returns>İşlem sonucu</returns>
    Task<CustomerPaymentResponseDto> ProcessCustomerPaymentAsync(CustomerPaymentRequestDto request);
        
    /// <summary>
    /// Müşteri verilerinin geçerliliğini kontrol eder
    /// </summary>
    /// <param name="request">Kontrol edilecek istek</param>
    /// <returns>Validasyon sonucu ve hata mesajları</returns>
    (bool IsValid, List<string> Errors) ValidateCustomerRequest(CustomerPaymentRequestDto request);
}