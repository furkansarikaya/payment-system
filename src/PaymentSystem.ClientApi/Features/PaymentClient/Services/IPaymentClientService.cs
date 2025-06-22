using PaymentSystem.ClientApi.Features.PaymentClient.DTOs;

namespace PaymentSystem.ClientApi.Features.PaymentClient.Services;

/// <summary>
/// Payment API ile iletişim kurmak için servis arayüzü.
/// Bu servis şifreleme ve HTTP istek işlemlerini yönetir.
/// </summary>
public interface IPaymentClientService
{
    /// <summary>
    /// Payment API'den public key'i alır ve önbelleğe kaydeder
    /// </summary>
    /// <returns>Public key alınma durumu</returns>
    Task<bool> RefreshPublicKeyAsync();
        
    /// <summary>
    /// Ödeme isteğini şifreleyip Payment API'ye gönderir
    /// </summary>
    /// <param name="paymentRequest">Ödeme talebi</param>
    /// <returns>Ödeme işlemi sonucu</returns>
    Task<PaymentResponseDto> ProcessPaymentAsync(PaymentRequestDto paymentRequest);
        
    /// <summary>
    /// Mevcut public key'in geçerliliğini kontrol eder
    /// </summary>
    /// <returns>Key geçerli mi?</returns>
    bool IsPublicKeyValid();
}