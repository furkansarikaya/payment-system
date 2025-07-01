using PaymentSystem.PaymentApi.Features.Payment.Models;

namespace PaymentSystem.PaymentApi.Features.Payment.DTOs;

public class EnhancedPaymentResponseDto : PaymentResponseDto
{
    public PaymentSecurityMetadata SecurityMetadata { get; set; } = new();
    public Dictionary<string, object> PerformanceMetadata { get; set; } = new();
}