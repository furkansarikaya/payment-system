namespace PaymentSystem.ClientApi.Features.PaymentClient.DTOs;

/// <summary>
/// Payment API'den dönen yanıt DTO'su
/// Bu Payment API'deki PaymentResponseDto ile aynı yapıda olmalı
/// </summary>
public class PaymentResponseDto
{
    public bool IsSuccessful { get; set; }
    public string TransactionId { get; set; } = string.Empty;
    public string Message { get; set; } = string.Empty;
    public DateTime ProcessedAt { get; set; }
    public decimal ProcessedAmount { get; set; }
    public string Currency { get; set; } = string.Empty;
    public string? ErrorCode { get; set; }
}