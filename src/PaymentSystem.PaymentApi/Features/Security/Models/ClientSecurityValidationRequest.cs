namespace PaymentSystem.PaymentApi.Features.Security.Models;

/// <summary>
/// Client security validation request
/// </summary>
public class ClientSecurityValidationRequest
{
    public string? Nonce { get; set; }
    public DateTime? Timestamp { get; set; }
    public string? Signature { get; set; }
    public string? RequestId { get; set; }
    public string? ClientVersion { get; set; }
}