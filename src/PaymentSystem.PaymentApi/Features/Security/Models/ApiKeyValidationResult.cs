namespace PaymentSystem.PaymentApi.Features.Security.Models;

/// <summary>
/// API Key validation result
/// </summary>
public class ApiKeyValidationResult
{
    public bool IsValid { get; set; }
    public string? ErrorMessage { get; set; }
    public ApiKeyConfig? ApiKeyConfig { get; set; }
    public bool IsBlocked { get; set; }
    public DateTime? BlockedUntil { get; set; }
}
