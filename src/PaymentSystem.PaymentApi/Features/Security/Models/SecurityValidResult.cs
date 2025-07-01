namespace PaymentSystem.PaymentApi.Features.Security.Models;

// <summary>
/// Individual validation result
/// </summary>
public class SecurityValidResult
{
    public string Field { get; set; } = string.Empty;
    public bool IsValid { get; set; }
    public string Message { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty; // info, warning, error
}