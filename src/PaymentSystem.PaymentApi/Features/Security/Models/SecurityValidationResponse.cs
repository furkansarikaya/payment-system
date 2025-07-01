namespace PaymentSystem.PaymentApi.Features.Security.Models;

/// <summary>
/// Security validation response
/// </summary>
public class SecurityValidationResponse
{
    public bool IsValid { get; set; }
    public List<SecurityValidResult> ValidationResults { get; set; } = new();
    public int SecurityScore { get; set; }
    public List<string> Recommendations { get; set; } = new();
}