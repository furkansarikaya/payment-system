namespace PaymentSystem.PaymentApi.Features.Security.Models;

/// <summary>
/// Security validation result
/// </summary>
public class SecurityValidationResult
{
    public bool IsValid { get; set; }
    public List<string> ValidationErrors { get; set; } = new();
    public SecurityRiskLevel RiskLevel { get; set; } = SecurityRiskLevel.Low;
    public bool RequiresAdditionalVerification { get; set; }
    public string? RecommendedAction { get; set; }
}