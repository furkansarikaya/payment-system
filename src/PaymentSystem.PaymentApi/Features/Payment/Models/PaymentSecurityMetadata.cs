namespace PaymentSystem.PaymentApi.Features.Payment.Models;

public class PaymentSecurityMetadata
{
    public string RequestId { get; set; } = string.Empty;
    public bool SecurityValidationPassed { get; set; }
    public double AnomalyScore { get; set; }
    public string RiskLevel { get; set; } = string.Empty;
    public string SecurityVersion { get; set; } = string.Empty;
    public DateTime ProcessingTime { get; set; }
    public List<string> ComplianceFlags { get; set; } = new();
}