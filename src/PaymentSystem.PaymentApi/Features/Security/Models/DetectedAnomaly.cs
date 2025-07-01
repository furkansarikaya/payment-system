namespace PaymentSystem.PaymentApi.Features.Security.Models;

public class DetectedAnomaly
{
    public string Type { get; set; } = string.Empty;
    public AnomalySeverity Severity { get; set; }
    public string Description { get; set; } = string.Empty;
    public double Confidence { get; set; }
    public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
}
