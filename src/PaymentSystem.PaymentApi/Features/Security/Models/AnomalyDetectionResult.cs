namespace PaymentSystem.PaymentApi.Features.Security.Models;

// Anomaly detection result models
public class AnomalyDetectionResult
{
    public bool IsAnomalous { get; set; }
    public double RiskScore { get; set; }
    public AnomalyRiskLevel RiskLevel { get; set; }
    public List<DetectedAnomaly> DetectedAnomalies { get; set; } = new();
    public Dictionary<string, double> RiskFactors { get; set; } = new();
    public string RecommendedAction { get; set; } = string.Empty;
    public DateTime AnalyzedAt { get; set; }
    public string? Error { get; set; }
}