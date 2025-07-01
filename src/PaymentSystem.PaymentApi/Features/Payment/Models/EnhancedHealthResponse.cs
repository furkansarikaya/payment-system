namespace PaymentSystem.PaymentApi.Features.Payment.Models;

public class EnhancedHealthResponse
{
    public string Status { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
    public string Version { get; set; } = string.Empty;
    public Dictionary<string, string> Services { get; set; } = new();
    public Dictionary<string, object> SecurityStatus { get; set; } = new();
    public Dictionary<string, object> PerformanceMetrics { get; set; } = new();
    public Dictionary<string, object> SystemInfo { get; set; } = new();
    public List<string>? Warnings { get; set; }
    public List<string>? Errors { get; set; }
}