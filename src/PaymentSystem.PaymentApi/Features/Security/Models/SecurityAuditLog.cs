namespace PaymentSystem.PaymentApi.Features.Security.Models;

/// <summary>
/// Security audit log entry
/// </summary>
public class SecurityAuditLog
{
    public string Id { get; set; } = Guid.NewGuid().ToString();
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string EventType { get; set; } = string.Empty; // challenge_requested, payment_processed, suspicious_activity
    public string ClientIp { get; set; } = string.Empty;
    public string UserAgent { get; set; } = string.Empty;
    public string ApiKey { get; set; } = string.Empty;
    public string RequestId { get; set; } = string.Empty;
    public string Details { get; set; } = string.Empty;
    public SecurityRiskLevel RiskLevel { get; set; } = SecurityRiskLevel.Low;
}