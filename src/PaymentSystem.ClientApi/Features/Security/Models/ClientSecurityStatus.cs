namespace PaymentSystem.ClientApi.Features.Security.Models;

/// <summary>
/// Client security status model
/// </summary>
public class ClientSecurityStatus
{
    public DateTime Timestamp { get; set; }
    public string OverallStatus { get; set; } = string.Empty; // healthy, degraded, unhealthy, error
    public string SecurityLevel { get; set; } = string.Empty;
    public bool ChallengeServiceAvailable { get; set; }
    public bool PaymentApiConnectivity { get; set; }
    public List<string> SecurityFeatures { get; set; } = new();
    public List<string>? Warnings { get; set; }
    public List<string>? Errors { get; set; }
}