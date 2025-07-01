namespace PaymentSystem.PaymentApi.Features.Security.Models;

/// <summary>
/// Security statistics response
/// </summary>
public class SecurityStatsResponse
{
    public ChallengeStatistics ChallengeStatistics { get; set; } = new();
    public string SystemStatus { get; set; } = string.Empty;
    public DateTime LastUpdated { get; set; }
    public string SecurityLevel { get; set; } = string.Empty;
}