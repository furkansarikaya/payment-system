namespace PaymentSystem.PaymentApi.Features.Security.Models;

/// <summary>
/// Security configuration response
/// </summary>
public class SecurityConfigResponse
{
    public Dictionary<string, int> ChallengeTimeout { get; set; } = new();
    public Dictionary<string, object> RateLimits { get; set; } = new();
    public List<string> SecurityFeatures { get; set; } = new();
    public Dictionary<string, object> Algorithms { get; set; } = new();
    public List<string> Compliance { get; set; } = new();
}