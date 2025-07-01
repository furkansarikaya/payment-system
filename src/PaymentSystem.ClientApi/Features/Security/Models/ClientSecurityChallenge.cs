namespace PaymentSystem.ClientApi.Features.Security.Models;

/// <summary>
/// Client-side security challenge model
/// </summary>
public class ClientSecurityChallenge
{
    public string Nonce { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
    public int ExpiresIn { get; set; } // Seconds
    public string Algorithm { get; set; } = string.Empty;
    public string Instructions { get; set; } = string.Empty;
    public Dictionary<string, object> Metadata { get; set; } = new();
    public DateTime RequestedAt { get; set; }
    public bool IsUsed { get; set; }
    
    public bool IsExpired => DateTime.UtcNow > RequestedAt.AddSeconds(ExpiresIn);
    public TimeSpan TimeToExpiry => RequestedAt.AddSeconds(ExpiresIn) - DateTime.UtcNow;
}