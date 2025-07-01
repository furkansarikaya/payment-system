namespace PaymentSystem.PaymentApi.Features.Security.Models;

/// <summary>
/// Rate limit check result
/// </summary>
public class RateLimitResult
{
    public bool IsAllowed { get; set; }
    public int RemainingRequests { get; set; }
    public TimeSpan ResetTime { get; set; }
    public string LimitType { get; set; } = string.Empty; // minute, hour, day
}