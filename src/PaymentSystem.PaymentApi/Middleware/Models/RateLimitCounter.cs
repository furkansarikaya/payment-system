namespace PaymentSystem.PaymentApi.Middleware.Models;

/// <summary>
/// Rate limit counter for tracking requests
/// </summary>
public class RateLimitCounter
{
    public int Count { get; set; }
    public int BurstUsed { get; set; }
    public DateTime WindowStart { get; set; }
    public DateTime LastRequest { get; set; }
    public int BlockedRequests { get; set; }
}