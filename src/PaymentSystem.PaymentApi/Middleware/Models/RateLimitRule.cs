namespace PaymentSystem.PaymentApi.Middleware.Models;

/// <summary>
/// Rate limit rule configuration
/// </summary>
public class RateLimitRule
{
    public int RequestsPerMinute { get; set; } = 60;
    public int BurstCapacity { get; set; } = 10;
    public bool IsEnabled { get; set; } = true;
}