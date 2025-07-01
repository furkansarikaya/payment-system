namespace PaymentSystem.PaymentApi.Features.Security.Models;

/// <summary>
/// Rate limiting configuration per API key
/// </summary>
public class RateLimitConfig
{
    /// <summary>
    /// Dakikada kaç istek (default: 60)
    /// </summary>
    public int RequestsPerMinute { get; set; } = 60;
    
    /// <summary>
    /// Saatte kaç istek (default: 1000)
    /// </summary>
    public int RequestsPerHour { get; set; } = 1000;
    
    /// <summary>
    /// Günde kaç istek (default: 10000)
    /// </summary>
    public int RequestsPerDay { get; set; } = 10000;
    
    /// <summary>
    /// Burst capacity - kısa süreli spike'lar için
    /// </summary>
    public int BurstCapacity { get; set; } = 10;
}