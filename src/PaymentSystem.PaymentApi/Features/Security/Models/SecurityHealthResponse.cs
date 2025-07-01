namespace PaymentSystem.PaymentApi.Features.Security.Models;

/// <summary>
/// Security health response
/// </summary>
public class SecurityHealthResponse
{
    public string Status { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
    public string ChallengeService { get; set; } = string.Empty;
    public string SecurityService { get; set; } = string.Empty;
    public string RateLimiting { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public List<string>? Warnings { get; set; }
    public List<string>? Errors { get; set; }
}