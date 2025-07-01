namespace PaymentSystem.PaymentApi.Features.Security.Models;

/// <summary>
/// Challenge Response DTO - Client'a döndürülen format
/// </summary>
public class ChallengeResponseDto
{
    public string Nonce { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
    public int ExpiresIn { get; set; } // Seconds
    public string Algorithm { get; set; } = "HMAC-SHA256";
    public string Instructions { get; set; } = "Include this nonce in your payment request";
    public Dictionary<string, object> Metadata { get; set; } = new();
}