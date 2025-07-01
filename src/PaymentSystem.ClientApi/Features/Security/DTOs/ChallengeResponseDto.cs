namespace PaymentSystem.ClientApi.Features.Security.DTOs;

/// <summary>
/// Challenge response from Payment API
/// </summary>
public class ChallengeResponseDto
{
    public string Nonce { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
    public int ExpiresIn { get; set; }
    public string Algorithm { get; set; } = string.Empty;
    public string Instructions { get; set; } = string.Empty;
    public Dictionary<string, object> Metadata { get; set; } = new();
}