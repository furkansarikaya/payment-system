namespace PaymentSystem.ClientApi.Features.PaymentClient.DTOs;

/// <summary>
/// Enhanced PublicKeyResponseDto for client-side
/// </summary>
public class PublicKeyResponseDto
{
    public string PublicKey { get; set; } = string.Empty;
    public DateTime GeneratedAt { get; set; }
    public int ValidityHours { get; set; }
    public int KeySize { get; set; }
    public string Algorithm { get; set; } = string.Empty;
    public string SupportedPadding { get; set; } = string.Empty;
    public int MaxDirectRsaSize { get; set; }
    public bool HybridSupport { get; set; }
    public string RecommendedApproach { get; set; } = string.Empty;
    public Dictionary<string, object> ClientGuidance { get; set; } = new();
}