namespace PaymentSystem.PaymentApi.Features.Payment.DTOs;

public class EnhancedPublicKeyResponseDto : PublicKeyResponseDto
{
    public string SecurityLevel { get; set; } = string.Empty;
    public List<string> RequiredHeaders { get; set; } = new();
    public bool ChallengeRequired { get; set; }
    public string ChallengeEndpoint { get; set; } = string.Empty;
    public Dictionary<string, object> PerformanceMetrics { get; set; } = new();
    public Dictionary<string, object> Compliance { get; set; } = new();
}