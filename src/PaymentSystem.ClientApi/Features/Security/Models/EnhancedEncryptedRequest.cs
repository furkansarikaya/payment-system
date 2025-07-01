namespace PaymentSystem.ClientApi.Features.Security.Models;

public class EnhancedEncryptedRequest
{
    public string EncryptedData { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
    public string RequestId { get; set; } = string.Empty;
    public string Nonce { get; set; } = string.Empty;
    public string? ClientSignature { get; set; }
    public string ClientId { get; set; } = string.Empty;
    public string Priority { get; set; } = "normal";
    public string ClientVersion { get; set; } = "2.0.0";
}