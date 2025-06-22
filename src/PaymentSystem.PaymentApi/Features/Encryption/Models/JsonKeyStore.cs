namespace PaymentSystem.PaymentApi.Features.Encryption.Models;

/// <summary>
/// Key store models for JSON deserialization
/// </summary>
public class JsonKeyStore
{
    public string Version { get; set; } = string.Empty;
    public DateTime GeneratedAt { get; set; }
    public string GeneratedBy { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public Dictionary<string, JsonEnvironmentKeys> Environments { get; set; } = new();
    public List<JsonRsaKeyPair> ArchivedKeys { get; set; } = new();
}