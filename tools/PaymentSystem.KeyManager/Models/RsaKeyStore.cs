using System.Text.Json.Serialization;

namespace PaymentSystem.KeyManager.Models;

/// <summary>
/// Key Store - Tüm key'leri organize eder
/// </summary>
public class RsaKeyStore
{
    [JsonPropertyName("version")]
    public string Version { get; set; } = "1.0.0";

    [JsonPropertyName("generatedAt")]
    public DateTime GeneratedAt { get; set; }

    [JsonPropertyName("generatedBy")]
    public string GeneratedBy { get; set; } = "PaymentSystem.KeyManager";

    [JsonPropertyName("description")]
    public string Description { get; set; } = "RSA Key Management for Payment System";

    [JsonPropertyName("environments")]
    public Dictionary<string, EnvironmentKeys> Environments { get; set; } = new();

    [JsonPropertyName("archivedKeys")]
    public List<RsaKeyPair> ArchivedKeys { get; set; } = new();
}