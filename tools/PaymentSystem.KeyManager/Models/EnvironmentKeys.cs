using System.Text.Json.Serialization;

namespace PaymentSystem.KeyManager.Models;

/// <summary>
/// Environment-specific key organization
/// </summary>
public class EnvironmentKeys
{
    [JsonPropertyName("environment")]
    public string Environment { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    [JsonPropertyName("currentKey")]
    public RsaKeyPair? CurrentKey { get; set; }

    [JsonPropertyName("nextKey")]
    public RsaKeyPair? NextKey { get; set; }  // Key rotation için

    [JsonPropertyName("backupKeys")]
    public List<RsaKeyPair> BackupKeys { get; set; } = new();

    [JsonPropertyName("keyRotationPolicy")]
    public KeyRotationPolicy RotationPolicy { get; set; } = new();
}