using System.Text.Json.Serialization;

namespace PaymentSystem.KeyManager.Models;

/// <summary>
/// RSA Key Pair Model - JSON storage için
/// </summary>
public class RsaKeyPair
{
    [JsonPropertyName("keyId")]
    public string KeyId { get; set; } = string.Empty;

    [JsonPropertyName("publicKey")]
    public string PublicKey { get; set; } = string.Empty;

    [JsonPropertyName("privateKey")]
    public string PrivateKey { get; set; } = string.Empty;

    [JsonPropertyName("keySize")]
    public int KeySize { get; set; }

    [JsonPropertyName("environment")]
    public string Environment { get; set; } = string.Empty;

    [JsonPropertyName("purpose")]
    public string Purpose { get; set; } = string.Empty;

    [JsonPropertyName("algorithm")]
    public string Algorithm { get; set; } = "RSA";

    [JsonPropertyName("createdAt")]
    public DateTime CreatedAt { get; set; }

    [JsonPropertyName("expiresAt")]
    public DateTime ExpiresAt { get; set; }

    [JsonPropertyName("isActive")]
    public bool IsActive { get; set; }

    [JsonPropertyName("version")]
    public int Version { get; set; }

    [JsonPropertyName("metadata")]
    public Dictionary<string, object> Metadata { get; set; } = new();
}