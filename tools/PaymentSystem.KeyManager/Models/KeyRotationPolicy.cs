using System.Text.Json.Serialization;

namespace PaymentSystem.KeyManager.Models;

/// <summary>
/// Key rotation policy
/// </summary>
public class KeyRotationPolicy
{
    [JsonPropertyName("rotationIntervalDays")]
    public int RotationIntervalDays { get; set; } = 90; // 3 ayda bir rotation

    [JsonPropertyName("warningDays")]
    public int WarningDays { get; set; } = 7; // 7 gün önceden uyarı

    [JsonPropertyName("overlapDays")]
    public int OverlapDays { get; set; } = 30; // 30 gün overlap period

    [JsonPropertyName("autoRotationEnabled")]
    public bool AutoRotationEnabled { get; set; } = false;

    [JsonPropertyName("lastRotation")]
    public DateTime? LastRotation { get; set; }

    [JsonPropertyName("nextRotation")]
    public DateTime? NextRotation { get; set; }
}