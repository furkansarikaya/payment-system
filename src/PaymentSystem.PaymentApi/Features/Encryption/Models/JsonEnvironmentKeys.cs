namespace PaymentSystem.PaymentApi.Features.Encryption.Models;

public class JsonEnvironmentKeys
{
    public string Environment { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public JsonRsaKeyPair? CurrentKey { get; set; }
    public JsonRsaKeyPair? NextKey { get; set; }
    public List<JsonRsaKeyPair> BackupKeys { get; set; } = new();
    public JsonKeyRotationPolicy RotationPolicy { get; set; } = new();
}