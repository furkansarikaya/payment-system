namespace PaymentSystem.PaymentApi.Features.Encryption.Models;

public class JsonRsaKeyPair
{
    public string KeyId { get; set; } = string.Empty;
    public string PublicKey { get; set; } = string.Empty;
    public string PrivateKey { get; set; } = string.Empty;
    public int KeySize { get; set; }
    public string Environment { get; set; } = string.Empty;
    public string Purpose { get; set; } = string.Empty;
    public string Algorithm { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public bool IsActive { get; set; }
    public int Version { get; set; }
    public Dictionary<string, object> Metadata { get; set; } = new();
}