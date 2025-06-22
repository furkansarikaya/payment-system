namespace PaymentSystem.ClientApi.Features.PaymentClient.Models;

/// <summary>
/// Client-side hybrid encryption result (same structure as server)
/// </summary>
public class ClientHybridEncryptionResult
{
    public string EncryptedData { get; set; } = string.Empty;
    public string EncryptedKey { get; set; } = string.Empty;
    public string Algorithm { get; set; } = string.Empty;
    public int KeySize { get; set; }
    public DateTime Timestamp { get; set; }
}
