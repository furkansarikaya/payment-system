namespace PaymentSystem.PaymentApi.Features.Encryption.Models;

/// <summary>
/// JSON Key Store configuration options
/// </summary>
public class JsonKeyStoreOptions
{
    public string KeyStoreFilePath { get; set; } = "keys/payment-keys.json";
    public int RefreshIntervalMinutes { get; set; } = 30;
    public int RequestTimeoutMinutes { get; set; } = 5;
    public string DefaultEnvironment { get; set; } = "development";
}