namespace PaymentSystem.PaymentApi.Features.Encryption.Models;

/// <summary>
/// Key store info models
/// </summary>
public class KeyStoreInfo
{
    public string Version { get; set; } = string.Empty;
    public DateTime GeneratedAt { get; set; }
    public DateTime LastRefresh { get; set; }
    public string FilePath { get; set; } = string.Empty;
    public int EnvironmentCount { get; set; }
    public List<EnvironmentKeyInfo> Environments { get; set; } = new();
}