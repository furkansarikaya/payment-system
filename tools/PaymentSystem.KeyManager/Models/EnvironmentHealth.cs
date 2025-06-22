namespace PaymentSystem.KeyManager.Models;

/// <summary>
/// Environment health bilgisi
/// </summary>
public class EnvironmentHealth
{
    public string Environment { get; set; } = string.Empty;
    public bool HasCurrentKey { get; set; }
    public bool HasNextKey { get; set; }
    public int BackupKeyCount { get; set; }
    public int DaysToExpiry { get; set; }
    public bool ExpirationWarning { get; set; }
}