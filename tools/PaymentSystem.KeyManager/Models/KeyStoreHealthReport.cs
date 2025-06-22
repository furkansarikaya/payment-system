namespace PaymentSystem.KeyManager.Models;

/// <summary>
/// Key store health report
/// </summary>
public class KeyStoreHealthReport
{
    public string FilePath { get; set; } = string.Empty;
    public bool IsValid { get; set; }
    public int EnvironmentCount { get; set; }
    public string? ValidationError { get; set; }
    public List<EnvironmentHealth> Environments { get; set; } = new();
}