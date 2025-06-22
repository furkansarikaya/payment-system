namespace PaymentSystem.KeyManager.Models;

public class EnvironmentConfig
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public int KeySize { get; set; } = 2048;
    public int RotationIntervalDays { get; set; } = 90;
    public int WarningDays { get; set; } = 7;
    public bool AutoRotationEnabled { get; set; } = false;
    public bool GenerateNextKey { get; set; } = true;
    public int BackupKeyCount { get; set; } = 2;
}