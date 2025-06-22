namespace PaymentSystem.PaymentApi.Features.Encryption.Models;

public class EnvironmentKeyInfo
{
    public string Environment { get; set; } = string.Empty;
    public string? CurrentKeyId { get; set; }
    public int KeySize { get; set; }
    public bool IsActive { get; set; }
    public DateTime? ExpiresAt { get; set; }
    public bool HasNextKey { get; set; }
    public int BackupKeyCount { get; set; }

    public int DaysToExpiry => ExpiresAt.HasValue ? (int)(ExpiresAt.Value - DateTime.UtcNow).TotalDays : 0;
    public bool ExpirationWarning => DaysToExpiry <= 7;
}