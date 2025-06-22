namespace PaymentSystem.PaymentApi.Features.Encryption.Models;

public class JsonKeyRotationPolicy
{
    public int RotationIntervalDays { get; set; }
    public int WarningDays { get; set; }
    public int OverlapDays { get; set; }
    public bool AutoRotationEnabled { get; set; }
    public DateTime? LastRotation { get; set; }
    public DateTime? NextRotation { get; set; }
}