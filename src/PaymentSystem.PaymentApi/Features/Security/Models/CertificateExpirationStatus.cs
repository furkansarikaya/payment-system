namespace PaymentSystem.PaymentApi.Features.Security.Models;

/// <summary>
/// Certificate expiration status
/// </summary>
public class CertificateExpirationStatus
{
    public DateTime NotBefore { get; set; }
    public DateTime ExpirationDate { get; set; }
    public bool IsExpired { get; set; }
    public int DaysToExpiration { get; set; }
    public bool ExpiresWithinWarningPeriod { get; set; }
}