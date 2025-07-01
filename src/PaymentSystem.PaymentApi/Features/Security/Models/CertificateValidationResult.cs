using System.Security.Cryptography.X509Certificates;

namespace PaymentSystem.PaymentApi.Features.Security.Models;

/// <summary>
/// Certificate validation result
/// </summary>
public class CertificateValidationResult
{
    public bool IsValid { get; set; }
    public string? ErrorMessage { get; set; }
    public List<string> ValidationErrors { get; set; } = new();
    public List<string> Warnings { get; set; } = new();
    public X509Certificate2? Certificate { get; set; }
    public string ClientIp { get; set; } = string.Empty;
    public DateTime ValidationTimestamp { get; set; }
    public ClientIdentity? ClientIdentity { get; set; }
    public CertificateTrustLevel TrustLevel { get; set; } = CertificateTrustLevel.Standard;
}