using System.Security.Cryptography.X509Certificates;
using PaymentSystem.PaymentApi.Features.Security.Models;

namespace PaymentSystem.PaymentApi.Features.Security.Services;

/// <summary>
/// TLS Client Certificate Authentication Service Interface
/// 
/// Bu servis Mutual TLS (mTLS) authentication sağlar:
/// - Client certificate validation
/// - Certificate chain verification  
/// - Revocation checking
/// - Certificate pinning
/// - Client identity mapping
/// 
/// Bu en güçlü network-level authentication'dır.
/// Public key + API key ele geçse bile, geçerli client certificate olmadan erişim IMKANSIZ.
/// </summary>
public interface ITlsClientCertificateService
{
    /// <summary>
    /// Client certificate'ı validate eder
    /// </summary>
    Task<CertificateValidationResult> ValidateCertificateAsync(X509Certificate2 certificate, string clientIp);
    
    /// <summary>
    /// Certificate'dan client identity'yi extract eder
    /// </summary>
    ClientIdentity ExtractClientIdentity(X509Certificate2 certificate);
    
    /// <summary>
    /// Certificate revocation durumunu kontrol eder
    /// </summary>
    Task<bool> IsCertificateRevokedAsync(X509Certificate2 certificate);
    
    /// <summary>
    /// Certificate pinning kontrolü yapar
    /// </summary>
    bool ValidateCertificatePinning(X509Certificate2 certificate, string expectedThumbprint);
    
    /// <summary>
    /// Certificate expiration warning kontrolü
    /// </summary>
    CertificateExpirationStatus CheckCertificateExpiration(X509Certificate2 certificate);
}