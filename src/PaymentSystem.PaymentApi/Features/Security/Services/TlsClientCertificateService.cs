using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Caching.Memory;
using PaymentSystem.PaymentApi.Features.Security.Models;

namespace PaymentSystem.PaymentApi.Features.Security.Services;

/// <summary>
/// TLS Client Certificate Service Implementation
/// 
/// CRITICAL SECURITY COMPONENT - En güçlü kimlik doğrulama katmanı
/// 
/// Bu servis şunları sağlar:
/// 1. Mutual TLS (mTLS) certificate validation
/// 2. Certificate chain verification
/// 3. Real-time revocation checking (OCSP)
/// 4. Certificate pinning for high-security clients
/// 5. Client identity mapping ve authorization
/// 
/// Security Level: MAXIMUM
/// Use Case: High-value transactions, enterprise clients
/// </summary>
public class TlsClientCertificateService : ITlsClientCertificateService
{
    private readonly ILogger<TlsClientCertificateService> _logger;
    private readonly IMemoryCache _cache;
    private readonly IConfiguration _configuration;
    private readonly ISecurityService _securityService;
    
    // Trusted certificate authorities
    private readonly HashSet<string> _trustedCaThumbprints;
    
    // Certificate pinning for high-security clients
    private readonly Dictionary<string, string> _pinnedCertificates;
    
    // Certificate cache for performance
    private readonly TimeSpan _validationCacheTtl = TimeSpan.FromMinutes(10);

    /// <summary>
    /// Constructor
    /// </summary>
    public TlsClientCertificateService(
        ILogger<TlsClientCertificateService> logger,
        IMemoryCache cache,
        IConfiguration configuration,
        ISecurityService securityService)
    {
        _logger = logger;
        _cache = cache;
        _configuration = configuration;
        _securityService = securityService;

        // Load trusted CAs from configuration
        _trustedCaThumbprints = LoadTrustedCertificateAuthorities();
        
        // Load pinned certificates for high-security clients
        _pinnedCertificates = LoadPinnedCertificates();
    }

    /// <summary>
    /// Comprehensive client certificate validation
    /// </summary>
    public async Task<CertificateValidationResult> ValidateCertificateAsync(X509Certificate2 certificate, string clientIp)
    {
        try
        {
            var validationResult = new CertificateValidationResult
            {
                Certificate = certificate,
                ClientIp = clientIp,
                ValidationTimestamp = DateTime.UtcNow
            };

            _logger.LogInformation("Starting TLS client certificate validation: Subject={Subject}, Issuer={Issuer}, IP={ClientIp}",
                certificate.Subject, certificate.Issuer, clientIp);

            // 1. Basic certificate properties validation
            if (!ValidateBasicCertificateProperties(certificate, validationResult))
            {
                return validationResult;
            }

            // 2. Certificate chain validation
            if (!await ValidateCertificateChainAsync(certificate, validationResult))
            {
                return validationResult;
            }

            // 3. Certificate expiration check
            var expirationStatus = CheckCertificateExpiration(certificate);
            if (expirationStatus.IsExpired)
            {
                validationResult.IsValid = false;
                validationResult.ErrorMessage = "Certificate has expired";
                validationResult.ValidationErrors.Add($"Certificate expired on {expirationStatus.ExpirationDate}");
                return validationResult;
            }

            if (expirationStatus.ExpiresWithinWarningPeriod)
            {
                validationResult.Warnings.Add($"Certificate expires in {expirationStatus.DaysToExpiration} days");
            }

            // 4. Revocation checking (OCSP/CRL)
            var cacheKey = $"cert_revocation:{certificate.Thumbprint}";
            var isRevoked = await _cache.GetOrCreateAsync(cacheKey, async entry =>
            {
                entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(30);
                return await IsCertificateRevokedAsync(certificate);
            });

            if (isRevoked)
            {
                validationResult.IsValid = false;
                validationResult.ErrorMessage = "Certificate has been revoked";
                validationResult.ValidationErrors.Add("Certificate appears on revocation list");
                
                await LogCertificateSecurityEvent("certificate_revoked", certificate, clientIp, SecurityRiskLevel.Critical);
                return validationResult;
            }

            // 5. Certificate pinning validation (for high-security clients)
            var clientIdentity = ExtractClientIdentity(certificate);
            if (clientIdentity.IsHighSecurityClient)
            {
                var expectedThumbprint = GetExpectedCertificateThumbprint(clientIdentity.ClientId);
                if (!string.IsNullOrEmpty(expectedThumbprint))
                {
                    if (!ValidateCertificatePinning(certificate, expectedThumbprint))
                    {
                        validationResult.IsValid = false;
                        validationResult.ErrorMessage = "Certificate pinning validation failed";
                        validationResult.ValidationErrors.Add("Certificate does not match pinned certificate");
                        
                        await LogCertificateSecurityEvent("certificate_pinning_failed", certificate, clientIp, SecurityRiskLevel.Critical);
                        return validationResult;
                    }
                }
            }

            // 6. Client identity validation
            if (!ValidateClientIdentity(clientIdentity, validationResult))
            {
                return validationResult;
            }

            // 7. IP address consistency check
            if (!ValidateIpConsistency(clientIdentity, clientIp, validationResult))
            {
                return validationResult;
            }

            // 8. Success
            validationResult.IsValid = true;
            validationResult.ClientIdentity = clientIdentity;
            validationResult.TrustLevel = DetermineTrustLevel(certificate, clientIdentity);

            await LogCertificateSecurityEvent("certificate_validated_successfully", certificate, clientIp, SecurityRiskLevel.Low);

            _logger.LogInformation("TLS client certificate validation successful: Subject={Subject}, ClientId={ClientId}, TrustLevel={TrustLevel}",
                certificate.Subject, clientIdentity.ClientId, validationResult.TrustLevel);

            return validationResult;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "TLS client certificate validation failed: Subject={Subject}, IP={ClientIp}",
                certificate.Subject, clientIp);

            return new CertificateValidationResult
            {
                Certificate = certificate,
                ClientIp = clientIp,
                IsValid = false,
                ErrorMessage = "Certificate validation failed due to internal error",
                ValidationErrors = new List<string> { "Internal certificate validation error" },
                ValidationTimestamp = DateTime.UtcNow
            };
        }
    }

    /// <summary>
    /// Extract client identity from certificate
    /// </summary>
    public ClientIdentity ExtractClientIdentity(X509Certificate2 certificate)
    {
        try
        {
            var identity = new ClientIdentity
            {
                CertificateSubject = certificate.Subject,
                CertificateIssuer = certificate.Issuer,
                CertificateThumbprint = certificate.Thumbprint,
                CertificateSerialNumber = certificate.SerialNumber,
                // Extract client ID from certificate Subject or SAN
                ClientId = ExtractClientIdFromCertificate(certificate),
                // Extract organization information
                OrganizationName = ExtractOrganizationFromSubject(certificate.Subject),
                // Determine client type and security level
                ClientType = DetermineClientType(certificate)
            };

            identity.IsHighSecurityClient = IsHighSecurityClient(identity.ClientId, identity.OrganizationName);

            // Extract allowed IP ranges from certificate extensions (if any)
            identity.AllowedIpRanges = ExtractAllowedIpRanges(certificate);

            _logger.LogDebug("Client identity extracted: ClientId={ClientId}, Organization={Organization}, Type={Type}",
                identity.ClientId, identity.OrganizationName, identity.ClientType);

            return identity;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to extract client identity from certificate: {Subject}", certificate.Subject);
            
            return new ClientIdentity
            {
                CertificateSubject = certificate.Subject,
                CertificateIssuer = certificate.Issuer,
                CertificateThumbprint = certificate.Thumbprint,
                ClientId = "unknown",
                IsValid = false
            };
        }
    }

    /// <summary>
    /// Check if certificate is revoked using OCSP/CRL
    /// </summary>
    public async Task<bool> IsCertificateRevokedAsync(X509Certificate2 certificate)
    {
        try
        {
            _logger.LogDebug("Checking certificate revocation status: {Thumbprint}", certificate.Thumbprint);

            // Build certificate chain for validation
            using var chain = new X509Chain();
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chain.ChainPolicy.VerificationTime = DateTime.Now;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;

            // Perform chain validation which includes revocation checking
            var chainIsValid = chain.Build(certificate);

            if (!chainIsValid)
            {
                // Check for revocation-specific errors
                foreach (var chainStatus in chain.ChainStatus)
                {
                    if (chainStatus.Status is not (X509ChainStatusFlags.Revoked or X509ChainStatusFlags.RevocationStatusUnknown)) continue;
                    _logger.LogWarning("Certificate revocation detected: {Status}, {StatusInfo}",
                        chainStatus.Status, chainStatus.StatusInformation);
                    return true;
                }
            }

            // Additional OCSP checking could be implemented here for more thorough validation
            // For now, rely on the built-in .NET revocation checking

            await Task.CompletedTask; // Maintain async signature for future OCSP implementation
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Certificate revocation check failed: {Thumbprint}", certificate.Thumbprint);
            
            // In case of revocation check failure, assume not revoked but log warning
            // In high-security environments, you might want to fail-safe (assume revoked)
            return false;
        }
    }

    /// <summary>
    /// Validate certificate pinning for high-security clients
    /// </summary>
    public bool ValidateCertificatePinning(X509Certificate2 certificate, string expectedThumbprint)
    {
        try
        {
            var actualThumbprint = certificate.Thumbprint;
            var isValid = string.Equals(actualThumbprint, expectedThumbprint, StringComparison.OrdinalIgnoreCase);

            _logger.LogDebug("Certificate pinning validation: Expected={Expected}, Actual={Actual}, Valid={Valid}",
                expectedThumbprint, actualThumbprint, isValid);

            return isValid;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Certificate pinning validation failed");
            return false;
        }
    }

    /// <summary>
    /// Check certificate expiration status
    /// </summary>
    public CertificateExpirationStatus CheckCertificateExpiration(X509Certificate2 certificate)
    {
        var now = DateTime.UtcNow;
        var notBefore = certificate.NotBefore.ToUniversalTime();
        var notAfter = certificate.NotAfter.ToUniversalTime();

        var status = new CertificateExpirationStatus
        {
            NotBefore = notBefore,
            ExpirationDate = notAfter,
            IsExpired = now > notAfter || now < notBefore,
            DaysToExpiration = (int)(notAfter - now).TotalDays
        };

        // Warning period: 30 days before expiration
        status.ExpiresWithinWarningPeriod = status.DaysToExpiration <= 30 && status.DaysToExpiration > 0;

        return status;
    }

    // Private helper methods

    private bool ValidateBasicCertificateProperties(X509Certificate2 certificate, CertificateValidationResult result)
    {
        // Check certificate format
        if (certificate == null)
        {
            result.IsValid = false;
            result.ErrorMessage = "Certificate is null";
            return false;
        }

        // Check certificate has private key (should NOT have private key on server side)
        if (certificate.HasPrivateKey)
        {
            result.Warnings.Add("Certificate contains private key (unexpected for client certificate)");
        }

        // Check certificate purpose (Client Authentication)
        var hasClientAuthExtension = certificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .Any(ext => ext.EnhancedKeyUsages
                .Cast<Oid>()
                .Any(oid => oid.Value == "1.3.6.1.5.5.7.3.2")); // Client Authentication OID

        if (!hasClientAuthExtension)
        {
            result.Warnings.Add("Certificate does not explicitly specify Client Authentication purpose");
        }

        return true;
    }

    private async Task<bool> ValidateCertificateChainAsync(X509Certificate2 certificate, CertificateValidationResult result)
    {
        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            chain.ChainPolicy.VerificationTime = DateTime.Now;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // We'll check revocation separately

            var chainIsValid = chain.Build(certificate);

            if (!chainIsValid)
            {
                foreach (var chainStatus in chain.ChainStatus)
                {
                    result.ValidationErrors.Add($"Chain validation error: {chainStatus.Status} - {chainStatus.StatusInformation}");
                }

                result.IsValid = false;
                result.ErrorMessage = "Certificate chain validation failed";
                return false;
            }

            // Verify the root CA is in our trusted list
            var rootCert = chain.ChainElements[^1].Certificate;
            if (!_trustedCaThumbprints.Contains(rootCert.Thumbprint))
            {
                result.IsValid = false;
                result.ErrorMessage = "Certificate is not issued by a trusted Certificate Authority";
                result.ValidationErrors.Add($"Untrusted root CA: {rootCert.Subject}");
                return false;
            }

            await Task.CompletedTask;
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Certificate chain validation failed");
            result.IsValid = false;
            result.ErrorMessage = "Certificate chain validation error";
            return false;
        }
    }

    private bool ValidateClientIdentity(ClientIdentity identity, CertificateValidationResult result)
    {
        if (string.IsNullOrEmpty(identity.ClientId))
        {
            result.IsValid = false;
            result.ErrorMessage = "Unable to extract client ID from certificate";
            return false;
        }

        if (IsAuthorizedClient(identity.ClientId)) return true;
        result.IsValid = false;
        result.ErrorMessage = $"Client '{identity.ClientId}' is not authorized";
        return false;

    }

    private static bool ValidateIpConsistency(ClientIdentity identity, string clientIp, CertificateValidationResult result)
    {
        if (identity.AllowedIpRanges.Count == 0) return true;
        if (IsIpInAllowedRanges(clientIp, identity.AllowedIpRanges)) return true;
        result.IsValid = false;
        result.ErrorMessage = "Client IP is not in the allowed range for this certificate";
        return false;

    }

    private async Task LogCertificateSecurityEvent(string eventType, X509Certificate2 certificate, string clientIp, SecurityRiskLevel riskLevel)
    {
        await _securityService.LogSecurityEventAsync(new SecurityAuditLog
        {
            EventType = eventType,
            ClientIp = clientIp,
            RiskLevel = riskLevel,
            Details = $"Certificate: {certificate.Subject}, Thumbprint: {certificate.Thumbprint}, Issuer: {certificate.Issuer}"
        });
    }

    // Configuration and data loading methods

    private HashSet<string> LoadTrustedCertificateAuthorities()
    {
        // In production, load from secure configuration or certificate store
        var trustedCAs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        
        var configCAs = _configuration.GetSection("Security:TrustedCertificateAuthorities").Get<string[]>();
        if (configCAs != null)
        {
            foreach (var ca in configCAs)
            {
                trustedCAs.Add(ca);
            }
        }

        // Add well-known CAs for demo/development
        if (trustedCAs.Count != 0) return trustedCAs;
        _logger.LogWarning("No trusted CAs configured, using development defaults");
        trustedCAs.Add("DEVELOPMENT_CA_THUMBPRINT_HERE");

        return trustedCAs;
    }

    private Dictionary<string, string> LoadPinnedCertificates()
    {
        var pinnedCerts = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        
        var configSection = _configuration.GetSection("Security:PinnedCertificates");
        foreach (var child in configSection.GetChildren())
        {
            pinnedCerts[child.Key] = child.Value ?? string.Empty;
        }

        return pinnedCerts;
    }

    private CertificateTrustLevel DetermineTrustLevel(X509Certificate2 certificate, ClientIdentity identity)
    {
        if (identity.IsHighSecurityClient && _pinnedCertificates.ContainsKey(identity.ClientId))
        {
            return CertificateTrustLevel.Maximum;
        }

        return identity.ClientType == ClientType.Enterprise ? CertificateTrustLevel.High : CertificateTrustLevel.Standard;
    }

    // Certificate parsing helper methods
    private static string ExtractClientIdFromCertificate(X509Certificate2 certificate)
    {
        // Try to extract from Common Name first
        var commonName = ExtractCommonNameFromSubject(certificate.Subject);
        if (!string.IsNullOrEmpty(commonName))
        {
            return commonName;
        }

        // Try to extract from Subject Alternative Name extension
        var sanExtension = certificate.Extensions["2.5.29.17"] as X509SubjectAlternativeNameExtension;
        return sanExtension != null ?
            // Parse SAN for client ID (implementation depends on your certificate format)
            // This is a simplified example
            "extracted_from_san" : "unknown";
    }

    private static string ExtractCommonNameFromSubject(string subject)
    {
        var cnMatch = System.Text.RegularExpressions.Regex.Match(subject, @"CN=([^,]+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase, TimeSpan.FromSeconds(5));
        return cnMatch.Success ? cnMatch.Groups[1].Value.Trim() : string.Empty;
    }

    private static string ExtractOrganizationFromSubject(string subject)
    {
        var oMatch = System.Text.RegularExpressions.Regex.Match(subject, @"O=([^,]+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase, TimeSpan.FromSeconds(5));
        return oMatch.Success ? oMatch.Groups[1].Value.Trim() : string.Empty;
    }

    private ClientType DetermineClientType(X509Certificate2 certificate)
    {
        var organization = ExtractOrganizationFromSubject(certificate.Subject);
        
        if (organization.Contains("Bank") || organization.Contains("Financial"))
        {
            return ClientType.Financial;
        }
        
        if (organization.Contains("Enterprise") || organization.Contains("Corporation"))
        {
            return ClientType.Enterprise;
        }

        return ClientType.Standard;
    }

    private static bool IsHighSecurityClient(string clientId, string organization)
    {
        var highSecurityPatterns = new[] { "bank", "financial", "government", "critical" };
        return highSecurityPatterns.Any(pattern => 
            clientId.Contains(pattern, StringComparison.CurrentCultureIgnoreCase) || organization.Contains(pattern, StringComparison.CurrentCultureIgnoreCase));
    }

    private static List<string> ExtractAllowedIpRanges(X509Certificate2 certificate)
    {
        // In a real implementation, you would extract IP ranges from certificate extensions
        // For now, return empty list
        return [];
    }

    private bool IsAuthorizedClient(string clientId)
    {
        // Check against authorized client list
        var authorizedClients = _configuration.GetSection("Security:AuthorizedClients").Get<string[]>();
        return authorizedClients?.Contains(clientId, StringComparer.OrdinalIgnoreCase) == true;
    }

    private string? GetExpectedCertificateThumbprint(string clientId)
    {
        return _pinnedCertificates.GetValueOrDefault(clientId);
    }

    private static bool IsIpInAllowedRanges(string clientIp, List<string> allowedRanges)
    {
        // Simplified IP range checking - in production, use proper CIDR validation
        return allowedRanges.Contains(clientIp);
    }
}