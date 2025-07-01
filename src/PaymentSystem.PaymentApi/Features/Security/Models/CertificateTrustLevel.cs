namespace PaymentSystem.PaymentApi.Features.Security.Models;

/// <summary>
/// Certificate trust levels
/// </summary>
public enum CertificateTrustLevel
{
    Standard = 0,    // Basic certificate validation
    High = 1,        // Enterprise-grade validation
    Maximum = 2      // Pinned certificate with full validation
}