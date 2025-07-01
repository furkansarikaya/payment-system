using PaymentSystem.PaymentApi.Features.Security.Models;

namespace PaymentSystem.PaymentApi.Features.Security.Services;

/// <summary>
/// Security Service Interface - Güvenlik operasyonları için contract
/// 
/// Bu servis şunları sağlar:
/// - API Key validation
/// - Request security validation  
/// - Client signature verification
/// - Security audit logging
/// - Suspicious activity detection
/// </summary>
public interface ISecurityService
{
    /// <summary>
    /// API Key'in geçerliliğini kontrol eder
    /// </summary>
    Task<ApiKeyValidationResult> ValidateApiKeyAsync(string apiKey, string clientIp);
    
    /// <summary>
    /// Enhanced request'in güvenlik kontrollerini yapar
    /// </summary>
    Task<SecurityValidationResult> ValidateRequestAsync(EnhancedEncryptedRequest request, string clientIp, string userAgent);
    
    /// <summary>
    /// Client signature'ı doğrular (HMAC-SHA256)
    /// </summary>
    bool ValidateClientSignature(string signature, string requestData, string clientSecret);
    
    /// <summary>
    /// Şüpheli aktivite kontrolü yapar
    /// </summary>
    Task<bool> IsSuspiciousActivityAsync(string clientIp, string apiKey, string userAgent);
    
    /// <summary>
    /// Güvenlik audit log'u yazar
    /// </summary>
    Task LogSecurityEventAsync(SecurityAuditLog auditLog);
    
    /// <summary>
    /// Rate limiting kontrolü yapar
    /// </summary>
    Task<RateLimitResult> CheckRateLimitAsync(string apiKey, string clientIp);
    
    /// <summary>
    /// Client'ı geçici olarak engeller
    /// </summary>
    Task BlockClientAsync(string identifier, TimeSpan duration, string reason);
}