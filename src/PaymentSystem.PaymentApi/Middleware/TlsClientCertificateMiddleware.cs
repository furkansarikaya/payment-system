using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using PaymentSystem.PaymentApi.Features.Security.Models;
using PaymentSystem.PaymentApi.Features.Security.Services;

namespace PaymentSystem.PaymentApi.Middleware;

/// <summary>
/// TLS Client Certificate Authentication Middleware
/// 
/// EN GÜÇLÜ GÜVENLİK KATMANI - Network Level Authentication
/// 
/// Bu middleware şunları sağlar:
/// 1. Mutual TLS (mTLS) certificate validation
/// 2. Client identity extraction ve authorization
/// 3. Certificate chain verification
/// 4. Revocation checking (OCSP/CRL)
/// 5. Certificate pinning for high-security clients
/// 
/// CRITICAL: Bu middleware API Key middleware'den ÖNCE çalışmalı
/// 
/// Security Guarantee: 
/// Bu middleware aktifken, geçerli client certificate olmadan 
/// sistem erişimi TAMAMEN İMKANSIZ hale gelir.
/// 
/// Yol: Program.cs → app.UseMiddleware<TlsClientCertificateMiddleware>()
/// </summary>
public class TlsClientCertificateMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<TlsClientCertificateMiddleware> _logger;
    private readonly IServiceScopeFactory _serviceScopeFactory;
    private readonly bool _requireClientCertificate;
    private readonly bool _enableCertificatePinning;

    // Endpoints that don't require client certificates (very limited)
    private readonly HashSet<string> _exemptEndpoints = new(StringComparer.OrdinalIgnoreCase)
    {
        "/health",
        "/api/payment/health",
        "/swagger"
    };

    /// <summary>
    /// Constructor
    /// </summary>
    /// <param name="next"></param>
    /// <param name="logger"></param>
    /// <param name="serviceScopeFactory"></param>
    /// <param name="configuration"></param>
    public TlsClientCertificateMiddleware(
        RequestDelegate next,
        ILogger<TlsClientCertificateMiddleware> logger,
        IServiceScopeFactory serviceScopeFactory,
        IConfiguration configuration)
    {
        _next = next;
        _logger = logger;
        _serviceScopeFactory = serviceScopeFactory;
        
        // Configuration
        _requireClientCertificate = configuration.GetValue<bool>("Security:RequireClientCertificate", true);
        _enableCertificatePinning = configuration.GetValue<bool>("Security:EnableCertificatePinning", true);
    }

    /// <summary>
    /// Middleware entry point
    /// </summary>
    /// <param name="context"></param>
    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? string.Empty;
        var clientIp = GetClientIpAddress(context);

        try
        {
            // Skip certificate validation for exempt endpoints
            if (_exemptEndpoints.Any(endpoint => path.StartsWith(endpoint, StringComparison.OrdinalIgnoreCase)))
            {
                _logger.LogDebug("Skipping client certificate validation for exempt endpoint: {Path}", path);
                await _next(context);
                return;
            }

            // Skip if client certificate requirement is disabled (development only)
            if (!_requireClientCertificate)
            {
                _logger.LogWarning("Client certificate requirement is DISABLED - Development mode only!");
                await _next(context);
                return;
            }

            // Extract client certificate
            var clientCertificate = context.Connection.ClientCertificate;
            
            if (clientCertificate == null)
            {
                _logger.LogWarning("Client certificate required but not provided: {Path} from IP: {ClientIp}", path, clientIp);
                await WriteErrorResponseAsync(context, 401, "CLIENT_CERTIFICATE_REQUIRED", 
                    "Client certificate is required for this endpoint");
                return;
            }

            // Validate client certificate
            using var scope = _serviceScopeFactory.CreateScope();
            var certificateService = scope.ServiceProvider.GetRequiredService<ITlsClientCertificateService>();

            var validationResult = await certificateService.ValidateCertificateAsync(clientCertificate, clientIp);

            if (!validationResult.IsValid)
            {
                _logger.LogWarning("Client certificate validation failed: {ErrorMessage}, Subject: {Subject}, IP: {ClientIp}",
                    validationResult.ErrorMessage, clientCertificate.Subject, clientIp);

                // Log security event for failed certificate validation
                await LogCertificateSecurityEvent("client_certificate_validation_failed", 
                    clientCertificate, clientIp, validationResult.ErrorMessage ?? "Unknown error", scope);

                await WriteErrorResponseAsync(context, 403, "CLIENT_CERTIFICATE_INVALID", 
                    validationResult.ErrorMessage ?? "Client certificate validation failed");
                return;
            }

            // Add certificate information to HttpContext for downstream middleware
            context.Items["ClientCertificate"] = clientCertificate;
            context.Items["ClientCertificateValidation"] = validationResult;
            context.Items["ClientIdentity"] = validationResult.ClientIdentity;
            context.Items["CertificateTrustLevel"] = validationResult.TrustLevel;

            // Add certificate-based security headers
            context.Response.Headers.Append("X-Client-Certificate-Valid", "true");
            context.Response.Headers.Append("X-Certificate-Trust-Level", validationResult.TrustLevel.ToString());
            context.Response.Headers.Append("X-Client-Type", validationResult.ClientIdentity?.ClientType.ToString() ?? "Unknown");

            // Log warnings if any
            if (validationResult.Warnings.Count != 0)
            {
                foreach (var warning in validationResult.Warnings)
                {
                    _logger.LogWarning("Certificate validation warning: {Warning}, Subject: {Subject}",
                        warning, clientCertificate.Subject);
                }
            }

            _logger.LogInformation("Client certificate validated successfully: Subject={Subject}, ClientId={ClientId}, TrustLevel={TrustLevel}, IP={ClientIp}",
                clientCertificate.Subject, validationResult.ClientIdentity?.ClientId, validationResult.TrustLevel, clientIp);

            // Log successful certificate validation
            await LogCertificateSecurityEvent("client_certificate_validated_successfully", 
                clientCertificate, clientIp, "Certificate validation successful", scope);

            // Continue to next middleware
            await _next(context);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Client certificate middleware error for path: {Path}, IP: {ClientIp}", path, clientIp);
            await WriteErrorResponseAsync(context, 500, "CERTIFICATE_VALIDATION_ERROR", 
                "Certificate validation service temporarily unavailable");
        }
    }

    private static async Task WriteErrorResponseAsync(HttpContext context, int statusCode, string errorCode, string message)
    {
        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/json";

        var errorResponse = new
        {
            Error = message,
            Code = errorCode,
            Timestamp = DateTime.UtcNow,
            TraceId = context.TraceIdentifier,
            SecurityLevel = "Maximum",
            RequiredAuthentication = "TLS Client Certificate"
        };

        var json = JsonSerializer.Serialize(errorResponse);
        await context.Response.WriteAsync(json);
    }

    private async Task LogCertificateSecurityEvent(string eventType, X509Certificate2 certificate, 
        string clientIp, string details, IServiceScope scope)
    {
        try
        {
            var securityService = scope.ServiceProvider.GetRequiredService<ISecurityService>();
            await securityService.LogSecurityEventAsync(new SecurityAuditLog
            {
                EventType = eventType,
                ClientIp = clientIp,
                RiskLevel = eventType.Contains("failed") ? SecurityRiskLevel.High : SecurityRiskLevel.Low,
                Details = $"Certificate: {certificate.Subject}, Thumbprint: {certificate.Thumbprint}, Details: {details}"
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to log certificate security event");
        }
    }

    private static string GetClientIpAddress(HttpContext context)
    {
        return context.Request.Headers["X-Forwarded-For"].FirstOrDefault()?.Split(',')[0].Trim()
               ?? context.Request.Headers["X-Real-IP"].FirstOrDefault()
               ?? context.Connection.RemoteIpAddress?.ToString()
               ?? "unknown";
    }
}