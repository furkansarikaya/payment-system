using System.Diagnostics;
using PaymentSystem.PaymentApi.Features.Security.Models;
using PaymentSystem.PaymentApi.Features.Security.Services;

namespace PaymentSystem.PaymentApi.Middleware;

/// <summary>
/// Security Audit Middleware
/// 
/// Bu middleware tüm HTTP request/response'ları izler ve:
/// 1. Detaylı audit log'ları tutar
/// 2. Performance metrics toplar
/// 3. Suspicious pattern detection yapar
/// 4. Security alerts gönderir
/// 5. Compliance logging sağlar
/// 
/// Önemli: Pipeline'da en son middleware olarak eklenmelidir
/// Yol: Program.cs → app.UseMiddleware<SecurityAuditMiddleware>()
/// </summary>
public class SecurityAuditMiddleware(
    RequestDelegate next,
    ILogger<SecurityAuditMiddleware> logger,
    IServiceScopeFactory serviceScopeFactory)
{
    // Sensitive headers that should not be logged
    private readonly HashSet<string> _sensitiveHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Authorization", "X-API-Key", "Cookie", "Set-Cookie"
    };

    // Paths that require special audit attention
    private readonly HashSet<string> _criticalPaths = new(StringComparer.OrdinalIgnoreCase)
    {
        "/api/payment/process",
        "/api/admin/keymanagement"
    };

    public async Task InvokeAsync(HttpContext context)
    {
        var stopwatch = Stopwatch.StartNew();
        var requestStartTime = DateTime.UtcNow;
        var path = context.Request.Path.Value ?? string.Empty;
        var method = context.Request.Method;
        var clientIp = GetClientIpAddress(context);
        var userAgent = context.Request.Headers.UserAgent.ToString();
        var apiKey = context.Items["ApiKey"]?.ToString();
        var clientId = context.Items["ClientId"]?.ToString();

        // Generate correlation ID for request tracking
        var correlationId = context.TraceIdentifier;
        context.Response.Headers.Append("X-Correlation-ID", correlationId);

        try
        {
            logger.LogInformation("Request started: {Method} {Path} | IP: {ClientIp} | Client: {ClientId} | Correlation: {CorrelationId}",
                method, path, clientIp, clientId ?? "anonymous", correlationId);

            // Check for suspicious patterns before processing
            await CheckSuspiciousPatterns(context, clientIp, userAgent, apiKey);

            // Execute next middleware
            await next(context);

            stopwatch.Stop();

            // Log successful request completion
            var responseTime = stopwatch.ElapsedMilliseconds;
            logger.LogInformation("Request completed: {Method} {Path} | Status: {StatusCode} | Duration: {Duration}ms | IP: {ClientIp} | Client: {ClientId}",
                method, path, context.Response.StatusCode, responseTime, clientIp, clientId ?? "anonymous");

            // Create audit log for critical paths
            if (_criticalPaths.Any(criticalPath => path.StartsWith(criticalPath, StringComparison.OrdinalIgnoreCase)))
            {
                await CreateSecurityAuditLog(context, requestStartTime, responseTime, clientIp, userAgent, apiKey);
            }

            // Performance monitoring
            if (responseTime > 5000) // Slow request threshold: 5 seconds
            {
                logger.LogWarning("Slow request detected: {Method} {Path} | Duration: {Duration}ms | IP: {ClientIp}",
                    method, path, responseTime, clientIp);
            }
        }
        catch (Exception ex)
        {
            stopwatch.Stop();
            var responseTime = stopwatch.ElapsedMilliseconds;

            logger.LogError(ex, "Request failed: {Method} {Path} | Duration: {Duration}ms | IP: {ClientIp} | Error: {Error}",
                method, path, responseTime, clientIp, ex.Message);

            // Log security event for exceptions in critical paths
            if (_criticalPaths.Any(criticalPath => path.StartsWith(criticalPath, StringComparison.OrdinalIgnoreCase)))
            {
                await LogSecurityException(context, ex, clientIp, userAgent, apiKey);
            }

            throw; // Re-throw to maintain exception handling flow
        }
    }

    private async Task CheckSuspiciousPatterns(HttpContext context, string clientIp, string userAgent, string? apiKey)
    {
        try
        {
            using var scope = serviceScopeFactory.CreateScope();
            var securityService = scope.ServiceProvider.GetRequiredService<ISecurityService>();

            var isSuspicious = await securityService.IsSuspiciousActivityAsync(clientIp, apiKey ?? "anonymous", userAgent);

            if (isSuspicious)
            {
                await securityService.LogSecurityEventAsync(new SecurityAuditLog
                {
                    EventType = "suspicious_request_pattern",
                    ClientIp = clientIp,
                    UserAgent = userAgent,
                    ApiKey = apiKey != null ? MaskApiKey(apiKey) : "anonymous",
                    RequestId = context.TraceIdentifier,
                    RiskLevel = SecurityRiskLevel.High,
                    Details = $"Suspicious pattern detected for {context.Request.Method} {context.Request.Path}"
                });

                // Add warning header for suspicious requests
                context.Response.Headers.Append("X-Security-Warning", "Request flagged for review");
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Suspicious pattern check failed for IP: {ClientIp}", clientIp);
        }
    }

    private async Task CreateSecurityAuditLog(HttpContext context, DateTime requestStartTime, long responseTime, 
        string clientIp, string userAgent, string? apiKey)
    {
        try
        {
            using var scope = serviceScopeFactory.CreateScope();
            var securityService = scope.ServiceProvider.GetRequiredService<ISecurityService>();

            var auditLog = new SecurityAuditLog
            {
                EventType = GetEventTypeFromPath(context.Request.Path),
                ClientIp = clientIp,
                UserAgent = userAgent,
                ApiKey = apiKey != null ? MaskApiKey(apiKey) : "anonymous",
                RequestId = context.TraceIdentifier,
                RiskLevel = GetRiskLevelFromResponse(context),
                Details = CreateAuditDetails(context, requestStartTime, responseTime)
            };

            await securityService.LogSecurityEventAsync(auditLog);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to create security audit log for request: {RequestId}", context.TraceIdentifier);
        }
    }

    private async Task LogSecurityException(HttpContext context, Exception exception, string clientIp, string userAgent, string? apiKey)
    {
        try
        {
            using var scope = serviceScopeFactory.CreateScope();
            var securityService = scope.ServiceProvider.GetRequiredService<ISecurityService>();

            await securityService.LogSecurityEventAsync(new SecurityAuditLog
            {
                EventType = "request_exception",
                ClientIp = clientIp,
                UserAgent = userAgent,
                ApiKey = apiKey != null ? MaskApiKey(apiKey) : "anonymous",
                RequestId = context.TraceIdentifier,
                RiskLevel = SecurityRiskLevel.Medium,
                Details = $"Exception in {context.Request.Method} {context.Request.Path}: {exception.Message}"
            });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to log security exception for request: {RequestId}", context.TraceIdentifier);
        }
    }

    private static string GetEventTypeFromPath(PathString path)
    {
        var pathValue = path.Value?.ToLower() ?? string.Empty;

        return pathValue switch
        {
            var p when p.Contains("/payment/process") => "payment_processed",
            var p when p.Contains("/payment/public-key") => "public_key_requested",
            var p when p.Contains("/security/challenge") => "challenge_requested",
            var p when p.Contains("/admin/") => "admin_operation",
            _ => "api_request"
        };
    }

    private static SecurityRiskLevel GetRiskLevelFromResponse(HttpContext context)
    {
        return context.Response.StatusCode switch
        {
            >= 200 and < 300 => SecurityRiskLevel.Low,     // Success
            >= 400 and < 500 => SecurityRiskLevel.Medium,  // Client errors
            >= 500 => SecurityRiskLevel.High,              // Server errors
            _ => SecurityRiskLevel.Low
        };
    }

    private string CreateAuditDetails(HttpContext context, DateTime requestStartTime, long responseTime)
    {
        var details = new Dictionary<string, object>
        {
            ["method"] = context.Request.Method,
            ["path"] = context.Request.Path.Value ?? string.Empty,
            ["statusCode"] = context.Response.StatusCode,
            ["responseTime"] = $"{responseTime}ms",
            ["requestSize"] = context.Request.ContentLength ?? 0,
            ["responseSize"] = context.Response.ContentLength ?? 0,
            ["timestamp"] = requestStartTime.ToString("O"),
            ["headers"] = GetSafeHeaders(context.Request.Headers)
        };

        return System.Text.Json.JsonSerializer.Serialize(details);
    }

    private Dictionary<string, string> GetSafeHeaders(IHeaderDictionary headers)
    {
        return headers
            .Where(h => !_sensitiveHeaders.Contains(h.Key))
            .ToDictionary(h => h.Key, h => h.Value.ToString());
    }

    private static string GetClientIpAddress(HttpContext context)
    {
        return context.Request.Headers["X-Forwarded-For"].FirstOrDefault()?.Split(',')[0].Trim()
               ?? context.Request.Headers["X-Real-IP"].FirstOrDefault()
               ?? context.Connection.RemoteIpAddress?.ToString()
               ?? "unknown";
    }

    private static string MaskApiKey(string apiKey)
    {
        if (string.IsNullOrEmpty(apiKey) || apiKey.Length < 8)
            return "***";

        return apiKey[..4] + "***" + apiKey[^4..];
    }
}