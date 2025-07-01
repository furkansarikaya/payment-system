using System.Text.Json;
using PaymentSystem.PaymentApi.Features.Security.Services;

namespace PaymentSystem.PaymentApi.Middleware;

/// <summary>
/// API Key Authentication Middleware
/// 
/// Bu middleware her HTTP request'i intercept eder ve:
/// 1. X-API-Key header'ını kontrol eder
/// 2. API key'in geçerliliğini doğrular
/// 3. Rate limiting uygular
/// 4. Security audit log'u tutar
/// 5. Blocked client'ları reddeder
/// 
/// Önemli: Bu middleware pipeline'da routing'den ÖNCE çalışmalı
/// Yol: Program.cs → app.UseMiddleware<ApiKeyAuthenticationMiddleware>()
/// </summary>
public class ApiKeyAuthenticationMiddleware(
    RequestDelegate next,
    ILogger<ApiKeyAuthenticationMiddleware> logger,
    IServiceScopeFactory serviceScopeFactory)
{
    // Public endpoints that don't require API key
    private readonly HashSet<string> _publicEndpoints = new(StringComparer.OrdinalIgnoreCase)
    {
        "/api/payment/health",
        "/api/payment/public-key",
        "/swagger",
        "/health"
    };

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? string.Empty;
        var clientIp = GetClientIpAddress(context);
        var userAgent = context.Request.Headers.UserAgent.ToString();

        try
        {
            // Skip API key check for public endpoints
            if (_publicEndpoints.Any(endpoint => path.StartsWith(endpoint, StringComparison.OrdinalIgnoreCase)))
            {
                logger.LogDebug("Skipping API key check for public endpoint: {Path}", path);
                await next(context);
                return;
            }

            // Extract API key from header
            if (!context.Request.Headers.TryGetValue("X-API-Key", out var apiKeyValues) ||
                string.IsNullOrEmpty(apiKeyValues.FirstOrDefault()))
            {
                logger.LogWarning("Missing API key for protected endpoint: {Path} from IP: {ClientIp}", path, clientIp);
                await WriteErrorResponseAsync(context, 401, "MISSING_API_KEY", "API Key is required");
                return;
            }

            var apiKey = apiKeyValues.First()!;

            // Validate API key using security service
            using var scope = serviceScopeFactory.CreateScope();
            var securityService = scope.ServiceProvider.GetRequiredService<ISecurityService>();

            var validationResult = await securityService.ValidateApiKeyAsync(apiKey, clientIp);

            if (!validationResult.IsValid)
            {
                logger.LogWarning("Invalid API key attempt: {ApiKey} from IP: {ClientIp}, Error: {Error}",
                    MaskApiKey(apiKey), clientIp, validationResult.ErrorMessage);

                var statusCode = validationResult.ErrorMessage?.Contains("limit") == true ? 429 : 403;
                await WriteErrorResponseAsync(context, statusCode, "INVALID_API_KEY", validationResult.ErrorMessage ?? "Invalid API key");
                return;
            }

            // Check if client is blocked
            if (validationResult.IsBlocked)
            {
                logger.LogWarning("Blocked client attempted access: {ApiKey} from IP: {ClientIp}, Blocked until: {BlockedUntil}",
                    MaskApiKey(apiKey), clientIp, validationResult.BlockedUntil);

                await WriteErrorResponseAsync(context, 429, "CLIENT_BLOCKED", 
                    $"Client temporarily blocked until {validationResult.BlockedUntil:yyyy-MM-dd HH:mm:ss} UTC");
                return;
            }

            // Rate limiting check
            var rateLimitResult = await securityService.CheckRateLimitAsync(apiKey, clientIp);
            if (!rateLimitResult.IsAllowed)
            {
                logger.LogWarning("Rate limit exceeded for API key: {ApiKey} from IP: {ClientIp}, Reset in: {ResetTime}",
                    MaskApiKey(apiKey), clientIp, rateLimitResult.ResetTime);

                // Add rate limit headers
                context.Response.Headers.Append("X-RateLimit-Limit", validationResult.ApiKeyConfig?.RateLimit.RequestsPerMinute.ToString() ?? "60");
                context.Response.Headers.Append("X-RateLimit-Remaining", "0");
                context.Response.Headers.Append("X-RateLimit-Reset", DateTimeOffset.UtcNow.Add(rateLimitResult.ResetTime).ToUnixTimeSeconds().ToString());

                await WriteErrorResponseAsync(context, 429, "RATE_LIMIT_EXCEEDED", 
                    $"Rate limit exceeded. Reset in {rateLimitResult.ResetTime.TotalSeconds:F0} seconds");
                return;
            }

            // Add API key info to HttpContext for downstream middleware
            context.Items["ApiKey"] = apiKey;
            context.Items["ClientId"] = validationResult.ApiKeyConfig?.ClientId;
            context.Items["ApiKeyConfig"] = validationResult.ApiKeyConfig;

            // Add rate limit headers for successful requests
            context.Response.Headers.Append("X-RateLimit-Limit", validationResult.ApiKeyConfig?.RateLimit.RequestsPerMinute.ToString() ?? "60");
            context.Response.Headers.Append("X-RateLimit-Remaining", rateLimitResult.RemainingRequests.ToString());
            context.Response.Headers.Append("X-RateLimit-Reset", DateTimeOffset.UtcNow.Add(rateLimitResult.ResetTime).ToUnixTimeSeconds().ToString());

            logger.LogDebug("API key authenticated successfully: {ApiKey} from IP: {ClientIp}, Client: {ClientId}",
                MaskApiKey(apiKey), clientIp, validationResult.ApiKeyConfig?.ClientId);

            // Continue to next middleware
            await next(context);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "API key authentication middleware error for path: {Path}, IP: {ClientIp}", path, clientIp);
            await WriteErrorResponseAsync(context, 500, "AUTHENTICATION_ERROR", "Authentication service temporarily unavailable");
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
            TraceId = context.TraceIdentifier
        };

        var json = JsonSerializer.Serialize(errorResponse);
        await context.Response.WriteAsync(json);
    }

    private static string GetClientIpAddress(HttpContext context)
    {
        // Try to get real IP from X-Forwarded-For header (if behind proxy/load balancer)
        var forwardedFor = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrEmpty(forwardedFor))
        {
            return forwardedFor.Split(',')[0].Trim();
        }

        // Try X-Real-IP header
        var realIp = context.Request.Headers["X-Real-IP"].FirstOrDefault();
        if (!string.IsNullOrEmpty(realIp))
        {
            return realIp;
        }

        // Fallback to connection remote IP
        return context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }

    private static string MaskApiKey(string apiKey)
    {
        if (string.IsNullOrEmpty(apiKey) || apiKey.Length < 8)
            return "***";

        return apiKey[..4] + "***" + apiKey[^4..];
    }
}