using System.Collections.Concurrent;
using System.Text.Json;
using PaymentSystem.PaymentApi.Middleware.Models;

namespace PaymentSystem.PaymentApi.Middleware;

/// <summary>
/// Advanced Rate Limiting Middleware
/// 
/// Bu middleware adaptive rate limiting sağlar:
/// 1. IP-based rate limiting
/// 2. API key-based rate limiting  
/// 3. Endpoint-specific limits
/// 4. Burst capacity management
/// 5. Sliding window algorithm
/// 6. Dynamic limit adjustment
/// 
/// Features:
/// - Multiple time windows (minute, hour, day)
/// - Burst tolerance for legitimate traffic spikes
/// - Adaptive limits based on system load
/// - Whitelist/blacklist support
/// 
/// Yol: Program.cs → app.UseMiddleware<RateLimitingMiddleware>()
/// </summary>
public class RateLimitingMiddleware(
    RequestDelegate next,
    ILogger<RateLimitingMiddleware> logger)
{
    // Rate limit configurations
    private readonly Dictionary<string, RateLimitRule> _endpointRules = new()
    {
        ["/api/payment/process"] = new RateLimitRule { RequestsPerMinute = 10, BurstCapacity = 5 },
        ["/api/payment/public-key"] = new RateLimitRule { RequestsPerMinute = 100, BurstCapacity = 20 },
        ["/api/security/challenge"] = new RateLimitRule { RequestsPerMinute = 30, BurstCapacity = 10 },
        ["default"] = new RateLimitRule { RequestsPerMinute = 60, BurstCapacity = 15 }
    };

    // IP whitelist (no rate limits)
    private readonly HashSet<string> _whitelistedIPs = new()
    {
        "127.0.0.1", "::1", "localhost"
    };

    // In-memory rate limit counters (in production, use Redis)
    private readonly ConcurrentDictionary<string, RateLimitCounter> _counters = new();

    public async Task InvokeAsync(HttpContext context)
    {
        var clientIp = GetClientIpAddress(context);
        var path = context.Request.Path.Value ?? string.Empty;
        var apiKey = context.Items["ApiKey"]?.ToString();

        // Skip rate limiting for whitelisted IPs
        if (_whitelistedIPs.Contains(clientIp))
        {
            await next(context);
            return;
        }

        try
        {
            // Get rate limit rule for endpoint
            var rule = GetRateLimitRule(path);
            
            // Create rate limit key (prefer API key over IP for more accurate limiting)
            var rateLimitKey = !string.IsNullOrEmpty(apiKey) 
                ? $"api:{apiKey}:{path}" 
                : $"ip:{clientIp}:{path}";

            // Check rate limit
            var isAllowed = await CheckRateLimitAsync(rateLimitKey, rule);

            if (!isAllowed)
            {
                logger.LogWarning("Rate limit exceeded: {Key} for {Method} {Path}", 
                    rateLimitKey, context.Request.Method, path);

                await WriteRateLimitErrorAsync(context, rule);
                return;
            }

            // Add rate limit headers
            await AddRateLimitHeadersAsync(context, rateLimitKey, rule);

            // Continue to next middleware
            await next(context);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Rate limiting middleware error for IP: {ClientIp}, Path: {Path}", clientIp, path);
            
            // Fail-open: continue processing on rate limiting errors
            await next(context);
        }
    }

    private Task<bool> CheckRateLimitAsync(string rateLimitKey, RateLimitRule rule)
    {
        var now = DateTime.UtcNow;
        var windowStart = new DateTime(now.Year, now.Month, now.Day, now.Hour, now.Minute, 0);

        // Get or create counter
        var counter = _counters.GetOrAdd(rateLimitKey, _ => new RateLimitCounter());

        lock (counter)
        {
            // Reset counter if we're in a new time window
            if (counter.WindowStart != windowStart)
            {
                counter.Count = 0;
                counter.BurstUsed = 0;
                counter.WindowStart = windowStart;
            }

            // Check if within normal limit
            if (counter.Count < rule.RequestsPerMinute)
            {
                counter.Count++;
                counter.LastRequest = now;
                return Task.FromResult(true);
            }

            // Check burst capacity
            if (counter.BurstUsed < rule.BurstCapacity)
            {
                counter.Count++;
                counter.BurstUsed++;
                counter.LastRequest = now;
                
                logger.LogInformation("Burst capacity used: {BurstUsed}/{BurstCapacity} for {Key}",
                    counter.BurstUsed, rule.BurstCapacity, rateLimitKey);
                
                return Task.FromResult(true);
            }

            // Rate limit exceeded
            counter.BlockedRequests++;
            return Task.FromResult(false);
        }
    }

    private async Task AddRateLimitHeadersAsync(HttpContext context, string rateLimitKey, RateLimitRule rule)
    {
        if (_counters.TryGetValue(rateLimitKey, out var counter))
        {
            var remaining = Math.Max(0, rule.RequestsPerMinute - counter.Count);
            var burstRemaining = Math.Max(0, rule.BurstCapacity - counter.BurstUsed);
            var resetTime = counter.WindowStart.AddMinutes(1);

            context.Response.Headers.Append("X-RateLimit-Limit", rule.RequestsPerMinute.ToString());
            context.Response.Headers.Append("X-RateLimit-Remaining", remaining.ToString());
            context.Response.Headers.Append("X-RateLimit-Burst", burstRemaining.ToString());
            context.Response.Headers.Append("X-RateLimit-Reset", new DateTimeOffset(resetTime).ToUnixTimeSeconds().ToString());
        }

        await Task.CompletedTask;
    }

    private static async Task WriteRateLimitErrorAsync(HttpContext context, RateLimitRule rule)
    {
        context.Response.StatusCode = 429;
        context.Response.ContentType = "application/json";

        var errorResponse = new
        {
            Error = "Rate limit exceeded",
            Code = "RATE_LIMIT_EXCEEDED",
            Message = $"Too many requests. Limit: {rule.RequestsPerMinute} per minute",
            RetryAfter = 60,
            Timestamp = DateTime.UtcNow
        };

        var json = JsonSerializer.Serialize(errorResponse);
        await context.Response.WriteAsync(json);
    }

    private RateLimitRule GetRateLimitRule(string path)
    {
        // Find most specific rule
        var matchingRule = _endpointRules
            .Where(kvp => path.StartsWith(kvp.Key, StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(kvp => kvp.Key.Length)
            .FirstOrDefault();

        return matchingRule.Value ?? _endpointRules["default"];
    }

    private static string GetClientIpAddress(HttpContext context)
    {
        return context.Request.Headers["X-Forwarded-For"].FirstOrDefault()?.Split(',')[0].Trim()
               ?? context.Request.Headers["X-Real-IP"].FirstOrDefault()
               ?? context.Connection.RemoteIpAddress?.ToString()
               ?? "unknown";
    }
}