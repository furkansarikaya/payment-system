using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Caching.Memory;
using PaymentSystem.PaymentApi.Features.Security.Models;

namespace PaymentSystem.PaymentApi.Features.Security.Services;

/// <summary>
/// Security Service Implementation
/// 
/// Bu servis payment API'nin güvenlik katmanlarını yönetir:
/// 1. API Key authentication ve authorization
/// 2. Rate limiting per client
/// 3. Suspicious activity detection
/// 4. Security audit logging
/// 5. Client signature verification
/// 
/// Performance Optimizations:
/// - Memory cache for API keys (5 min TTL)
/// - Redis cache for rate limiting counters
/// - Async logging to prevent blocking
/// </summary>
public class SecurityService(
    ILogger<SecurityService> logger,
    IMemoryCache cache)
    : ISecurityService
{
    // API Key cache TTL
    private readonly TimeSpan _apiKeyCacheTtl = TimeSpan.FromMinutes(5);
    
    // Rate limiting time windows
    private readonly Dictionary<string, TimeSpan> _rateLimitWindows = new()
    {
        ["minute"] = TimeSpan.FromMinutes(1),
        ["hour"] = TimeSpan.FromHours(1),
        ["day"] = TimeSpan.FromDays(1)
    };
    
    // Suspicious activity patterns
    private readonly Dictionary<string, int> _suspiciousPatterns = new()
    {
        ["rapid_requests"] = 100, // 100+ requests in 1 minute
        ["failed_auth"] = 5,      // 5+ failed auth in 5 minutes
        ["invalid_signature"] = 3 // 3+ invalid signatures in 1 hour
    };

    /// <summary>
    /// API Key validation with caching and security checks
    /// </summary>
    public async Task<ApiKeyValidationResult> ValidateApiKeyAsync(string apiKey, string clientIp)
    {
        try
        {
            // Cache check
            var cacheKey = $"apikey:{apiKey}";
            if (cache.TryGetValue(cacheKey, out ApiKeyConfig? cachedConfig))
            {
                logger.LogDebug("API key found in cache: {ApiKey}", MaskApiKey(apiKey));
                return await ValidateApiKeyConfig(cachedConfig!, clientIp);
            }

            // Database/config lookup (simulated with in-memory config)
            var apiKeyConfig = await GetApiKeyConfigAsync(apiKey);
            
            if (apiKeyConfig == null)
            {
                logger.LogWarning("Invalid API key attempted: {ApiKey} from IP: {ClientIp}", 
                    MaskApiKey(apiKey), clientIp);
                
                await LogSecurityEventAsync(new SecurityAuditLog
                {
                    EventType = "invalid_api_key",
                    ClientIp = clientIp,
                    ApiKey = MaskApiKey(apiKey),
                    RiskLevel = SecurityRiskLevel.Medium,
                    Details = "Invalid API key attempted"
                });

                return new ApiKeyValidationResult
                {
                    IsValid = false,
                    ErrorMessage = "Invalid API key"
                };
            }

            // Cache valid API key config
            cache.Set(cacheKey, apiKeyConfig,new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = _apiKeyCacheTtl,
                Size = 1
            });
            
            return await ValidateApiKeyConfig(apiKeyConfig, clientIp);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "API key validation error for key: {ApiKey}", MaskApiKey(apiKey));
            return new ApiKeyValidationResult
            {
                IsValid = false,
                ErrorMessage = "API key validation failed"
            };
        }
    }

    /// <summary>
    /// Enhanced request validation with multiple security layers
    /// </summary>
    public async Task<SecurityValidationResult> ValidateRequestAsync(
        EnhancedEncryptedRequest request, 
        string clientIp, 
        string userAgent)
    {
        var result = new SecurityValidationResult();
        var errors = new List<string>();

        try
        {
            logger.LogDebug("Validating enhanced request: {RequestId} from {ClientIp}", 
                request.RequestId, clientIp);

            // 1. Basic field validation
            if (string.IsNullOrEmpty(request.EncryptedData))
                errors.Add("Encrypted data is required");
            
            if (string.IsNullOrEmpty(request.RequestId))
                errors.Add("Request ID is required");
            
            if (string.IsNullOrEmpty(request.Nonce))
                errors.Add("Nonce is required");

            // 2. Timestamp validation (5 minute window)
            var timeDiff = Math.Abs((DateTime.UtcNow - request.Timestamp).TotalMinutes);
            if (timeDiff > 5)
            {
                errors.Add($"Request timestamp is outside allowed window ({timeDiff:F1} minutes)");
                result.RiskLevel = SecurityRiskLevel.Medium;
            }

            // 3. Nonce validation (implemented in ChallengeService)
            var challengeService = GetChallengeService();
            if (!await challengeService.ValidateNonceAsync(request.Nonce, clientIp))
            {
                errors.Add("Invalid or expired nonce");
                result.RiskLevel = SecurityRiskLevel.High;
            }

            // 4. Request ID format validation
            if (!IsValidRequestIdFormat(request.RequestId))
            {
                errors.Add("Invalid request ID format");
                result.RiskLevel = SecurityRiskLevel.Medium;
            }

            // 5. Client signature validation (if provided)
            if (!string.IsNullOrEmpty(request.ClientSignature))
            {
                var clientSecret = await GetClientSecretAsync(request.ClientId);
                if (clientSecret != null)
                {
                    var requestData = $"{request.RequestId}{request.Timestamp:O}{request.Nonce}{request.EncryptedData}";
                    if (!ValidateClientSignature(request.ClientSignature, requestData, clientSecret))
                    {
                        errors.Add("Invalid client signature");
                        result.RiskLevel = SecurityRiskLevel.High;
                    }
                }
            }

            // 6. Suspicious activity check
            if (await IsSuspiciousActivityAsync(clientIp, request.ClientId, userAgent))
            {
                errors.Add("Suspicious activity detected");
                result.RiskLevel = SecurityRiskLevel.Critical;
                result.RequiresAdditionalVerification = true;
            }

            // 7. Result compilation
            result.IsValid = errors.Count == 0;
            result.ValidationErrors = errors;

            if (!result.IsValid)
            {
                await LogSecurityEventAsync(new SecurityAuditLog
                {
                    EventType = "request_validation_failed",
                    ClientIp = clientIp,
                    UserAgent = userAgent,
                    RequestId = request.RequestId,
                    RiskLevel = result.RiskLevel,
                    Details = string.Join("; ", errors)
                });
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Request validation error for request: {RequestId}", request.RequestId);
            return new SecurityValidationResult
            {
                IsValid = false,
                ValidationErrors = ["Request validation failed"],
                RiskLevel = SecurityRiskLevel.High
            };
        }
    }

    /// <summary>
    /// HMAC-SHA256 client signature validation
    /// </summary>
    public bool ValidateClientSignature(string signature, string requestData, string clientSecret)
    {
        try
        {
            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(clientSecret));
            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(requestData));
            var computedSignature = Convert.ToBase64String(computedHash);
            
            // Constant-time comparison to prevent timing attacks
            return CryptographicOperations.FixedTimeEquals(
                Encoding.UTF8.GetBytes(signature),
                Encoding.UTF8.GetBytes(computedSignature)
            );
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Client signature validation error");
            return false;
        }
    }

    /// <summary>
    /// Multi-layered suspicious activity detection
    /// </summary>
    public async Task<bool> IsSuspiciousActivityAsync(string clientIp, string apiKey, string userAgent)
    {
        try
        {
            var suspiciousFactors = 0;

            // 1. Rapid requests check
            var requestKey = $"requests:{clientIp}:{DateTime.UtcNow:yyyyMMddHHmm}";
            var requestCount = cache.Get<int>(requestKey);
            if (requestCount > _suspiciousPatterns["rapid_requests"])
            {
                suspiciousFactors++;
                logger.LogWarning("Rapid requests detected: {Count} from {ClientIp}", requestCount, clientIp);
            }

            // 2. Geographic anomaly (simplified)
            if (await IsGeographicAnomalyAsync(clientIp, apiKey))
            {
                suspiciousFactors++;
            }

            // 3. User agent analysis
            if (IsSuspiciousUserAgent(userAgent))
            {
                suspiciousFactors++;
            }

            // 4. Time-based patterns
            if (IsUnusualTimePattern(DateTime.UtcNow))
            {
                suspiciousFactors++;
            }

            var isSuspicious = suspiciousFactors >= 2;

            if (isSuspicious)
            {
                await LogSecurityEventAsync(new SecurityAuditLog
                {
                    EventType = "suspicious_activity_detected",
                    ClientIp = clientIp,
                    UserAgent = userAgent,
                    ApiKey = MaskApiKey(apiKey),
                    RiskLevel = SecurityRiskLevel.High,
                    Details = $"Suspicious factors: {suspiciousFactors}"
                });
            }

            return isSuspicious;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Suspicious activity check failed for {ClientIp}", clientIp);
            return false; // Güvenlik hatası durumunda false döndür (fail-open)
        }
    }

    /// <summary>
    /// Rate limiting check per API key
    /// </summary>
    public async Task<RateLimitResult> CheckRateLimitAsync(string apiKey, string clientIp)
    {
        try
        {
            var apiKeyConfig = await GetApiKeyConfigAsync(apiKey);
            if (apiKeyConfig?.RateLimit == null)
            {
                return new RateLimitResult { IsAllowed = false };
            }

            // Check minute-level rate limit
            var minuteKey = $"rate:{apiKey}:{DateTime.UtcNow:yyyyMMddHHmm}";
            var minuteCount = cache.Get<int>(minuteKey);
            
            if (minuteCount >= apiKeyConfig.RateLimit.RequestsPerMinute)
            {
                return new RateLimitResult
                {
                    IsAllowed = false,
                    RemainingRequests = 0,
                    ResetTime = TimeSpan.FromSeconds(60 - DateTime.UtcNow.Second),
                    LimitType = "minute"
                };
            }

            // Increment counters
            cache.Set(minuteKey, minuteCount + 1, new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(1),
                Size = 1
            });

            return new RateLimitResult
            {
                IsAllowed = true,
                RemainingRequests = apiKeyConfig.RateLimit.RequestsPerMinute - minuteCount - 1,
                ResetTime = TimeSpan.FromSeconds(60 - DateTime.UtcNow.Second),
                LimitType = "minute"
            };
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Rate limit check failed for API key: {ApiKey}", MaskApiKey(apiKey));
            return new RateLimitResult { IsAllowed = true }; // Fail-open for availability
        }
    }

    /// <summary>
    /// Security audit logging with async processing
    /// </summary>
    public async Task LogSecurityEventAsync(SecurityAuditLog auditLog)
    {
        try
        {
            // Async logging to prevent blocking main thread
            _ = Task.Run(() =>
            {
                logger.LogInformation("Security Event: {EventType} | IP: {ClientIp} | Risk: {RiskLevel} | Details: {Details}",
                    auditLog.EventType, auditLog.ClientIp, auditLog.RiskLevel, auditLog.Details);
                
                // Here you would typically write to:
                // - Database for permanent storage
                // - SIEM system for security monitoring
                // - Event streaming for real-time analysis
            });

            await Task.CompletedTask;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to log security event: {EventType}", auditLog.EventType);
        }
    }

    /// <summary>
    /// Block client temporarily
    /// </summary>
    public async Task BlockClientAsync(string identifier, TimeSpan duration, string reason)
    {
        var blockKey = $"blocked:{identifier}";
        var blockInfo = new
        {
            BlockedAt = DateTime.UtcNow,
            BlockedUntil = DateTime.UtcNow.Add(duration),
            Reason = reason
        };

        cache.Set(blockKey, blockInfo, new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = duration,
            Size = 1
        });

        await LogSecurityEventAsync(new SecurityAuditLog
        {
            EventType = "client_blocked",
            ClientIp = identifier,
            RiskLevel = SecurityRiskLevel.High,
            Details = $"Client blocked for {duration.TotalMinutes} minutes. Reason: {reason}"
        });
    }

    // Private helper methods

    private async Task<ApiKeyValidationResult> ValidateApiKeyConfig(ApiKeyConfig config, string clientIp)
    {
        if (!config.IsActive)
        {
            return new ApiKeyValidationResult
            {
                IsValid = false,
                ErrorMessage = "API key is inactive"
            };
        }

        // IP whitelist check
        if (config.AllowedIPs.Count != 0 && !config.AllowedIPs.Contains(clientIp))
        {
            await LogSecurityEventAsync(new SecurityAuditLog
            {
                EventType = "ip_not_whitelisted",
                ClientIp = clientIp,
                ApiKey = MaskApiKey(config.ApiKey),
                RiskLevel = SecurityRiskLevel.Medium,
                Details = "Request from non-whitelisted IP"
            });

            return new ApiKeyValidationResult
            {
                IsValid = false,
                ErrorMessage = "IP address not authorized"
            };
        }

        // Daily usage limit check
        if (config.TodayUsage >= config.DailyLimit)
        {
            return new ApiKeyValidationResult
            {
                IsValid = false,
                ErrorMessage = "Daily usage limit exceeded"
            };
        }

        return new ApiKeyValidationResult
        {
            IsValid = true,
            ApiKeyConfig = config
        };
    }

    private static async Task<ApiKeyConfig?> GetApiKeyConfigAsync(string apiKey)
    {
        // In production, this would query your database
        // For demo, using in-memory configuration
        var hardcodedKeys = new Dictionary<string, ApiKeyConfig>
        {
            ["ak_test_payment_demo_12345"] = new()
            {
                ApiKey = "ak_test_payment_demo_12345",
                Name = "Demo Payment Client",
                ClientId = "demo_client",
                Environment = "development",
                CreatedAt = DateTime.UtcNow.AddDays(-30),
                IsActive = true,
                RateLimit = new RateLimitConfig
                {
                    RequestsPerMinute = 60,
                    RequestsPerHour = 1000,
                    RequestsPerDay = 10000
                },
                DailyLimit = 10000,
                Permissions = ["payment.process", "payment.query", "challenge.request"]
            },
            ["ak_live_production_67890"] = new()
            {
                ApiKey = "ak_live_production_67890",
                Name = "Production Client",
                ClientId = "prod_client",
                Environment = "production",
                CreatedAt = DateTime.UtcNow.AddDays(-90),
                IsActive = true,
                RateLimit = new RateLimitConfig
                {
                    RequestsPerMinute = 100,
                    RequestsPerHour = 5000,
                    RequestsPerDay = 50000
                },
                DailyLimit = 50000,
                AllowedIPs = ["192.168.1.100", "10.0.0.50"],
                Permissions = ["payment.process", "payment.query", "challenge.request", "admin.view"]
            }
        };

        await Task.Delay(1); // Simulate async database call
        return hardcodedKeys.GetValueOrDefault(apiKey);
    }

    private static async Task<string?> GetClientSecretAsync(string clientId)
    {
        // In production, retrieve from secure key management service
        var clientSecrets = new Dictionary<string, string>
        {
            ["demo_client"] = "demo_secret_12345_very_secure_key",
            ["prod_client"] = "prod_secret_67890_ultra_secure_key"
        };

        await Task.Delay(1);
        return clientSecrets.GetValueOrDefault(clientId);
    }

    private IChallengeService GetChallengeService()
    {
        // This would be injected in real implementation
        // For now, return a simple implementation
        return new ChallengeService(new LoggerFactory().CreateLogger<ChallengeService>(), cache);
    }

    private static bool IsValidRequestIdFormat(string requestId)
    {
        if (string.IsNullOrEmpty(requestId) || requestId.Length < 20)
            return false;

        return requestId.StartsWith("REQ_") && 
               System.Text.RegularExpressions.Regex.IsMatch(requestId, @"^[A-Za-z0-9_-]+$", System.Text.RegularExpressions.RegexOptions.IgnoreCase, TimeSpan.FromSeconds(5));
    }

    private static async Task<bool> IsGeographicAnomalyAsync(string clientIp, string apiKey)
    {
        // Simplified geographic check
        // In production, use geolocation service to detect unusual locations
        await Task.Delay(1);
        
        // For demo, check if IP is from unexpected country
        return clientIp.StartsWith("192.168.") || clientIp.StartsWith("10.0."); // Private IPs are "suspicious" for demo
    }

    private static bool IsSuspiciousUserAgent(string userAgent)
    {
        var suspiciousPatterns = new[]
        {
            "bot", "crawler", "spider", "scraper",
            "curl", "wget", "python-requests",
            string.Empty // Empty user agent
        };

        return suspiciousPatterns.Any(pattern => 
            userAgent.Contains(pattern, StringComparison.CurrentCultureIgnoreCase));
    }

    private static bool IsUnusualTimePattern(DateTime requestTime)
    {
        // Business hours check (9 AM - 6 PM UTC)
        var hour = requestTime.Hour;
        return hour is < 9 or > 18;
    }

    private static string MaskApiKey(string apiKey)
    {
        if (string.IsNullOrEmpty(apiKey) || apiKey.Length < 8)
            return "***";

        return apiKey[..4] + "***" + apiKey[^4..];
    }
}