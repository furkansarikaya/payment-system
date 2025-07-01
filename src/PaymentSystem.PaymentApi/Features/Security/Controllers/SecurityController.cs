using Microsoft.AspNetCore.Mvc;
using PaymentSystem.PaymentApi.Features.Security.Models;
using PaymentSystem.PaymentApi.Features.Security.Services;

namespace PaymentSystem.PaymentApi.Features.Security.Controllers;

/// <summary>
/// Security Controller - Challenge-Response Authentication ve Security Operations
/// 
/// Bu controller şunları sağlar:
/// 1. Challenge generation (/api/security/challenge)
/// 2. Security statistics (/api/security/stats)
/// 3. Client health check (/api/security/health)
/// 4. Security configuration (/api/security/config)
/// 
/// Güvenlik Özellikleri:
/// - Rate limiting per endpoint
/// - API key authentication required
/// - IP-based access control
/// - Audit logging for all operations
/// 
/// Yol: Client → GET /api/security/challenge → Nonce → Payment Request
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class SecurityController(
    IChallengeService challengeService,
    ISecurityService securityService,
    ILogger<SecurityController> logger)
    : ControllerBase
{
    /// <summary>
    /// Challenge generation endpoint
    /// 
    /// Client flow:
    /// 1. Client requests challenge: GET /api/security/challenge
    /// 2. Server returns nonce with expiration
    /// 3. Client includes nonce in payment request
    /// 4. Server validates nonce (one-time use)
    /// 
    /// Rate Limit: 30 requests/minute per API key
    /// </summary>
    [HttpGet("challenge")]
    public async Task<ActionResult<ChallengeResponseDto>> GetChallenge(
        [FromQuery] string? difficulty = "standard",
        [FromQuery] bool highValue = false)
    {
        try
        {
            var clientIp = GetClientIpAddress();
            var apiKey = HttpContext.Items["ApiKey"]?.ToString() ?? "anonymous";
            var userAgent = Request.Headers.UserAgent.ToString();

            logger.LogInformation("Challenge requested: IP={ClientIp}, ApiKey={ApiKey}, Difficulty={Difficulty}",
                clientIp, MaskApiKey(apiKey), difficulty);

            // Parse difficulty level
            var challengeDifficulty = ParseChallengeDifficulty(difficulty, highValue);

            // Suspicious activity check
            if (await securityService.IsSuspiciousActivityAsync(clientIp, apiKey, userAgent))
            {
                logger.LogWarning("Challenge request from suspicious client: IP={ClientIp}, ApiKey={ApiKey}",
                    clientIp, MaskApiKey(apiKey));

                // Use higher difficulty for suspicious clients
                challengeDifficulty = ChallengeDifficulty.Suspicious;
            }

            // Generate challenge
            var challenge = await challengeService.CreateChallengeAsync(clientIp, challengeDifficulty);

            // Security audit log
            await securityService.LogSecurityEventAsync(new SecurityAuditLog
            {
                EventType = "challenge_requested",
                ClientIp = clientIp,
                UserAgent = userAgent,
                ApiKey = MaskApiKey(apiKey),
                RequestId = HttpContext.TraceIdentifier,
                RiskLevel = SecurityRiskLevel.Low,
                Details = $"Challenge generated with difficulty: {challengeDifficulty}"
            });

            // Add security headers
            Response.Headers.Append("X-Challenge-Difficulty", challengeDifficulty.ToString());
            Response.Headers.Append("X-Security-Level", GetSecurityLevelName(challengeDifficulty));

            logger.LogInformation("Challenge generated successfully: Nonce={Nonce}, IP={ClientIp}, ExpiresIn={ExpiresIn}s",
                MaskNonce(challenge.Nonce), clientIp, challenge.ExpiresIn);

            return Ok(challenge);
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("rate limit"))
        {
            logger.LogWarning("Challenge rate limit exceeded: IP={ClientIp}, Error={Error}", 
                GetClientIpAddress(), ex.Message);

            return StatusCode(429, new
            {
                Error = "Challenge request rate limit exceeded",
                Code = "CHALLENGE_RATE_LIMIT",
                Message = "Too many challenge requests. Please wait before requesting a new challenge.",
                RetryAfter = 60
            });
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("active challenges"))
        {
            logger.LogWarning("Too many active challenges: IP={ClientIp}, Error={Error}", 
                GetClientIpAddress(), ex.Message);

            return BadRequest(new
            {
                Error = "Too many active challenges",
                Code = "TOO_MANY_CHALLENGES",
                Message = "You have too many active challenges. Please use existing challenges or wait for them to expire."
            });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Challenge generation failed: IP={ClientIp}", GetClientIpAddress());

            return StatusCode(503, new
            {
                Error = "Challenge service temporarily unavailable",
                Code = "CHALLENGE_SERVICE_ERROR",
                Message = "Unable to generate challenge at this time. Please try again later."
            });
        }
    }

    /// <summary>
    /// Security statistics endpoint for monitoring
    /// Requires admin permissions
    /// </summary>
    [HttpGet("stats")]
    public async Task<ActionResult<SecurityStatsResponse>> GetSecurityStats()
    {
        try
        {
            var apiKeyConfig = HttpContext.Items["ApiKeyConfig"] as ApiKeyConfig;
            
            // Check admin permission
            if (apiKeyConfig?.Permissions?.Contains("admin.view") != true)
            {
                return Forbid("Admin permissions required");
            }

            var challengeStats = await challengeService.GetChallengeStatisticsAsync();
            var clientIp = GetClientIpAddress();

            var response = new SecurityStatsResponse
            {
                ChallengeStatistics = challengeStats,
                SystemStatus = "healthy",
                LastUpdated = DateTime.UtcNow,
                SecurityLevel = "normal"
            };

            logger.LogInformation("Security stats requested by admin: IP={ClientIp}, ApiKey={ApiKey}",
                clientIp, MaskApiKey(apiKeyConfig?.ApiKey ?? "unknown"));

            return Ok(response);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Security stats request failed");
            return StatusCode(503, new { Error = "Security stats temporarily unavailable" });
        }
    }

    /// <summary>
    /// Security health check endpoint
    /// </summary>
    [HttpGet("health")]
    public async Task<ActionResult<SecurityHealthResponse>> GetSecurityHealth()
    {
        try
        {
            var challengeStats = await challengeService.GetChallengeStatisticsAsync();
            var clientIp = GetClientIpAddress();

            var health = new SecurityHealthResponse
            {
                Status = "healthy",
                Timestamp = DateTime.UtcNow,
                ChallengeService = challengeStats.ActiveChallenges < 1000 ? "healthy" : "degraded",
                SecurityService = "healthy",
                RateLimiting = "healthy",
                Version = "2.0.0"
            };

            // Check system health indicators
            if (challengeStats.ActiveChallenges <= 5000) return Ok(health);
            health.Status = "degraded";
            health.Warnings = ["High number of active challenges"];

            return Ok(health);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Security health check failed");
            
            return StatusCode(503, new SecurityHealthResponse
            {
                Status = "unhealthy",
                Timestamp = DateTime.UtcNow,
                Errors = ["Security service check failed"]
            });
        }
    }

    /// <summary>
    /// Security configuration endpoint
    /// Returns client-safe configuration information
    /// </summary>
    [HttpGet("config")]
    public ActionResult<SecurityConfigResponse> GetSecurityConfig()
    {
        try
        {
            var config = new SecurityConfigResponse
            {
                ChallengeTimeout = new Dictionary<string, int>
                {
                    ["standard"] = 5,    // 5 minutes
                    ["highValue"] = 3,   // 3 minutes
                    ["suspicious"] = 1   // 1 minute
                },
                RateLimits = new Dictionary<string, object>
                {
                    ["challenge"] = new { RequestsPerMinute = 30, BurstCapacity = 10 },
                    ["payment"] = new { RequestsPerMinute = 10, BurstCapacity = 5 },
                    ["publicKey"] = new { RequestsPerMinute = 100, BurstCapacity = 20 }
                },
                SecurityFeatures =
                [
                    "challenge-response-authentication",
                    "api-key-authentication",
                    "rate-limiting",
                    "suspicious-activity-detection",
                    "audit-logging",
                    "ip-based-access-control"
                ],
                Algorithms = new Dictionary<string, object>
                {
                    ["challenge"] = new { Type = "nonce-based", Algorithm = "cryptographically-secure-random" },
                    ["signature"] = new { Type = "HMAC-SHA256", Encoding = "base64" },
                    ["encryption"] = new { Type = "hybrid", Algorithms = "RSA-2048 + AES-256-CBC" }
                },
                Compliance = ["PCI DSS", "GDPR", "SOC 2"]
            };

            return Ok(config);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Security config request failed");
            return StatusCode(503, new { Error = "Security configuration temporarily unavailable" });
        }
    }

    /// <summary>
    /// Client security validation endpoint
    /// Helps clients validate their security implementation
    /// </summary>
    [HttpPost("validate")]
    public Task<ActionResult<SecurityValidationResponse>> ValidateClientSecurity(
        [FromBody] ClientSecurityValidationRequest request)
    {
        try
        {
            var clientIp = GetClientIpAddress();
            var apiKey = HttpContext.Items["ApiKey"]?.ToString() ?? "anonymous";

            logger.LogInformation("Client security validation requested: IP={ClientIp}, ApiKey={ApiKey}",
                clientIp, MaskApiKey(apiKey));

            var validationResults = new List<SecurityValidResult>();

            // Validate nonce format
            if (!string.IsNullOrEmpty(request.Nonce))
            {
                var nonceValid = request.Nonce.StartsWith("CHG_") && request.Nonce.Length >= 20;
                validationResults.Add(new SecurityValidResult
                {
                    Field = "nonce",
                    IsValid = nonceValid,
                    Message = nonceValid ? "Valid nonce format" : "Invalid nonce format",
                    Severity = nonceValid ? "info" : "error"
                });
            }

            // Validate timestamp format
            if (request.Timestamp.HasValue)
            {
                var timeDiff = Math.Abs((DateTime.UtcNow - request.Timestamp.Value).TotalMinutes);
                var timestampValid = timeDiff <= 5;
                validationResults.Add(new SecurityValidResult
                {
                    Field = "timestamp",
                    IsValid = timestampValid,
                    Message = timestampValid ? "Valid timestamp" : $"Timestamp outside allowed window ({timeDiff:F1} minutes)",
                    Severity = timestampValid ? "info" : "warning"
                });
            }

            // Validate signature format
            if (!string.IsNullOrEmpty(request.Signature))
            {
                var signatureValid = IsValidBase64(request.Signature) && request.Signature.Length >= 40;
                validationResults.Add(new SecurityValidResult
                {
                    Field = "signature",
                    IsValid = signatureValid,
                    Message = signatureValid ? "Valid signature format" : "Invalid signature format",
                    Severity = signatureValid ? "info" : "error"
                });
            }

            var response = new SecurityValidationResponse
            {
                IsValid = validationResults.All(r => r.IsValid),
                ValidationResults = validationResults,
                SecurityScore = CalculateSecurityScore(validationResults),
                Recommendations = GenerateSecurityRecommendations(validationResults)
            };

            return Task.FromResult<ActionResult<SecurityValidationResponse>>(Ok(response));
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Client security validation failed");
            return Task.FromResult<ActionResult<SecurityValidationResponse>>(StatusCode(503, new { Error = "Security validation service temporarily unavailable" }));
        }
    }

    // Private helper methods

    private static ChallengeDifficulty ParseChallengeDifficulty(string? difficulty, bool highValue)
    {
        if (highValue)
            return ChallengeDifficulty.HighValue;

        return difficulty?.ToLower() switch
        {
            "standard" => ChallengeDifficulty.Standard,
            "high" or "highvalue" => ChallengeDifficulty.HighValue,
            "suspicious" or "maximum" => ChallengeDifficulty.Suspicious,
            _ => ChallengeDifficulty.Standard
        };
    }

    private static string GetSecurityLevelName(ChallengeDifficulty difficulty)
    {
        return difficulty switch
        {
            ChallengeDifficulty.Standard => "Normal",
            ChallengeDifficulty.HighValue => "Enhanced",
            ChallengeDifficulty.Suspicious => "Maximum",
            _ => "Unknown"
        };
    }

    private string GetClientIpAddress()
    {
        return Request.Headers["X-Forwarded-For"].FirstOrDefault()?.Split(',')[0].Trim()
               ?? Request.Headers["X-Real-IP"].FirstOrDefault()
               ?? HttpContext.Connection.RemoteIpAddress?.ToString()
               ?? "unknown";
    }

    private static string MaskApiKey(string apiKey)
    {
        if (string.IsNullOrEmpty(apiKey) || apiKey.Length < 8)
            return "***";

        return apiKey[..4] + "***" + apiKey[^4..];
    }

    private static string MaskNonce(string nonce)
    {
        if (string.IsNullOrEmpty(nonce) || nonce.Length < 8)
            return "***";

        return nonce[..6] + "***" + nonce[^4..];
    }

    private static bool IsValidBase64(string input)
    {
        try
        {
            Convert.FromBase64String(input);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private int CalculateSecurityScore(List<SecurityValidResult> results)
    {
        if (results.Count == 0) return 0;

        var validCount = results.Count(r => r.IsValid);
        return (int)((double)validCount / results.Count * 100);
    }

    private static List<string> GenerateSecurityRecommendations(List<SecurityValidResult> results)
    {
        var recommendations = new List<string>();

        if (results.Any(r => r is { Field: "nonce", IsValid: false }))
        {
            recommendations.Add("Ensure nonce is obtained from /api/security/challenge endpoint");
        }

        if (results.Any(r => r is { Field: "timestamp", IsValid: false }))
        {
            recommendations.Add("Use current UTC timestamp within 5-minute window");
        }

        if (results.Any(r => r is { Field: "signature", IsValid: false }))
        {
            recommendations.Add("Generate HMAC-SHA256 signature with proper client secret");
        }

        if (recommendations.Count == 0)
        {
            recommendations.Add("Security implementation looks good!");
        }

        return recommendations;
    }
}