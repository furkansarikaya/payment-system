using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Caching.Memory;
using PaymentSystem.ClientApi.Features.Security.DTOs;
using PaymentSystem.ClientApi.Features.Security.Models;

namespace PaymentSystem.ClientApi.Features.Security.Services;

/// <summary>
/// Client Security Service Implementation
/// 
/// Bu servis Client API'nin güvenlik operasyonlarını yönetir:
/// 1. Payment API'den challenge isteme
/// 2. Nonce cache management
/// 3. Client signature generation
/// 4. Security status monitoring
/// 
/// Cache Strategy:
/// - Challenge'ları memory'de cache'ler
/// - Automatic expiration handling
/// - Thread-safe operations
/// </summary>
public class ClientSecurityService(
    HttpClient httpClient,
    IMemoryCache cache,
    ILogger<ClientSecurityService> logger,
    IConfiguration configuration)
    : IClientSecurityService
{
    private readonly string _paymentApiBaseUrl = configuration["PaymentApi:BaseUrl"] ?? "https://localhost:7000";
    private readonly SemaphoreSlim _challengeLock = new(1, 1);

    /// <summary>
    /// Get security challenge from Payment API with caching
    /// </summary>
    public async Task<ClientSecurityChallenge?> GetChallengeAsync(string difficulty = "standard", bool highValue = false)
    {
        await _challengeLock.WaitAsync();
        try
        {
            logger.LogDebug("Requesting security challenge: difficulty={Difficulty}, highValue={HighValue}",
                difficulty, highValue);

            // Check cache first
            var cacheKey = $"challenge:{difficulty}:{highValue}";
            if (cache.TryGetValue(cacheKey, out ClientSecurityChallenge? cachedChallenge) && 
                cachedChallenge is { IsExpired: false })
            {
                logger.LogDebug("Using cached challenge: {Nonce}", MaskNonce(cachedChallenge.Nonce));
                return cachedChallenge;
            }

            // Request new challenge
            var queryParams = new List<string>();
            if (!string.IsNullOrEmpty(difficulty) && difficulty != "standard")
            {
                queryParams.Add($"difficulty={Uri.EscapeDataString(difficulty)}");
            }
            if (highValue)
            {
                queryParams.Add("highValue=true");
            }

            var queryString = queryParams.Any() ? "?" + string.Join("&", queryParams) : "";
            var requestUrl = $"{_paymentApiBaseUrl}/api/security/challenge{queryString}";

            logger.LogDebug("Requesting challenge from: {Url}", requestUrl);

            var response = await httpClient.GetAsync(requestUrl);

            if (!response.IsSuccessStatusCode)
            {
                logger.LogError("Challenge request failed: {StatusCode} - {ReasonPhrase}", 
                    response.StatusCode, response.ReasonPhrase);
                return null;
            }

            var jsonContent = await response.Content.ReadAsStringAsync();
            var challengeResponse = JsonSerializer.Deserialize<ChallengeResponseDto>(jsonContent, 
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            if (challengeResponse == null || string.IsNullOrEmpty(challengeResponse.Nonce))
            {
                logger.LogError("Invalid challenge response received");
                return null;
            }

            var clientChallenge = new ClientSecurityChallenge
            {
                Nonce = challengeResponse.Nonce,
                Timestamp = challengeResponse.Timestamp,
                ExpiresIn = challengeResponse.ExpiresIn,
                Algorithm = challengeResponse.Algorithm,
                Instructions = challengeResponse.Instructions,
                Metadata = challengeResponse.Metadata,
                RequestedAt = DateTime.UtcNow,
                IsUsed = false
            };

            // Cache the challenge
            var cacheExpiry = TimeSpan.FromSeconds(challengeResponse.ExpiresIn);
            cache.Set(cacheKey, clientChallenge, new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = cacheExpiry,
                Size = 1
            });

            logger.LogInformation("Challenge obtained successfully: {Nonce}, ExpiresIn={ExpiresIn}s",
                MaskNonce(clientChallenge.Nonce), challengeResponse.ExpiresIn);

            return clientChallenge;
        }
        catch (HttpRequestException ex)
        {
            logger.LogError(ex, "HTTP error requesting challenge from Payment API");
            return null;
        }
        catch (TaskCanceledException ex)
        {
            logger.LogError(ex, "Timeout requesting challenge from Payment API");
            return null;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Unexpected error requesting challenge");
            return null;
        }
        finally
        {
            _challengeLock.Release();
        }
    }

    /// <summary>
    /// Generate HMAC-SHA256 client signature for request integrity
    /// </summary>
    public string GenerateClientSignature(string requestData, string clientSecret)
    {
        try
        {
            logger.LogDebug("Generating client signature for data length: {Length}", requestData.Length);

            using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(clientSecret));
            var hashBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(requestData));
            var signature = Convert.ToBase64String(hashBytes);

            logger.LogDebug("Client signature generated successfully");
            return signature;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to generate client signature");
            throw new InvalidOperationException("Client signature generation failed", ex);
        }
    }

    /// <summary>
    /// Clean up expired challenges from cache
    /// </summary>
    public async Task ClearExpiredChallengesAsync()
    {
        await Task.CompletedTask; // Memory cache handles expiration automatically
        logger.LogDebug("Expired challenges cleanup completed (automatic via MemoryCache)");
    }

    /// <summary>
    /// Get current client security status
    /// </summary>
    public async Task<ClientSecurityStatus> GetSecurityStatusAsync()
    {
        try
        {
            var status = new ClientSecurityStatus
            {
                Timestamp = DateTime.UtcNow,
                SecurityLevel = "enhanced",
                ChallengeServiceAvailable = await TestChallengeServiceAsync(),
                PaymentApiConnectivity = await TestPaymentApiConnectivityAsync(),
                SecurityFeatures =
                [
                    "challenge-response-authentication",
                    "hmac-signature-generation",
                    "automatic-challenge-caching",
                    "secure-http-client",
                    "request-timeout-handling"
                ]
            };

            // Determine overall status
            if (status is { ChallengeServiceAvailable: true, PaymentApiConnectivity: true })
            {
                status.OverallStatus = "healthy";
            }
            else if (status.PaymentApiConnectivity)
            {
                status.OverallStatus = "degraded";
                status.Warnings = ["Challenge service unavailable"];
            }
            else
            {
                status.OverallStatus = "unhealthy";
                status.Errors = ["Payment API connectivity failed"];
            }

            return status;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to get security status");
            
            return new ClientSecurityStatus
            {
                Timestamp = DateTime.UtcNow,
                OverallStatus = "error",
                SecurityLevel = "unknown",
                Errors = ["Security status check failed"]
            };
        }
    }

    // Private helper methods

    private async Task<bool> TestChallengeServiceAsync()
    {
        try
        {
            var challenge = await GetChallengeAsync("standard", false);
            return challenge != null && !string.IsNullOrEmpty(challenge.Nonce);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Challenge service test failed");
            return false;
        }
    }

    private async Task<bool> TestPaymentApiConnectivityAsync()
    {
        try
        {
            var response = await httpClient.GetAsync($"{_paymentApiBaseUrl}/api/payment/health");
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Payment API connectivity test failed");
            return false;
        }
    }

    private static string MaskNonce(string nonce)
    {
        if (string.IsNullOrEmpty(nonce) || nonce.Length < 8)
            return "***";

        return nonce[..6] + "***" + nonce[^4..];
    }
}