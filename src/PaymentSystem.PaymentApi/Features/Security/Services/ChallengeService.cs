using System.Collections.Concurrent;
using Microsoft.Extensions.Caching.Memory;
using PaymentSystem.PaymentApi.Features.Security.Models;

namespace PaymentSystem.PaymentApi.Features.Security.Services;

/// <summary>
/// Challenge Service Implementation
/// 
/// Bu servis challenge-response authentication'ı yönetir:
/// 1. Cryptographically secure nonce generation
/// 2. Memory-based challenge storage with TTL
/// 3. One-time use enforcement
/// 4. Automatic cleanup of expired challenges
/// 5. Rate limiting per IP for challenge requests
/// 
/// Performance Features:
/// - In-memory storage for fast validation
/// - Concurrent dictionary for thread safety
/// - Background cleanup for memory management
/// - Configurable difficulty levels
/// </summary>
public class ChallengeService : IChallengeService
{
    private readonly ILogger<ChallengeService> _logger;
    private readonly IMemoryCache _cache;
    private readonly ConcurrentDictionary<string, SecurityChallenge> _challenges;
    private readonly Timer _cleanupTimer;
    
    // Challenge configuration
    private readonly Dictionary<ChallengeDifficulty, int> _difficultyTimeouts = new()
    {
        [ChallengeDifficulty.Standard] = 5,    // 5 minutes
        [ChallengeDifficulty.HighValue] = 3,   // 3 minutes
        [ChallengeDifficulty.Suspicious] = 1   // 1 minute
    };
    
    // Rate limiting for challenge requests
    private const int MaxChallengesPerIpPerMinute = 10;
    private const int MaxActiveChallengesPerIp = 5;

    public ChallengeService(ILogger<ChallengeService> logger, IMemoryCache cache)
    {
        _logger = logger;
        _cache = cache;
        _challenges = new ConcurrentDictionary<string, SecurityChallenge>();
        
        // Cleanup timer - her 2 dakikada bir expired challenge'ları temizle
        _cleanupTimer = new Timer(async _ => await CleanupExpiredChallengesAsync(), 
            null, TimeSpan.FromMinutes(2), TimeSpan.FromMinutes(2));
    }

    /// <summary>
    /// Cryptographically secure challenge generation
    /// </summary>
    public async Task<ChallengeResponseDto> CreateChallengeAsync(string clientIp, ChallengeDifficulty difficulty = ChallengeDifficulty.Standard)
    {
        try
        {
            // Rate limiting check
            if (!await CheckChallengeRateLimitAsync(clientIp))
            {
                _logger.LogWarning("Challenge rate limit exceeded for IP: {ClientIp}", clientIp);
                throw new InvalidOperationException("Challenge request rate limit exceeded");
            }

            // Active challenge limit check
            var activeChallenges = await GetActiveChallengeCountAsync(clientIp);
            if (activeChallenges >= MaxActiveChallengesPerIp)
            {
                _logger.LogWarning("Too many active challenges for IP: {ClientIp} (Count: {Count})", 
                    clientIp, activeChallenges);
                throw new InvalidOperationException("Too many active challenges");
            }

            // Generate cryptographically secure nonce
            var nonce = GenerateSecureNonce();
            var timeoutMinutes = _difficultyTimeouts[difficulty];
            
            var challenge = new SecurityChallenge
            {
                Nonce = nonce,
                CreatedAt = DateTime.UtcNow,
                ExpiresInMinutes = timeoutMinutes,
                Difficulty = difficulty,
                ClientIp = clientIp
            };

            // Store challenge
            _challenges[nonce] = challenge;
            
            // Cache for quick lookup
            var cacheKey = $"challenge:{nonce}";
            _cache.Set(cacheKey, challenge, new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(timeoutMinutes),
                Size = 1
            });

            _logger.LogInformation("Challenge created: {Nonce} for IP: {ClientIp}, Difficulty: {Difficulty}, Expires: {ExpiresAt}",
                MaskNonce(nonce), clientIp, difficulty, challenge.ExpiresAt);

            // Increment rate limiting counter
            await IncrementChallengeCounterAsync(clientIp);

            return new ChallengeResponseDto
            {
                Nonce = nonce,
                Timestamp = challenge.CreatedAt,
                ExpiresIn = (int)TimeSpan.FromMinutes(timeoutMinutes).TotalSeconds,
                Algorithm = "HMAC-SHA256",
                Instructions = "Include this nonce in your payment request within the specified time limit",
                Metadata = new Dictionary<string, object>
                {
                    ["difficulty"] = difficulty.ToString(),
                    ["maxUses"] = 1,
                    ["clientIp"] = clientIp,
                    ["securityLevel"] = GetSecurityLevelForDifficulty(difficulty)
                }
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Challenge creation failed for IP: {ClientIp}", clientIp);
            throw;
        }
    }

    /// <summary>
    /// Validate nonce and mark as used (one-time use)
    /// </summary>
    public Task<bool> ValidateNonceAsync(string nonce, string clientIp)
    {
        try
        {
            _logger.LogDebug("Validating nonce: {Nonce} for IP: {ClientIp}", MaskNonce(nonce), clientIp);

            // Check if challenge exists
            if (!_challenges.TryGetValue(nonce, out var challenge))
            {
                _logger.LogWarning("Nonce not found: {Nonce} from IP: {ClientIp}", MaskNonce(nonce), clientIp);
                return Task.FromResult(false);
            }

            // Check if already used
            if (challenge.IsUsed)
            {
                _logger.LogWarning("Nonce already used: {Nonce} from IP: {ClientIp}", MaskNonce(nonce), clientIp);
                return Task.FromResult(false);
            }

            // Check expiration
            if (DateTime.UtcNow > challenge.ExpiresAt)
            {
                _logger.LogWarning("Nonce expired: {Nonce} from IP: {ClientIp}, Expired at: {ExpiresAt}",
                    MaskNonce(nonce), clientIp, challenge.ExpiresAt);
                
                // Remove expired challenge
                _challenges.TryRemove(nonce, out _);
                _cache.Remove($"challenge:{nonce}");
                
                return Task.FromResult(false);
            }

            // IP validation (challenge must be used from same IP)
            if (challenge.ClientIp != clientIp)
            {
                _logger.LogWarning("Nonce IP mismatch: {Nonce}, Expected: {ExpectedIp}, Actual: {ActualIp}",
                    MaskNonce(nonce), challenge.ClientIp, clientIp);
                return Task.FromResult(false);
            }

            // Mark as used (one-time use)
            challenge.IsUsed = true;
            challenge.UsedAt = DateTime.UtcNow;
            
            // Update cache
            _cache.Set($"challenge:{nonce}", challenge, new MemoryCacheEntryOptions
            {
                AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(5),
                Size = 1
            }); // Keep for audit

            _logger.LogInformation("Nonce successfully validated and marked as used: {Nonce} for IP: {ClientIp}",
                MaskNonce(nonce), clientIp);

            return Task.FromResult(true);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Nonce validation failed for: {Nonce}", MaskNonce(nonce));
            return Task.FromResult(false);
        }
    }

    /// <summary>
    /// Get active challenge count for specific IP
    /// </summary>
    public async Task<int> GetActiveChallengeCountAsync(string clientIp)
    {
        await Task.CompletedTask; // For async interface compatibility
        
        var now = DateTime.UtcNow;
        return _challenges.Values.Count(c => 
            c.ClientIp == clientIp && 
            !c.IsUsed && 
            c.ExpiresAt > now);
    }

    /// <summary>
    /// Background cleanup of expired challenges
    /// </summary>
    public async Task CleanupExpiredChallengesAsync()
    {
        try
        {
            var now = DateTime.UtcNow;
            var expiredNonces = _challenges
                .Where(kvp => kvp.Value.ExpiresAt <= now)
                .Select(kvp => kvp.Key)
                .ToList();

            var cleanedCount = 0;
            foreach (var nonce in expiredNonces.Where(nonce => _challenges.TryRemove(nonce, out _)))
            {
                _cache.Remove($"challenge:{nonce}");
                cleanedCount++;
            }

            if (cleanedCount > 0)
            {
                _logger.LogInformation("Cleaned up {Count} expired challenges. Active challenges: {ActiveCount}",
                    cleanedCount, _challenges.Count);
            }

            await Task.CompletedTask;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Challenge cleanup failed");
        }
    }

    /// <summary>
    /// Get challenge statistics for monitoring
    /// </summary>
    public async Task<ChallengeStatistics> GetChallengeStatisticsAsync()
    {
        await Task.CompletedTask;

        var now = DateTime.UtcNow;
        var allChallenges = _challenges.Values.ToList();

        var statistics = new ChallengeStatistics
        {
            TotalChallengesCreated = allChallenges.Count,
            ActiveChallenges = allChallenges.Count(c => !c.IsUsed && c.ExpiresAt > now),
            ExpiredChallenges = allChallenges.Count(c => c.ExpiresAt <= now),
            UsedChallenges = allChallenges.Count(c => c.IsUsed),
            AverageTimeToUse = allChallenges
                .Where(c => c is { IsUsed: true, UsedAt: not null })
                .Select(c => (c.UsedAt!.Value - c.CreatedAt).TotalSeconds)
                .DefaultIfEmpty(0)
                .Average(),
            ChallengesByDifficulty = allChallenges
                .GroupBy(c => c.Difficulty.ToString())
                .ToDictionary(g => g.Key, g => g.Count())
        };

        return statistics;
    }

    // Private helper methods

    private static string GenerateSecureNonce()
    {
        // Cryptographically secure random nonce generation
        var timestamp = DateTime.UtcNow.ToString("yyyyMMddHHmmss");
        var randomBytes = new byte[16]; // 128-bit entropy
        using (var rng = System.Security.Cryptography.RandomNumberGenerator.Create())
        {
            rng.GetBytes(randomBytes);
        }
        var randomPart = Convert.ToBase64String(randomBytes)
            .Replace("+", "")
            .Replace("/", "")
            .Replace("=", "")[..12]; // 12 character random part

        return $"CHG_{timestamp}_{randomPart}";
    }

    private async Task<bool> CheckChallengeRateLimitAsync(string clientIp)
    {
        var rateLimitKey = $"challenge_rate:{clientIp}:{DateTime.UtcNow:yyyyMMddHHmm}";
        var currentCount = _cache.Get<int>(rateLimitKey);
        
        if (currentCount >= MaxChallengesPerIpPerMinute)
        {
            return false;
        }

        _cache.Set(rateLimitKey, currentCount + 1, new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(1),
            Size = 1
        });
        await Task.CompletedTask;
        return true;
    }

    private async Task IncrementChallengeCounterAsync(string clientIp)
    {
        var counterKey = $"challenge_count:{clientIp}";
        var currentCount = _cache.Get<int>(counterKey);
        _cache.Set(counterKey, currentCount + 1, new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(1),
            Size = 1
        });
        await Task.CompletedTask;
    }

    private static string GetSecurityLevelForDifficulty(ChallengeDifficulty difficulty)
    {
        return difficulty switch
        {
            ChallengeDifficulty.Standard => "Normal",
            ChallengeDifficulty.HighValue => "Enhanced",
            ChallengeDifficulty.Suspicious => "Maximum",
            _ => "Unknown"
        };
    }

    private static string MaskNonce(string nonce)
    {
        if (string.IsNullOrEmpty(nonce) || nonce.Length < 8)
            return "***";

        return nonce[..6] + "***" + nonce[^4..];
    }

    public void Dispose()
    {
        _cleanupTimer?.Dispose();
    }
}