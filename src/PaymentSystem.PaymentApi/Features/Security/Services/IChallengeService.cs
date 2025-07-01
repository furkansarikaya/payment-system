using PaymentSystem.PaymentApi.Features.Security.Models;

namespace PaymentSystem.PaymentApi.Features.Security.Services;

/// <summary>
/// Challenge-Response Authentication Service Interface
/// 
/// Bu servis şunları sağlar:
/// - Unique nonce generation
/// - Challenge validation
/// - One-time use enforcement
/// - Expiration management
/// - Anti-replay protection
/// </summary>
public interface IChallengeService
{
    /// <summary>
    /// Yeni security challenge oluşturur
    /// </summary>
    Task<ChallengeResponseDto> CreateChallengeAsync(string clientIp, ChallengeDifficulty difficulty = ChallengeDifficulty.Standard);
    
    /// <summary>
    /// Nonce'un geçerliliğini kontrol eder ve tek kullanım için işaretler
    /// </summary>
    Task<bool> ValidateNonceAsync(string nonce, string clientIp);
    
    /// <summary>
    /// Belirli client için aktif challenge sayısını döndürür
    /// </summary>
    Task<int> GetActiveChallengeCountAsync(string clientIp);
    
    /// <summary>
    /// Expired challenge'ları temizler
    /// </summary>
    Task CleanupExpiredChallengesAsync();
    
    /// <summary>
    /// Challenge istatistiklerini döndürür
    /// </summary>
    Task<ChallengeStatistics> GetChallengeStatisticsAsync();
}