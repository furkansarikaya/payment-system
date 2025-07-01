using PaymentSystem.ClientApi.Features.Security.Models;

namespace PaymentSystem.ClientApi.Features.Security.Services;

/// <summary>
/// Client Security Service Interface
/// 
/// Bu servis Client API tarafında güvenlik operasyonlarını yönetir:
/// - Challenge istekleri
/// - Nonce yönetimi
/// - Client signature generation
/// - Security metadata tracking
/// </summary>
public interface IClientSecurityService
{
    /// <summary>
    /// Payment API'den security challenge alır
    /// </summary>
    Task<ClientSecurityChallenge?> GetChallengeAsync(string difficulty = "standard", bool highValue = false);
    
    /// <summary>
    /// HMAC-SHA256 client signature oluşturur
    /// </summary>
    string GenerateClientSignature(string requestData, string clientSecret);
    
    /// <summary>
    /// Challenge cache'ini temizler
    /// </summary>
    Task ClearExpiredChallengesAsync();
    
    /// <summary>
    /// Client güvenlik durumunu kontrol eder
    /// </summary>
    Task<ClientSecurityStatus> GetSecurityStatusAsync();
}