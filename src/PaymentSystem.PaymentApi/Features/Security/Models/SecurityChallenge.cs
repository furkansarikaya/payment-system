namespace PaymentSystem.PaymentApi.Features.Security.Models;

/// <summary>
/// Challenge-Response Authentication için güvenlik challenge'ı
/// 
/// Bu sistem şu şekilde çalışır:
/// 1. Client challenge ister
/// 2. Server benzersiz nonce + timestamp döndürür  
/// 3. Client bu bilgilerle request oluşturur
/// 4. Server nonce'u validate eder (tek kullanım)
/// 5. Başarılı validation sonrası nonce expire edilir
/// 
/// Faydalar:
/// - Replay attack koruması
/// - Time-bound security
/// - Stateless challenge verification
/// </summary>
public class SecurityChallenge
{
    /// <summary>
    /// Benzersiz challenge identifier
    /// Format: CHG_YYYYMMDDHHMMSS_GUID
    /// </summary>
    public string Nonce { get; set; } = string.Empty;
    
    /// <summary>
    /// Challenge oluşturulma zamanı
    /// </summary>
    public DateTime CreatedAt { get; set; }
    
    /// <summary>
    /// Challenge geçerlilik süresi (dakika)
    /// Default: 5 dakika
    /// </summary>
    public int ExpiresInMinutes { get; set; } = 5;
    
    /// <summary>
    /// Challenge expire zamanı
    /// </summary>
    public DateTime ExpiresAt => CreatedAt.AddMinutes(ExpiresInMinutes);
    
    /// <summary>
    /// Challenge complexity level
    /// </summary>
    public ChallengeDifficulty Difficulty { get; set; } = ChallengeDifficulty.Standard;
    
    /// <summary>
    /// Challenge oluşturan client IP
    /// </summary>
    public string ClientIp { get; set; } = string.Empty;
    
    /// <summary>
    /// Challenge kullanıldı mı?
    /// </summary>
    public bool IsUsed { get; set; } = false;
    
    /// <summary>
    /// Kullanım zamanı
    /// </summary>
    public DateTime? UsedAt { get; set; }
}