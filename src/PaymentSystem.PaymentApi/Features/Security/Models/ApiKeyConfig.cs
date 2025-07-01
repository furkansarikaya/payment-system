namespace PaymentSystem.PaymentApi.Features.Security.Models;

/// <summary>
/// API Key Configuration ve Management
/// 
/// Her client için unique API key ile:
/// - Authentication
/// - Rate limiting per key
/// - Usage tracking
/// - Permission management
/// </summary>
public class ApiKeyConfig
{
    /// <summary>
    /// Unique API Key identifier
    /// Format: ak_live_XXXXXXXXXXXXXXXX (production)
    ///         ak_test_XXXXXXXXXXXXXXXX (development)
    /// </summary>
    public string ApiKey { get; set; } = string.Empty;
    
    /// <summary>
    /// API Key'in insan okunabilir adı
    /// </summary>
    public string Name { get; set; } = string.Empty;
    
    /// <summary>
    /// Client/Organization identifier
    /// </summary>
    public string ClientId { get; set; } = string.Empty;
    
    /// <summary>
    /// Environment (development, staging, production)
    /// </summary>
    public string Environment { get; set; } = string.Empty;
    
    /// <summary>
    /// API Key oluşturulma tarihi
    /// </summary>
    public DateTime CreatedAt { get; set; }
    
    /// <summary>
    /// Son kullanım tarihi
    /// </summary>
    public DateTime? LastUsedAt { get; set; }
    
    /// <summary>
    /// Aktif mi?
    /// </summary>
    public bool IsActive { get; set; } = true;
    
    /// <summary>
    /// Rate limiting configuration
    /// </summary>
    public RateLimitConfig RateLimit { get; set; } = new();
    
    /// <summary>
    /// İzin verilen IP adresleri (opsiyonel)
    /// </summary>
    public List<string> AllowedIPs { get; set; } = new();
    
    /// <summary>
    /// API Key permissions
    /// </summary>
    public List<string> Permissions { get; set; } = new() { "payment.process", "payment.query" };
    
    /// <summary>
    /// Günlük kullanım limiti
    /// </summary>
    public int DailyLimit { get; set; } = 1000;
    
    /// <summary>
    /// Bugün kullanım sayısı
    /// </summary>
    public int TodayUsage { get; set; } = 0;
}