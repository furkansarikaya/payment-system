namespace PaymentSystem.PaymentApi.Features.Payment.DTOs;

/// <summary>
/// Enhanced Public Key Response - Hybrid encryption bilgileri eklendi
/// </summary>
public class PublicKeyResponseDto
{
    public string PublicKey { get; set; } = string.Empty;
    public DateTime GeneratedAt { get; set; }
    public int ValidityHours { get; set; }
    public int KeySize { get; set; }
    public string Algorithm { get; set; } = string.Empty;
    public string SupportedPadding { get; set; } = string.Empty;
        
    // Hybrid encryption için yeni alanlar
    public int MaxDirectRsaSize { get; set; }          // Pure RSA ile şifrelenebilecek maksimum boyut
    public bool HybridSupport { get; set; }            // Hybrid encryption desteği var mı?
    public string RecommendedApproach { get; set; } = "Hybrid encryption for all data sizes"; // Önerilen yaklaşım
        
    // Client'a yardımcı bilgiler
    public Dictionary<string, object> ClientGuidance { get; set; } = new()
    {
        ["small_data_threshold"] = 200,  // 200 byte altı "küçük" sayılır
        ["always_use_hybrid"] = true,    // Her zaman hybrid kullan
        ["performance_benefit"] = "~10x faster than pure RSA for large data"
    };
}