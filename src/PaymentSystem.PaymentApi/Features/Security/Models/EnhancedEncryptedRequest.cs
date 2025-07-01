namespace PaymentSystem.PaymentApi.Features.Security.Models;

/// <summary>
/// Gelişmiş şifrelenmiş istek modeli - Güvenlik katmanları eklendi
/// 
/// Güvenlik Özellikleri:
/// 1. Nonce - Her istek için benzersiz challenge
/// 2. Client Signature - İsteğin bütünlüğü doğrulaması  
/// 3. API Key Header - Client authentication
/// 4. Enhanced Timestamp - Replay attack koruması
/// 
/// Kullanım Akışı:
/// 1. Client /api/security/challenge endpoint'inden nonce alır
/// 2. Nonce + timestamp + data ile signature oluşturur
/// 3. Bu bilgilerle enhanced request gönderir
/// 4. Server nonce'u validate eder ve tek kullanım için siler
/// </summary>
public class EnhancedEncryptedRequest
{
    /// <summary>
    /// Hybrid encryption ile şifrelenmiş payment data
    /// </summary>
    public string EncryptedData { get; set; } = string.Empty;
    
    /// <summary>
    /// İstek zaman damgası - 5 dakika tolerance
    /// </summary>
    public DateTime Timestamp { get; set; }
    
    /// <summary>
    /// Benzersiz istek ID'si (REQ_YYYYMMDD_HHMMSS_GUID formatında)
    /// </summary>
    public string RequestId { get; set; } = string.Empty;
    
    /// <summary>
    /// Challenge endpoint'inden alınan tek kullanımlık nonce
    /// Replay attack'ları önler
    /// </summary>
    public string Nonce { get; set; } = string.Empty;
    
    /// <summary>
    /// Client tarafından oluşturulan request signature (opsiyonel)
    /// HMAC-SHA256(RequestId + Timestamp + Nonce + EncryptedData, ClientSecret)
    /// </summary>
    public string? ClientSignature { get; set; }
    
    /// <summary>
    /// Client identifier - monitoring ve rate limiting için
    /// </summary>
    public string ClientId { get; set; } = string.Empty;
    
    /// <summary>
    /// Request priority (normal, high, critical)
    /// Premium client'lar için farklı rate limits
    /// </summary>
    public string Priority { get; set; } = "normal";
    
    /// <summary>
    /// Client application version - compatibility check için
    /// </summary>
    public string ClientVersion { get; set; } = "1.0.0";
}