namespace PaymentSystem.PaymentApi.Features.Security.Models;

/// <summary>
/// Challenge difficulty levels
/// </summary>
public enum ChallengeDifficulty
{
    /// <summary>
    /// Standard challenge - 5 dakika geçerli
    /// </summary>
    Standard = 0,
    
    /// <summary>
    /// High-value transaction - 3 dakika geçerli
    /// </summary>
    HighValue = 1,
    
    /// <summary>
    /// Suspicious client - 1 dakika geçerli
    /// </summary>
    Suspicious = 2
}