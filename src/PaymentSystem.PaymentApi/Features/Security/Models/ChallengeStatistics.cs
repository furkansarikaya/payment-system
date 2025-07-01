namespace PaymentSystem.PaymentApi.Features.Security.Models;

/// <summary>
/// Challenge statistics model
/// </summary>
public class ChallengeStatistics
{
    public int TotalChallengesCreated { get; set; }
    public int ActiveChallenges { get; set; }
    public int ExpiredChallenges { get; set; }
    public int UsedChallenges { get; set; }
    public double AverageTimeToUse { get; set; } // seconds
    public Dictionary<string, int> ChallengesByDifficulty { get; set; } = new();
}