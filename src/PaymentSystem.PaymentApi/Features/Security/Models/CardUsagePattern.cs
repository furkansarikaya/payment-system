namespace PaymentSystem.PaymentApi.Features.Security.Models;

public class CardUsagePattern
{
    public HashSet<string> UsedIPs { get; set; } = new();
    public DateTime LastUsed { get; set; }
    public int UsageCount { get; set; }
    public HashSet<string> UsedCountries { get; set; } = new();
}