namespace PaymentSystem.PaymentApi.Features.Security.Models;

// Tracking models for pattern analysis
public class TransactionHistory
{
    public int TransactionCount { get; set; }
    public decimal TotalAmount { get; set; }
    public DateTime LastTransaction { get; set; }
    public HashSet<string> Currencies { get; set; } = new();
    public List<decimal> RecentAmounts { get; set; } = new();
}