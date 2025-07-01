using PaymentSystem.PaymentApi.Features.Payment.Models;
using PaymentSystem.PaymentApi.Features.Security.Models;

namespace PaymentSystem.PaymentApi.Features.Security.Services;

/// <summary>
/// Payment Anomaly Detection Service
/// 
/// Bu servis şüpheli ödeme pattern'larını tespit eder:
/// 1. Unusual amount patterns (round numbers, large amounts)
/// 2. Repeated card usage from different locations  
/// 3. High-frequency transactions
/// 4. Suspicious timing patterns
/// 5. Card number patterns (sequential, test cards)
/// 6. Geographic anomalies
/// 7. User agent anomalies
/// 8. Velocity checks (too many transactions)
/// 
/// Machine Learning Features:
/// - Pattern recognition algorithms
/// - Behavioral analysis
/// - Risk scoring models
/// - Adaptive thresholds
/// 
/// Yol: PaymentService → AnomalyDetector → Risk Assessment
/// </summary>
// Interface for anomaly detector
public interface IPaymentAnomalyDetector
{
    Task<AnomalyDetectionResult> AnalyzePaymentAsync(
        PaymentRequest paymentRequest, 
        string clientIp, 
        string userAgent, 
        string apiKey);
}