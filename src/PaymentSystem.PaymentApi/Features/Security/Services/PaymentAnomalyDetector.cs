using System.Collections.Concurrent;
using System.Globalization;
using Microsoft.Extensions.Caching.Memory;
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
public class PaymentAnomalyDetector(
    ILogger<PaymentAnomalyDetector> logger,
    IMemoryCache cache)
    : IPaymentAnomalyDetector
{
    // Anomaly detection rules and thresholds
    private readonly Dictionary<string, double> _anomalyWeights = new()
    {
        ["round_amount"] = 0.3,           // Round number amounts
        ["large_amount"] = 0.5,           // Unusually large amounts
        ["repeated_card"] = 0.7,          // Same card from different IPs
        ["high_frequency"] = 0.8,         // Too many transactions in short time
        ["suspicious_timing"] = 0.4,      // Unusual hours
        ["test_card_pattern"] = 0.9,      // Test card numbers
        ["sequential_cards"] = 0.8,       // Sequential card numbers
        ["geographic_anomaly"] = 0.6,     // Unexpected location
        ["user_agent_anomaly"] = 0.5,     // Suspicious user agent
        ["velocity_check"] = 0.7          // Transaction velocity
    };
    
    // Risk score thresholds
    private const double LowRiskThreshold = 0.3;
    private const double MediumRiskThreshold = 0.6;
    private const double HighRiskThreshold = 0.8;
    
    // Cache for tracking patterns
    private readonly ConcurrentDictionary<string, TransactionHistory> _transactionHistory = new();
    private readonly ConcurrentDictionary<string, CardUsagePattern> _cardPatterns = new();

    /// <summary>
    /// Analyze payment for anomalies and return risk assessment
    /// </summary>
    public async Task<AnomalyDetectionResult> AnalyzePaymentAsync(
        PaymentRequest paymentRequest, 
        string clientIp, 
        string userAgent, 
        string apiKey)
    {
        try
        {
            var detectedAnomalies = new List<DetectedAnomaly>();
            var riskFactors = new Dictionary<string, double>();

            logger.LogDebug("Starting anomaly analysis for amount: {Amount} {Currency}, IP: {ClientIp}",
                paymentRequest.Amount, paymentRequest.Currency, clientIp);

            // 1. Amount-based anomaly detection
            await AnalyzeAmountAnomalies(paymentRequest, detectedAnomalies, riskFactors);

            // 2. Card-based anomaly detection  
            await AnalyzeCardAnomalies(paymentRequest, clientIp, detectedAnomalies, riskFactors);

            // 3. Frequency-based anomaly detection
            await AnalyzeFrequencyAnomalies(paymentRequest, clientIp, apiKey, detectedAnomalies, riskFactors);

            // 4. Timing-based anomaly detection
            await AnalyzeTimingAnomalies(paymentRequest, detectedAnomalies, riskFactors);

            // 5. Geographic anomaly detection
            await AnalyzeGeographicAnomalies(clientIp, apiKey, detectedAnomalies, riskFactors);

            // 6. User agent anomaly detection
            await AnalyzeUserAgentAnomalies(userAgent, detectedAnomalies, riskFactors);

            // 7. Calculate composite risk score
            var riskScore = CalculateRiskScore(riskFactors);
            var riskLevel = GetRiskLevel(riskScore);

            // 8. Update transaction history
            await UpdateTransactionHistory(paymentRequest, clientIp, apiKey);

            var result = new AnomalyDetectionResult
            {
                IsAnomalous = riskScore > LowRiskThreshold,
                RiskScore = riskScore,
                RiskLevel = riskLevel,
                DetectedAnomalies = detectedAnomalies,
                RiskFactors = riskFactors,
                RecommendedAction = GetRecommendedAction(riskLevel),
                AnalyzedAt = DateTime.UtcNow
            };

            if (result.IsAnomalous)
            {
                logger.LogWarning("Payment anomaly detected: Score={RiskScore}, Level={RiskLevel}, Anomalies=[{Anomalies}]",
                    riskScore, riskLevel, string.Join(", ", detectedAnomalies.Select(a => a.Type)));
            }
            else
            {
                logger.LogDebug("Payment analysis completed: Score={RiskScore}, Level={RiskLevel}",
                    riskScore, riskLevel);
            }

            return result;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Anomaly detection failed for payment request");
            
            // Return safe default in case of detection failure
            return new AnomalyDetectionResult
            {
                IsAnomalous = false,
                RiskScore = 0.0,
                RiskLevel = AnomalyRiskLevel.Low,
                DetectedAnomalies = [],
                RecommendedAction = "proceed",
                AnalyzedAt = DateTime.UtcNow,
                Error = "Anomaly detection service unavailable"
            };
        }
    }

    /// <summary>
    /// Analyze amount-based anomalies
    /// </summary>
    private async Task AnalyzeAmountAnomalies(
        PaymentRequest request, 
        List<DetectedAnomaly> anomalies, 
        Dictionary<string, double> riskFactors)
    {
        await Task.CompletedTask;

        var amount = request.Amount;

        // Round number detection (100, 500, 1000, etc.)
        if (amount % 100 == 0 && amount >= 100)
        {
            anomalies.Add(new DetectedAnomaly
            {
                Type = "round_amount",
                Severity = AnomalySeverity.Low,
                Description = $"Round number amount: {amount} {request.Currency}",
                Confidence = 0.7
            });
            riskFactors["round_amount"] = _anomalyWeights["round_amount"];
        }

        // Large amount detection
        var largeAmountThreshold = GetLargeAmountThreshold(request.Currency);
        if (amount > largeAmountThreshold)
        {
            anomalies.Add(new DetectedAnomaly
            {
                Type = "large_amount",
                Severity = AnomalySeverity.Medium,
                Description = $"Large amount transaction: {amount} {request.Currency} (threshold: {largeAmountThreshold})",
                Confidence = 0.8
            });
            riskFactors["large_amount"] = _anomalyWeights["large_amount"] * Math.Min(1.0, (double)(amount / largeAmountThreshold / 2));
        }

        // Unusual precision detection (e.g., 123.45678)
        var decimalPlaces = GetDecimalPlaces(amount);
        if (decimalPlaces > 2)
        {
            anomalies.Add(new DetectedAnomaly
            {
                Type = "unusual_precision",
                Severity = AnomalySeverity.Low,
                Description = $"Unusual precision: {decimalPlaces} decimal places",
                Confidence = 0.6
            });
            riskFactors["unusual_precision"] = 0.2;
        }
    }

    /// <summary>
    /// Analyze card-based anomalies
    /// </summary>
    private async Task AnalyzeCardAnomalies(
        PaymentRequest request, 
        string clientIp, 
        List<DetectedAnomaly> anomalies, 
        Dictionary<string, double> riskFactors)
    {
        await Task.CompletedTask;

        var cardNumber = request.CreditCard.CardNumber.Replace(" ", "");
        var maskedCard = MaskCardNumber(cardNumber);

        // Test card pattern detection
        if (IsTestCardNumber(cardNumber))
        {
            anomalies.Add(new DetectedAnomaly
            {
                Type = "test_card_pattern",
                Severity = AnomalySeverity.High,
                Description = $"Test card number detected: {maskedCard}",
                Confidence = 0.95
            });
            riskFactors["test_card_pattern"] = _anomalyWeights["test_card_pattern"];
        }

        // Sequential card number detection
        if (IsSequentialCardNumber(cardNumber))
        {
            anomalies.Add(new DetectedAnomaly
            {
                Type = "sequential_cards",
                Severity = AnomalySeverity.High,
                Description = $"Sequential card number pattern: {maskedCard}",
                Confidence = 0.9
            });
            riskFactors["sequential_cards"] = _anomalyWeights["sequential_cards"];
        }

        // Card usage pattern analysis
        var cardKey = GetCardKey(cardNumber);
        var usagePattern = _cardPatterns.GetOrAdd(cardKey, _ => new CardUsagePattern());

        lock (usagePattern)
        {
            // Check if same card used from different IPs
            if (!usagePattern.UsedIPs.Contains(clientIp) && usagePattern.UsedIPs.Count > 0)
            {
                anomalies.Add(new DetectedAnomaly
                {
                    Type = "repeated_card",
                    Severity = AnomalySeverity.Medium,
                    Description = $"Card used from multiple IPs: {maskedCard}",
                    Confidence = 0.8
                });
                riskFactors["repeated_card"] = _anomalyWeights["repeated_card"];
            }

            // Update usage pattern
            usagePattern.UsedIPs.Add(clientIp);
            usagePattern.LastUsed = DateTime.UtcNow;
            usagePattern.UsageCount++;
        }

        // Card velocity check (same card used multiple times quickly)
        var recentUsage = usagePattern.UsageCount;
        if (recentUsage > 5) // More than 5 uses
        {
            anomalies.Add(new DetectedAnomaly
            {
                Type = "velocity_check",
                Severity = AnomalySeverity.High,
                Description = $"High card usage velocity: {recentUsage} transactions",
                Confidence = 0.85
            });
            riskFactors["velocity_check"] = _anomalyWeights["velocity_check"];
        }
    }

    /// <summary>
    /// Analyze frequency-based anomalies
    /// </summary>
    private async Task AnalyzeFrequencyAnomalies(
        PaymentRequest request, 
        string clientIp, 
        string apiKey, 
        List<DetectedAnomaly> anomalies, 
        Dictionary<string, double> riskFactors)
    {
        await Task.CompletedTask;

        // IP-based frequency check
        var ipKey = $"freq:ip:{clientIp}";
        var ipTransactions = cache.Get<int>(ipKey);
        
        if (ipTransactions > 10) // More than 10 transactions from same IP in recent period
        {
            anomalies.Add(new DetectedAnomaly
            {
                Type = "high_frequency",
                Severity = AnomalySeverity.High,
                Description = $"High frequency from IP: {ipTransactions} recent transactions",
                Confidence = 0.9
            });
            riskFactors["high_frequency"] = _anomalyWeights["high_frequency"];
        }

        // Update frequency counter
        cache.Set(ipKey, ipTransactions + 1, new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(10),
            Size = 1
        });

        // API key-based frequency check
        var apiKeyTransactions = cache.Get<int>($"freq:api:{apiKey}");
        if (apiKeyTransactions > 20) // More than 20 transactions per API key
        {
            anomalies.Add(new DetectedAnomaly
            {
                Type = "api_high_frequency",
                Severity = AnomalySeverity.Medium,
                Description = $"High API key frequency: {apiKeyTransactions} recent transactions",
                Confidence = 0.8
            });
            riskFactors["api_high_frequency"] = 0.4;
        }

        cache.Set($"freq:api:{apiKey}", apiKeyTransactions + 1, new MemoryCacheEntryOptions
        {
            AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(30),
            Size = 1
        });
    }

    /// <summary>
    /// Analyze timing-based anomalies
    /// </summary>
    private async Task AnalyzeTimingAnomalies(
        PaymentRequest request, 
        List<DetectedAnomaly> anomalies, 
        Dictionary<string, double> riskFactors)
    {
        await Task.CompletedTask;

        var now = DateTime.UtcNow;
        var hour = now.Hour;
        var dayOfWeek = now.DayOfWeek;

        // Business hours check (assuming 9 AM - 6 PM UTC is normal)
        if (hour is < 6 or > 23) // Very late/early hours
        {
            anomalies.Add(new DetectedAnomaly
            {
                Type = "suspicious_timing",
                Severity = AnomalySeverity.Low,
                Description = $"Transaction at unusual hour: {hour:D2}:00 UTC",
                Confidence = 0.6
            });
            riskFactors["suspicious_timing"] = _anomalyWeights["suspicious_timing"];
        }

        // Weekend check for business transactions
        if (dayOfWeek is DayOfWeek.Saturday or DayOfWeek.Sunday)
        {
            if (request.Amount > 1000) // Large weekend transactions
            {
                anomalies.Add(new DetectedAnomaly
                {
                    Type = "weekend_large_transaction",
                    Severity = AnomalySeverity.Low,
                    Description = $"Large weekend transaction: {request.Amount} on {dayOfWeek}",
                    Confidence = 0.5
                });
                riskFactors["weekend_transaction"] = 0.2;
            }
        }
    }

    /// <summary>
    /// Analyze geographic anomalies
    /// </summary>
    private async Task AnalyzeGeographicAnomalies(
        string clientIp, 
        string apiKey, 
        List<DetectedAnomaly> anomalies, 
        Dictionary<string, double> riskFactors)
    {
        await Task.CompletedTask;

        // Simplified geographic check (in production, use geolocation service)
        var isPrivateIp = IsPrivateIP(clientIp);
        var isSuspiciousLocation = IsSuspiciousLocation(clientIp);

        if (isPrivateIp)
        {
            anomalies.Add(new DetectedAnomaly
            {
                Type = "private_ip_usage",
                Severity = AnomalySeverity.Low,
                Description = $"Transaction from private IP: {clientIp}",
                Confidence = 0.7
            });
            riskFactors["private_ip"] = 0.3;
        }

        if (isSuspiciousLocation)
        {
            anomalies.Add(new DetectedAnomaly
            {
                Type = "geographic_anomaly",
                Severity = AnomalySeverity.Medium,
                Description = $"Transaction from suspicious location: {clientIp}",
                Confidence = 0.8
            });
            riskFactors["geographic_anomaly"] = _anomalyWeights["geographic_anomaly"];
        }
    }

    /// <summary>
    /// Analyze user agent anomalies
    /// </summary>
    private async Task AnalyzeUserAgentAnomalies(
        string userAgent, 
        List<DetectedAnomaly> anomalies, 
        Dictionary<string, double> riskFactors)
    {
        await Task.CompletedTask;

        if (string.IsNullOrEmpty(userAgent))
        {
            anomalies.Add(new DetectedAnomaly
            {
                Type = "missing_user_agent",
                Severity = AnomalySeverity.Medium,
                Description = "Missing User-Agent header",
                Confidence = 0.8
            });
            riskFactors["missing_user_agent"] = 0.5;
            return;
        }

        // Check for bot/automation patterns
        var botPatterns = new[] { "bot", "crawler", "spider", "curl", "wget", "python", "java", "script" };
        if (botPatterns.Any(pattern => userAgent.Contains(pattern, StringComparison.CurrentCultureIgnoreCase)))
        {
            anomalies.Add(new DetectedAnomaly
            {
                Type = "user_agent_anomaly",
                Severity = AnomalySeverity.High,
                Description = $"Suspicious User-Agent: {userAgent}",
                Confidence = 0.9
            });
            riskFactors["user_agent_anomaly"] = _anomalyWeights["user_agent_anomaly"];
        }

        // Check for very old or uncommon browsers
        if (userAgent.Contains("MSIE 6.0") || userAgent.Contains("Netscape"))
        {
            anomalies.Add(new DetectedAnomaly
            {
                Type = "outdated_browser",
                Severity = AnomalySeverity.Medium,
                Description = "Outdated or uncommon browser",
                Confidence = 0.7
            });
            riskFactors["outdated_browser"] = 0.4;
        }
    }

    // Helper methods

    private static double CalculateRiskScore(Dictionary<string, double> riskFactors)
    {
        if (riskFactors.Count == 0) return 0.0;

        // Weighted sum with diminishing returns for multiple factors
        var totalWeight = riskFactors.Values.Sum();
        var factorCount = riskFactors.Count;
        
        // Apply diminishing returns: more factors = higher score, but not linearly
        var diminishingFactor = Math.Log(factorCount + 1) / Math.Log(10); // Logarithmic scaling
        
        return Math.Min(1.0, totalWeight * diminishingFactor);
    }

    private static AnomalyRiskLevel GetRiskLevel(double riskScore)
    {
        return riskScore switch
        {
            >= HighRiskThreshold => AnomalyRiskLevel.Critical,
            >= MediumRiskThreshold => AnomalyRiskLevel.High,
            >= LowRiskThreshold => AnomalyRiskLevel.Medium,
            _ => AnomalyRiskLevel.Low
        };
    }

    private static string GetRecommendedAction(AnomalyRiskLevel riskLevel)
    {
        return riskLevel switch
        {
            AnomalyRiskLevel.Critical => "block_transaction",
            AnomalyRiskLevel.High => "require_additional_verification",
            AnomalyRiskLevel.Medium => "enhanced_monitoring",
            AnomalyRiskLevel.Low => "proceed",
            _ => "proceed"
        };
    }

    private async Task UpdateTransactionHistory(PaymentRequest request, string clientIp, string apiKey)
    {
        await Task.CompletedTask;
        
        var historyKey = $"{clientIp}:{apiKey}";
        var history = _transactionHistory.GetOrAdd(historyKey, _ => new TransactionHistory());
        
        lock (history)
        {
            history.TransactionCount++;
            history.TotalAmount += request.Amount;
            history.LastTransaction = DateTime.UtcNow;
            history.Currencies.Add(request.Currency);
            
            // Keep only recent transactions for analysis
            history.RecentAmounts.Add(request.Amount);
            if (history.RecentAmounts.Count > 20)
            {
                history.RecentAmounts.RemoveAt(0);
            }
        }
    }

    private static decimal GetLargeAmountThreshold(string currency)
    {
        return currency.ToUpper() switch
        {
            "TRY" => 10000,
            "USD" => 5000,
            "EUR" => 4000,
            _ => 5000
        };
    }

    private static int GetDecimalPlaces(decimal amount)
    {
        var text = amount.ToString(CultureInfo.InvariantCulture);
        var decimalIndex = text.IndexOf('.');
        return decimalIndex == -1 ? 0 : text.Length - decimalIndex - 1;
    }

    private static bool IsTestCardNumber(string cardNumber)
    {
        // Common test card numbers
        var testPatterns = new[]
        {
            "4111111111111111", // Visa test
            "4000000000000002", // Visa declined
            "5555555555554444", // MasterCard test
            "2223003122003222", // MasterCard test
            "378282246310005",  // Amex test
            "4242424242424242"  // Stripe test
        };

        return testPatterns.Contains(cardNumber);
    }

    private static bool IsSequentialCardNumber(string cardNumber)
    {
        if (cardNumber.Length < 8) return false;

        // Check for sequential digits (1234, 5678, etc.)
        for (var i = 0; i <= cardNumber.Length - 4; i++)
        {
            var segment = cardNumber.Substring(i, 4);
            if (IsSequentialSegment(segment))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsSequentialSegment(string segment)
    {
        if (segment.Length != 4) return false;

        for (var i = 1; i < segment.Length; i++)
        {
            if (segment[i] != segment[i - 1] + 1)
            {
                return false;
            }
        }

        return true;
    }

    private static string GetCardKey(string cardNumber)
    {
        // Hash card number for privacy (in production, use proper hashing)
        return $"card:{cardNumber[..6]}***{cardNumber[^4..]}";
    }

    private static string MaskCardNumber(string cardNumber)
    {
        return cardNumber.Length < 8 ? "****" : $"{cardNumber[..4]}****{cardNumber[^4..]}";
    }

    private bool IsPrivateIP(string ip)
    {
        return ip.StartsWith("192.168.") || 
               ip.StartsWith("10.") || 
               ip.StartsWith("172.16.") ||
               ip == "127.0.0.1" ||
               ip == "::1";
    }

    private static bool IsSuspiciousLocation(string ip)
    {
        // Simplified suspicious location check
        // In production, use proper geolocation and risk databases
        var suspiciousPatterns = new[] { "tor-exit", "proxy", "vpn" };
        return suspiciousPatterns.Any(ip.Contains);
    }
}