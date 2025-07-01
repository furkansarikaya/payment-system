using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PaymentSystem.ClientApi.Features.PaymentClient.DTOs;
using PaymentSystem.ClientApi.Features.PaymentClient.Models;
using PaymentSystem.ClientApi.Features.Security.Models;
using PaymentSystem.ClientApi.Features.Security.Services;

namespace PaymentSystem.ClientApi.Features.PaymentClient.Services;

/// <summary>
/// Enhanced Payment Client Service with Security Integration
/// 
/// Bu servis Payment API ile güvenli iletişim kurar:
/// 1. Enhanced security challenge integration
/// 2. Nonce-based request authentication
/// 3. Optional client signature generation
/// 4. Comprehensive error handling
/// 5. Performance monitoring
/// 
/// Security Flow:
/// 1. Get challenge (if needed)
/// 2. Generate enhanced encrypted request
/// 3. Include nonce and security metadata
/// 4. Send with proper headers
/// 5. Handle security-related responses
/// </summary>
public class PaymentClientService : IPaymentClientService
{
    private readonly HttpClient _httpClient;
    private readonly IClientSecurityService _securityService;
    private readonly ILogger<PaymentClientService> _logger;
    private readonly string _paymentApiBaseUrl;

    // Enhanced public key cache
    private PublicKeyResponseDto? _cachedPublicKeyResponse;
    private DateTime _publicKeyExpiry;
    private readonly object _keyLock = new object();

    // Client configuration
    private readonly string _clientId;
    private readonly string? _clientSecret;
    private readonly bool _enableSignatures;

    public PaymentClientService(
        HttpClient httpClient,
        IClientSecurityService securityService,
        ILogger<PaymentClientService> logger,
        IConfiguration configuration)
    {
        _httpClient = httpClient;
        _securityService = securityService;
        _logger = logger;
        _paymentApiBaseUrl = configuration["PaymentApi:BaseUrl"] ?? "https://localhost:7000";

        // Client configuration
        _clientId = configuration["PaymentApi:ClientId"] ?? "demo_client";
        _clientSecret = configuration["PaymentApi:ClientSecret"];
        _enableSignatures = !string.IsNullOrEmpty(_clientSecret);

        _httpClient.Timeout = TimeSpan.FromSeconds(30);
        
        // Add default headers
        _httpClient.DefaultRequestHeaders.Add("User-Agent", "PaymentSystem-ClientApi/2.0");
        _httpClient.DefaultRequestHeaders.Add("Accept", "application/json");
        _httpClient.DefaultRequestHeaders.Add("X-Client-Version", "2.0.0");
    }

    /// <summary>
    /// Enhanced payment processing with security integration
    /// </summary>
    public async Task<PaymentResponseDto> ProcessPaymentAsync(PaymentRequestDto paymentRequest)
    {
        try
        {
            var requestId = GenerateRequestId();
            var startTime = DateTime.UtcNow;

            _logger.LogInformation("Enhanced payment processing started: {RequestId}, ClientId: {ClientId}",
                requestId, _clientId);

            // 1. Ensure public key is available
            if (!await EnsurePublicKeyAsync())
            {
                return CreateErrorResponse("KEY_UNAVAILABLE", "Unable to obtain encryption key");
            }

            // 2. Get security challenge
            var challenge = await _securityService.GetChallengeAsync("standard", paymentRequest.Amount > 5000);
            if (challenge == null)
            {
                _logger.LogWarning("Failed to obtain security challenge for request: {RequestId}", requestId);
                return CreateErrorResponse("CHALLENGE_UNAVAILABLE", "Security challenge unavailable");
            }

            _logger.LogDebug("Security challenge obtained: {Nonce} for request: {RequestId}",
                challenge.Nonce[..8] + "***", requestId);

            // 3. Prepare enhanced encrypted request
            var timestamp = DateTime.UtcNow;
            var enhancedRequest = new EnhancedEncryptedRequest
            {
                RequestId = requestId,
                Timestamp = timestamp,
                Nonce = challenge.Nonce,
                ClientId = _clientId,
                ClientVersion = "2.0.0",
                Priority = paymentRequest.Amount > 10000 ? "high" : "normal"
            };

            // 4. Serialize and encrypt payment data
            var paymentJson = JsonSerializer.Serialize(paymentRequest, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });

            enhancedRequest.EncryptedData = await EncryptDataAsync(paymentJson);

            // 5. Generate client signature (if enabled)
            if (_enableSignatures && !string.IsNullOrEmpty(_clientSecret))
            {
                var signatureData = $"{requestId}{timestamp:O}{challenge.Nonce}{enhancedRequest.EncryptedData}";
                enhancedRequest.ClientSignature = _securityService.GenerateClientSignature(signatureData, _clientSecret);
                _logger.LogDebug("Client signature generated for request: {RequestId}", requestId);
            }

            // 6. Send enhanced request
            var requestJson = JsonSerializer.Serialize(enhancedRequest, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });

            var content = new StringContent(requestJson, Encoding.UTF8, "application/json");

            // Add enhanced headers
            content.Headers.Add("X-Request-ID", requestId);
            content.Headers.Add("X-Client-ID", _clientId);
            if (_enableSignatures)
            {
                content.Headers.Add("X-Signature-Enabled", "true");
            }

            _logger.LogDebug("Sending enhanced payment request: {RequestId}, Size: {Size} bytes",
                requestId, requestJson.Length);

            var response = await _httpClient.PostAsync($"{_paymentApiBaseUrl}/api/payment/process", content);
            var responseJson = await response.Content.ReadAsStringAsync();

            // 7. Parse and enhance response
            var paymentResponse = JsonSerializer.Deserialize<PaymentResponseDto>(responseJson, 
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            if (paymentResponse == null)
            {
                return CreateErrorResponse("INVALID_RESPONSE", "Invalid response from payment service");
            }

            // 8. Log performance metrics
            var processingTime = (DateTime.UtcNow - startTime).TotalMilliseconds;
            _logger.LogInformation("Enhanced payment processing completed: {RequestId}, Success: {Success}, Time: {Time}ms",
                requestId, paymentResponse.IsSuccessful, processingTime);

            // 9. Mark challenge as used (client-side tracking)
            challenge.IsUsed = true;

            // 10. Add client-side metadata to response
            if (paymentResponse.IsSuccessful)
            {
                _logger.LogInformation("Payment successful: {RequestId}, TransactionId: {TransactionId}",
                    requestId, paymentResponse.TransactionId);
            }
            else
            {
                _logger.LogWarning("Payment failed: {RequestId}, Error: {ErrorCode}",
                    requestId, paymentResponse.ErrorCode);
            }

            return paymentResponse;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Enhanced payment processing failed");
            return CreateErrorResponse("CLIENT_ERROR", "Payment processing failed");
        }
    }

    /// <summary>
    /// Enhanced public key refresh with metadata
    /// </summary>
    public async Task<bool> RefreshPublicKeyAsync()
    {
        try
        {
            _logger.LogInformation("Refreshing enhanced public key from: {Url}", 
                $"{_paymentApiBaseUrl}/api/payment/public-key");

            var response = await _httpClient.GetAsync($"{_paymentApiBaseUrl}/api/payment/public-key");

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("Enhanced public key request failed: {StatusCode}", response.StatusCode);
                return false;
            }

            var jsonContent = await response.Content.ReadAsStringAsync();
            var publicKeyResponse = JsonSerializer.Deserialize<PublicKeyResponseDto>(jsonContent, 
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });

            if (publicKeyResponse == null || string.IsNullOrEmpty(publicKeyResponse.PublicKey))
            {
                _logger.LogError("Invalid enhanced public key response");
                return false;
            }

            lock (_keyLock)
            {
                _cachedPublicKeyResponse = publicKeyResponse;
                _publicKeyExpiry = publicKeyResponse.GeneratedAt.AddHours(publicKeyResponse.ValidityHours);
            }

            _logger.LogInformation("Enhanced public key cached successfully: KeySize={KeySize} bits, " +
                                   "HybridSupport={HybridSupport}, ValidUntil={ValidUntil}",
                publicKeyResponse.KeySize, publicKeyResponse.HybridSupport, _publicKeyExpiry);

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Enhanced public key refresh failed");
            return false;
        }
    }

    /// <summary>
    /// Enhanced public key validity check
    /// </summary>
    public bool IsPublicKeyValid()
    {
        lock (_keyLock)
        {
            return _cachedPublicKeyResponse != null &&
                   !string.IsNullOrEmpty(_cachedPublicKeyResponse.PublicKey) &&
                   DateTime.UtcNow < _publicKeyExpiry;
        }
    }

    // Private helper methods

    private async Task<bool> EnsurePublicKeyAsync()
    {
        if (!IsPublicKeyValid())
        {
            return await RefreshPublicKeyAsync();
        }
        return true;
    }

    private async Task<string> EncryptDataAsync(string plainText)
    {
        return await Task.Run(() =>
        {
            try
            {
                lock (_keyLock)
                {
                    if (_cachedPublicKeyResponse == null || string.IsNullOrEmpty(_cachedPublicKeyResponse.PublicKey))
                    {
                        throw new InvalidOperationException("Public key not available");
                    }

                    return PerformHybridEncryption(plainText, _cachedPublicKeyResponse.PublicKey);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Enhanced client-side encryption failed");
                throw new InvalidOperationException("Enhanced encryption failed", ex);
            }
        });
    }

    private static string PerformHybridEncryption(string plainText, string publicKeyPem)
    {
        // 1. Generate AES key and IV
        using var aes = Aes.Create();
        aes.GenerateKey();
        aes.GenerateIV();

        // 2. Encrypt data with AES
        byte[] encryptedData;
        using (var encryptor = aes.CreateEncryptor())
        using (var msEncrypt = new MemoryStream())
        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
        using (var swEncrypt = new StreamWriter(csEncrypt))
        {
            swEncrypt.Write(plainText);
            swEncrypt.Flush();
            csEncrypt.FlushFinalBlock();
            encryptedData = msEncrypt.ToArray();
        }

        // 3. Encrypt AES key + IV with RSA
        using var rsa = RSA.Create();
        rsa.ImportFromPem(publicKeyPem);

        var keyAndIV = new byte[aes.Key.Length + aes.IV.Length];
        Array.Copy(aes.Key, 0, keyAndIV, 0, aes.Key.Length);
        Array.Copy(aes.IV, 0, keyAndIV, aes.Key.Length, aes.IV.Length);

        var encryptedKeyAndIV = rsa.Encrypt(keyAndIV, RSAEncryptionPadding.OaepSHA256);

        // 4. Create hybrid result
        var hybridResult = new ClientHybridEncryptionResult
        {
            EncryptedData = Convert.ToBase64String(encryptedData),
            EncryptedKey = Convert.ToBase64String(encryptedKeyAndIV),
            Algorithm = "AES-256-CBC + RSA-OAEP-SHA256",
            KeySize = rsa.KeySize,
            Timestamp = DateTime.UtcNow
        };

        return JsonSerializer.Serialize(hybridResult);
    }

    private static PaymentResponseDto CreateErrorResponse(string errorCode, string message)
    {
        return new PaymentResponseDto
        {
            IsSuccessful = false,
            Message = message,
            ErrorCode = errorCode,
            ProcessedAt = DateTime.UtcNow
        };
    }

    private static string GenerateRequestId()
    {
        return $"REQ_{DateTime.UtcNow:yyyyMMdd_HHmmss}_{Guid.NewGuid():N}"[..32];
    }
}
