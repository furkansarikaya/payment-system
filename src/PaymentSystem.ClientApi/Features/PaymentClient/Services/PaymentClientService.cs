using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PaymentSystem.ClientApi.Features.PaymentClient.DTOs;
using PaymentSystem.ClientApi.Features.PaymentClient.Models;

namespace PaymentSystem.ClientApi.Features.PaymentClient.Services;

/// <summary>
/// Payment API ile güvenli iletişim kuran servis implementasyonu.
/// Bu sınıf RSA şifreleme, public key yönetimi ve HTTP istekleri yapar.
/// 
/// Çalışma mantığı:
/// 1. Payment API'den public key'i alır ve cache'ler
/// 2. Kredi kartı bilgilerini JSON'a çevirir
/// 3. Bu JSON'u RSA public key ile şifreler
/// 4. Şifrelenmiş veriyi Payment API'ye gönderir
/// </summary>
public class PaymentClientService : IPaymentClientService
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<PaymentClientService> _logger;
    private readonly string _paymentApiBaseUrl;

    // Public key cache variables - Enhanced for hybrid
    private PublicKeyResponseDto? _cachedPublicKeyResponse;
    private DateTime _publicKeyExpiry;
    private readonly object _keyLock = new object();

    public PaymentClientService(
        HttpClient httpClient,
        ILogger<PaymentClientService> logger,
        IConfiguration configuration)
    {
        _httpClient = httpClient;
        _logger = logger;
        _paymentApiBaseUrl = configuration["PaymentApi:BaseUrl"] ?? "https://localhost:7000";

        _httpClient.Timeout = TimeSpan.FromSeconds(30);
    }

    /// <summary>
    /// Enhanced public key refresh with hybrid encryption support
    /// </summary>
    public async Task<bool> RefreshPublicKeyAsync()
    {
        try
        {
            _logger.LogInformation("Public key yenileniyor: {Url}", $"{_paymentApiBaseUrl}/api/payment/public-key");

            var response = await _httpClient.GetAsync($"{_paymentApiBaseUrl}/api/payment/public-key");

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("Public key alınamadı. Status: {Status}", response.StatusCode);
                return false;
            }

            var jsonContent = await response.Content.ReadAsStringAsync();
            var publicKeyResponse = JsonSerializer.Deserialize<PublicKeyResponseDto>(jsonContent, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

            if (publicKeyResponse == null || string.IsNullOrEmpty(publicKeyResponse.PublicKey))
            {
                _logger.LogError("Public key yanıtı geçersiz");
                return false;
            }

            lock (_keyLock)
            {
                _cachedPublicKeyResponse = publicKeyResponse;
                _publicKeyExpiry = publicKeyResponse.GeneratedAt.AddHours(publicKeyResponse.ValidityHours);
            }

            _logger.LogInformation("Public key başarıyla cache'lendi. " +
                                   "Key size: {KeySize} bits, Hybrid support: {HybridSupport}, Geçerlilik: {Expiry}",
                publicKeyResponse.KeySize, publicKeyResponse.HybridSupport, _publicKeyExpiry);

            return true;
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "Payment API'ye ulaşılamadı");
            return false;
        }
        catch (TaskCanceledException ex)
        {
            _logger.LogError(ex, "Public key isteği timeout oldu");
            return false;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Public key alınırken beklenmeyen hata");
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

    /// <summary>
    /// Enhanced payment processing with hybrid encryption support
    /// </summary>
    public async Task<PaymentResponseDto> ProcessPaymentAsync(PaymentRequestDto paymentRequest)
    {
        try
        {
            // 1. Public key validation
            if (!IsPublicKeyValid())
            {
                _logger.LogInformation("Public key geçersiz, yenileniyor...");

                var keyRefreshed = await RefreshPublicKeyAsync();
                if (!keyRefreshed)
                {
                    return CreateErrorResponse("KEY_UNAVAILABLE", "Şifreleme anahtarı alınamadı");
                }
            }

            // 2. Payment request preparation
            var requestId = GenerateRequestId();

            _logger.LogInformation("Ödeme işlemi başlatılıyor: {RequestId}, Hybrid encryption: {HybridSupport}",
                requestId, _cachedPublicKeyResponse?.HybridSupport ?? false);

            // 3. Data serialization
            var paymentJson = JsonSerializer.Serialize(paymentRequest, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            });

            var paymentDataSize = Encoding.UTF8.GetByteCount(paymentJson);
            _logger.LogDebug("Payment data size: {Size} bytes. " +
                             "Max direct RSA size: {MaxRsaSize} bytes. Using hybrid: {UsingHybrid}",
                paymentDataSize,
                _cachedPublicKeyResponse?.MaxDirectRsaSize ?? 0,
                paymentDataSize > (_cachedPublicKeyResponse?.MaxDirectRsaSize ?? 0));

            // 4. Hybrid encryption
            var encryptedData = await EncryptDataAsync(paymentJson);

            var encryptedRequest = new EncryptedRequestDto
            {
                EncryptedData = encryptedData,
                Timestamp = DateTime.UtcNow,
                RequestId = requestId
            };

            // 5. API call
            var requestJson = JsonSerializer.Serialize(encryptedRequest);
            var content = new StringContent(requestJson, Encoding.UTF8, "application/json");

            _logger.LogDebug("Payment API'ye istek gönderiliyor: {Url}", $"{_paymentApiBaseUrl}/api/payment/process");

            var response = await _httpClient.PostAsync($"{_paymentApiBaseUrl}/api/payment/process", content);
            var responseJson = await response.Content.ReadAsStringAsync();

            var paymentResponse = JsonSerializer.Deserialize<PaymentResponseDto>(responseJson, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

            if (paymentResponse == null)
            {
                return CreateErrorResponse("INVALID_RESPONSE", "API yanıtı geçersiz");
            }

            if (paymentResponse.IsSuccessful)
            {
                _logger.LogInformation("Ödeme başarılı: {RequestId}, TransactionId: {TransactionId}",
                    requestId, paymentResponse.TransactionId);
            }
            else
            {
                _logger.LogWarning("Ödeme başarısız: {RequestId}, Error: {ErrorCode}",
                    requestId, paymentResponse.ErrorCode);
            }

            return paymentResponse;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Ödeme işlemi sırasında hata oluştu");
            return CreateErrorResponse("CLIENT_ERROR", "İşlem sırasında teknik hata oluştu");
        }
    }

    /// <summary>
    /// Client-side hybrid encryption implementation
    /// </summary>
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
                        throw new InvalidOperationException("Public key cache'de yok");
                    }

                    // Client-side hybrid encryption implementation
                    return PerformHybridEncryption(plainText, _cachedPublicKeyResponse.PublicKey);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Client-side encryption failed");
                throw new InvalidOperationException("Client şifreleme işlemi başarısız", ex);
            }
        });
    }

    /// <summary>
    /// Client-side hybrid encryption (same logic as server)
    /// </summary>
    private static string PerformHybridEncryption(string plainText, string publicKeyPem)
    {
        // 1. AES key ve IV oluştur
        using var aes = Aes.Create();
        aes.GenerateKey();
        aes.GenerateIV();

        var aesKey = aes.Key;
        var aesIV = aes.IV;

        // 2. Veriyi AES ile şifrele
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

        // 3. AES key ve IV'yi RSA ile şifrele
        using var rsa = RSA.Create();
        rsa.ImportFromPem(publicKeyPem);

        var keyAndIV = new byte[aesKey.Length + aesIV.Length];
        Array.Copy(aesKey, 0, keyAndIV, 0, aesKey.Length);
        Array.Copy(aesIV, 0, keyAndIV, aesKey.Length, aesIV.Length);

        var encryptedKeyAndIV = rsa.Encrypt(keyAndIV, RSAEncryptionPadding.OaepSHA256);

        // 4. Result'ı JSON olarak paketla
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