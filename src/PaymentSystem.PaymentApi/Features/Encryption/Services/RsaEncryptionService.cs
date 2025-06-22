using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using PaymentSystem.PaymentApi.Features.Encryption.Models;
using PaymentSystem.PaymentApi.Features.Payment.DTOs;

namespace PaymentSystem.PaymentApi.Features.Encryption.Services;

/// <summary>
/// Complete RSA Encryption Service - Hybrid encryption ile güncellendi
/// Tüm IEncryptionService metodlarını implement ediyor
/// </summary>
public class RsaEncryptionService(
    IOptions<EncryptionConfiguration> config,
    IHybridEncryptionService hybridEncryption,
    ILogger<RsaEncryptionService> logger)
    : IEncryptionService
{
    private readonly EncryptionConfiguration _config = config.Value;

    /// <summary>
    /// Hybrid encryption ile veri şifreleme
    /// </summary>
    public string EncryptData(string plainText)
    {
        if (string.IsNullOrEmpty(plainText))
        {
            throw new ArgumentException("Şifrelenecek veri boş olamaz", nameof(plainText));
        }

        try
        {
            var dataSize = Encoding.UTF8.GetByteCount(plainText);
            logger.LogDebug("Encrypting data of size: {Size} bytes", dataSize);

            return hybridEncryption.EncryptData(plainText, _config.PublicKey);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Encryption failed for data size: {Size} bytes",
                Encoding.UTF8.GetByteCount(plainText));
            throw new InvalidOperationException("Şifreleme işlemi başarısız", ex);
        }
    }

    /// <summary>
    /// Hybrid decryption ile veri çözme
    /// </summary>
    public string DecryptData(string encryptedData)
    {
        if (string.IsNullOrEmpty(encryptedData))
        {
            throw new ArgumentException("Şifreli veri boş olamaz", nameof(encryptedData));
        }

        try
        {
            return hybridEncryption.DecryptData(encryptedData, _config.PrivateKey);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Decryption failed");
            throw new InvalidOperationException("Şifre çözme işlemi başarısız", ex);
        }
    }

    /// <summary>
    /// Public key'i döndür - Client API için
    /// </summary>
    public PublicKeyResponseDto GetPublicKey()
    {
        try
        {
            logger.LogDebug("Public key requested");

            // RSA key bilgilerini al
            using var rsa = RSA.Create();
            rsa.ImportFromPem(_config.PublicKey);

            var response = new PublicKeyResponseDto
            {
                PublicKey = _config.PublicKey,
                GeneratedAt = DateTime.UtcNow,
                ValidityHours = 24, // 24 saat geçerli
                KeySize = rsa.KeySize,
                Algorithm = "RSA + AES-256 Hybrid Encryption",
                SupportedPadding = "OAEP-SHA256",
                MaxDirectRsaSize = (rsa.KeySize / 8) - 66, // OAEP padding overhead
                HybridSupport = true // Artık hybrid encryption destekleniyor
            };

            logger.LogInformation("Public key provided. Key size: {KeySize} bits, Hybrid support: enabled",
                response.KeySize);

            return response;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to provide public key");
            throw new InvalidOperationException("Public key alınamadı", ex);
        }
    }

    /// <summary>
    /// Request geçerliliğini kontrol et - timestamp ve format validation
    /// </summary>
    public bool IsRequestValid(EncryptedRequestDto request)
    {
        try
        {
            logger.LogDebug("Validating request: {RequestId}", request.RequestId);

            // 1. Null check
            if (request == null)
            {
                logger.LogWarning("Request validation failed: request is null");
                return false;
            }

            // 2. Required fields check
            if (string.IsNullOrEmpty(request.EncryptedData))
            {
                logger.LogWarning("Request validation failed: encrypted data is missing");
                return false;
            }

            if (string.IsNullOrEmpty(request.RequestId))
            {
                logger.LogWarning("Request validation failed: request ID is missing");
                return false;
            }

            // 3. Timestamp validation
            if (!ValidateTimestamp(request.Timestamp, _config.RequestTimeoutMinutes))
            {
                logger.LogWarning("Request validation failed: timestamp is invalid or expired. " +
                                   "Request time: {RequestTime}, Current time: {CurrentTime}, Timeout: {TimeoutMinutes} minutes",
                    request.Timestamp, DateTime.UtcNow, _config.RequestTimeoutMinutes);
                return false;
            }

            // 4. Encrypted data format validation (hybrid encryption format check)
            if (!IsValidHybridEncryptionFormat(request.EncryptedData))
            {
                logger.LogWarning("Request validation failed: invalid hybrid encryption format");
                return false;
            }

            // 5. Request ID format validation (prevent replay attacks)
            if (!IsValidRequestId(request.RequestId))
            {
                logger.LogWarning("Request validation failed: invalid request ID format");
                return false;
            }

            logger.LogDebug("Request validation successful: {RequestId}", request.RequestId);
            return true;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Request validation error for request ID: {RequestId}",
                request?.RequestId ?? "unknown");
            return false;
        }
    }

    /// <summary>
    /// Timestamp geçerliliğini kontrol et
    /// </summary>
    public bool ValidateTimestamp(DateTime timestamp, int timeoutMinutes)
    {
        var timeDifference = Math.Abs((DateTime.UtcNow - timestamp).TotalMinutes);
        var isValid = timeDifference <= timeoutMinutes;

        logger.LogDebug("Timestamp validation: Time difference: {TimeDifference} minutes, " +
                         "Timeout: {TimeoutMinutes} minutes, Valid: {IsValid}",
            timeDifference, timeoutMinutes, isValid);

        return isValid;
    }

    /// <summary>
    /// Hybrid encryption formatının geçerli olup olmadığını kontrol et
    /// </summary>
    private bool IsValidHybridEncryptionFormat(string encryptedData)
    {
        try
        {
            // Hybrid encryption JSON format'ını parse etmeye çalış
            var hybridResult = JsonSerializer.Deserialize<HybridEncryptionResult>(encryptedData);

            if (hybridResult == null)
                return false;

            // Required fields kontrolü
            if (string.IsNullOrEmpty(hybridResult.EncryptedData) ||
                string.IsNullOrEmpty(hybridResult.EncryptedKey) ||
                string.IsNullOrEmpty(hybridResult.Algorithm))
            {
                return false;
            }

            // Base64 format kontrolü
            try
            {
                _ = Convert.FromBase64String(hybridResult.EncryptedData);
                _ = Convert.FromBase64String(hybridResult.EncryptedKey);
            }
            catch (FormatException)
            {
                return false;
            }

            // Algorithm kontrolü
            return hybridResult.Algorithm.Contains("AES") && hybridResult.Algorithm.Contains("RSA");
        }
        catch (JsonException)
        {
            // JSON parse hatası = geçersiz format
            return false;
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Hybrid encryption format validation error");
            return false;
        }
    }

    /// <summary>
    /// Request ID formatının geçerli olup olmadığını kontrol et
    /// </summary>
    private bool IsValidRequestId(string requestId)
    {
        // Request ID format: REQ_YYYYMMDD_HHMMSS_GUID kısmı
        // Minimum uzunluk kontrolü
        if (string.IsNullOrEmpty(requestId) || requestId.Length < 20)
        {
            return false;
        }

        // REQ_ ile başlamalı
        return requestId.StartsWith("REQ_") &&
               // Sadece alphanumeric ve underscore karakterler
               Regex.IsMatch(requestId, @"^[A-Za-z0-9_-]+$", RegexOptions.IgnoreCase, TimeSpan.FromSeconds(5));
    }
}