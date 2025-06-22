using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using PaymentSystem.PaymentApi.Features.Encryption.Models;
using PaymentSystem.PaymentApi.Features.Encryption.Services;
using PaymentSystem.PaymentApi.Features.Payment.DTOs;
using PaymentSystem.PaymentApi.Features.Payment.Models;
using PaymentSystem.PaymentApi.Features.Payment.Services;

namespace PaymentSystem.PaymentApi.Features.Payment.Controllers;

[ApiController]
[Route("api/[controller]")]
[EnableRateLimiting("PaymentPolicy")]
public class PaymentController(
    IPaymentService paymentService,
    IEncryptionService encryptionService,
    ILogger<PaymentController> logger)
    : ControllerBase
{
    /// <summary>
    /// Enhanced public key endpoint with hybrid encryption support
    /// </summary>
    [HttpGet("public-key")]
    public Task<ActionResult<PublicKeyResponseDto>> GetPublicKey()
    {
        try
        {
            logger.LogInformation("Public key istendi. Client IP: {ClientIP}",
                HttpContext.Connection.RemoteIpAddress?.ToString());

            var publicKeyResponse = encryptionService.GetPublicKey();

            logger.LogInformation("Public key sağlandı. Key size: {KeySize} bits, Hybrid support: {HybridSupport}",
                publicKeyResponse.KeySize, publicKeyResponse.HybridSupport);

            // Response headers ekle
            Response.Headers.Append("X-Key-Size", publicKeyResponse.KeySize.ToString());
            Response.Headers.Append("X-Hybrid-Support", publicKeyResponse.HybridSupport.ToString());
            Response.Headers.Append("X-Max-Direct-RSA-Size", publicKeyResponse.MaxDirectRsaSize.ToString());

            return Task.FromResult<ActionResult<PublicKeyResponseDto>>(Ok(publicKeyResponse));
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Public key sağlanırken hata oluştu");
            return Task.FromResult<ActionResult<PublicKeyResponseDto>>(StatusCode(503, new { Error = "Public key şu anda kullanılamıyor", Code = "KEY_UNAVAILABLE" }));
        }
    }

    /// <summary>
    /// Enhanced payment processing with hybrid encryption support and comprehensive validation
    /// </summary>
    [HttpPost("process")]
    public async Task<ActionResult<PaymentResponseDto>> ProcessPayment([FromBody] EncryptedRequestDto encryptedRequest)
    {
        string? requestId = null;

        try
        {
            requestId = encryptedRequest?.RequestId ?? "unknown";

            logger.LogInformation("Ödeme isteği alındı: {RequestId}, Timestamp: {Timestamp}",
                requestId, encryptedRequest?.Timestamp);

            // 1. Input validation
            if (encryptedRequest == null)
            {
                logger.LogWarning("Ödeme isteği null: {RequestId}", requestId);
                return BadRequest(new PaymentResponseDto
                {
                    IsSuccessful = false,
                    Message = "Ödeme isteği geçersiz",
                    ErrorCode = "INVALID_REQUEST",
                    ProcessedAt = DateTime.UtcNow
                });
            }

            // 2. Request validation (includes hybrid format validation)
            if (!encryptionService.IsRequestValid(encryptedRequest))
            {
                logger.LogWarning("Ödeme isteği geçersiz: {RequestId}", requestId);
                return BadRequest(new PaymentResponseDto
                {
                    IsSuccessful = false,
                    Message = "İstek formatı geçersiz veya süresi dolmuş",
                    ErrorCode = "INVALID_REQUEST_FORMAT",
                    ProcessedAt = DateTime.UtcNow
                });
            }

            // 3. Decrypt payment data using hybrid decryption
            string decryptedJson;
            try
            {
                decryptedJson = encryptionService.DecryptData(encryptedRequest.EncryptedData);
                logger.LogDebug("Hybrid decryption başarılı: {RequestId}", requestId);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Şifre çözme hatası: {RequestId}", requestId);
                return Unauthorized(new PaymentResponseDto
                {
                    IsSuccessful = false,
                    Message = "Şifre çözme hatası",
                    ErrorCode = "DECRYPTION_FAILED",
                    ProcessedAt = DateTime.UtcNow
                });
            }

            // 4. Deserialize payment request
            PaymentRequest? paymentRequest;
            try
            {
                paymentRequest = System.Text.Json.JsonSerializer.Deserialize<PaymentRequest>(decryptedJson,
                    new System.Text.Json.JsonSerializerOptions
                    {
                        PropertyNameCaseInsensitive = true,
                        AllowTrailingCommas = true
                    });
                if (paymentRequest == null)
                {
                    throw new InvalidOperationException("Deserialization resulted in null");
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "JSON deserialization hatası: {RequestId}", requestId);
                return BadRequest(new PaymentResponseDto
                {
                    IsSuccessful = false,
                    Message = "Ödeme verisi formatı geçersiz",
                    ErrorCode = "INVALID_PAYMENT_DATA",
                    ProcessedAt = DateTime.UtcNow
                });
            }

            // 5. Add request tracking information
            paymentRequest.CustomerReference = requestId;

            // 6. Process payment
            logger.LogInformation("Ödeme işleme başlatılıyor: {RequestId}, Tutar: {Amount} {Currency}",
                requestId, paymentRequest.Amount, paymentRequest.Currency);

            var result = await paymentService.ProcessPaymentAsync(paymentRequest);

            // 7. Log result
            if (result.IsSuccessful)
            {
                logger.LogInformation("Ödeme başarılı: {RequestId}, TransactionId: {TransactionId}",
                    requestId, result.TransactionId);
            }
            else
            {
                logger.LogWarning("Ödeme başarısız: {RequestId}, Hata: {ErrorCode}",
                    requestId, result.ErrorCode);
            }

            return Ok(result);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Ödeme işlemi sırasında beklenmeyen hata: {RequestId}", requestId);

            return StatusCode(503, new PaymentResponseDto
            {
                IsSuccessful = false,
                Message = "Ödeme servisi geçici olarak kullanılamıyor",
                ErrorCode = "SERVICE_UNAVAILABLE",
                ProcessedAt = DateTime.UtcNow
            });
        }
    }

    /// <summary>
    /// Health check endpoint
    /// </summary>
    [HttpGet("health")]
    public Task<ActionResult> HealthCheck()
    {
        try
        {
            // Test encryption service
            var publicKey = encryptionService.GetPublicKey();

            // Test hybrid encryption with small data
            const string testData = "health-check";
            var encrypted = encryptionService.EncryptData(testData);
            var decrypted = encryptionService.DecryptData(encrypted);

            if (decrypted != testData)
            {
                throw new InvalidOperationException("Hybrid encryption health check failed");
            }

            var healthStatus = new
            {
                Status = "Healthy",
                Timestamp = DateTime.UtcNow,
                EncryptionService = "OK",
                HybridEncryption = "OK",
                KeySize = publicKey.KeySize,
                HybridSupport = publicKey.HybridSupport,
                Version = "1.0.0"
            };

            return Task.FromResult<ActionResult>(Ok(healthStatus));
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Health check failed");

            return Task.FromResult<ActionResult>(StatusCode(503, new
            {
                Status = "Unhealthy",
                Timestamp = DateTime.UtcNow,
                Error = ex.Message,
                Version = "1.0.0"
            }));
        }
    }
}