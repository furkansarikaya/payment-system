using Microsoft.AspNetCore.Mvc;
using PaymentSystem.ClientApi.Features.Customer.DTOs;
using PaymentSystem.ClientApi.Features.Customer.Services;

namespace PaymentSystem.ClientApi.Features.Customer.Controllers;

/// <summary>
/// Müşteri işlemleri için ana Controller. Bu controller müşteri tarafındaki
/// tüm ödeme isteklerini karşılar ve uygun servislere yönlendirir.
/// 
/// RESTful API prensiplerine uygun olarak tasarlanmıştır:
/// - POST /api/customer/payment -> Yeni ödeme işlemi
/// - GET /api/customer/health -> Sistem durumu kontrolü
/// 
/// Güvenlik katmanları:
/// - Model validation (automatic via ModelState)
/// - Business rule validation (CustomerService içinde)
/// - Rate limiting (Program.cs'de configure edilmiş)
/// - HTTPS enforcement
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class CustomerController(
    ICustomerService customerService,
    ILogger<CustomerController> logger)
    : ControllerBase
{
    /// <summary>
    /// Müşteri ödeme isteğini işler. Bu endpoint web arayüzü, mobil uygulama
    /// veya üçüncü parti entegrasyonlardan gelen ödeme isteklerini karşılar.
    /// 
    /// İşlem akışı:
    /// 1. HTTP request validation (ASP.NET Core automatic)
    /// 2. Model binding ve basic validation
    /// 3. Business logic validation (CustomerService)
    /// 4. Payment API'ye güvenli istek gönderme
    /// 5. Müşteri dostu response döndürme
    /// 
    /// Güvenlik önlemleri:
    /// - Hassas veri log'lanmaz (kredi kartı bilgileri)
    /// - Hata mesajları kullanıcı dostu (teknik detay verilmez)
    /// - Request tracing (debugging için)
    /// </summary>
    /// <param name="request">Müşteri ödeme talebi</param>
    /// <returns>Ödeme işlemi sonucu</returns>
    [HttpPost("payment")]
    public async Task<ActionResult<CustomerPaymentResponseDto>> ProcessPayment([FromBody] CustomerPaymentRequestDto request)
    {
        try
        {
            // Request tracking için benzersiz ID oluştur
            var requestId = GenerateRequestId();

            // Güvenli logging - hassas bilgi olmadan
            logger.LogInformation("Müşteri ödeme isteği alındı: {RequestId}, Email: {Email}, Tutar: {Amount} {Currency}",
                requestId, request.CustomerEmail, request.Amount, request.Currency);

            // 1. Basic model validation kontrolü (ASP.NET Core automatic validation)
            if (!ModelState.IsValid)
            {
                var validationErrors = ModelState
                    .SelectMany(x => x.Value?.Errors ?? new Microsoft.AspNetCore.Mvc.ModelBinding.ModelErrorCollection())
                    .Select(e => e.ErrorMessage)
                    .ToList();

                logger.LogWarning("Model validation hatası: {RequestId}, Errors: {Errors}",
                    requestId, string.Join(", ", validationErrors));

                return BadRequest(new CustomerPaymentResponseDto
                {
                    IsSuccessful = false,
                    Message = "Lütfen tüm alanları doğru şekilde doldurunuz.",
                    ErrorCategory = "VALIDATION_ERROR",
                    ProcessedAt = DateTime.UtcNow
                });
            }

            // 2. Business logic validation ve işlem
            var result = await customerService.ProcessCustomerPaymentAsync(request);

            // 3. HTTP status code'u response'a göre ayarla
            if (result.IsSuccessful)
            {
                logger.LogInformation("Müşteri ödemesi başarılı: {RequestId}, TransactionId: {TransactionId}",
                    requestId, result.TransactionId);

                return Ok(result);
            }

            logger.LogWarning("Müşteri ödemesi başarısız: {RequestId}, Category: {Category}, Message: {Message}",
                requestId, result.ErrorCategory, result.Message);

            // Hata kategorisine göre uygun HTTP status code döndür
            return result.ErrorCategory switch
            {
                "VALIDATION_ERROR" => BadRequest(result),
                "CARD_ERROR" => BadRequest(result),
                "AMOUNT_ERROR" => BadRequest(result),
                "SYSTEM_ERROR" => StatusCode(503, result), // Service Unavailable
                _ => BadRequest(result)
            };
        }
        catch (ArgumentNullException ex)
        {
            logger.LogError(ex, "Null request alındı");

            return BadRequest(new CustomerPaymentResponseDto
            {
                IsSuccessful = false,
                Message = "Geçersiz istek formatı.",
                ErrorCategory = "VALIDATION_ERROR",
                ProcessedAt = DateTime.UtcNow
            });
        }
        catch (Exception ex)
        {
            // Global exception handler - beklenmeyen hatalar için
            logger.LogError(ex, "Customer controller'da beklenmeyen hata oluştu");

            return StatusCode(500, new CustomerPaymentResponseDto
            {
                IsSuccessful = false,
                Message = "Sistem hatası oluştu. Lütfen daha sonra tekrar deneyiniz.",
                ErrorCategory = "SYSTEM_ERROR",
                ProcessedAt = DateTime.UtcNow
            });
        }
    }

    /// <summary>
    /// Sistem durumu kontrolü. Bu endpoint load balancer'lar, monitoring
    /// sistemleri ve health check'ler tarafından kullanılır.
    /// 
    /// Response içeriği:
    /// - API durumu (Healthy/Unhealthy)
    /// - Timestamp
    /// - Version bilgisi
    /// - Payment API connectivity durumu
    /// </summary>
    [HttpGet("health")]
    public Task<IActionResult> HealthCheck()
    {
        try
        {
            // Payment API connectivity kontrolü yapılabilir
            // Şu an basit health check döndürüyoruz

            logger.LogDebug("Health check isteği alındı");

            return Task.FromResult<IActionResult>(Ok(new
            {
                Status = "Healthy",
                Timestamp = DateTime.UtcNow,
                Version = "1.0.0",
                ApiName = "Payment System Client API",
                Environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Development"
            }));
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Health check sırasında hata oluştu");

            return Task.FromResult<IActionResult>(StatusCode(503, new
            {
                Status = "Unhealthy",
                Timestamp = DateTime.UtcNow,
                Error = "Health check failed"
            }));
        }
    }

    /// <summary>
    /// API kullanım bilgileri ve dokümantasyon endpoint'i.
    /// Frontend developer'lar için faydalı bilgiler içerir.
    /// </summary>
    [HttpGet("info")]
    public IActionResult GetApiInfo()
    {
        return Ok(new
        {
            ApiName = "Payment System Client API",
            Version = "1.0.0",
            Description = "Güvenli ödeme işlemleri için müşteri API'si",
            Endpoints = new[]
            {
                new { Method = "POST", Path = "/api/customer/payment", Description = "Ödeme işlemi gerçekleştir" },
                new { Method = "GET", Path = "/api/customer/health", Description = "Sistem durumu kontrolü" },
                new { Method = "GET", Path = "/api/customer/info", Description = "API bilgileri" }
            },
            SupportedCurrencies = new[] { "TRY", "USD", "EUR" },
            MaxTransactionAmount = 50000,
            SecurityFeatures = new[]
            {
                "RSA Encryption",
                "HTTPS Enforcement",
                "Rate Limiting",
                "Input Validation",
                "Error Sanitization"
            },
            Contact = new
            {
                Email = "support@paymentsystem.com",
                Documentation = "https://docs.paymentsystem.com"
            }
        });
    }

    /// <summary>
    /// Demo/test amaçlı sahte kredi kartı numaraları listesi.
    /// Sadece development ortamında aktif olur.
    /// </summary>
    [HttpGet("test-cards")]
    public IActionResult GetTestCards()
    {
        // Sadece development ortamında test kartları göster
        if (!Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT")?.Equals("Development", StringComparison.OrdinalIgnoreCase) == true)
        {
            return NotFound();
        }

        return Ok(new
        {
            Message = "Test ortamı için sahte kredi kartı numaraları",
            TestCards = new[]
            {
                new { CardNumber = "4111111111111111", Type = "Visa", Status = "Valid" },
                new { CardNumber = "5555555555554444", Type = "MasterCard", Status = "Valid" },
                new { CardNumber = "4000000000000002", Type = "Visa", Status = "Declined" },
                new { CardNumber = "4242424242424242", Type = "Visa", Status = "Always Approved" }
            },
            Note = "Bu kartlar sadece test amaçlıdır. Production ortamında gerçek kart numaraları kullanın.",
            ExampleExpiry = "12/25",
            ExampleCVV = "123"
        });
    }

    /// <summary>
    /// Request tracking için benzersiz ID oluşturur
    /// </summary>
    private static string GenerateRequestId()
    {
        return $"CUST_{DateTime.UtcNow:yyyyMMddHHmmss}_{Guid.NewGuid():N}"[..32];
    }
}