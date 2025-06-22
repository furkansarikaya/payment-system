using Microsoft.AspNetCore.Mvc;
using PaymentSystem.PaymentApi.Features.Encryption.Models;
using PaymentSystem.PaymentApi.Features.Encryption.Services;

namespace PaymentSystem.PaymentApi.Features.Admin.Controllers;

/// <summary>
/// Key Management Admin API - Production key management için
/// </summary>
[ApiController]
[Route("api/admin/[controller]")]
// [Authorize(Roles = "KeyAdmin")] // Production'da authorization ekleyin
public class KeyManagementController(
    IJsonKeyStoreService keyStoreService,
    ILogger<KeyManagementController> logger)
    : ControllerBase
{
    /// <summary>
    /// Key store health check ve bilgi
    /// </summary>
    [HttpGet("info")]
    public async Task<ActionResult<KeyStoreInfo>> GetKeyStoreInfo()
    {
        try
        {
            var info = await keyStoreService.GetKeyStoreInfoAsync();

            logger.LogInformation("Key store info requested. Environments: {Count}", info.EnvironmentCount);

            return Ok(info);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to get key store info");
            return StatusCode(503, new { Error = "Key store bilgisi alınamadı", Details = ex.Message });
        }
    }

    /// <summary>
    /// Specific environment key bilgisi
    /// </summary>
    [HttpGet("environment/{environment}")]
    public async Task<ActionResult> GetEnvironmentKeyInfo(string environment)
    {
        try
        {
            var config = await keyStoreService.GetEncryptionConfigurationAsync(environment.ToLower());
            var rotationNeeded = await keyStoreService.IsKeyRotationNeededAsync(environment.ToLower());

            var response = new
            {
                Environment = environment,
                KeyId = config.KeyId,
                KeySize = config.KeySize,
                CreatedAt = config.CreatedAt,
                ExpiresAt = config.ExpiresAt,
                DaysToExpiry = config.DaysToExpiry,
                ExpirationWarning = config.ExpirationWarning,
                RotationNeeded = rotationNeeded,
                IsExpired = config.IsExpired
            };

            return Ok(response);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to get environment key info: {Environment}", environment);
            return NotFound(new { Error = $"Environment not found: {environment}", Details = ex.Message });
        }
    }

    /// <summary>
    /// Key store'u reload et
    /// </summary>
    [HttpPost("refresh")]
    public async Task<ActionResult> RefreshKeyStore()
    {
        try
        {
            logger.LogInformation("Key store refresh requested");

            var success = await keyStoreService.RefreshKeyStoreAsync();

            if (success)
            {
                logger.LogInformation("Key store refreshed successfully");
                return Ok(new { Message = "Key store başarıyla yenilendi", RefreshedAt = DateTime.UtcNow });
            }

            logger.LogWarning("Key store refresh failed");
            return StatusCode(503, new { Error = "Key store yenilenemedi" });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Key store refresh error");
            return StatusCode(503, new { Error = "Key store refresh hatası", Details = ex.Message });
        }
    }

    /// <summary>
    /// Tüm environment'lar için rotation check
    /// </summary>
    [HttpGet("rotation-status")]
    public async Task<ActionResult> GetRotationStatus()
    {
        try
        {
            var keyStoreInfo = await keyStoreService.GetKeyStoreInfoAsync();
            var rotationStatus = new List<object>();

            foreach (var env in keyStoreInfo.Environments)
            {
                var rotationNeeded = await keyStoreService.IsKeyRotationNeededAsync(env.Environment);

                rotationStatus.Add(new
                {
                    Environment = env.Environment,
                    CurrentKeyId = env.CurrentKeyId,
                    DaysToExpiry = env.DaysToExpiry,
                    RotationNeeded = rotationNeeded,
                    ExpirationWarning = env.ExpirationWarning,
                    HasNextKey = env.HasNextKey
                });
            }

            return Ok(new
            {
                CheckedAt = DateTime.UtcNow,
                Environments = rotationStatus,
                TotalEnvironments = rotationStatus.Count,
                NeedingRotation = rotationStatus.Count(r => (bool)r.GetType().GetProperty("RotationNeeded")?.GetValue(r)!)
            });
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to get rotation status");
            return StatusCode(503, new { Error = "Rotation status alınamadı", Details = ex.Message });
        }
    }
}