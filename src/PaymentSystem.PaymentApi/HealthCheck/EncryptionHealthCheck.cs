using Microsoft.Extensions.Diagnostics.HealthChecks;
using PaymentSystem.PaymentApi.Features.Encryption.Services;

namespace PaymentSystem.PaymentApi.HealthCheck;

public class EncryptionHealthCheck(IEncryptionService encryptionService) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            const string testData = "health-check";
            var encrypted = encryptionService.EncryptData(testData);
            var decrypted = encryptionService.DecryptData(encrypted);

            return decrypted == testData ? HealthCheckResult.Healthy("Encryption service is working correctly") : HealthCheckResult.Degraded("Encryption test failed");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("Encryption service failed", ex);
        }
    }
}