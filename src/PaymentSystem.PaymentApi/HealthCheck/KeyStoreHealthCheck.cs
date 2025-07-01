using Microsoft.Extensions.Diagnostics.HealthChecks;
using PaymentSystem.PaymentApi.Features.Encryption.Services;

namespace PaymentSystem.PaymentApi.HealthCheck;

public class KeyStoreHealthCheck(IJsonKeyStoreService keyStoreService) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            var keyStoreInfo = await keyStoreService.GetKeyStoreInfoAsync();
            
            if (keyStoreInfo.EnvironmentCount == 0)
            {
                return HealthCheckResult.Unhealthy("No environments found in key store");
            }

            var expiringKeys = keyStoreInfo.Environments.Count(e => e.ExpirationWarning);
            if (expiringKeys > 0)
            {
                return HealthCheckResult.Degraded($"{expiringKeys} key(s) expiring soon");
            }

            return HealthCheckResult.Healthy($"Key store healthy with {keyStoreInfo.EnvironmentCount} environments");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("Key store health check failed", ex);
        }
    }
}