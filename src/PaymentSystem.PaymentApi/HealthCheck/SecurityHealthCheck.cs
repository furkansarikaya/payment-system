using Microsoft.Extensions.Diagnostics.HealthChecks;
using PaymentSystem.PaymentApi.Features.Security.Services;

namespace PaymentSystem.PaymentApi.HealthCheck;

public class SecurityHealthCheck(ISecurityService securityService, IChallengeService challengeService)
    : IHealthCheck
{
    private readonly ISecurityService _securityService = securityService;

    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
    {
        try
        {
            // Test challenge creation
            var challenge = await challengeService.CreateChallengeAsync("127.0.0.1");
            
            if (string.IsNullOrEmpty(challenge.Nonce))
            {
                return HealthCheckResult.Degraded("Challenge service not generating nonces");
            }

            return HealthCheckResult.Healthy("Security services are working correctly");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("Security services failed", ex);
        }
    }
}