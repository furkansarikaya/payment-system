using PaymentSystem.PaymentApi.Features.Security.Services;

namespace PaymentSystem.PaymentApi.BackgroundServices;

public class SecurityCleanupService(IServiceScopeFactory serviceScopeFactory, ILogger<SecurityCleanupService> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = serviceScopeFactory.CreateScope();
                var challengeService = scope.ServiceProvider.GetRequiredService<IChallengeService>();
                
                await challengeService.CleanupExpiredChallengesAsync();
                logger.LogDebug("Security cleanup completed");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Security cleanup failed");
            }

            await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
        }
    }
}