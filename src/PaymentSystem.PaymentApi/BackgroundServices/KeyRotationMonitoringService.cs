using PaymentSystem.PaymentApi.Features.Encryption.Services;

namespace PaymentSystem.PaymentApi.BackgroundServices;

public class KeyRotationMonitoringService(IServiceScopeFactory serviceScopeFactory, ILogger<KeyRotationMonitoringService> logger)
    : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = serviceScopeFactory.CreateScope();
                var keyStoreService = scope.ServiceProvider.GetRequiredService<IJsonKeyStoreService>();
                var keyStoreInfo = await keyStoreService.GetKeyStoreInfoAsync();

                foreach (var env in keyStoreInfo.Environments)
                {
                    if (env.ExpirationWarning)
                    {
                        logger.LogWarning("Key rotation needed for {Environment}: {DaysToExpiry} days remaining",
                            env.Environment, env.DaysToExpiry);
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Key rotation monitoring failed");
            }

            await Task.Delay(TimeSpan.FromHours(1), stoppingToken);
        }
    }
}