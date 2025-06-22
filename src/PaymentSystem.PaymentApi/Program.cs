using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.RateLimiting;
using PaymentSystem.PaymentApi.Features.Encryption.Models;
using PaymentSystem.PaymentApi.Features.Encryption.Services;
using PaymentSystem.PaymentApi.Features.Payment.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

builder.Services.AddControllers();

// API Controllers'ı ekle
builder.Services.AddControllers();

// API documentation için Swagger/OpenAPI
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo
    {
        Title = "Payment System API",
        Version = "v1",
        Description = "Güvenli ödeme işlemleri için RSA şifrelemeli API"
    });
});

// CORS konfigürasyonu - Client API'nin erişebilmesi için
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowClientApi", policy =>
    {
        policy.WithOrigins("https://localhost:7001", "http://localhost:5177") // Client API URL'leri
            .AllowAnyHeader()
            .AllowAnyMethod();
    });
});

// JSON Key Store Configuration
builder.Services.Configure<JsonKeyStoreOptions>(
    builder.Configuration.GetSection("JsonKeyStore"));

// Servislerimizi DI container'a kaydet
builder.Services.AddScoped<IJsonKeyStoreService, JsonKeyStoreService>();
builder.Services.AddScoped<IHybridEncryptionService, HybridEncryptionService>();
// Environment-aware encryption service factory
builder.Services.AddScoped<IEncryptionService>(serviceProvider =>
{
    var keyStoreService = serviceProvider.GetRequiredService<IJsonKeyStoreService>();
    var hybridEncryption = serviceProvider.GetRequiredService<IHybridEncryptionService>();
    var logger = serviceProvider.GetRequiredService<ILogger<RsaEncryptionService>>();
    var configuration = serviceProvider.GetRequiredService<IConfiguration>();

    // Environment'ı belirle
    var environment = configuration["Environment"] ??
                      Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ??
                      "Development";

    // Key store'dan configuration al
    var encryptionConfig = keyStoreService.GetEncryptionConfigurationAsync(environment.ToLower()).Result;
    var options = Microsoft.Extensions.Options.Options.Create(encryptionConfig);

    return new RsaEncryptionService(options, hybridEncryption, logger);
});

builder.Services.AddScoped<IPaymentService, PaymentService>();

// Rate limiting ekle - DDoS koruması için
builder.Services.AddRateLimiter(options =>
{
    options.AddFixedWindowLimiter("PaymentPolicy", configure =>
    {
        configure.PermitLimit = 10; // 10 istek
        configure.Window = TimeSpan.FromMinutes(1); // Dakikada
        configure.QueueProcessingOrder = System.Threading.RateLimiting.QueueProcessingOrder.OldestFirst;
        configure.QueueLimit = 5;
    });

    options.AddFixedWindowLimiter("PublicKeyPolicy", configure =>
    {
        configure.PermitLimit = 100; // Public key için daha yüksek limit
        configure.Window = TimeSpan.FromMinutes(1);
    });
});

var app = builder.Build();


var scope = app.Services.CreateScope();

// Test hybrid encryption on startup
var logger = app.Services.GetRequiredService<ILogger<Program>>();
try
{
    var encryptionService = scope.ServiceProvider.CreateScope().ServiceProvider.GetRequiredService<IEncryptionService>();

    // Test payload size calculation
    var testData = JsonSerializer.Serialize(new
    {
        CreditCard = new
        {
            CardNumber = "4111111111111111",
            CardHolderName = "TEST USER WITH VERY LONG NAME THAT MIGHT CAUSE ISSUES",
            ExpiryDate = "12/25",
            CVV = "123"
        },
        Amount = 1000.50m,
        Currency = "TRY",
        Description = "Very detailed description that might make the JSON quite large and potentially exceed RSA encryption limits",
        CustomerEmail = "test.user.with.very.long.email.address@example.com",
        OrderReference = "ORDER-REF-123456789-ABCDEFGHIJKLMNOP-VERY-LONG-REFERENCE"
    });

    var testDataSize = Encoding.UTF8.GetByteCount(testData);
    var publicKeyInfo = encryptionService.GetPublicKey();

    logger.LogInformation("=== HYBRID ENCRYPTION STATUS ===");
    logger.LogInformation("Test payload size: {Size} bytes", testDataSize);
    logger.LogInformation("Max direct RSA size: {MaxSize} bytes", publicKeyInfo.MaxDirectRsaSize);
    logger.LogInformation("Hybrid support enabled: {HybridSupport}", publicKeyInfo.HybridSupport);
    logger.LogInformation("RSA key size: {KeySize} bits", publicKeyInfo.KeySize);

    if (testDataSize > publicKeyInfo.MaxDirectRsaSize)
    {
        logger.LogInformation("✅ Using Hybrid Encryption (payload > RSA limit)");
    }
    else
    {
        logger.LogInformation("ℹ️ Payload fits in RSA, but Hybrid Encryption provides better performance");
    }

    // Test actual encryption/decryption
    var encrypted = encryptionService.EncryptData("test-startup-encryption");
    var decrypted = encryptionService.DecryptData(encrypted);

    if (decrypted == "test-startup-encryption")
    {
        logger.LogInformation("✅ Hybrid encryption test successful");
    }
    else
    {
        logger.LogError("❌ Hybrid encryption test failed");
    }

    logger.LogInformation("================================");
}
catch (Exception ex)
{
    logger.LogError(ex, "Startup encryption test failed");
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Payment System API V1");
        c.RoutePrefix = string.Empty; // Swagger'ı root path'te aç
    });
}

app.UseHttpsRedirection();

app.UseCors("AllowClientApi"); // CORS politikasını aktif et

app.UseRateLimiter(); // Rate limiting'i aktif et

// Global exception handler - tüm hataları yakalar
app.UseExceptionHandler(errorApp =>
{
    errorApp.Run(async context =>
    {
        context.Response.StatusCode = 500;
        context.Response.ContentType = "application/json";

        var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
        logger.LogError("Global exception handler çalıştı");

        await context.Response.WriteAsync(System.Text.Json.JsonSerializer.Serialize(new
        {
            Error = "Sistem hatası oluştu",
            Code = "SYSTEM_ERROR",
            Timestamp = DateTime.UtcNow
        }));
    });
});

app.MapControllers(); // Controller routing'i aktif et

// Enhanced startup logging with JSON key store info
var startupLogger = app.Services.GetRequiredService<ILogger<Program>>();
var keyStoreService = scope.ServiceProvider.GetRequiredService<IJsonKeyStoreService>();

try
{
    var keyStoreInfo = await keyStoreService.GetKeyStoreInfoAsync();

    startupLogger.LogInformation("=== JSON KEY STORE STATUS ===");
    startupLogger.LogInformation("Key Store Version: {Version}", keyStoreInfo.Version);
    startupLogger.LogInformation("Generated At: {GeneratedAt}", keyStoreInfo.GeneratedAt);
    startupLogger.LogInformation("Environments: {Count}", keyStoreInfo.EnvironmentCount);
    startupLogger.LogInformation("File Path: {FilePath}", keyStoreInfo.FilePath);

    foreach (var env in keyStoreInfo.Environments)
    {
        startupLogger.LogInformation("Environment: {Environment}", env.Environment);
        startupLogger.LogInformation("  Current Key: {KeyId}", env.CurrentKeyId);
        startupLogger.LogInformation("  Key Size: {KeySize} bits", env.KeySize);
        startupLogger.LogInformation("  Days to Expiry: {Days}", env.DaysToExpiry);

        if (env.ExpirationWarning)
        {
            startupLogger.LogWarning("  ⚠️ Key expires soon!");
        }

        startupLogger.LogInformation("  Has Next Key: {HasNextKey}", env.HasNextKey);
        startupLogger.LogInformation("  Backup Keys: {BackupCount}", env.BackupKeyCount);
    }

    // Test current environment encryption
    var environment = app.Configuration["Environment"] ?? app.Environment.EnvironmentName;
    var encryptionService = scope.ServiceProvider.GetRequiredService<IEncryptionService>();

    var testEncryption = encryptionService.EncryptData("startup-test");
    var testDecryption = encryptionService.DecryptData(testEncryption);

    if (testDecryption == "startup-test")
    {
        startupLogger.LogInformation("✅ Encryption test successful for environment: {Environment}", environment);
    }
    else
    {
        startupLogger.LogError("❌ Encryption test failed for environment: {Environment}", environment);
    }

    startupLogger.LogInformation("==============================");
}
catch (Exception ex)
{
    startupLogger.LogError(ex, "❌ Key store initialization failed");
    throw; // Stop startup if key store is not available
}

// Rate limiting politikalarını endpoint'lere ata
app.MapControllerRoute(
        name: "payment",
        pattern: "api/payment/process")
    .RequireRateLimiting("PaymentPolicy");

app.MapControllerRoute(
        name: "publickey",
        pattern: "api/payment/public-key")
    .RequireRateLimiting("PublicKeyPolicy");

// Startup log'u
logger.LogInformation("Payment API başlatılıyor...");
await app.RunAsync();