using Microsoft.AspNetCore.RateLimiting;
using PaymentSystem.ClientApi.Features.Customer.Services;
using PaymentSystem.ClientApi.Features.PaymentClient.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi(); // API Controllers'ı ekle
builder.Services.AddControllers();

// API documentation için Swagger/OpenAPI
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo
    {
        Title = "Payment System Client API",
        Version = "v1",
        Description = "Müşteri ödeme işlemleri için Client API - Payment API ile güvenli iletişim kurar",
        Contact = new Microsoft.OpenApi.Models.OpenApiContact
        {
            Name = "Payment System Support",
            Email = "support@paymentsystem.com"
        }
    });

    // Swagger'da örnek değerler göstermek için
    c.EnableAnnotations();
});

// CORS konfigürasyonu - Frontend uygulamalarının erişebilmesi için
// Production'da specific domain'ler belirtilmeli
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", policy =>
    {
        if (builder.Environment.IsDevelopment())
        {
            // Development'ta tüm origin'lere izin ver
            policy.AllowAnyOrigin()
                .AllowAnyHeader()
                .AllowAnyMethod();
        }
        else
        {
            // Production'da sadece belirli domain'lere izin ver
            policy.WithOrigins(
                    "https://www.yourwebsite.com",
                    "https://app.yourwebsite.com"
                )
                .AllowAnyHeader()
                .AllowAnyMethod();
        }
    });
});

// HttpClient konfigürasyonu - Payment API ile iletişim için
// Bu çok önemli: HttpClient factory pattern kullanarak connection pooling optimizasyonu
builder.Services.AddHttpClient<IPaymentClientService, PaymentClientService>((serviceProvider, client) =>
    {
        var configuration = serviceProvider.GetRequiredService<IConfiguration>();
        var baseUrl = configuration["PaymentApi:BaseUrl"] ?? "https://localhost:7000";

        client.BaseAddress = new Uri(baseUrl);
        client.DefaultRequestHeaders.Add("User-Agent", "PaymentSystem-ClientApi/1.0");
        client.DefaultRequestHeaders.Add("Accept", "application/json");

        // Timeout ayarları - network latency için
        client.Timeout = TimeSpan.FromSeconds(30);
    })
    .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler()
    {
        // SSL sertifika validasyonu - Production'da true olmalı
        ServerCertificateCustomValidationCallback = builder.Environment.IsDevelopment()
            ? HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
            : null
    });

// Rate limiting konfigürasyonu - DDoS ve abuse koruması
builder.Services.AddRateLimiter(options =>
{
    // Ödeme işlemleri için katı rate limiting
    options.AddFixedWindowLimiter("PaymentPolicy", configure =>
    {
        configure.PermitLimit = 5; // Dakikada 5 ödeme işlemi
        configure.Window = TimeSpan.FromMinutes(1);
        configure.QueueProcessingOrder = System.Threading.RateLimiting.QueueProcessingOrder.OldestFirst;
        configure.QueueLimit = 2; // Maksimum 2 istek bekletilir
    });

    // Genel API istekleri için daha esnek rate limiting
    options.AddFixedWindowLimiter("GeneralPolicy", configure =>
    {
        configure.PermitLimit = 100; // Dakikada 100 istek
        configure.Window = TimeSpan.FromMinutes(1);
    });

    // IP bazlı global rate limiting
    options.AddFixedWindowLimiter("GlobalPolicy", configure =>
    {
        configure.PermitLimit = 200; // IP başına dakikada 200 istek
        configure.Window = TimeSpan.FromMinutes(1);
    });
});

// Business servislerimizi DI container'a kaydet
// Scoped lifetime: Her HTTP request için yeni instance
builder.Services.AddScoped<ICustomerService, CustomerService>();

// PaymentClientService zaten HttpClient ile birlikte kayıtlı

// Health checks ekleme - monitoring için
// builder.Services.AddHealthChecks()
//     .AddCheck("self", () => Microsoft.Extensions.Diagnostics.HealthChecks.HealthCheckResult.Healthy())
//     .AddHttpClient("payment-api", options =>
//     {
//         var configuration = builder.Services.BuildServiceProvider().GetRequiredService<IConfiguration>();
//         options.BaseAddress = new Uri(configuration["PaymentApi:BaseUrl"] ?? "https://localhost:7000");
//     });

// Memory caching - public key cache için
builder.Services.AddMemoryCache();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Payment System Client API V1");
        c.RoutePrefix = string.Empty; // Swagger'ı root path'te aç
        c.DisplayRequestDuration(); // Request süresini göster
    });
}

app.UseHttpsRedirection();

// Güvenlik header'ları ekle
app.Use(async (context, next) =>
{
    // XSS koruması
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("X-XSS-Protection", "1; mode=block");
    
    // HSTS (HTTP Strict Transport Security)
    if (!app.Environment.IsDevelopment())
    {
        context.Response.Headers.Append("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    }
    
    await next();
});

app.UseCors("AllowFrontend"); // CORS politikasını aktif et

app.UseRateLimiter(); // Rate limiting'i aktif et

// Global exception handler - tüm beklenmeyen hataları yakalar
app.UseExceptionHandler(errorApp =>
{
    errorApp.Run(async context =>
    {
        context.Response.StatusCode = 500;
        context.Response.ContentType = "application/json";
        
        var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
        logger.LogError("Global exception handler tetiklendi");
        
        // Hassas bilgi vermemek için genel hata mesajı
        var errorResponse = new
        {
            Error = "Sistem hatası oluştu",
            Code = "SYSTEM_ERROR",
            Timestamp = DateTime.UtcNow,
            TraceId = context.TraceIdentifier // Debugging için
        };
        
        await context.Response.WriteAsync(System.Text.Json.JsonSerializer.Serialize(errorResponse));
    });
});

// Controller routing'i aktif et
app.MapControllers();

// Health check endpoint'ini map et
//app.MapHealthChecks("/health");

// Rate limiting politikalarını belirli endpoint'lere ata
app.MapControllerRoute(
    name: "payment",
    pattern: "api/customer/payment")
    .RequireRateLimiting("PaymentPolicy");

app.MapControllerRoute(
    name: "general", 
    pattern: "api/customer/{action}")
    .RequireRateLimiting("GeneralPolicy");

// Startup log'ları
var logger = app.Services.GetRequiredService<ILogger<Program>>();
logger.LogInformation("Client API başlatılıyor...");
logger.LogInformation("Ortam: {Environment}", app.Environment.EnvironmentName);
logger.LogInformation("Payment API Base URL: {BaseUrl}", 
    app.Configuration["PaymentApi:BaseUrl"] ?? "https://localhost:7000");

// Başlangıçta Payment API connectivity kontrolü
try
{
    var httpClientFactory = app.Services.GetRequiredService<IHttpClientFactory>();
    var healthClient = httpClientFactory.CreateClient();
    var paymentApiUrl = app.Configuration["PaymentApi:BaseUrl"] ?? "https://localhost:7000";
    
    logger.LogInformation("Payment API bağlantısı kontrol ediliyor: {Url}", paymentApiUrl);
    
    // Bu async işlem startup'ı yavaşlatabilir, production'da kaldırılabilir
    if (app.Environment.IsDevelopment())
    {
        var response = await healthClient.GetAsync($"{paymentApiUrl}/api/payment/health");
        if (response.IsSuccessStatusCode)
        {
            logger.LogInformation("Payment API bağlantısı başarılı");
        }
        else
        {
            logger.LogWarning("Payment API'ye ulaşılamadı. Status: {Status}", response.StatusCode);
        }
    }
}
catch (Exception ex)
{
    logger.LogWarning(ex, "Payment API connectivity kontrolü başarısız");
}

await app.RunAsync();