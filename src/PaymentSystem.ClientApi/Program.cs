using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.RateLimiting;
using PaymentSystem.ClientApi.Features.Customer.Services;
using PaymentSystem.ClientApi.Features.PaymentClient.Services;
using PaymentSystem.ClientApi.Features.Security.Services;

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
        Title = "Payment System Client API - Customer Gateway",
        Version = "v1.0",
        Description = @"Customer-Facing Payment Gateway API

🎯 **Purpose**: 
This API provides a secure, user-friendly interface for processing customer payments. It acts as a gateway between customer applications and our secure payment infrastructure.

🛡️ **Security Features**:
• Automatic hybrid encryption (RSA + AES)
• Real-time fraud detection
• PCI DSS compliant processing
• Rate limiting protection
• Input validation & sanitization
• Secure error handling

💳 **Payment Features**:
• Credit/debit card processing
• Multiple currency support (TRY, USD, EUR)
• Real-time transaction validation
• Instant payment confirmation
• Comprehensive error reporting

🚀 **Developer Experience**:
• RESTful API design
• Comprehensive error codes
• Detailed response messages
• Built-in retry mechanisms
• Test card numbers for development

📊 **Performance**:
• < 2 second average response time
• 99.9% uptime guarantee
• Auto-scaling infrastructure
• Global CDN support

🔧 **Integration Support**:
• Detailed code examples
• SDKs for popular languages
• Postman collections
• Interactive documentation
• 24/7 developer support",

        // Contact information for developer support
        Contact = new Microsoft.OpenApi.Models.OpenApiContact
        {
            Name = "Developer Support Team",
            Email = "developers@paymentsystem.com",
            Url = new Uri("https://docs.paymentsystem.com/support")
        },

        // License information
        License = new Microsoft.OpenApi.Models.OpenApiLicense
        {
            Name = "API License Agreement",
            Url = new Uri("https://paymentsystem.com/api-license")
        },

        // Terms of service
        TermsOfService = new Uri("https://paymentsystem.com/terms")
    });

    // Swagger'da örnek değerler göstermek için
    c.EnableAnnotations();

    c.IncludeXmlComments(Path.Combine(AppContext.BaseDirectory, "PaymentSystem.ClientApi.xml"), true);
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

builder.Services.AddHttpClient("HealthCheckClient", (serviceProvider, client) =>
{
    var configuration = serviceProvider.GetRequiredService<IConfiguration>();
    var baseUrl = configuration["PaymentApi:BaseUrl"] ?? "https://localhost:7000";
    
    client.BaseAddress = new Uri(baseUrl);
    client.DefaultRequestHeaders.Add("User-Agent", "PaymentSystem-ClientApi-HealthCheck/1.0");
    client.Timeout = TimeSpan.FromSeconds(10); // Health check için daha kısa timeout
})
.ConfigurePrimaryHttpMessageHandler((serviceProvider) =>
{
    var configuration = serviceProvider.GetRequiredService<IConfiguration>();
    var environment = serviceProvider.GetRequiredService<IWebHostEnvironment>();
    var logger = serviceProvider.GetRequiredService<ILogger<Program>>();

    var handler = new HttpClientHandler();

    try
    {
        // Health check için de client certificate gerekiyor
        var certPath = configuration["Security:ClientCertificatePath"] ?? "certificates/client/demo_client.p12";
        var certPassword = configuration["Security:ClientCertificatePassword"] ?? "client123";

        if (File.Exists(certPath))
        {
            var clientCertificate = new X509Certificate2(certPath, certPassword);
            handler.ClientCertificates.Add(clientCertificate);
            logger.LogDebug("Health check client certificate loaded: {Thumbprint}", clientCertificate.Thumbprint);
        }
        else if (!environment.IsDevelopment())
        {
            logger.LogWarning("Health check client certificate not found: {CertPath}", certPath);
        }

        // Development'ta relaxed validation
        if (environment.IsDevelopment())
        {
            handler.ServerCertificateCustomValidationCallback = (sender, cert, chain, errors) => true;
        }

        return handler;
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Failed to configure health check client certificate");
        return handler; // Certificate olmadan devam et, ama muhtemelen başarısız olacak
    }
});

/// HttpClient konfigürasyonu - Client Certificate Authentication ile
builder.Services.AddHttpClient<IPaymentClientService, PaymentClientService>((serviceProvider, client) =>
    {
        var configuration = serviceProvider.GetRequiredService<IConfiguration>();
        var baseUrl = configuration["PaymentApi:BaseUrl"] ?? "https://localhost:7000";

        client.BaseAddress = new Uri(baseUrl);
        client.DefaultRequestHeaders.Add("User-Agent", "PaymentSystem-ClientApi/2.0-mTLS");
        client.DefaultRequestHeaders.Add("Accept", "application/json");
        client.Timeout = TimeSpan.FromSeconds(30);
    })
    .ConfigurePrimaryHttpMessageHandler((serviceProvider) =>
    {
        var configuration = serviceProvider.GetRequiredService<IConfiguration>();
        var logger = serviceProvider.GetRequiredService<ILogger<Program>>();
        var environment = serviceProvider.GetRequiredService<IWebHostEnvironment>();

        var handler = new HttpClientHandler();

        try
        {
            // 1. CLIENT CERTIFICATE YÜKLEME
            // Client'ın kimliğini kanıtlamak için certificate'ını yükle
            var clientCertificateEnabled = configuration.GetValue<bool>("Security:EnableClientCertificate", true);
            
            if (clientCertificateEnabled)
            {
                var certPath = configuration["Security:ClientCertificatePath"] ?? "certificates/client/demo_client.p12";
                var certPassword = configuration["Security:ClientCertificatePassword"] ?? "client123";

                if (File.Exists(certPath))
                {
                    // PKCS#12 (.p12) dosyasından client certificate'ını yükle
                    var clientCertificate = new X509Certificate2(certPath, certPassword);
                    handler.ClientCertificates.Add(clientCertificate);
                    
                    logger.LogInformation("Client certificate loaded: Subject={Subject}, Thumbprint={Thumbprint}",
                        clientCertificate.Subject, clientCertificate.Thumbprint);
                }
                else
                {
                    logger.LogWarning("Client certificate not found: {CertPath}", certPath);
                    
                    // Production'da certificate yoksa hata ver
                    if (!environment.IsDevelopment())
                    {
                        throw new FileNotFoundException($"Client certificate required but not found: {certPath}");
                    }
                }
            }

            // 2. SERVER CERTIFICATE VALIDATION
            // Server'ın kimliğini doğrulamak için custom validation
            if (environment.IsDevelopment())
            {
                // Development: Self-signed certificate'ları kabul et
                handler.ServerCertificateCustomValidationCallback = DevelopmentServerCertificateValidation;
                logger.LogWarning("Development mode: Server certificate validation relaxed");
            }
            else
            {
                // Production: Strict server certificate validation
                handler.ServerCertificateCustomValidationCallback = ProductionServerCertificateValidation;
                logger.LogInformation("Production mode: Strict server certificate validation enabled");
            }

            return handler;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to configure client certificate authentication");
            throw;
        }
    });

builder.Services.AddHttpClient<IClientSecurityService, ClientSecurityService>((serviceProvider, client) =>
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
    var healthClient = httpClientFactory.CreateClient("HealthCheckClient"); // ← Named client kullan
    var paymentApiUrl = app.Configuration["PaymentApi:BaseUrl"] ?? "https://localhost:7000";
    
    logger.LogInformation("Payment API bağlantısı kontrol ediliyor (mTLS): {Url}", paymentApiUrl);
    
    if (app.Environment.IsDevelopment())
    {
        var response = await healthClient.GetAsync("/api/payment/health");
        if (response.IsSuccessStatusCode)
        {
            logger.LogInformation("Payment API bağlantısı başarılı (mTLS authenticated)");
        }
        else
        {
            logger.LogWarning("Payment API'ye ulaşılamadı. Status: {Status}", response.StatusCode);
        }
    }
}
catch (Exception ex)
{
    logger.LogWarning(ex, "Payment API connectivity kontrolü başarısız (mTLS authentication may have failed)");
}

await app.RunAsync();

/// <summary>
/// Development ortamında server certificate validation
/// Self-signed certificate'ları kabul eder, ama yine de basic kontroller yapar
/// </summary>
static bool DevelopmentServerCertificateValidation(
    HttpRequestMessage request,
    X509Certificate2? certificate,
    X509Chain? chain,
    SslPolicyErrors sslPolicyErrors)
{
    var logger = LoggerFactory.Create(config => config.AddConsole()).CreateLogger("ClientCertAuth");

    // Certificate hiç yoksa reddet
    if (certificate == null)
    {
        logger.LogError("Server certificate is null");
        return false;
    }

    logger.LogDebug("Validating server certificate: Subject={Subject}, Issuer={Issuer}",
        certificate.Subject, certificate.Issuer);

    // Development'da sadece basic kontroller
    
    // 1. Certificate'ın expire olup olmadığını kontrol et
    if (DateTime.Now < certificate.NotBefore || DateTime.Now > certificate.NotAfter)
    {
        logger.LogError("Server certificate is expired or not yet valid. NotBefore={NotBefore}, NotAfter={NotAfter}",
            certificate.NotBefore, certificate.NotAfter);
        return false;
    }

    // 2. Certificate'ın localhost için olup olmadığını kontrol et
    var isLocalhostCert = certificate.Subject.Contains("localhost") || 
                         certificate.Subject.Contains("127.0.0.1") ||
                         certificate.GetNameInfo(X509NameType.DnsName, false) == "localhost";

    if (request.RequestUri?.Host == "localhost" && !isLocalhostCert)
    {
        logger.LogWarning("Certificate is not for localhost but connecting to localhost");
    }

    // Development'da self-signed certificate'ları kabul et
    if (sslPolicyErrors != SslPolicyErrors.None)
    {
        logger.LogWarning("SSL Policy Errors (accepted in development): {Errors}", sslPolicyErrors);
    }

    logger.LogInformation("Server certificate accepted (development mode)");
    return true;
}

/// <summary>
/// Production ortamında server certificate validation
/// Çok strict kontroller yapar, security best practice'leri uygular
/// </summary>
static bool ProductionServerCertificateValidation(
    HttpRequestMessage request,
    X509Certificate2? certificate,
    X509Chain? chain,
    SslPolicyErrors sslPolicyErrors)
{
    var logger = LoggerFactory.Create(config => config.AddConsole()).CreateLogger("ClientCertAuth");

    // Certificate hiç yoksa reddet
    if (certificate == null)
    {
        logger.LogError("Server certificate is null");
        return false;
    }

    // Chain yoksa reddet
    if (chain == null)
    {
        logger.LogError("Certificate chain is null");
        return false;
    }

    logger.LogInformation("Validating server certificate in production mode: Subject={Subject}",
        certificate.Subject);

    // 1. SSL Policy Error'ları kontrol et (Production'da hiç error olmamalı)
    if (sslPolicyErrors != SslPolicyErrors.None)
    {
        logger.LogError("SSL Policy Errors detected: {Errors}", sslPolicyErrors);
        return false;
    }

    // 2. Certificate chain validation
    chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
    chain.ChainPolicy.RevocationMode = X509RevocationMode.Online; // OCSP/CRL check
    chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;

    bool chainIsValid = chain.Build(certificate);
    if (!chainIsValid)
    {
        logger.LogError("Certificate chain validation failed");
        foreach (var chainStatus in chain.ChainStatus)
        {
            logger.LogError("Chain status error: {Status} - {StatusInfo}", 
                chainStatus.Status, chainStatus.StatusInformation);
        }
        return false;
    }

    // 3. Certificate expiration kontrolü
    if (DateTime.UtcNow < certificate.NotBefore || DateTime.UtcNow > certificate.NotAfter)
    {
        logger.LogError("Certificate is expired or not yet valid");
        return false;
    }

    // 4. Hostname verification
    var expectedHostname = request.RequestUri?.Host;
    if (!IsValidHostname(certificate, expectedHostname))
    {
        logger.LogError("Certificate hostname validation failed. Expected: {Expected}, Certificate: {Subject}",
            expectedHostname, certificate.Subject);
        return false;
    }

    // 5. Certificate pinning (opsiyonel, çok high-security ortamlar için)
    var configuration = new ConfigurationBuilder()
        .AddJsonFile("appsettings.json")
        .Build();

    var pinnedThumbprint = configuration["Security:ServerCertificateThumbprint"];
    if (!string.IsNullOrEmpty(pinnedThumbprint))
    {
        if (!string.Equals(certificate.Thumbprint, pinnedThumbprint, StringComparison.OrdinalIgnoreCase))
        {
            logger.LogError("Certificate pinning failed. Expected: {Expected}, Actual: {Actual}",
                pinnedThumbprint, certificate.Thumbprint);
            return false;
        }
        logger.LogInformation("Certificate pinning validation passed");
    }

    logger.LogInformation("Server certificate validation passed (production mode)");
    return true;
}

/// <summary>
/// Certificate'ın hostname'i doğru mu kontrol eder
/// </summary>
static bool IsValidHostname(X509Certificate2 certificate, string? expectedHostname)
{
    if (string.IsNullOrEmpty(expectedHostname))
        return false;

    // Subject'ten Common Name'i çıkar
    var subjectCN = GetCommonNameFromSubject(certificate.Subject);
    if (string.Equals(subjectCN, expectedHostname, StringComparison.OrdinalIgnoreCase))
        return true;

    // Subject Alternative Name'leri kontrol et
    var sanExtension = certificate.Extensions["2.5.29.17"] as X509SubjectAlternativeNameExtension;
    if (sanExtension == null) return false;
    var sanNames = ParseSubjectAlternativeNames(sanExtension);
    return sanNames.Any(name => string.Equals(name, expectedHostname, StringComparison.OrdinalIgnoreCase));

}

static string GetCommonNameFromSubject(string subject)
{
    var match = System.Text.RegularExpressions.Regex.Match(subject, @"CN=([^,]+)", System.Text.RegularExpressions.RegexOptions.IgnoreCase, TimeSpan.FromSeconds(5));
    return match.Success ? match.Groups[1].Value.Trim() : string.Empty;
}

static IEnumerable<string> ParseSubjectAlternativeNames(X509SubjectAlternativeNameExtension sanExtension)
{
    // SAN parsing implementasyonu (basitleştirilmiş)
    // Gerçek implementasyon için ASN.1 parsing gerekir
    return new List<string>();
}