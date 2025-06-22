using System.CommandLine;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using PaymentSystem.KeyManager.Models;
using PaymentSystem.KeyManager.Services;

namespace PaymentSystem.KeyManager;

/// <summary>
/// RSA Key Management Console Application
/// 
/// Bu uygulama payment system için RSA key'leri yönetir:
/// - Multiple environment key generation
/// - Key rotation
/// - Key store management
/// - Security validation
/// </summary>
public class Program
{
    public static async Task<int> Main(string[] args)
    {
        // Services setup
        var services = new ServiceCollection();
        ConfigureServices(services);
        var serviceProvider = services.BuildServiceProvider();

        // Root command
        var rootCommand = new RootCommand("Payment System RSA Key Management Tool")
        {
            CreateGenerateCommand(serviceProvider),
            CreateRotateCommand(serviceProvider),
            CreateValidateCommand(serviceProvider),
            CreateBackupCommand(serviceProvider),
            CreateInfoCommand(serviceProvider)
        };

        rootCommand.Description = """
                                  Payment System RSA Key Management Console

                                  Bu tool ile:
                                  • Multiple environment için RSA key'ler üretebilirsiniz
                                  • Key rotation yapabilirsiniz  
                                  • Key store health check'i yapabilirsiniz
                                  • Backup ve restore işlemleri yapabilirsiniz
                                  """;

        return await rootCommand.InvokeAsync(args);
    }

    private static void ConfigureServices(ServiceCollection services)
    {
        // Configuration
        var configuration = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json", optional: true)
            .Build();

        services.AddSingleton<IConfiguration>(configuration);

        // Logging
        services.AddLogging(builder =>
        {
            builder.AddConsole();
            builder.SetMinimumLevel(LogLevel.Information);
        });

        // Services
        services.AddScoped<IKeyGeneratorService, KeyGeneratorService>();
        services.AddScoped<IKeyStoreService, KeyStoreService>();
    }

    /// <summary>
    /// Generate command - Yeni key store oluştur
    /// </summary>
    private static Command CreateGenerateCommand(ServiceProvider serviceProvider)
    {
        var generateCommand = new Command("generate", "Yeni RSA key store oluştur");

        var outputOption = new Option<string>(
            aliases: new[] { "--output", "-o" },
            description: "Output JSON dosya yolu",
            getDefaultValue: () => "keys/payment-keys.json"
        );

        var environmentsOption = new Option<string[]>(
            aliases: new[] { "--environments", "-e" },
            description: "Environment listesi (development,staging,production)",
            getDefaultValue: () => new[] { "development", "staging", "production" }
        );

        var keySizeOption = new Option<int>(
            aliases: new[] { "--key-size", "-k" },
            description: "RSA key size (bits)",
            getDefaultValue: () => 2048
        );

        var rotationDaysOption = new Option<int>(
            aliases: new[] { "--rotation-days", "-r" },
            description: "Key rotation interval (days)",
            getDefaultValue: () => 90
        );

        generateCommand.AddOption(outputOption);
        generateCommand.AddOption(environmentsOption);
        generateCommand.AddOption(keySizeOption);
        generateCommand.AddOption(rotationDaysOption);

        generateCommand.SetHandler(async (output, environments, keySize, rotationDays) =>
        {
            var logger = serviceProvider.GetRequiredService<ILogger<Program>>();
            var keyGenerator = serviceProvider.GetRequiredService<IKeyGeneratorService>();
            var keyStore = serviceProvider.GetRequiredService<IKeyStoreService>();

            try
            {
                Console.WriteLine("🔐 Payment System RSA Key Generation");
                Console.WriteLine("=====================================");
                Console.WriteLine();

                var request = new KeyGenerationRequest
                {
                    Name = "PaymentSystemKeys",
                    Description = $"RSA keys for Payment System - Generated at {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC"
                };

                foreach (var env in environments)
                {
                    request.Environments.Add(new EnvironmentConfig
                    {
                        Name = env.ToLower(),
                        Description = $"{env} environment keys",
                        KeySize = keySize,
                        RotationIntervalDays = rotationDays,
                        GenerateNextKey = true,
                        BackupKeyCount = 2
                    });
                }

                Console.WriteLine($"🚀 Key generation başlatılıyor:");
                Console.WriteLine($"   📁 Output: {output}");
                Console.WriteLine($"   🏷️  Environments: {string.Join(", ", environments)}");
                Console.WriteLine($"   🔢 Key Size: {keySize} bits");
                Console.WriteLine($"   🔄 Rotation: {rotationDays} days");
                Console.WriteLine();

                var keyStoreData = await keyGenerator.GenerateKeyStoreAsync(request);
                await keyStore.SaveKeyStoreAsync(keyStoreData, output);

                Console.WriteLine("✅ Key generation tamamlandı!");
                Console.WriteLine();
                Console.WriteLine("📊 Özet:");
                foreach (var env in keyStoreData.Environments)
                {
                    Console.WriteLine($"   🌍 {env.Key}:");
                    Console.WriteLine($"      🔑 Current Key: {env.Value.CurrentKey?.KeyId}");
                    Console.WriteLine($"      ⏭️  Next Key: {env.Value.NextKey?.KeyId}");
                    Console.WriteLine($"      🛡️  Backup Keys: {env.Value.BackupKeys.Count}");
                }

                Console.WriteLine();
                Console.WriteLine($"💾 Dosya: {Path.GetFullPath(output)}");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Key generation failed");
                Console.WriteLine($"❌ Hata: {ex.Message}");
                Environment.Exit(1);
            }
        }, outputOption, environmentsOption, keySizeOption, rotationDaysOption);

        return generateCommand;
    }

    /// <summary>
    /// Rotate command - Key rotation işlemi
    /// </summary>
    private static Command CreateRotateCommand(ServiceProvider serviceProvider)
    {
        var rotateCommand = new Command("rotate", "Key rotation işlemi yap");

        var inputOption = new Option<string>(
            aliases: new[] { "--input", "-i" },
            description: "Input key store JSON dosyası"
        ) { IsRequired = true };

        var environmentOption = new Option<string>(
            aliases: new[] { "--environment", "-e" },
            description: "Rotate edilecek environment"
        ) { IsRequired = true };

        var outputOption = new Option<string?>(
            aliases: new[] { "--output", "-o" },
            description: "Output dosya (boşsa input üzerine yazar)"
        );

        rotateCommand.AddOption(inputOption);
        rotateCommand.AddOption(environmentOption);
        rotateCommand.AddOption(outputOption);

        rotateCommand.SetHandler(async (input, environment, output) =>
        {
            var logger = serviceProvider.GetRequiredService<ILogger<Program>>();
            var keyGenerator = serviceProvider.GetRequiredService<IKeyGeneratorService>();
            var keyStore = serviceProvider.GetRequiredService<IKeyStoreService>();

            try
            {
                Console.WriteLine("🔄 Key Rotation");
                Console.WriteLine("===============");
                Console.WriteLine();

                var keyStoreData = await keyStore.LoadKeyStoreAsync(input);

                Console.WriteLine($"🌍 Environment: {environment}");

                if (!keyStoreData.Environments.ContainsKey(environment))
                {
                    Console.WriteLine($"❌ Environment bulunamadı: {environment}");
                    Console.WriteLine($"📝 Mevcut environments: {string.Join(", ", keyStoreData.Environments.Keys)}");
                    Environment.Exit(1);
                }

                var currentKey = keyStoreData.Environments[environment].CurrentKey?.KeyId;
                Console.WriteLine($"🔑 Current Key: {currentKey}");
                Console.WriteLine();
                Console.Write("⚠️  Key rotation yapmak istediğinizden emin misiniz? (y/N): ");

                var confirmation = Console.ReadLine();
                if (!string.Equals(confirmation, "y", StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine("❌ Rotation iptal edildi");
                    return;
                }

                Console.WriteLine("🔄 Rotation başlatılıyor...");
                var rotatedStore = await keyGenerator.RotateKeysAsync(keyStoreData, environment);

                var outputPath = output ?? input;
                await keyStore.SaveKeyStoreAsync(rotatedStore, outputPath);

                var newKey = rotatedStore.Environments[environment].CurrentKey?.KeyId;
                Console.WriteLine("✅ Key rotation tamamlandı!");
                Console.WriteLine($"🔑 New Current Key: {newKey}");
                Console.WriteLine($"💾 Updated: {Path.GetFullPath(outputPath)}");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Key rotation failed");
                Console.WriteLine($"❌ Hata: {ex.Message}");
                Environment.Exit(1);
            }
        }, inputOption, environmentOption, outputOption);

        return rotateCommand;
    }

    /// <summary>
    /// Validate command - Key store health check
    /// </summary>
    private static Command CreateValidateCommand(ServiceProvider serviceProvider)
    {
        var validateCommand = new Command("validate", "Key store health check yap");

        var inputOption = new Option<string>(
            aliases: new[] { "--input", "-i" },
            description: "Key store JSON dosyası"
        ) { IsRequired = true };

        validateCommand.AddOption(inputOption);

        validateCommand.SetHandler(async (input) =>
        {
            var keyStore = serviceProvider.GetRequiredService<IKeyStoreService>();

            try
            {
                Console.WriteLine("🔍 Key Store Health Check");
                Console.WriteLine("=========================");
                Console.WriteLine();

                var report = await keyStore.ValidateKeyStoreAsync(input);

                Console.WriteLine($"📁 File: {report.FilePath}");
                Console.WriteLine($"✅ Valid: {(report.IsValid ? "Yes" : "No")}");

                if (!report.IsValid)
                {
                    Console.WriteLine($"❌ Error: {report.ValidationError}");
                    Environment.Exit(1);
                }

                Console.WriteLine($"🌍 Environments: {report.EnvironmentCount}");
                Console.WriteLine();

                foreach (var env in report.Environments)
                {
                    Console.WriteLine($"🌍 {env.Environment}:");
                    Console.WriteLine($"   🔑 Current Key: {(env.HasCurrentKey ? "✅" : "❌")}");
                    Console.WriteLine($"   ⏭️  Next Key: {(env.HasNextKey ? "✅" : "❌")}");
                    Console.WriteLine($"   🛡️  Backup Keys: {env.BackupKeyCount}");
                    Console.WriteLine($"   ⏰ Days to Expiry: {env.DaysToExpiry}");

                    if (env.ExpirationWarning)
                    {
                        Console.WriteLine($"   ⚠️  WARNING: Key expires soon!");
                    }

                    Console.WriteLine();
                }

                Console.WriteLine("✅ Health check tamamlandı");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Validation failed: {ex.Message}");
                Environment.Exit(1);
            }
        }, inputOption);

        return validateCommand;
    }

    /// <summary>
    /// Backup command - Key store backup
    /// </summary>
    private static Command CreateBackupCommand(ServiceProvider serviceProvider)
    {
        var backupCommand = new Command("backup", "Key store backup oluştur");

        var inputOption = new Option<string>(
            aliases: new[] { "--input", "-i" },
            description: "Backup edilecek key store"
        ) { IsRequired = true };

        var backupDirOption = new Option<string>(
            aliases: new[] { "--backup-dir", "-b" },
            description: "Backup directory",
            getDefaultValue: () => "backups"
        );

        backupCommand.AddOption(inputOption);
        backupCommand.AddOption(backupDirOption);

        backupCommand.SetHandler(async (input, backupDir) =>
        {
            var keyStore = serviceProvider.GetRequiredService<IKeyStoreService>();

            try
            {
                Console.WriteLine("💾 Key Store Backup");
                Console.WriteLine("===================");
                Console.WriteLine();

                var success = await keyStore.BackupKeyStoreAsync(input, backupDir);

                if (success)
                {
                    Console.WriteLine("✅ Backup başarıyla oluşturuldu");
                    Console.WriteLine($"📁 Backup Directory: {Path.GetFullPath(backupDir)}");
                }
                else
                {
                    Console.WriteLine("❌ Backup oluşturulamadı");
                    Environment.Exit(1);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Backup failed: {ex.Message}");
                Environment.Exit(1);
            }
        }, inputOption, backupDirOption);

        return backupCommand;
    }

    /// <summary>
    /// Info command - Key store bilgilerini göster
    /// </summary>
    private static Command CreateInfoCommand(ServiceProvider serviceProvider)
    {
        var infoCommand = new Command("info", "Key store detaylı bilgilerini göster");

        var inputOption = new Option<string>(
            aliases: new[] { "--input", "-i" },
            description: "Key store JSON dosyası"
        ) { IsRequired = true };

        var environmentOption = new Option<string?>(
            aliases: new[] { "--environment", "-e" },
            description: "Specific environment info (opsiyonel)"
        );

        var showKeysOption = new Option<bool>(
            aliases: new[] { "--show-keys", "-k" },
            description: "Public key'leri göster"
        );

        infoCommand.AddOption(inputOption);
        infoCommand.AddOption(environmentOption);
        infoCommand.AddOption(showKeysOption);

        infoCommand.SetHandler(async (input, environment, showKeys) =>
        {
            var keyStore = serviceProvider.GetRequiredService<IKeyStoreService>();

            try
            {
                Console.WriteLine("ℹ️  Key Store Information");
                Console.WriteLine("=========================");
                Console.WriteLine();

                var keyStoreData = await keyStore.LoadKeyStoreAsync(input);

                Console.WriteLine($"📁 File: {Path.GetFullPath(input)}");
                Console.WriteLine($"📅 Generated: {keyStoreData.GeneratedAt:yyyy-MM-dd HH:mm:ss} UTC");
                Console.WriteLine($"📝 Description: {keyStoreData.Description}");
                Console.WriteLine($"🔢 Version: {keyStoreData.Version}");
                Console.WriteLine();

                var environments = string.IsNullOrEmpty(environment)
                    ? keyStoreData.Environments.Keys.ToArray()
                    : [environment];

                foreach (var envName in environments)
                {
                    if (!keyStoreData.Environments.ContainsKey(envName))
                    {
                        Console.WriteLine($"❌ Environment not found: {envName}");
                        continue;
                    }

                    var env = keyStoreData.Environments[envName];
                    Console.WriteLine($"🌍 Environment: {envName}");
                    Console.WriteLine($"   📝 Description: {env.Description}");
                    Console.WriteLine();

                    if (env.CurrentKey != null)
                    {
                        Console.WriteLine($"   🔑 Current Key:");
                        PrintKeyInfo(env.CurrentKey, showKeys);
                    }

                    if (env.NextKey != null)
                    {
                        Console.WriteLine($"   ⏭️  Next Key:");
                        PrintKeyInfo(env.NextKey, showKeys);
                    }

                    if (env.BackupKeys.Any())
                    {
                        Console.WriteLine($"   🛡️  Backup Keys ({env.BackupKeys.Count}):");
                        foreach (var backupKey in env.BackupKeys)
                        {
                            PrintKeyInfo(backupKey, showKeys, "      ");
                        }
                    }

                    Console.WriteLine($"   ⚙️  Rotation Policy:");
                    Console.WriteLine($"      📅 Interval: {env.RotationPolicy.RotationIntervalDays} days");
                    Console.WriteLine($"      ⚠️  Warning: {env.RotationPolicy.WarningDays} days before");
                    Console.WriteLine($"      🤖 Auto-rotation: {env.RotationPolicy.AutoRotationEnabled}");

                    if (env.RotationPolicy.NextRotation.HasValue)
                    {
                        Console.WriteLine($"      📅 Next Rotation: {env.RotationPolicy.NextRotation:yyyy-MM-dd}");
                    }

                    Console.WriteLine();
                }

                if (keyStoreData.ArchivedKeys.Any())
                {
                    Console.WriteLine($"🗄️  Archived Keys: {keyStoreData.ArchivedKeys.Count}");
                    Console.WriteLine();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Info failed: {ex.Message}");
                Environment.Exit(1);
            }
        }, inputOption, environmentOption, showKeysOption);

        return infoCommand;
    }

    private static void PrintKeyInfo(RsaKeyPair key, bool showPublicKey, string indent = "      ")
    {
        Console.WriteLine($"{indent}🆔 ID: {key.KeyId}");
        Console.WriteLine($"{indent}🔢 Size: {key.KeySize} bits");
        Console.WriteLine($"{indent}📅 Created: {key.CreatedAt:yyyy-MM-dd HH:mm:ss}");
        Console.WriteLine($"{indent}⏰ Expires: {key.ExpiresAt:yyyy-MM-dd HH:mm:ss}");
        Console.WriteLine($"{indent}✅ Active: {key.IsActive}");
        Console.WriteLine($"{indent}🎯 Purpose: {key.Purpose}");

        if (showPublicKey)
        {
            Console.WriteLine($"{indent}🔑 Public Key:");
            var publicKeyLines = key.PublicKey.Split('\n');
            foreach (var line in publicKeyLines.Take(3))
            {
                Console.WriteLine($"{indent}   {line}");
            }

            if (publicKeyLines.Length > 3)
            {
                Console.WriteLine($"{indent}   ... ({publicKeyLines.Length - 3} more lines)");
            }
        }

        Console.WriteLine();
    }
}