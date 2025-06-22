using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using PaymentSystem.PaymentApi.Features.Encryption.Models;

namespace PaymentSystem.PaymentApi.Features.Encryption.Services;

public class HybridEncryptionService(ILogger<HybridEncryptionService> logger) : IHybridEncryptionService
{
    /// <summary>
    /// Hybrid encryption: AES + RSA kombinasyonu
    /// </summary>
    public string EncryptData(string plainText, string publicKeyPem)
    {
        try
        {
            logger.LogDebug("Starting hybrid encryption for data size: {Size} bytes",
                Encoding.UTF8.GetByteCount(plainText));

            // 1. AES key ve IV oluştur
            using var aes = Aes.Create();
            aes.GenerateKey(); // 256-bit key
            aes.GenerateIV(); // 128-bit IV

            var aesKey = aes.Key;
            var aesIV = aes.IV;

            logger.LogDebug("Generated AES key: {KeySize} bits, IV: {IVSize} bits",
                aesKey.Length * 8, aesIV.Length * 8);

            // 2. Veriyi AES ile şifrele
            byte[] encryptedData;
            using (var encryptor = aes.CreateEncryptor())
            using (var msEncrypt = new MemoryStream())
            using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
            using (var swEncrypt = new StreamWriter(csEncrypt))
            {
                swEncrypt.Write(plainText);
                swEncrypt.Flush();
                csEncrypt.FlushFinalBlock();
                encryptedData = msEncrypt.ToArray();
            }

            logger.LogDebug("AES encryption completed. Encrypted data size: {Size} bytes", encryptedData.Length);

            // 3. AES key ve IV'yi RSA ile şifrele
            using var rsa = RSA.Create();
            rsa.ImportFromPem(publicKeyPem);

            // AES key + IV'yi birleştir (32 + 16 = 48 bytes total)
            var keyAndIV = new byte[aesKey.Length + aesIV.Length];
            Array.Copy(aesKey, 0, keyAndIV, 0, aesKey.Length);
            Array.Copy(aesIV, 0, keyAndIV, aesKey.Length, aesIV.Length);

            logger.LogDebug("Combined AES key+IV size: {Size} bytes (RSA can handle up to ~245 bytes)", keyAndIV.Length);

            var encryptedKeyAndIV = rsa.Encrypt(keyAndIV, RSAEncryptionPadding.OaepSHA256);

            logger.LogDebug("RSA encryption completed. Encrypted key size: {Size} bytes", encryptedKeyAndIV.Length);

            // 4. Sonucu JSON olarak paketla
            var hybridResult = new HybridEncryptionResult
            {
                EncryptedData = Convert.ToBase64String(encryptedData),
                EncryptedKey = Convert.ToBase64String(encryptedKeyAndIV),
                Algorithm = "AES-256-CBC + RSA-OAEP-SHA256",
                KeySize = rsa.KeySize,
                Timestamp = DateTime.UtcNow
            };

            var result = JsonSerializer.Serialize(hybridResult);

            logger.LogInformation("Hybrid encryption successful. Original: {OriginalSize} bytes, Final: {FinalSize} bytes",
                Encoding.UTF8.GetByteCount(plainText), Encoding.UTF8.GetByteCount(result));

            return result;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Hybrid encryption failed");
            throw new InvalidOperationException("Hybrid şifreleme işlemi başarısız", ex);
        }
    }

    /// <summary>
    /// Hybrid decryption: Tersine işlem
    /// </summary>
    public string DecryptData(string encryptedData, string privateKeyPem)
    {
        try
        {
            logger.LogDebug("Starting hybrid decryption");

            // 1. JSON'ı parse et
            var hybridResult = JsonSerializer.Deserialize<HybridEncryptionResult>(encryptedData);

            if (hybridResult == null)
            {
                throw new InvalidOperationException("Geçersiz hybrid encryption formatı");
            }

            var encryptedDataBytes = Convert.FromBase64String(hybridResult.EncryptedData);
            var encryptedKeyAndIV = Convert.FromBase64String(hybridResult.EncryptedKey);

            logger.LogDebug("Parsed hybrid data. Encrypted data: {DataSize} bytes, Encrypted key: {KeySize} bytes",
                encryptedDataBytes.Length, encryptedKeyAndIV.Length);

            // 2. RSA ile AES key ve IV'yi decrypt et
            using var rsa = RSA.Create();
            rsa.ImportFromPem(privateKeyPem);

            var keyAndIV = rsa.Decrypt(encryptedKeyAndIV, RSAEncryptionPadding.OaepSHA256);

            // AES key ve IV'yi ayır
            var aesKey = new byte[32]; // 256 bits
            var aesIV = new byte[16]; // 128 bits
            Array.Copy(keyAndIV, 0, aesKey, 0, 32);
            Array.Copy(keyAndIV, 32, aesIV, 0, 16);

            logger.LogDebug("RSA decryption completed. Recovered AES key and IV");

            // 3. AES ile asıl veriyi decrypt et
            using var aes = Aes.Create();
            aes.Key = aesKey;
            aes.IV = aesIV;

            string decryptedText;
            using (var decryptor = aes.CreateDecryptor())
            using (var msDecrypt = new MemoryStream(encryptedDataBytes))
            using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
            using (var srDecrypt = new StreamReader(csDecrypt))
            {
                decryptedText = srDecrypt.ReadToEnd();
            }

            logger.LogInformation("Hybrid decryption successful. Decrypted data size: {Size} bytes",
                Encoding.UTF8.GetByteCount(decryptedText));

            return decryptedText;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Hybrid decryption failed");
            throw new InvalidOperationException("Hybrid şifre çözme işlemi başarısız", ex);
        }
    }
}