namespace PaymentSystem.PaymentApi.Features.Encryption.Services;

/// <summary>
/// Hybrid Encryption Service - RSA boyut sınırlamasını çözer
/// 
/// Hybrid Encryption Nasıl Çalışır:
/// 1. AES symmetric key (32 byte) oluştur
/// 2. Veriyi AES ile şifrele (boyut sınırı yok)
/// 3. AES key'i RSA ile şifrele (32 byte < 245 byte ✅)
/// 4. Her ikisini birlikte gönder
/// 
/// Avantajları:
/// - Unlimited veri boyutu desteği
/// - RSA security + AES performance
/// - Industry standard approach
/// </summary>
public interface IHybridEncryptionService
{
    string EncryptData(string plainText, string publicKeyPem);
    string DecryptData(string encryptedData, string privateKeyPem);
}