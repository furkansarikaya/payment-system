using PaymentSystem.KeyManager.Models;

namespace PaymentSystem.KeyManager.Services;

/// <summary>
/// RSA Key Generation Service - Security best practices ile
/// </summary>
public interface IKeyGeneratorService
{
    RsaKeyPair GenerateKeyPair(string environment, string purpose, int keySize = 2048);
    Task<RsaKeyStore> GenerateKeyStoreAsync(KeyGenerationRequest request);
    Task<bool> ValidateKeyPairAsync(RsaKeyPair keyPair);
    Task<RsaKeyStore> RotateKeysAsync(RsaKeyStore keyStore, string environment);
}