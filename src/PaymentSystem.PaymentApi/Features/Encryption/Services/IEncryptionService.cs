using PaymentSystem.PaymentApi.Features.Encryption.Models;
using PaymentSystem.PaymentApi.Features.Payment.DTOs;

namespace PaymentSystem.PaymentApi.Features.Encryption.Services;

/// <summary>
/// Encryption Service Interface - Complete method definitions
/// </summary>
public interface IEncryptionService
{
    /// <summary>
    /// Encrypt data using hybrid encryption (AES + RSA)
    /// </summary>
    string EncryptData(string plainText);

    /// <summary>
    /// Decrypt data using hybrid decryption
    /// </summary>
    string DecryptData(string encryptedData);

    /// <summary>
    /// Get public key for client encryption
    /// </summary>
    PublicKeyResponseDto GetPublicKey();

    /// <summary>
    /// Validate if request is valid (timestamp, format, etc.)
    /// </summary>
    bool IsRequestValid(EncryptedRequestDto request);

    /// <summary>
    /// Validate timestamp within allowed timeframe
    /// </summary>
    bool ValidateTimestamp(DateTime timestamp, int timeoutMinutes);
}