# Encryption Implementation

## Hybrid Encryption Overview

The system uses a hybrid encryption approach combining RSA and AES:

### Why Hybrid Encryption?

1. **RSA Limitations**: RSA can only encrypt data smaller than key size
2. **Performance**: AES is much faster for large data encryption
3. **Security**: Combines asymmetric and symmetric encryption benefits
4. **Industry Standard**: Same approach used by TLS, VPNs, banking systems

## Implementation Details

### Client-Side Encryption

1. **AES Key Generation**
   ```csharp
   using var aes = Aes.Create();
   aes.GenerateKey(); // 256-bit key
   aes.GenerateIV();  // 128-bit IV
   ```

2. **Data Encryption**
   ```csharp
   // Encrypt payment data with AES
   var encryptedData = aes.CreateEncryptor().TransformFinalBlock(data);
   ```

3. **Key Encryption**
   ```csharp
   // Encrypt AES key + IV with RSA
   var keyAndIV = Combine(aes.Key, aes.IV);
   var encryptedKey = rsa.Encrypt(keyAndIV, RSAEncryptionPadding.OaepSHA256);
   ```

### Server-Side Decryption

1. **Key Decryption**
   ```csharp
   // Decrypt AES key + IV with RSA private key
   var keyAndIV = rsa.Decrypt(encryptedKey, RSAEncryptionPadding.OaepSHA256);
   ```

2. **Data Decryption**
   ```csharp
   // Decrypt data with recovered AES key
   aes.Key = recoveredKey;
   aes.IV = recoveredIV;
   var originalData = aes.CreateDecryptor().TransformFinalBlock(encryptedData);
   ```

## Security Properties

### Confidentiality
- **AES-256-CBC**: Strong symmetric encryption
- **RSA-2048-OAEP**: Strong asymmetric encryption
- **Perfect Forward Secrecy**: New AES key per request

### Integrity
- **HMAC**: Message authentication codes
- **Digital Signatures**: RSA signature verification
- **Timestamp Validation**: Replay attack prevention

### Authenticity
- **Certificate Validation**: Server identity verification
- **Key Validation**: RSA key authenticity
- **Request Signatures**: Message origin verification

## Key Management

### Key Generation
- **RSA-2048**: Industry standard key size
- **Secure Random**: Cryptographically secure random number generation
- **Key Metadata**: Creation time, expiration, purpose

### Key Rotation
- **Scheduled Rotation**: Every 90 days
- **Emergency Rotation**: Immediate rotation capability
- **Overlap Period**: 30-day transition period

### Key Storage
- **File Permissions**: 600 (owner read/write only)
- **Environment Separation**: Separate keys per environment
- **Backup Strategy**: Multiple backup keys maintained

---