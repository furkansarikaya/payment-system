# Data Flow Architecture

## Payment Processing Flow

1. **Client Request**
    - Customer submits payment data to Client API
    - Client API validates request format

2. **Key Retrieval**
    - Client API requests public key from Payment API
    - Public key cached for performance

3. **Client-side Encryption**
    - Payment data encrypted using hybrid encryption
    - AES key generated for session
    - AES key encrypted with RSA public key

4. **Secure Transmission**
    - Encrypted payload sent to Payment API
    - TLS provides transport security

5. **Server-side Decryption**
    - Payment API decrypts AES key with RSA private key
    - AES key used to decrypt payment data

6. **Payment Processing**
    - Business validation performed
    - Payment gateway integration
    - Transaction recording

7. **Response**
    - Success/failure response sent back
    - No sensitive data in response

## Key Management Flow

1. **Key Generation**
    - Key Manager CLI generates RSA key pairs
    - Environment-specific key organization
    - JSON file storage

2. **Key Loading**
    - Payment API loads keys on startup
    - Environment-based key selection
    - Periodic key refresh

3. **Key Rotation**
    - Scheduled key replacement
    - Backup key management
    - Zero-downtime updates

---