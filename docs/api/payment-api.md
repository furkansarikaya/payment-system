# Payment API Documentation

**Base URL**: `https://localhost:7000/api`

## Endpoints

### Get Public Key

**Endpoint**: `GET /payment/public-key`

**Description**: Retrieves the current RSA public key for client-side encryption.

**Response**:
```json
{
  "publicKey": "-----BEGIN RSA PUBLIC KEY-----\n...",
  "keySize": 2048,
  "hybridSupport": true,
  "maxDirectRsaSize": 190,
  "algorithm": "RSA + AES-256 Hybrid Encryption",
  "generatedAt": "2024-12-15T14:30:22.123Z",
  "validityHours": 24
}
```

### Process Payment

**Endpoint**: `POST /payment/process`

**Description**: Processes encrypted payment data.

**Request Headers**:
```
Content-Type: application/json
```

**Request Body**:
```json
{
  "encryptedData": "{ hybrid encrypted payment JSON }",
  "requestId": "REQ_20241215_143022_ABC123",
  "timestamp": "2024-12-15T14:30:22.123Z"
}
```

**Response**:
```json
{
  "isSuccessful": true,
  "transactionId": "TXN_20241215_143022_XYZ789",
  "message": "Payment processed successfully",
  "processedAt": "2024-12-15T14:30:22.123Z",
  "amount": 100.50,
  "currency": "TRY"
}
```

### Health Check

**Endpoint**: `GET /payment/health`

**Description**: System health status.

**Response**:
```json
{
  "status": "Healthy",
  "timestamp": "2024-12-15T14:30:22.123Z",
  "encryptionService": "OK",
  "hybridEncryption": "OK",
  "keySize": 2048,
  "version": "1.0.0"
}
```

---