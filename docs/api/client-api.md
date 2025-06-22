# docs/api/client-api.md
# Client API Documentation

**Base URL**: `https://localhost:7001/api`

## Endpoints

### Customer Payment

**Endpoint**: `POST /customer/payment`

**Description**: Processes customer payment with automatic encryption.

**Request Headers**:
```
Content-Type: application/json
```

**Request Body**:
```json
{
  "creditCard": {
    "cardNumber": "4111111111111111",
    "cardHolderName": "TEST USER",
    "expiryDate": "12/25",
    "cvv": "123"
  },
  "amount": 100.50,
  "currency": "TRY",
  "description": "Payment description",
  "customerEmail": "customer@example.com",
  "orderReference": "ORDER-001"
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
  "currency": "TRY",
  "customerReference": "REQ_20241215_143022_ABC123"
}
```

### Customer Health Check

**Endpoint**: `GET /customer/health`

**Description**: Client API health status.

**Response**:
```json
{
  "status": "Healthy",
  "timestamp": "2024-12-15T14:30:22.123Z",
  "paymentApiStatus": "Connected",
  "encryptionReady": true,
  "version": "1.0.0"
}
```

---