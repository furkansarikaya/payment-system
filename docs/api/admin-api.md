# Admin API Documentation

**Base URL**: `https://localhost:7000/api/admin`

## Key Management Endpoints

### Get Key Store Information

**Endpoint**: `GET /keymanagement/info`

**Description**: Retrieves key store status and information.

**Response**:
```json
{
  "version": "1.0.0",
  "generatedAt": "2024-12-15T10:00:00.000Z",
  "environmentCount": 3,
  "environments": [
    {
      "environment": "development",
      "currentKeyId": "DEV_PAYMENT_20241215_A1B2C3D4",
      "keySize": 2048,
      "daysToExpiry": 89,
      "hasNextKey": true,
      "backupKeyCount": 2
    }
  ]
}
```

### Get Environment Key Info

**Endpoint**: `GET /keymanagement/environment/{environment}`

**Description**: Get specific environment key information.

**Response**:
```json
{
  "environment": "production",
  "keyId": "PROD_PAYMENT_20241215_A1B2C3D4",
  "keySize": 2048,
  "createdAt": "2024-12-15T10:00:00.000Z",
  "expiresAt": "2024-03-15T10:00:00.000Z",
  "daysToExpiry": 89,
  "rotationNeeded": false,
  "isExpired": false
}
```

### Refresh Key Store

**Endpoint**: `POST /keymanagement/refresh`

**Description**: Reload key store from file.

**Response**:
```json
{
  "message": "Key store başarıyla yenilendi",
  "refreshedAt": "2024-12-15T14:30:22.123Z"
}
```

### Get Rotation Status

**Endpoint**: `GET /keymanagement/rotation-status`

**Description**: Check key rotation status for all environments.

**Response**:
```json
{
  "checkedAt": "2024-12-15T14:30:22.123Z",
  "totalEnvironments": 3,
  "needingRotation": 0,
  "environments": [
    {
      "environment": "production",
      "currentKeyId": "PROD_PAYMENT_20241215_A1B2C3D4",
      "daysToExpiry": 89,
      "rotationNeeded": false,
      "hasNextKey": true
    }
  ]
}
```

---