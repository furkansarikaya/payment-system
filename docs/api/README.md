# API Documentation

## Overview

The Payment System provides two main APIs:

1. **Payment API** (Port 7000) - Core payment processing
2. **Client API** (Port 7001) - Client-facing gateway

## Authentication

All APIs use RSA+AES hybrid encryption for secure data transmission.

## Rate Limiting

- **Client API**: 100 requests per minute per IP
- **Payment API**: 50 requests per minute per client
- **Admin API**: 10 requests per minute (authenticated only)

## Error Handling

All APIs return consistent error responses:

```json
{
  "error": "Error description",
  "code": "ERROR_CODE",
  "timestamp": "2024-12-15T14:30:22.123Z",
  "correlationId": "abc-123-def"
}
```

## API Documentation Files

- [Payment API Endpoints](payment-api.md)
- [Client API Endpoints](client-api.md)
- [Admin API Endpoints](admin-api.md)
- [Error Codes](error-codes.md)

---