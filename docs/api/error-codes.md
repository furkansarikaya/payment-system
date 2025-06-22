# API Error Codes

## Client API Error Codes

| Code | Description | HTTP Status |
|------|-------------|-------------|
| `INVALID_REQUEST` | Invalid request format | 400 |
| `INVALID_CARD_NUMBER` | Invalid credit card number | 400 |
| `INVALID_EXPIRY_DATE` | Invalid expiry date format | 400 |
| `INVALID_CVV` | Invalid CVV code | 400 |
| `INVALID_AMOUNT` | Invalid payment amount | 400 |
| `ENCRYPTION_FAILED` | Client-side encryption failed | 500 |
| `PAYMENT_API_UNAVAILABLE` | Payment API not responding | 503 |
| `KEY_UNAVAILABLE` | Public key not available | 503 |

## Payment API Error Codes

| Code | Description | HTTP Status |
|------|-------------|-------------|
| `INVALID_REQUEST_FORMAT` | Invalid request format | 400 |
| `DECRYPTION_FAILED` | Unable to decrypt request | 401 |
| `INVALID_PAYMENT_DATA` | Invalid payment data format | 400 |
| `VALIDATION_FAILED` | Payment validation failed | 400 |
| `GATEWAY_ERROR` | Payment gateway error | 502 |
| `SYSTEM_ERROR` | Internal system error | 500 |
| `SERVICE_UNAVAILABLE` | Service temporarily unavailable | 503 |

## Key Management Error Codes

| Code | Description | HTTP Status |
|------|-------------|-------------|
| `KEY_STORE_UNAVAILABLE` | Key store file not accessible | 503 |
| `ENVIRONMENT_NOT_FOUND` | Environment not found in key store | 404 |
| `KEY_EXPIRED` | Current key has expired | 401 |
| `REFRESH_FAILED` | Key store refresh failed | 503 |

---