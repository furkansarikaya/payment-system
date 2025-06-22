# docs/key-management/lifecycle.md
# Key Lifecycle Management

## Key States

### 1. Generated
- **Status**: Newly created, not yet active
- **Location**: Key store file
- **Usage**: Not used for encryption/decryption
- **Next State**: Active

### 2. Active (Current)
- **Status**: Currently used for encryption/decryption
- **Location**: Loaded in memory and key store
- **Usage**: All payment processing operations
- **Next State**: Transitioning or Expired

### 3. Next
- **Status**: Prepared for rotation, not yet active
- **Location**: Key store file
- **Usage**: Not used, ready for activation
- **Next State**: Active

### 4. Backup
- **Status**: Previous active keys kept for recovery
- **Location**: Key store file
- **Usage**: Emergency decryption only
- **Next State**: Archived

### 5. Archived
- **Status**: Old keys moved to archive
- **Location**: Archive section of key store
- **Usage**: Compliance and audit purposes only
- **Next State**: Deleted (after retention period)

### 6. Expired
- **Status**: Past expiration date
- **Location**: Key store file
- **Usage**: Emergency decryption only
- **Next State**: Archived

## Lifecycle Transitions

### Generation → Active
- Manual activation through CLI
- Automatic activation during rotation
- Validation checks performed

### Active → Backup
- Triggered by key rotation
- Previous active key becomes backup
- Maintains decryption capability

### Backup → Archived
- Triggered by retention policy
- After maximum backup count reached
- Moved to archive section

### Any State → Expired
- Automatic based on expiration date
- Continues to work for emergency decryption
- Rotation recommended immediately

## Lifecycle Events

### Key Generation Event
```json
{
  "event": "KeyGenerated",
  "keyId": "PROD_PAYMENT_20241215_A1B2C3D4",
  "environment": "production",
  "keySize": 2048,
  "purpose": "payment-encryption",
  "generatedAt": "2024-12-15T10:00:00.000Z",
  "expiresAt": "2024-03-15T10:00:00.000Z"
}
```

### Key Activation Event
```json
{
  "event": "KeyActivated",
  "keyId": "PROD_PAYMENT_20241215_A1B2C3D4",
  "environment": "production",
  "previousKeyId": "PROD_PAYMENT_20241015_X1Y2Z3W4",
  "activatedAt": "2024-12-15T10:00:00.000Z"
}
```

### Key Rotation Event
```json
{
  "event": "KeyRotated",
  "environment": "production",
  "newCurrentKey": "PROD_PAYMENT_20241215_A1B2C3D4",
  "previousCurrentKey": "PROD_PAYMENT_20241015_X1Y2Z3W4",
  "newNextKey": "PROD_PAYMENT_20241215_B2C3D4E5",
  "rotatedAt": "2024-12-15T10:00:00.000Z"
}
```

---