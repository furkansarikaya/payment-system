# Key Rotation Guide

## Rotation Strategy

### Scheduled Rotation
- **Frequency**: Every 90 days
- **Warning Period**: 7 days before expiration
- **Overlap Period**: 30 days for gradual transition

### Emergency Rotation
- **Triggers**: Security incident, key compromise suspicion
- **Timeline**: Immediate (within 1 hour)
- **Coordination**: All environments must be updated

## Rotation Process

### 1. Pre-Rotation Checks
```bash
# Validate current key store
dotnet run -- validate --input keys/payment-keys.json

# Check rotation status
dotnet run -- info --input keys/payment-keys.json --environment production

# Backup current key store
dotnet run -- backup --input keys/payment-keys.json --backup-dir backups
```

### 2. Key Rotation Execution
```bash
# Rotate production keys
dotnet run -- rotate \
  --input keys/payment-keys.json \
  --environment production \
  --output keys/payment-keys-rotated.json
```

### 3. Validation
```bash
# Validate rotated key store
dotnet run -- validate --input keys/payment-keys-rotated.json

# Check new key information
dotnet run -- info --input keys/payment-keys-rotated.json --environment production
```

### 4. Deployment
```bash
# Replace current key store
mv keys/payment-keys-rotated.json keys/payment-keys.json

# Refresh API key store (zero-downtime)
curl -X POST https://localhost:7000/api/admin/keymanagement/refresh
```

### 5. Post-Rotation Verification
```bash
# Test encryption with new keys
curl -X POST https://localhost:7001/api/customer/payment \
  -H "Content-Type: application/json" \
  -d '{ "test": "payment" }'

# Monitor for errors
curl https://localhost:7000/api/payment/health
```

## Rotation Scenarios

### Standard Rotation (Planned)
1. **Notification**: 7 days before expiration
2. **Planning**: Schedule maintenance window
3. **Execution**: During low-traffic period
4. **Monitoring**: 24-hour monitoring post-rotation

### Emergency Rotation (Unplanned)
1. **Detection**: Security incident or key compromise
2. **Immediate Action**: Stop using current keys
3. **Rapid Rotation**: Emergency key generation and deployment
4. **Investigation**: Root cause analysis

### Multi-Environment Rotation
1. **Development**: Test rotation procedure
2. **Staging**: Validate rotation in staging environment
3. **Production**: Execute production rotation
4. **Rollback Plan**: Prepare rollback procedure

## Best Practices

### Before Rotation
- ✅ Backup current key store
- ✅ Validate current system health
- ✅ Check dependencies and integrations
- ✅ Notify stakeholders
- ✅ Prepare rollback procedure

### During Rotation
- ✅ Validate each step
- ✅ Keep rollback option ready
- ✅ Document any issues

### After Rotation
- ✅ Verify new keys working
- ✅ Monitor for 24 hours
- ✅ Update documentation
- ✅ Clean up old backups

---