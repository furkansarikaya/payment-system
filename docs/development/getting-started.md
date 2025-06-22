# Getting Started - Developer Guide

## Prerequisites

### Required Software
- **.NET 9.0 SDK** - [Download](https://dotnet.microsoft.com/download/dotnet/9.0)
- **Git** - [Download](https://git-scm.com/)

### Optional Tools
- **Postman** - API testing
- **Docker Desktop** - Container development
- **Windows Terminal** - Better terminal experience
- **Mac Terminal** - For macOS users

## Initial Setup

### 1. Clone Repository
```bash
git clone https://github.com/furkansarikaya/payment-system.git
cd payment-system
```

### 2. Verify .NET Installation
```bash
dotnet --version
# Should show 9.0.x
```

### 3. Restore Dependencies
```bash
dotnet restore PaymentSystem.sln
```

### 4. Generate Development Keys
```bash
cd tools/PaymentSystem.KeyManager
dotnet build -c Release

# Generate keys for development
dotnet run -- generate \
  --output "../../src/PaymentSystem.PaymentApi/keys/payment-keys.json" \
  --environments development \
  --key-size 2048
```

### 5. Build Solution
```bash
cd ../../
dotnet build PaymentSystem.sln
```

## Development Workflow

### 1. Start Payment API
```bash
cd src/PaymentSystem.PaymentApi
dotnet run
```

Expected output:
```
[INFO] === JSON KEY STORE STATUS ===
[INFO] Key Store Version: 1.0.0
[INFO] Environment: development
[INFO] ✅ Encryption test successful for environment: Development
```

### 2. Start Client API (New Terminal)
```bash
cd src/PaymentSystem.ClientApi
dotnet run
```

### 3. Test APIs
```bash
# Test Payment API health
curl -k https://localhost:7000/api/payment/health

# Test Client API health  
curl -k https://localhost:7001/api/customer/health

# Test payment flow
curl -X POST https://localhost:7001/api/customer/payment \
  -H "Content-Type: application/json" \
  -k \
  -d '{
    "creditCard": {
      "cardNumber": "4111111111111111",
      "cardHolderName": "DEV TEST",
      "expiryDate": "12/25",
      "cvv": "123"
    },
    "amount": 50.00,
    "currency": "TRY",
    "description": "Development test",
    "customerEmail": "dev@test.com",
    "orderReference": "DEV-001"
  }'
```

## IDE Configuration

### Visual Studio 2022
1. Open `PaymentSystem.sln`
2. Set multiple startup projects:
    - `PaymentSystem.PaymentApi`
    - `PaymentSystem.ClientApi`
3. Configure debugging ports in `launchSettings.json`

### VS Code
1. Open root folder
2. Install recommended extensions:
    - C# Dev Kit
    - REST Client
    - Thunder Client
3. Use provided `.vscode/launch.json` for debugging

## Environment Variables

### Development Environment
```bash
export ASPNETCORE_ENVIRONMENT=Development
export JsonKeyStore__KeyStoreFilePath="keys/payment-keys.json"
```

### Local Testing
```bash
export ASPNETCORE_URLS="https://localhost:7000;http://localhost:5000"
export Logging__LogLevel__Default="Debug"
```

## Common Development Tasks

### Generate New Keys
```bash
cd tools/PaymentSystem.KeyManager
dotnet run -- generate --environments development staging
```

### Rotate Development Keys
```bash
dotnet run -- rotate --environment development --input "../../src/PaymentSystem.PaymentApi/keys/payment-keys.json"
```

### Run Unit Tests
```bash
cd tests/PaymentSystem.Tests
dotnet test
```

### Check Key Store Health
```bash
cd tools/PaymentSystem.KeyManager
dotnet run -- validate --input "../../src/PaymentSystem.PaymentApi/keys/payment-keys.json"
```

---