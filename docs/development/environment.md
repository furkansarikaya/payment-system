# Development Environment Setup

## Project Structure Understanding

```
payment-system/
├── src/                          # Source code
│   ├── PaymentSystem.PaymentApi/ # Core payment processing
│   └── PaymentSystem.ClientApi/  # Client gateway
├── tools/                        # Development tools
│   └── PaymentSystem.KeyManager/ # Key management CLI
├── tests/                        # Test projects
├── docs/                         # Documentation
└── deployment/                   # Deployment configs
```

## Configuration Management

### appsettings.json Hierarchy
1. `appsettings.json` - Base configuration
2. `appsettings.Development.json` - Development overrides
3. Environment variables - Runtime overrides
4. Command line arguments - Highest priority

### Key Configuration Sections

#### Payment API Configuration
```json
{
  "JsonKeyStore": {
    "KeyStoreFilePath": "keys/payment-keys.json",
    "RefreshIntervalMinutes": 30,
    "RequestTimeoutMinutes": 5
  },
  "ApplicationInsights": {
    "ConnectionString": "InstrumentationKey=dev-key",
    "EnableAdaptiveSampling": false
  }
}
```

#### Client API Configuration
```json
{
  "PaymentApi": {
    "BaseUrl": "https://localhost:7000",
    "TimeoutSeconds": 30,
    "RetryCount": 3
  }
}
```

## Local Development Setup

### HTTPS Development Certificates
```bash
# Generate development certificate
dotnet dev-certs https --trust

# Verify certificate
dotnet dev-certs https --check
```

### Local Database (Optional)
```bash
# If using Entity Framework
dotnet ef database update
```

### Environment Configuration
```bash
# Windows
set ASPNETCORE_ENVIRONMENT=Development
set JsonKeyStore__KeyStoreFilePath=keys/payment-keys.json

# Linux/Mac
export ASPNETCORE_ENVIRONMENT=Development
export JsonKeyStore__KeyStoreFilePath=keys/payment-keys.json
```

## Debugging Configuration

### Visual Studio Launch Profiles
```json
{
  "profiles": {
    "PaymentSystem.PaymentApi": {
      "commandName": "Project",
      "launchBrowser": false,
      "applicationUrl": "https://localhost:7000;http://localhost:5000",
      "environmentVariables": {
        "ASPNETCORE_ENVIRONMENT": "Development"
      }
    },
    "PaymentSystem.ClientApi": {
      "commandName": "Project", 
      "launchBrowser": false,
      "applicationUrl": "https://localhost:7001;http://localhost:5001",
      "environmentVariables": {
        "ASPNETCORE_ENVIRONMENT": "Development"
      }
    }
  }
}
```

### VS Code Debug Configuration
```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Payment API",
      "type": "coreclr",
      "request": "launch",
      "program": "${workspaceFolder}/src/PaymentSystem.PaymentApi/bin/Debug/net9.0/PaymentSystem.PaymentApi.dll",
      "args": [],
      "cwd": "${workspaceFolder}/src/PaymentSystem.PaymentApi",
      "env": {
        "ASPNETCORE_ENVIRONMENT": "Development"
      }
    },
    {
      "name": "Client API",
      "type": "coreclr", 
      "request": "launch",
      "program": "${workspaceFolder}/src/PaymentSystem.ClientApi/bin/Debug/net9.0/PaymentSystem.ClientApi.dll",
      "args": [],
      "cwd": "${workspaceFolder}/src/PaymentSystem.ClientApi",
      "env": {
        "ASPNETCORE_ENVIRONMENT": "Development"
      }
    }
  ],
  "compounds": [
    {
      "name": "Launch Both APIs",
      "configurations": ["Payment API", "Client API"]
    }
  ]
}
```

## Hot Reload Setup

### Enable Hot Reload
```bash
# In development, use watch mode
dotnet watch run --project src/PaymentSystem.PaymentApi
dotnet watch run --project src/PaymentSystem.ClientApi
```

### File Watching Configuration
```xml
<!-- In .csproj files -->
<PropertyGroup>
  <UsePollingFileWatcher>true</UsePollingFileWatcher>
  <DefaultItemExcludes>$(DefaultItemExcludes);*.tmp</DefaultItemExcludes>
</PropertyGroup>
```

---