# System Architecture Overview

## High-Level Architecture

The Payment System consists of three main components:

1. **Client API** - Customer-facing gateway
2. **Payment API** - Core payment processing
3. **Key Manager** - RSA key management CLI

## Design Patterns

### API Gateway Pattern
- Client API acts as a gateway to Payment API
- Handles client authentication and encryption
- Provides abstraction layer for clients

### Repository Pattern
- Separation of data access logic
- Easy testing and mocking
- Database agnostic design

### Factory Pattern
- Encryption service factory based on environment
- Payment gateway factory for different providers
- Flexible service instantiation

### Service Layer Pattern
- Business logic encapsulation
- Clear separation between controllers and business logic
- Reusable business components

## Technology Stack

### Backend
- **.NET 9.0** - Latest LTS runtime
- **ASP.NET Core** - Web API framework
- **C# 12** - Latest language features

### Security
- **RSA-2048** - Asymmetric encryption
- **AES-256-CBC** - Symmetric encryption
- **TLS 1.3** - Transport security

### Storage
- **JSON Files** - Key store management
- **In-Memory** - Session state
- **File System** - Configuration and keys

---