# Microservices Architecture

## Service Boundaries

### Client API Service
**Responsibility**: Customer-facing operations
- Payment request handling
- Client-side encryption coordination
- Request validation
- Response formatting

**Port**: 7001
**Dependencies**: Payment API

### Payment API Service
**Responsibility**: Core payment processing
- Payment business logic
- Server-side decryption
- Key management
- Gateway integration

**Port**: 7000
**Dependencies**: Key Store, Payment Gateway

### Key Manager Service
**Responsibility**: RSA key lifecycle management
- Key generation
- Key rotation
- Backup management
- Health monitoring

**Type**: CLI Tool
**Dependencies**: File System

## Communication Patterns

### Synchronous Communication
- **Client API → Payment API**: HTTPS REST calls
- **Admin → Payment API**: HTTPS REST calls for key management

### File-based Communication
- **Key Manager → Payment API**: JSON file-based key store
- **Configuration**: Environment-specific JSON files

## Service Discovery

### Static Configuration
- Services use fixed ports and URLs
- Environment-specific configuration files
- Docker Compose for container orchestration

## Data Consistency

### Eventually Consistent
- Key updates are eventually consistent across services
- Manual key refresh capability via API

### Transactional Consistency
- Payment processing is atomic within Payment API
- No distributed transactions needed

---