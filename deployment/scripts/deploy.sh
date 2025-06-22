#!/bin/bash

set -euo pipefail

# Production Deployment Script
# Usage: ./deploy.sh [environment] [version]

ENVIRONMENT=${1:-staging}
VERSION=${2:-latest}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
echo -e "${BLUE}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_success() {
echo -e "${GREEN}[SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_warning() {
echo -e "${YELLOW}[WARNING]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_error() {
echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Validate environment
validate_environment() {
case $ENVIRONMENT in
development|staging|production)
log_info "Deploying to $ENVIRONMENT environment"
;;
*)
log_error "Invalid environment: $ENVIRONMENT"
log_info "Valid environments: development, staging, production"
exit 1
;;
esac
}

# Pre-deployment checks
pre_deployment_checks() {
log_info "Running pre-deployment checks..."

    # Check required tools
    command -v docker >/dev/null 2>&1 || { log_error "Docker is required but not installed"; exit 1; }
    command -v docker-compose >/dev/null 2>&1 || { log_error "Docker Compose is required but not installed"; exit 1; }
    
    # Check environment-specific requirements
    if [[ "$ENVIRONMENT" == "production" ]]; then
        # Production-specific checks
        if [[ ! -f "$PROJECT_ROOT/deployment/environments/production.env" ]]; then
            log_error "Production environment file not found"
            exit 1
        fi
    fi
    
    log_success "Pre-deployment checks passed"
}

# Generate or validate keys
ensure_keys() {
log_info "Ensuring RSA keys are available..."

    local key_file="$PROJECT_ROOT/src/PaymentSystem.PaymentApi/keys/payment-keys.json"
    
    if [[ ! -f "$key_file" ]]; then
        log_info "Generating RSA keys for $ENVIRONMENT..."
        
        cd "$PROJECT_ROOT/tools/PaymentSystem.KeyManager"
        dotnet run -- generate \
            --output "../../src/PaymentSystem.PaymentApi/keys/payment-keys.json" \
            --environments "$ENVIRONMENT" \
            --key-size 2048
            
        log_success "RSA keys generated"
    else
        log_info "RSA keys already exist, validating..."
        
        cd "$PROJECT_ROOT/tools/PaymentSystem.KeyManager"
        if dotnet run -- validate --input "../../src/PaymentSystem.PaymentApi/keys/payment-keys.json"; then
            log_success "RSA keys validation passed"
        else
            log_error "RSA keys validation failed"
            exit 1
        fi
    fi
}

# Build application
build_application() {
log_info "Building application..."

    cd "$PROJECT_ROOT"
    
    # Build solution
    dotnet build --configuration Release --no-restore
    
    # Build Docker images
    docker-compose -f deployment/docker-compose.yml build --no-cache
    
    log_success "Application built successfully"
}

# Deploy application
deploy_application() {
log_info "Deploying application to $ENVIRONMENT..."

    cd "$PROJECT_ROOT"
    
    # Stop existing containers
    docker-compose -f deployment/docker-compose.yml down
    
    # Start new deployment
    docker-compose -f deployment/docker-compose.yml up -d
    
    log_success "Application deployed"
}

# Health check
health_check() {
log_info "Performing health checks..."

    local max_attempts=30
    local attempt=0
    
    while [[ $attempt -lt $max_attempts ]]; do
        if curl -f -s -k https://localhost:7000/api/payment/health > /dev/null; then
            log_success "Payment API health check passed"
            break
        fi
        
        attempt=$((attempt + 1))
        log_info "Health check attempt $attempt/$max_attempts..."
        sleep 10
    done
    
    if [[ $attempt -eq $max_attempts ]]; then
        log_error "Health check failed after $max_attempts attempts"
        exit 1
    fi
    
    # Test Client API
    if curl -f -s -k https://localhost:7001/api/customer/health > /dev/null; then
        log_success "Client API health check passed"
    else
        log_error "Client API health check failed"
        exit 1
    fi
}

# Post-deployment verification
post_deployment_verification() {
log_info "Running post-deployment verification..."

    # Test payment flow
    local test_response
    test_response=$(curl -s -k -X POST https://localhost:7001/api/customer/payment \
        -H "Content-Type: application/json" \
        -d '{
            "creditCard": {
                "cardNumber": "4111111111111111",
                "cardHolderName": "DEPLOYMENT TEST",
                "expiryDate": "12/25",
                "cvv": "123"
            },
            "amount": 1.00,
            "currency": "TRY",
            "description": "Deployment verification test",
            "customerEmail": "deploy-test@example.com",
            "orderReference": "DEPLOY-TEST-001"
        }')
    
    if echo "$test_response" | jq -e '.isSuccessful == true' > /dev/null; then
        log_success "Payment flow verification passed"
    else
        log_warning "Payment flow verification failed, but deployment continues"
        log_info "Response: $test_response"
    fi
    
    # Check container status
    if docker-compose -f deployment/docker-compose.yml ps | grep -q "Up"; then
        log_success "All containers are running"
    else
        log_error "Some containers are not running"
        docker-compose -f deployment/docker-compose.yml ps
        exit 1
    fi
}

# Main deployment flow
main() {
log_info "Starting deployment process..."
log_info "Environment: $ENVIRONMENT"
log_info "Version: $VERSION"

    validate_environment
    pre_deployment_checks
    ensure_keys
    build_application
    deploy_application
    health_check
    post_deployment_verification
    
    log_success "Deployment completed successfully!"
    log_info "Services are available at:"
    log_info "  Payment API: https://localhost:7000"
    log_info "  Client API: https://localhost:7001"
}

# Run main function
main "$@"