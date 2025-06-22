#!/bin/bash

set -euo pipefail

# Rollback Script for Payment System
# Usage: ./rollback.sh [backup_path]

BACKUP_PATH=${1}
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
echo -e "${YELLOW}[ROLLBACK]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_success() {
echo -e "${GREEN}[SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_error() {
echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

validate_backup() {
if [[ ! -d "$BACKUP_PATH" ]]; then
log_error "Backup directory not found: $BACKUP_PATH"
exit 1
fi

    if [[ ! -f "$BACKUP_PATH/manifest.json" ]]; then
        log_error "Backup manifest not found: $BACKUP_PATH/manifest.json"
        exit 1
    fi
    
    log_info "Backup validation passed"
}

confirm_rollback() {
local backup_date
backup_date=$(jq -r '.backup_date' "$BACKUP_PATH/manifest.json")

    echo
    log_info "About to rollback to backup from: $backup_date"
    log_info "Backup path: $BACKUP_PATH"
    echo
    
    read -p "Are you sure you want to proceed with rollback? (yes/no): " -r
    if [[ ! $REPLY =~ ^yes$ ]]; then
        log_info "Rollback cancelled"
        exit 0
    fi
}

perform_rollback() {
log_info "Starting rollback process..."

    # Stop current services
    docker-compose down
    
    # Restore key store
    if [[ -f "$BACKUP_PATH/payment-keys.json" ]]; then
        cp "$BACKUP_PATH/payment-keys.json" "/secure/keys/payment-keys.json"
        log_success "Key store restored"
    fi
    
    # Restore configuration
    if [[ -f "$BACKUP_PATH/docker-compose.yml" ]]; then
        cp "$BACKUP_PATH/docker-compose.yml" "docker-compose.yml"
        log_success "Docker compose configuration restored"
    fi
    
    # Restore environment configuration
    if [[ -f "$BACKUP_PATH/environment.env" ]]; then
        local env_name
        env_name=$(jq -r '.environment' "$BACKUP_PATH/manifest.json")
        cp "$BACKUP_PATH/environment.env" "environments/$env_name.env"
        log_success "Environment configuration restored"
    fi
    
    # Start services with restored configuration
    docker-compose up -d
    
    log_success "Rollback completed"
}

verify_rollback() {
log_info "Verifying rollback..."

    # Wait for services to start
    sleep 30
    
    # Health check
    if curl -f -s -k https://localhost:7000/api/payment/health > /dev/null; then
        log_success "Payment API health check passed"
    else
        log_error "Payment API health check failed"
        exit 1
    fi
    
    if curl -f -s -k https://localhost:7001/api/customer/health > /dev/null; then
        log_success "Client API health check passed"
    else
        log_error "Client API health check failed"
        exit 1
    fi
    
    log_success "Rollback verification completed"
}

main() {
if [[ -z "${BACKUP_PATH:-}" ]]; then
log_error "Backup path is required"
echo "Usage: $0 <backup_path>"
echo "Example: $0 /backups/payment-system/20241215_143000"
exit 1
fi

    validate_backup
    confirm_rollback
    perform_rollback
    verify_rollback
    
    log_success "Rollback process completed successfully!"
}

main "$@"