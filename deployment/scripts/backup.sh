#!/bin/bash

set -euo pipefail

# Backup Script for Payment System
# Usage: ./backup.sh [environment]

ENVIRONMENT=${1:-production}
BACKUP_DIR="/backups/payment-system/$(date +%Y%m%d_%H%M%S)"
RETENTION_DAYS=30

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
echo -e "${BLUE}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_success() {
echo -e "${GREEN}[SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

main() {
log_info "Starting backup for $ENVIRONMENT environment"

    # Create backup directory
    mkdir -p "$BACKUP_DIR"
    
    # Backup key store
    if [[ -f "/secure/keys/payment-keys.json" ]]; then
        cp "/secure/keys/payment-keys.json" "$BACKUP_DIR/payment-keys.json"
        log_success "Key store backed up"
    fi
    
    # Backup configuration
    docker-compose -f docker-compose.yml config > "$BACKUP_DIR/docker-compose.yml"
    
    # Backup environment configuration
    if [[ -f "environments/$ENVIRONMENT.env" ]]; then
        cp "environments/$ENVIRONMENT.env" "$BACKUP_DIR/environment.env"
    fi
    
    # Create backup manifest
    cat > "$BACKUP_DIR/manifest.json" << EOF
{
"backup_date": "$(date -Iseconds)",
"environment": "$ENVIRONMENT",
"files": [
"payment-keys.json",
"docker-compose.yml",
"environment.env"
]
}
EOF

    # Cleanup old backups
    find "/backups/payment-system" -type d -mtime +$RETENTION_DAYS -exec rm -rf {} + 2>/dev/null || true
    
    log_success "Backup completed: $BACKUP_DIR"
}

main "$@"