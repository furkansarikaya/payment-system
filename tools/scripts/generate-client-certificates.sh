#!/bin/bash

# Client Certificate Generation Script for Payment System
# This script generates client certificates for mTLS authentication

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="$SCRIPT_DIR/../certificates"
CA_DIR="$CERT_DIR/ca"
CLIENT_DIR="$CERT_DIR/clients"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Create directories
mkdir -p "$CA_DIR" "$CLIENT_DIR"

# Generate CA private key
if [ ! -f "$CA_DIR/ca-key.pem" ]; then
    log_info "Generating CA private key..."
    openssl genrsa -out "$CA_DIR/ca-key.pem" 4096
    chmod 400 "$CA_DIR/ca-key.pem"
fi

# Generate CA certificate
if [ ! -f "$CA_DIR/ca-cert.pem" ]; then
    log_info "Generating CA certificate..."
    openssl req -new -x509 -days 3650 -key "$CA_DIR/ca-key.pem" -out "$CA_DIR/ca-cert.pem" \
        -subj "/C=TR/ST=Istanbul/L=Istanbul/O=Payment System CA/OU=Security/CN=Payment System Root CA"
fi

# Generate client certificates
generate_client_cert() {
    local client_name=$1
    local client_org=$2
    local client_type=$3
    
    log_info "Generating client certificate for: $client_name"
    
    # Generate client private key
    openssl genrsa -out "$CLIENT_DIR/$client_name-key.pem" 2048
    chmod 400 "$CLIENT_DIR/$client_name-key.pem"
    
    # Generate client CSR
    openssl req -new -key "$CLIENT_DIR/$client_name-key.pem" -out "$CLIENT_DIR/$client_name.csr" \
        -subj "/C=TR/ST=Istanbul/L=Istanbul/O=$client_org/OU=$client_type/CN=$client_name"
    
    # Generate client certificate
    openssl x509 -req -days 365 -in "$CLIENT_DIR/$client_name.csr" \
        -CA "$CA_DIR/ca-cert.pem" -CAkey "$CA_DIR/ca-key.pem" -CAcreateserial \
        -out "$CLIENT_DIR/$client_name-cert.pem" \
        -extensions client_cert -extfile <(cat << EOF
[client_cert]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = $client_name
DNS.2 = $client_name.payment-system.local
EOF
)
    
    # Create PKCS#12 bundle for client
    openssl pkcs12 -export -out "$CLIENT_DIR/$client_name.p12" \
        -inkey "$CLIENT_DIR/$client_name-key.pem" \
        -in "$CLIENT_DIR/$client_name-cert.pem" \
        -certfile "$CA_DIR/ca-cert.pem" \
        -passout pass:client123
    
    # Get certificate thumbprint
    local thumbprint=$(openssl x509 -in "$CLIENT_DIR/$client_name-cert.pem" -fingerprint -sha1 -noout | cut -d= -f2 | tr -d :)
    
    log_success "Client certificate generated: $client_name"
    echo "  Certificate: $CLIENT_DIR/$client_name-cert.pem"
    echo "  Private Key: $CLIENT_DIR/$client_name-key.pem"
    echo "  PKCS#12:     $CLIENT_DIR/$client_name.p12 (password: client123)"
    echo "  Thumbprint:  $thumbprint"
    echo ""
    
    # Clean up CSR
    rm "$CLIENT_DIR/$client_name.csr"
}

# Generate certificates for different client types
log_info "Generating client certificates for Payment System mTLS..."

generate_client_cert "demo_client" "Demo Organization" "Development"
generate_client_cert "high_security_client_1" "High Security Corp" "Enterprise"
generate_client_cert "financial_client_bank" "Financial Bank Ltd" "Financial"
generate_client_cert "enterprise_client_corp" "Enterprise Corporation" "Enterprise"

# Display CA certificate info
log_info "Certificate Authority Information:"
echo "  CA Certificate: $CA_DIR/ca-cert.pem"
echo "  CA Private Key: $CA_DIR/ca-key.pem"

# Show CA thumbprint for configuration
ca_thumbprint=$(openssl x509 -in "$CA_DIR/ca-cert.pem" -fingerprint -sha1 -noout | cut -d= -f2 | tr -d :)
echo "  CA Thumbprint: $ca_thumbprint"
echo ""

log_warning "IMPORTANT SECURITY NOTES:"
echo "1. Store CA private key securely and restrict access"
echo "2. Distribute CA certificate to all clients for server verification"
echo "3. Each client should have only their own certificate and private key"
echo "4. Use strong passwords for PKCS#12 files in production"
echo "5. Implement certificate revocation procedures"
echo ""

log_success "Certificate generation completed!"
echo "Configure appsettings.json with CA thumbprint: $ca_thumbprint"
