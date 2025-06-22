#!/bin/bash

# Health Check Script
# Usage: ./health-check.sh [environment]

ENVIRONMENT=${1:-production}

check_service() {
local service_name=$1
local url=$2
local expected_status=${3:-200}

    echo -n "Checking $service_name... "
    
    if curl -f -s -o /dev/null -w "%{http_code}" "$url" | grep -q "$expected_status"; then
        echo "✅ OK"
        return 0
    else
        echo "❌ FAILED"
        return 1
    fi
}

main() {
echo "=== Payment System Health Check ==="
echo "Environment: $ENVIRONMENT"
echo "Timestamp: $(date)"
echo

    local failed=0

    # Check Payment API
    check_service "Payment API Health" "https://localhost:7000/api/payment/health" || failed=1
    check_service "Payment API Public Key" "https://localhost:7000/api/payment/public-key" || failed=1

    # Check Client API
    check_service "Client API Health" "https://localhost:7001/api/customer/health" || failed=1

    # Check Admin API
    check_service "Admin Key Info" "https://localhost:7000/api/admin/keymanagement/info" || failed=1

    echo
    if [[ $failed -eq 0 ]]; then
        echo "✅ All health checks passed"
        exit 0
    else
        echo "❌ Some health checks failed"
        exit 1
    fi
}

main "$@"