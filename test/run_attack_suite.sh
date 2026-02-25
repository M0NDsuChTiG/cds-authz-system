#!/bin/bash
set -e

# --- Configuration ---
CDS_SOCKET="/run/cds/cds.sock"
TRUST_DB="/var/lib/cds/trust.db"

# --- Colors ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }
info() { echo -e "${YELLOW}[*] $1${NC}"; }

cleanup() {
    info "Cleaning up..."
    sudo systemctl start cds-daemon >/dev/null 2>&1 || true
    docker rmi alpine:3.19 busybox:latest >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "=== CDS v0.5.0 Attack Simulation Suite ==="

# Pre-flight
info "Checking services..."
sudo systemctl is-active --quiet cds-daemon || fail "cds-daemon not running"
pgrep -f cds-authz-plugin >/dev/null || fail "cds-authz-plugin not running"

# Helper
update_trust() {
    sudo curl --silent --unix-socket "$CDS_SOCKET" -X POST -H "Content-Type: application/json" \
        -d "$1" http://localhost/v1/trust/add > /dev/null
}

# Test 1: Baseline ALLOW
info "Test 1: Trusted image must ALLOW"
docker pull alpine:3.19 >/dev/null
DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' alpine:3.19 | cut -d'@' -f2)
update_trust "{\"target\":\"alpine:3.19\",\"digest\":\"$DIGEST\"}"

if docker run --rm alpine:3.19 echo "OK" >/dev/null 2>&1; then
    pass "Trusted image allowed"
else
    fail "Trusted image denied"
fi

# Test 2: Unknown DENY
info "Test 2: Unknown image must DENY"
docker pull busybox:latest >/dev/null
if docker run --rm busybox:latest echo "FAIL" >/dev/null 2>&1; then
    fail "Unknown image allowed"
else
    pass "Unknown image denied"
fi

# Test 3: Fail-Closed
info "Test 3: Daemon down must DENY"
sudo systemctl stop cds-daemon
if docker run --rm alpine:3.19 echo "FAIL" >/dev/null 2>&1; then
    fail "Allowed run while daemon down"
else
    pass "Fail-closed confirmed"
fi

echo -e "${GREEN}=== ALL TESTS PASSED ===${NC}"
