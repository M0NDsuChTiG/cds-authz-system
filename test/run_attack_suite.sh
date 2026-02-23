#!/bin/bash
# ==============================================================================
# CDS v6.2.1 Attack Simulation Suite
#
# This script verifies the security guarantees of the CDS authorization plugin
# and daemon, ensuring fail-closed behavior.
#
# It must be run with sudo/root privileges to interact with systemctl and docker.
# ==============================================================================

set -e

# --- Configuration ---
CDS_SOCKET="/run/cds.sock"
TRUST_DB="/var/lib/cds/trust.db"
PLUGIN_LOG_FILE="/tmp/cds-authz-plugin.log"
DAEMON_LOG_CMD="journalctl -u cds-daemon.service"

# --- Colors and Formatting ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

fail() {
    echo -e "${RED}[FAIL]${NC} $1" >&2
    # On failure, dump logs for diagnosis
    echo "--- Dumping Plugin Log ---"
    cat "$PLUGIN_LOG_FILE" || echo "Plugin log not available."
    echo "--- Dumping Daemon Log ---"
    $DAEMON_LOG_CMD -n 20 || echo "Daemon log not available."
    exit 1
}

info() {
    echo -e "${YELLOW}[*] $1${NC}"
}

cleanup() {
    info "Running cleanup..."
    # Ensure daemon is running after tests
    if ! systemctl is-active --quiet cds-daemon.service; then
        echo "Restarting cds-daemon.service..."
        systemctl start cds-daemon.service
    fi
    # Clean up test images to ensure a fresh state on next run
    docker rmi alpine:3.19 >/dev/null 2>&1 || true
    docker rmi busybox:latest >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "================================="
echo "=== CDS Attack Simulation Suite ==="
echo "================================="

# ------------------------------------------------------------------------------
# Pre-flight Checks
# ------------------------------------------------------------------------------
info "Performing pre-flight checks..."

if ! systemctl is-active --quiet cds-daemon.socket; then
    fail "cds-daemon.socket is not active. Please run install.sh first."
fi
if ! pgrep -f cds-authz-plugin > /dev/null; then
    fail "cds-authz-plugin is not running. Please run it in a separate terminal."
fi
if ! docker info >/dev/null 2>&1; then
    fail "Docker daemon is not responsive."
fi

# Clear the trust DB for a clean test run
info "Resetting trust database for a clean run..."
# Stop the daemon to safely delete the file, systemd will restart it on next socket access
systemctl stop cds-daemon.service
rm -f "$TRUST_DB"
# The socket will auto-start the service on the first curl request.

# ------------------------------------------------------------------------------
# Helper Functions
# ------------------------------------------------------------------------------
resolve_digest() {
    docker inspect --format='{{index .RepoDigests 0}}' "$1" 2>/dev/null | cut -d'@' -f2
}

update_trust() {
    local data="$1"
    info "Updating trust with data: $data"
    curl --silent --unix-socket "$CDS_SOCKET" 
      -X POST http://localhost/v1/update 
      -d "$data" >/dev/null
}


# ------------------------------------------------------------------------------
# Test Case 1: Baseline ALLOW (via Tag Resolution)
# ------------------------------------------------------------------------------
info "Test 1: VERIFIED image (via tag) must ALLOW"

docker pull alpine:3.19 >/dev/null
DIGEST=$(resolve_digest alpine:3.19)
[ -z "$DIGEST" ] && fail "Could not resolve digest for alpine:3.19"

update_trust "{"digest":"$DIGEST","status":"VERIFIED","reason":"test1"}"

if docker run --rm alpine:3.19 echo "Test 1 OK" >/dev/null 2>&1; then
    pass "Baseline tag resolution allowed"
else
    fail "Baseline tag resolution was denied"
fi

# ------------------------------------------------------------------------------
# Test Case 2: Unknown must DENY
# ------------------------------------------------------------------------------
info "Test 2: Unknown image must DENY"

docker pull busybox:latest >/dev/null
# This digest is NOT in our trust DB
UNKNOWN_DIGEST=$(resolve_digest busybox:latest)
[ -z "$UNKNOWN_DIGEST" ] && fail "Could not resolve digest for busybox:latest"

if docker run --rm busybox:latest echo "Test 2 FAIL" >/dev/null 2>&1; then
    fail "Unknown image was allowed"
else
    pass "Unknown image correctly denied"
fi

# ------------------------------------------------------------------------------
# Test Case 3: Stale TTL must DENY
# ------------------------------------------------------------------------------
info "Test 3: Stale TTL must DENY"

# A timestamp from 2 days ago
OLD_TS=$(($(date +%s) - 172800))

update_trust "{"digest":"$DIGEST","status":"VERIFIED","reason":"stale","updated_at":$OLD_TS}"

if docker run --rm alpine:3.19 echo "Test 3 FAIL" >/dev/null 2>&1; then
    fail "Stale image was allowed"
else
    pass "Stale image correctly denied"
fi

# ------------------------------------------------------------------------------
# Test Case 4: Daemon Down must DENY (Fail-Closed)
# ------------------------------------------------------------------------------
info "Test 4: Daemon down must DENY"

# Make sure the image is verified again first
update_trust "{"digest":"$DIGEST","status":"VERIFIED","reason":"test4"}"

info "Stopping cds-daemon.service..."
systemctl stop cds-daemon.service
systemctl stop cds-daemon.socket

if docker run --rm alpine:3.19 echo "Test 4 FAIL" >/dev/null 2>&1; then
    # Restart daemon before failing
    systemctl start cds-daemon.socket
    fail "Allowed container creation while daemon was down"
else
    pass "Correctly denied container creation when daemon is down"
fi

info "Restarting cds-daemon.socket..."
systemctl start cds-daemon.socket
# Give a moment for the socket to be ready
sleep 1

# ------------------------------------------------------------------------------
# Test Case 5: Denied by Digest must DENY
# ------------------------------------------------------------------------------
info "Test 5: Explicitly DENIED digest must be denied"

update_trust "{"digest":"$DIGEST","status":"FAILED","reason":"revoked"}"

if docker run --rm alpine:3.19 echo "Test 5 FAIL" >/dev/null 2>&1; then
    fail "Explicitly FAILED image was allowed"
else
    pass "Explicitly FAILED image correctly denied"
fi


echo ""
echo -e "${GREEN}=========================="
echo "=== ALL TESTS PASSED ==="
echo "=========================="
${NC}
