#!/bin/bash
set -e

# ==============================================================================
# CDS v0.6.1 Installer
#
# This script builds the daemon, plugin, and the updated CLI.
# ==============================================================================

echo "[+] Initializing Go module and dependencies..."
go mod tidy

echo "[+] Building binaries..."
go build -o ./daemon/cds-daemon ./daemon
go build -o ./plugin/cds-authz-plugin ./plugin
# Note: CLI is now a standalone main.go in cmd/cds-cli/
go build -o ./cmd/cds-cli/cds-cli ./cmd/cds-cli/main.go
echo "Binaries built."


echo "[+] Installing binaries with sudo..."
sudo install ./daemon/cds-daemon /usr/local/bin/
sudo install ./plugin/cds-authz-plugin /usr/local/bin/
sudo install ./cmd/cds-cli/cds-cli /usr/local/bin/
echo "Binaries installed in /usr/local/bin/."


echo "[+] Installing systemd units with sudo..."
sudo cp ./systemd/*.service /etc/systemd/system/
sudo systemctl daemon-reload
echo "Systemd units installed."


echo "[+] Enabling and starting CDS services..."
sudo systemctl enable --now cds-daemon.service
sudo systemctl enable --now cds-authz-plugin.service
echo "CDS services enabled."

echo "--------------------------------------------------------"
echo "CDS Bundle Installation Complete (v0.6.1)."
echo "--------------------------------------------------------"
