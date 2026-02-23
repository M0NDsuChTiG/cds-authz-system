#!/bin/bash
set -e

# ==============================================================================
# CDS v6.2.1 Installer
#
# This script builds the daemon and plugin as the current user, then uses
# sudo for installation steps.
# ==============================================================================

echo "[+] Initializing Go modules..."
(cd daemon && (/usr/bin/go mod init cds-daemon >/dev/null 2>&1 || true) && /usr/bin/go mod tidy)
(cd plugin && (/usr/bin/go mod init cds-authz-plugin >/dev/null 2>&1 || true) && /usr/bin/go mod tidy)


echo "[+] Building daemon..."
(cd daemon && /usr/bin/go build -o cds-daemon)
echo "Daemon built."

echo "[+] Building plugin..."
(cd plugin && /usr/bin/go build -o cds-authz-plugin)
echo "Plugin built."


echo "[+] Installing binaries with sudo..."
sudo mv daemon/cds-daemon /usr/local/bin/
sudo mv plugin/cds-authz-plugin /usr/local/bin/
echo "Binaries installed in /usr/local/bin/."


echo "[+] Installing systemd units with sudo..."
sudo cp ./systemd/* /etc/systemd/system/
sudo systemctl daemon-reload
echo "Systemd units installed."


echo "[+] Enabling and starting CDS daemon via socket activation..."
sudo systemctl enable --now cds-daemon.socket
sudo systemctl enable cds-daemon.service
echo "CDS services enabled."

# Check if the socket is active
if sudo systemctl is-active --quiet cds-daemon.socket; then
  echo "CDS socket is active."
else
  echo "Warning: CDS socket failed to start. Check 'sudo systemctl status cds-daemon.socket'." >&2
fi


echo "--------------------------------------------------------"
echo "CDS Bundle Installation Complete."
echo "--------------------------------------------------------"
echo ""
echo "Next steps to fully enable and test the Docker Authorization Plugin:"
echo ""
echo "1. Ensure CDS Daemon is active (systemd handles this, just check status):"
echo "   sudo systemctl status cds-daemon.socket"
echo ""
echo "2. Run the CDS Authorization Plugin (it will create /run/docker/plugins/cds-authz.sock):"
echo "   In a NEW terminal, run:"
echo "   sudo /usr/local/bin/cds-authz-plugin"
echo ""
echo "   Keep this terminal open to see plugin logs. Ensure no errors."
echo ""
echo "3. Verify the plugin handshake before restarting Docker:"
echo "   curl --unix-socket /run/docker/plugins/cds-authz.sock http://unix/AuthZPlugin.Activate"
echo "   (Expected output: {\"Implements\":[\"authz\"]})"
echo ""
echo "4. Configure Docker to use the authorization plugin:"
echo "   Create or edit /etc/docker/daemon.json with the following content:"
echo ""
echo '   {'
echo '     "authorization-plugins": ["cds-authz"]'
echo '   }'
echo ""
echo "5. Restart the Docker daemon:"
echo "   sudo systemctl restart docker"
echo ""
echo "6. Run the attack simulation suite in another terminal:"
echo "   cd cds-bundle"
echo "   sudo ./test/run_attack_suite.sh"
echo ""
