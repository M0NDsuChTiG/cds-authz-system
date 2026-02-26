# CDS v0.6.0 - Docker Zero-Trust Authorization System

[![CI](https://github.com/M0NDsuChTiG/cds-authz-system/actions/workflows/ci.yml/badge.svg)](https://github.com/M0NDsuChTiG/cds-authz-system/actions/workflows/ci.yml)

## Architecture Overview

CDS v0.6.0 introduces a **Managed Trust Authority** model. A central CDS daemon maintains a secure key store and trust database, issuing and rotating signing keys according to policy. The daemon enforces image authorization by verifying each image’s signature against the managed key store. If an image is unsigned or has an invalid signature (and signature enforcement is enabled), the request is denied (fail-closed). A lightweight Docker authorization plugin calls the daemon to make real-time allow/deny decisions on container creation.

Key components in v0.6.0:
- **Managed Key Store:** Automated key rotation and revocation with audit-tracking. Administrators can add or retire public keys, and set rotation schedules.  
- **Signature Verification:** Images must be signed using Sigstore/Cosign with one of the trusted keys. The `cds-cli` tool can be used to sign images and trust them in the system.  
- **Audit Streaming:** All trust decisions and key management events are logged and streamed to syslog/Journald. The log can be forwarded to centralized SIEM or monitoring systems.

## Installation

Install CDS v0.6.0 on a Linux host (tested on major distros and container-optimized OS). Use the provided package or build from source:
1. **Download Assets:** Download `cds-daemon`, `cds-cli`, and `cds-v0.6.0.tar.gz` from the release page.
2. **Extract Config Bundle:** If upgrading or restoring, extract the bundle:  
   ```bash
   tar xzf cds-v0.6.0.tar.gz -C /etc/cds
   ```  
3. **Install Daemon & CLI:** Copy `cds-daemon` and `cds-cli` to `/usr/local/bin/` and set executable permissions.  
4. **Enable Services:** Use the provided systemd unit (or Docker plugin) files. For example:  
   ```bash
   sudo cp cds-daemon.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable cds-daemon
   sudo systemctl start cds-daemon
   ```  
   The `cds-daemon.service` is pre-hardened with security directives.
5. **Configure Trust:** Use `cds-cli` to initialize the trust store. For example:  
   ```bash
   cds-cli key import --path new-key.pub --id prod
   ```

## CLI Usage Examples

The `cds-cli` tool lets you manage trust and policy. Example workflows:

```bash
# 1. Sign an image and add to trust (TTL: 24h)
cosign sign --key mykey.pem nginx:latest
cds-cli trust add nginx:latest --ttl 24h --require-signature --key-id prod

# 2. Enforce that only signed images run (daemon must be running)
cds-cli config set require_signature true

# 3. List current trust records
cds-cli trust list

# 4. Export current configuration bundle (backup of keys and DB)
cds-cli backup --output cds-backup.tar.gz
```

## Security Posture

CDS is designed for high-security and edge deployment environments. Key features:
- **Fail-Closed by Default:** If the CDS daemon or trust authority is unreachable, or if any verification step fails, container launches are denied.
- **Systemd Hardening:** The systemd service units use strict sandboxing: `ProtectSystem=strict`, `ProtectProc=invisible`, `NoNewPrivileges=true`, etc.
- **Audit Logging:** Every allow/deny decision is logged to syslog and the local audit log.
