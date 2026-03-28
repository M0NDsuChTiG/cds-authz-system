# CDS v0.6.1 - Docker Zero-Trust Authorization System

[![CI](https://github.com/M0NDsuChTiG/cds-authz-system/actions/workflows/ci.yml/badge.svg)](https://github.com/M0NDsuChTiG/cds-authz-system/actions/workflows/ci.yml)

## Architecture Overview

CDS introduces a **Managed Trust Authority** model for Docker environments. A central CDS daemon maintains a secure key store and trust database. The daemon enforces image authorization by verifying each image’s signature or explicit trust record. A lightweight Docker authorization plugin calls the daemon to make real-time allow/deny decisions on container creation (fail-closed).

Key components:
- **Managed Key Store:** Centralized storage for public keys with versioning and audit-tracking.
- **Signature Verification:** Integration with Sigstore/Cosign for cryptographic image validation.
- **Docker AuthZ Plugin:** Real-time enforcement of trust policies during `docker run` and `docker create`.
- **Audit Logging:** Every decision is logged to syslog/Journald and a local BoltDB audit store.

## Installation

Install CDS v0.6.1 on a Linux host (tested on Ubuntu 22.04/24.04 and Debian 12). 

### Prerequisites
- **Docker** (20.10+)
- **Go** (1.19+) - for building from source
- **Cosign** (Optional, for signing)

### Step-by-Step Installation
1. **Clone the repository:**
   ```bash
   git clone https://github.com/M0NDsuChTiG/cds-authz-system.git
   cd cds-authz-system
   ```

2. **Run the Installer:**
   The provided script builds the daemon, plugin, and CLI, then installs them to `/usr/local/bin/` and sets up systemd services.
   ```bash
   chmod +x install.sh
   ./install.sh
   ```

3. **Configure Docker:**
   Enable the authorization plugin by adding it to `/etc/docker/daemon.json`:
   ```json
   {
     "authorization-plugins": ["cds-authz"]
   }
   ```
   Then restart Docker:
   ```bash
   sudo systemctl restart docker
   ```

## CLI Usage Examples

The `cds-cli` tool manages keys and trust records.

```bash
# 1. Import a public key for verification
cds-cli key import --id prod --path ./my-key.pub

# 2. Add trust for an image (using its digest for precision)
# Get digest: docker inspect --format='{{index .RepoDigests 0}}' alpine:latest
cds-cli trust add alpine:latest --key-id prod --digest sha256:abcd... --ttl 24h

# 3. List current trust records
cds-cli trust list

# 4. List imported keys
cds-cli key list
```

## Security Posture

- **Fail-Closed:** If the CDS daemon is unreachable or verification fails, container launches are denied.
- **Systemd Hardening:** Services use `ProtectSystem=strict`, `NoNewPrivileges=true`, and private temporary directories.
- **Auditability:** Full trace of allow/deny decisions with reasons in the audit log.
