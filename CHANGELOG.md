## [0.6.1] - 2026-03-28
### Fixed
- **CDS-CLI**: Implemented full standalone CLI logic in `cmd/cds-cli/main.go` to resolve missing `cmd` subpackage issues and broken imports.
- **Installer**: Updated `install.sh` to correctly build the new CLI and handle systemd services more robustly.

### Added
- **CDS-CLI**: Added `--digest` flag to `trust add` command for manual digest specification.
- **CDS-CLI**: Added `trust list` command for better visibility into current trust records.

## [0.6.0] - 2025-02-26
### Added
- **Managed Key Store:** Centralized trust authority with automated key rotation and revocation policies.  
- **Signature Enforcement:** New `--require-signature` option ensures only signed OCI images (via Sigstore/Cosign) are allowed. Unsigned images are blocked (fail-closed).  
- **Audit Log Streaming:** Full audit logging of trust decisions with syslog/Journald integration; CLI command to export or stream audit logs to external systems.  
- **CLI Bundle Export:** `cds-cli backup` can export/import the entire configuration bundle (`.tar.gz`) including keys, policies, and database state.  
- **Systemd Hardening:** Updated `cds-daemon.service` with recommended security options (`ProtectSystem=strict`, `ProtectKernelLogs=true`, `ProtectProc=invisible`, `NoNewPrivileges=true`, etc.) to improve service isolation and security.

### Changed
- **Default Behavior:** The plugin now enforces signature verification by default. You can opt-out with `cds-cli config set require_signature false` (not recommended).  
- **Logging:** Authorization failures and key events are explicitly logged. The `cds-cli trust list` command now shows expiration and signature status.
