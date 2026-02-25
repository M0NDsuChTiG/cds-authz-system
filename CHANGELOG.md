# Changelog

## [v0.6.0] - 2026-02-25

### Added
- **Managed Trust Authority**: Full lifecycle management for public keys (trust anchors).
- **Key Versioning & Fingerprinting**: Automatic versioning on key rotation and fingerprint-based deduplication.
- **Revocation Policy**: Implemented `revalidate_on_key_revoke` and `revalidate_on_key_rotation` policies.
- **Forensic Audit Layer**: 
    - BoltDB immutable event bucket.
    - Syslog backend for external SIEM integration.
    - `cds-cli trust audit --export <file>` for offline JSON analysis.
- **Disaster Recovery**: `cds-cli export-bundle <file>` command to create a complete encrypted/compressed snapshot of DB, Keys, and Audit.
- **API v1**: Fully versioned internal API over Unix Socket.

### Fixed
- **Cosign Hardening**: Forced `--offline` mode and isolated runtime (HOME=/tmp) to prevent writes to read-only filesystems under `ProtectSystem=strict`.
- **Race Conditions**: Synchronized daemon/plugin startup via systemd dependencies.

### Security
- **Fail-Closed Enforcement**: Guaranteed denial of container creation if the Trust Authority is unreachable or crypto verification fails.
- **Privilege Minimization**: Services run with `ProtectSystem=strict` and `StateDirectory` isolation.

## [v0.5.0] - 2026-02-25
- Initial BoltDB persistence and basic Cosign integration.
