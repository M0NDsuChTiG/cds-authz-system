# CDS v6.6 - Docker Zero-Trust Authorization System

[![CI](https://github.com/M0NDsuChTiG/cds-authz-system/actions/workflows/ci.yml/badge.svg)](https://github.com/M0NDsuChTiG/cds-authz-system/actions/workflows/ci.yml)

This project implements a production-grade, fail-closed authorization plugin for Docker to enforce Zero-Trust security policies. It ensures that only explicitly trusted container images can be run on a host.

## Architecture

The system follows a decoupled, high-performance architecture:

```text
Docker CLI -> Docker Daemon -> AuthZ Plugin -> CDS Daemon -> BoltDB (Trust/Keys/Audit)
                                     |             |
                                     +---[DENY]---+ (If Offline/Failure)
```

*   **`cds-daemon`**: The central "Trust Authority". Manages versioned keys, enforces policies, and maintains a forensic audit trail in BoltDB.
*   **`cds-authz-plugin`**: A thin enforcer proxy. Intercepts `containers/create` and `images/create`, resolves tags to digests, and queries the daemon.
*   **`cds-cli`**: Management tool for trust anchors and image policies.

## Threat Model

CDS is designed to protect against:
- **Unauthorized Image Execution**: Blocks any container not matching a trusted digest.
- **Tag Mutation Attacks**: Enforces digest-level pinning regardless of mutable tags (e.g., `latest`).
- **Compromised Registry**: Even if a registry is breached, only signed/trusted digests are allowed.
- **Key Compromise**: Supports immediate revocation of trust anchors, invalidating all associated images (Strict Policy).

## Operational Security

### Access Control
Access to the CDS Unix socket (`/run/cds/cds.sock`) is restricted to the `root` user and the `cds` group. 
To allow a non-root user to manage trust:
```bash
sudo usermod -aG cds <username>
```

### Key Rotation Policy
By default, CDS enforces:
- `revalidate_on_key_revoke: true`: Revoking a key immediately blocks all containers signed by it.
- `revalidate_on_key_rotation: false`: Older images remain valid after a key is rotated (new version imported), until the old version is explicitly revoked.

## Installation and Testing

> **Prerequisites**: A Linux system with Go 1.19+, Docker, and `systemd`.

The entire process of building, installing, configuring, and testing the system is automated and guided by the `install.sh` script.

### 1. Installation

First, make the installer executable and run it. The script will build the binaries as the current user and then ask for `sudo` permissions only for the installation steps.

```sh
chmod +x install.sh
./install.sh
```

This script will:
1.  Build `cds-daemon` and `cds-authz-plugin`.
2.  Install the binaries to `/usr/local/bin/`.
3.  Install and enable the `systemd` units for `cds-daemon`.

### 2. Usage and Verification

After installation, the `install.sh` script provides detailed, step-by-step instructions to activate and test the plugin. The recommended procedure is as follows:

1.  **Run the Plugin**: The plugin must be running *before* Docker is configured to use it. It must be run as root to create its socket.
    ```sh
    # In a new terminal
    sudo /usr/local/bin/cds-authz-plugin
    ```

2.  **Verify Plugin Handshake**: Check that the plugin is active and responding correctly.
    ```sh
    curl --unix-socket /run/docker/plugins/cds-authz.sock http://unix/AuthZPlugin.Activate
    # Expected output: {"Implements":["authz"]}
    ```

3.  **Configure Docker**: Create or edit `/etc/docker/daemon.json` to contain:
    ```json
    {
      "authorization-plugins": ["cds-authz"]
    }
    ```

4.  **Restart Docker**:
    ```sh
    sudo systemctl restart docker
    ```

5.  **Run the Attack Simulation Suite**: With the system active, run the test suite to validate its security guarantees.
    ```sh
    # In another new terminal
    cd /path/to/cds-bundle/
    sudo ./test/run_attack_suite.sh
    ```
    This script will automatically test scenarios like allowing verified images, denying unknown images, denying stale images, and denying operations when the `cds-daemon` is down (fail-closed behavior).

## Threat Model

CDS-AuthZ-System is designed to enforce Zero-Trust in Docker runtime, protecting against:

- **Supply chain attacks on images**: Verifies digest against trusted store; rejects mutated or untrusted tags/digests (e.g., compromised registry).
- **Unauthorized container launches**: Blocks run/create for non-trusted images, even if pulled.
- **Time-based drift**: TTL on trusts auto-revokes expired entries (e.g., after CVE discovery).
- **Daemon failure/attack**: Fail-closed — if daemon is down or unresponsive, all launches denied.
- **Offline risks**: Heavy verification (signatures, scans) done offline, runtime check <1ms.

Out of scope:  
- Post-launch monitoring (use Falco/Sysdig).  
- Host/kernel security (combine with seccomp, AppArmor).  
- Registry authentication (use with Harbor/Notary).

Assumptions: Docker daemon configured with plugin; unix socket secure (chown/chmod).

## Comparison with Alternatives

- **Docker Scout**: Cloud-heavy, fail-open по умолчанию, фокус на scanning, но не на runtime authz.
- **Notary v2 / Ratify**: Отличны для OCI artifact verification, но K8s-oriented (CRD/admission), сложнее для plain Docker, нет built-in TTL.
- **OPA Gatekeeper / Kyverno**: Policy-based (Rego/JSON), мощные, но overhead (API calls на каждый request), fail-open если policy engine down.
- **OPA opa-docker-authz**: Похожий plugin, но policy-driven (не trust DB), нет fail-closed.
- Преимущества CDS: Простота (Go-native, systemd-ready), fail-closed, offline heavy ops, TTL для proactive revocation.

## Roadmap

- **v0.1 (MVP, current)**: Basic trust DB (in-memory/SQLite), unix socket API, fail-closed plugin.
- **v0.2**: CLI tool (cds-cli) для trust add/list/revoke/status.
- **v0.3**: Integration with Sigstore/Cosign for signature verification + Trivy/Grype for offline CVE scanning.
- **v0.5**: Prometheus metrics export, audit logging (journald/Syslog).
- **v1.0**: HA mode (multiple daemons), config reload without restart, full docs/examples.
- Future: Kubernetes admission webhook adapter, OCI registry proxy mode.

Contributions welcome — see issues for priorities!

[<image-card alt="Latest Release" src="https://img.shields.io/github/v/release/M0NDsuChTiG/cds-authz-system?color=green" ></image-card>](https://github.com/M0NDsuChTiG/cds-authz-system/releases/latest)

Последняя версия: **[v0.5.0 – Cryptographic Trust Foundation](https://github.com/M0NDsuChTiG/cds-authz-system/releases/tag/v0.5.0)**

## License

This project is licensed under the MIT License.
