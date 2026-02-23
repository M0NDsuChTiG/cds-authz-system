# CDS v6.2 - Docker Zero-Trust Authorization System

This project implements a production-grade, fail-closed authorization plugin for Docker to enforce Zero-Trust security policies. It ensures that only explicitly trusted container images can be run on a host.

## Architecture

The system follows a decoupled, high-performance architecture:

*   **`cds-daemon`**: A central Go service that acts as the "Trust Authority". It maintains a persistent database of trusted image digests and their TTLs (Time-To-Live). It provides decisions via a secure UNIX socket API.
*   **`cds-authz-plugin`**: A native Docker authorization plugin written in Go. It integrates with the Docker daemon via a UNIX socket (`/run/docker/plugins/cds-authz.sock`), intercepting container creation requests. It resolves the image tag to its cryptographic digest and queries `cds-daemon` to get an `ALLOW` or `DENY` decision.
*   **Offline Verification**: All heavy operations like signature verification or vulnerability scanning are performed offline by other processes (e.g., `cds-verify.sh`), which then update the `cds-daemon`'s trust database. The authorization path remains extremely fast (sub-millisecond).

## Components

The repository is structured as follows:

*   `/daemon`: Source code for the `cds-daemon`.
*   `/plugin`: Source code for the `cds-authz-plugin`.
*   `/systemd`: Unit files (`.service`, `.socket`) for managing the `cds-daemon` with systemd.
*   `/test`: Contains the `run_attack_suite.sh` script to validate the system's security guarantees.
*   `install.sh`: The main installation script.

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

## License

This project is licensed under the MIT License.
