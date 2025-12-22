# Bastille

Bastille is a simple SSH jump server written in Go, named after the famous French fortress in Paris, the Bastille Saint-Antoine—famously stormed and sacked during the French Revolution.

![overview](doc/bastille.jpg)

- Hardened cryptographic defaults (based on [sshaudit.com](https://www.sshaudit.com/hardening_guides.html)).
- Single binary Go executable.

## Usage

Deploy between networks on a rootless Docker or Podman host and secure it with a firewall.

### User access

Create a `home/` directory with one file per allowed user; each file is that user's `authorized_keys`. Mount it at `/home` (read-only). Use `permitopen` to restrict destinations per key.

```
home/
├── lilo
└── stitch
```

Example content for file `lilo`:

```
permitopen="172.16.4.12:22",permitopen="172.16.4.13:22" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE2AwAOD0CjqmxGvstxApYZLg+oji5zMDpyxb0FS7Uw/ lilo@localhost
```

Example content for file `stitch`:

```
permitopen="172.16.4.13:22" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMXLNYeiSxUg23XlqXj33yJG2iKF5dd9+DmeUM3JGte/ stitch@localhost
```

The `lilo` key allows 172.16.4.12:22 and 172.16.4.13:22; `stitch` only 172.16.4.13:22.
Target hosts must also be configured with SSH public keys for the users (these need not be the same keys used on the jump server).

### Host keys

Create a writable `hostkeys/` directory and mount it at `/hostkeys` in the container. Generate keys with `ssh-keygen` (e.g., `ssh-keygen -t ed25519 -f hostkeys/ssh_host_ed25519_key -N ""`). Ensure private keys are not group- or world-readable.

```
hostkeys/
├── ssh_host_ed25519_key
├── ssh_host_ed25519_key.pub
├── ssh_host_rsa_key
└── ssh_host_rsa_key.pub
```

If an ed25519 key is missing at startup, Bastille generates and persists it under `/hostkeys` (and writes the matching `.pub`). You may provide additional key types if desired. The server refuses to start if no host keys can be loaded or generated.

### Runtime

Create a `docker-compose.yml`, then run `docker compose up -d`.

```yaml
services:
  bastille:
    image: karloie/bastille:0.1.0
    restart: unless-stopped
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    ports:
      - 22222:22222/tcp
    read_only: true
    tmpfs:
      - /run
      - /tmp
    volumes:
      - ./home:/home:ro
      - ./hostkeys:/hostkeys:rw
```

You can now access target hosts through the jump server.

```bash
ssh root@172.16.4.12 -J lilo@127.0.0.1:22222
ssh root@172.16.4.13 -J stitch@127.0.0.1:22222
```

### Email notification

Configure `SMTP_*` to send an email on each successful SSH jump. Use `SMTP_PASS_FILE` to point to a mounted password file (default `/run/secrets/smtp_pass`). See Configuration for all `SMTP_*` variables.

### Configuration (env vars)

The jump server can be configured further with these environment variables.

#### Server parameters

- Set `LISTEN` (e.g., `0.0.0.0:22222`) or `LISTEN_PORT` (default `22222`).
- MAX_TUNNELS: 5 per user (default)
- `RATE`: 10 connection attempts per IP per minute (default).
- LOGLEVEL: INFO|VERBOSE|DEBUG (default INFO)
- TESTING: yes|no (default no)
- `STRICTMODES`: enforces safe permissions on `AUTH_KEYS` files (default `no`).
- MODULI_MIN: optional (e.g., 2048)

#### SSHD parameters ([sshd_config](https://www.ssh.com/academy/ssh/sshd_config))

- AGENT_FORWARDING: no
- GATEWAY_PORTS: no
- PERMIT_TUNNEL: no
- TCP_FORWARDING: yes
- X11_FORWARDING: no

#### Crypto parameters
Hardened lists are applied by default; override via env vars (full lists, +additions, -removals). Defaults favor modern algorithms; legacy algorithms are disabled. See the [sshaudit hardening guides](https://www.sshaudit.com/hardening_guides.html).
- CASIGNATUREALGORITHMS, CIPHERS, HOSTBASEDACCEPTEDALGORITHMS, HOSTKEYALGORITHMS, KEXALGORITHMS, MACS, PUBKEYACCEPTEDALGORITHMS
- REQUIREDRSASIZE: default 3072

#### SMTP parameters

- SMTP_HOST: host
- SMTP_MAIL: sender address
- SMTP_PORT: 587 (default)
- SMTP_USER: username
- SMTP_PASS_FILE: path to password file (default /run/secrets/smtp_pass)

## Development

### Prerequisites

- Go 1.24+
- Make

### Building

```bash
make build
```

This produces a `bastille` binary in the project root.

### Testing

The project uses pure Go tests with no Docker dependencies:

```bash
# Generate test data and run all tests
make test

# Or step by step
make test-setup  # Generate SSH keys and test data
go test -v ./...
```

All test data is generated in `./test/` and can be cleaned with:

```bash
make clean
```

### Project Structure

```
bastille/
├── app/              # Main application code
│   ├── auth.go       # SSH authentication
│   ├── config.go     # Configuration management
│   ├── crypto.go     # Key loading and crypto utils
│   ├── main.go       # Server and proxy logic
│   ├── notify.go     # Email notifications
│   └── test-setup/   # Test data generation
├── test/             # Generated test data (gitignored)
├── doc/              # Documentation
├── Dockerfile        # Production container image
└── Makefile          # Build automation
```

### Running Tests

Tests use fixed ports (22222, 22223, 22224) and run serially (`-p 1`) to avoid conflicts. Test data includes:

- SSH keys for test users (lilo, stitch, certuser)
- CA keys and certificates
- Host keys for mock SSH servers
- Authorized keys with `permitopen` restrictions

License: see `doc/LICENSE`.
