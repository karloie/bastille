# Bastille

Bastille is a simple SSH jump server written in Go, named after the famous French fortress in Paris, the Bastille Saint-Antoine—famously stormed and sacked during the French Revolution.

![overview](doc/bastille.jpg)

- Hardened cryptographic defaults (based on [sshaudit.com](https://www.sshaudit.com/hardening_guides.html)).
- Single binary Go executable.

## Usage

Deploy between networks on a rootless Docker or Podman host and secure it with a firewall.

### User access

Create `home/` directory with one file per user containing their `authorized_keys`. Mount at `/home` (read-only). Use `permitopen` to restrict destinations.

```
home/
├── lilo
└── stitch
```

Example `lilo`:
```
permitopen="172.16.4.12:22",permitopen="172.16.4.13:22" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE2AwAOD0CjqmxGvstxApYZLg+oji5zMDpyxb0FS7Uw/ lilo@localhost
```

Example `stitch`:
```
permitopen="172.16.4.13:22" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMXLNYeiSxUg23XlqXj33yJG2iKF5dd9+DmeUM3JGte/ stitch@localhost
```

### Host keys

Create writable `hostkeys/` directory and mount at `/hostkeys`. Generate with `ssh-keygen -t ed25519 -f hostkeys/ssh_host_ed25519_key -N ""`. If missing, Bastille auto-generates ed25519 key on startup.

### Runtime

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

Run with `docker compose up -d`.

Connect through jump server:
```bash
ssh root@172.16.4.12 -J lilo@127.0.0.1:22222
```

## Configuration

Environment variables:

**Server**
- `LISTEN` or `LISTEN_PORT` (default 22222)
- `MAX_TUNNELS` (default 5 per user)
- `RATE` (default 10 per IP per minute)
- `LOGLEVEL` (INFO, VERBOSE, DEBUG)
- `STRICTMODES` (default no) - enforces safe permissions on AUTH_KEYS files

**Crypto** - Hardened defaults applied. Override with: `CIPHERS`, `KEXALGORITHMS`, `MACS`

**SMTP** (optional email notifications)
- `SMTP_HOST`, `SMTP_MAIL`, `SMTP_USER`
- `SMTP_PORT` (default 587)
- `SMTP_PASS_FILE` (default /run/secrets/smtp_pass)

**Key paths** (comma-separated, support `{user}` placeholder and globs)
- `AUTH_KEYS` - authorized_keys files (e.g., `/home/{user}/.ssh/authorized_keys`)
- `CERT_KEYS` - CA public keys (e.g., `/ca` for static, `/home/{user}/.ssh/ca.pub` for per-user)
- `HOST_KEYS` - server private keys (e.g., `/hostkeys`)

StrictModes validates paths are within allowed bases with safe permissions. For CERT_KEYS with `{user}`, strict checks always apply.

## Development

**Requirements:** Go 1.24+, Make

**Build:** `make build`

**Test:** `make test` (generates test data in `./test/`)

**Clean:** `make clean`

**Structure:**
```
app/              Main code (auth, config, crypto, server, notify)
test/             Generated test data (gitignored)
doc/              Documentation and license
Dockerfile        Production image
Makefile          Build automation
```

License: see `doc/LICENSE`
