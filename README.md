# Bastille

<img src="doc/vibe-coded.badge.small.png" alt="Vibe Coded!" width="200" align="right">

Bastille is a simple SSH jump server written in Go with hardened cryptographic defaults (based on [sshaudit.com](https://www.sshaudit.com/hardening_guides.html)).

![Bastille Saint-Antoine](doc/bastille.jpg)

Named after the famous French fortress in Paris, the Bastille Saint-Antoine—famously stormed and sacked during the French Revolution.

## Usage

Deploy between networks on a rootless Docker or Podman host and secure it with a firewall.

### User access

Create `home/` directory with user subdirectories containing `authorized_keys`. Mount at `/home` (read-only). Use `permitopen` to restrict destinations.

```
home/
├── lilo/
│   └── .ssh/
│       └── authorized_keys
├── nani/
│   └── .ssh/
│       ├── authorized_keys
│       └── ca.pub
└── stitch/
    └── .ssh/
        └── authorized_keys
```

Example `home/lilo/.ssh/authorized_keys`:
```
permitopen="172.16.4.12:22",permitopen="172.16.4.13:22" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE2AwAOD0CjqmxGvstxApYZLg+oji5zMDpyxb0FS7Uw/ lilo@localhost
```

Example `home/nani/.ssh/authorized_keys`:
```
permitopen="172.16.4.12:22" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJxT8KqPvqQHqhHjHqPqLqLz8YvZ1rDkjH8vN7aQvKL nani@localhost
```

Example `home/stitch/.ssh/authorized_keys`:
```
permitopen="172.16.4.13:22" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMXLNYeiSxUg23XlqXj33yJG2iKF5dd9+DmeUM3JGte/ stitch@localhost
```

### Certificate authority (optional)

For per-user CA keys, add `ca.pub` files containing trusted CA public keys. Users can then authenticate with certificates signed by their CA.

Example `home/nani/.ssh/ca.pub`:
```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBq8FNKqPvqQHqhHjHqPqLqLz8YvZ1rDkjH8vN7aQvKL nani-ca
```

Users authenticate with signed certificates:
```bash
ssh-keygen -s /path/to/ca_key -I nani -n nani -V +52w ~/.ssh/id_ed25519.pub
ssh root@172.16.4.12 -J nani@127.0.0.1:22222
```

### Host keys

Create writable `hostkeys/` directory and mount at `/hostkeys`. Bastille auto-generates an ed25519 key on startup if missing, or you can pre-generate with `ssh-keygen -t ed25519 -f hostkeys/ssh_host_ed25519_key -N ""`.

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
      - 9090:9090/tcp
    read_only: true
    tmpfs:
      - /run
      - /tmp
    volumes:
      - ./home:/home:ro
      - ./hostkeys:/hostkeys:rw
    environment:
      ListenAddress: ""
      Port: 22222
      MaxSessions: 5
      PerSourceMaxStartups: 10
      LogLevel: INFO
      StrictModes: no
      MetricsAddress: "0.0.0.0:9090"
      AuthorizedKeysFile: "/home/{user}/.ssh/authorized_keys"
      TrustedUserCAKeys: "/home/{user}/.ssh/ca.pub,/ca"
      HostKey: "/hostkeys"
      Ciphers: "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr"
      KexAlgorithms: "sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512"
      MACs: "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com"
      RequiredRSASize: 3072
```

Run with `docker compose up -d`.

Connect through jump server:
```bash
ssh root@172.16.4.12 -J lilo@127.0.0.1:22222
```

## Configuration

Environment variables:

**Server** (OpenSSH-style where possible)
- `ListenAddress` (default empty; binds all interfaces)
- `Port` (default 22222)
- `MaxSessions` (default 5; per-user tunnel limit)
- `PerSourceMaxStartups` (default 10; per-source rate limit)
- `LogLevel` (INFO, VERBOSE, DEBUG, WARN, ERROR)
- `StrictModes` (default no) - enforces safe permissions on key file paths
- `MetricsAddress` (default empty; disabled) - Prometheus metrics endpoint (e.g., `0.0.0.0:9090`)

**Key paths** (OpenSSH-style directive names; comma-separated; `{user}` placeholder and globs)
- `AuthorizedKeysFile` - authorized_keys files (e.g., `/home/{user}/.ssh/authorized_keys`)
- `TrustedUserCAKeys` - CA public keys (e.g., `/ca` for static, `/home/{user}/.ssh/ca.pub` for per-user)
- `HostKey` - server private keys (e.g., `/hostkeys`)

**Crypto** (OpenSSH directive names)
- `Ciphers`
- `KexAlgorithms`
- `MACs`
- `RequiredRSASize` (default 3072)

**SMTP** (Bastille-specific)
- `SMTP_HOST`, `SMTP_MAIL`, `SMTP_USER`
- `SMTP_PORT` (default 587)
- `SMTP_PASS_FILE` (default /run/secrets/smtp_pass)

**Observability**
- `MetricsAddress` - Prometheus metrics endpoint (e.g., `127.0.0.1:9090`)
  - Exposes `/metrics` endpoint with connection stats, tunnel counts, auth failures, rate limits, bytes transferred
  - Exposes `/health` endpoint returning `ok`
  - Disabled by default (empty string)

**Structure:**
```
app/              Main code
doc/              Documentation and license
Dockerfile        Production image
Makefile          Build automation
```

License: see `doc/LICENSE`
