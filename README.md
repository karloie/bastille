# Bastille

Bastille is a [cryptographically hardened](https://www.sshaudit.com/hardening_guides.html#ubuntu_24_04_lts), and reasonably secure, [SSH jump server](https://en.wikipedia.org/wiki/Jump_server) application of [OpenSSH-Server](https://www.openssh.com). 
The project is named after the famous fortress in Paris, known as the [Bastille Saint-Antoine](https://en.wikipedia.org/wiki/Bastille). It was stormed and sacked by a crowd on 14 July 1789, during the French Revolution.

![overview](doc/bastille.jpg)

This project was made because I needed a SSH jump server myself, and saw an opportunity to learn more about SSH in general. You probably don't want to use this server for other than "educational purposes", as it comes with no warranty what so ever. However if you do, feel free give me feedback.

## Features

- SSH jump server with [hardened defaults](https://www.sshaudit.com/hardening_guides.html#ubuntu_24_04_lts).
- Small and lightweight [Alpine Linux](https://www.alpinelinux.org).
- SSH public key access only with allowed hosts list.
- Easy deployment.

## Usage

The jump server should be deployed between two networks in a *rootless* container host like [Podman](https://podman.io/) or [Docker](https://docs.docker.com/engine/security/rootless/) and secured by a firewall. Securing the host machine itself is beyond the scope of this project.

### User access configuration

First create a directory with a file named for each user you want to allow. As no shell is allowed these users can be used as access groups and does not have to match a real user. Each user named file will act as the `authorized_keys` file for the SSH authentication. This directory should be mounted onto the path `/home` in the container. 

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

Here we allow the `lilo@localhost` key to access both `172.16.4.12:22` and `172.16.4.13:22`, while the `stitch@localhost` key can only access `172.16.4.13:22`. Please RTFM at [ssh.com](https://www.ssh.com/academy/ssh/authorized-keys-openssh#format-of-the-authorized-keys-file) for information about the `authorized_keys` file format.

The target hosts must also be configured with public SSH keys for the users. These public keys should not necessarily be the same as the keys used on the jump server.

### Host identity configuration

Secondly create a directory with the SSH server's host keys. This directory should be mounted onto the path `/hostkeys` in the container. This mount must be writable.

```
hostkeys/
├── ssh_host_ed25519_key
├── ssh_host_ed25519_key.pub
├── ssh_host_rsa_key
└── ssh_host_rsa_key.pub
```

If these keys doesn't exist the server will generate them on startup. So for the first run you can leave this directory empty.

### Runtime configuration

Finally create a `docker-compose.yml` file for deployment, and run `docker compose up`

```yaml
services:
  bastille:
    image: karloie/bastille:latest
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

Now you should be able to access your target hosts through the jump server.

```bash
ssh root@172.16.4.12 -J lilo@127.0.0.1:22222
ssh root@172.16.4.13 -J stitch@127.0.0.1:22222
```

### Email notification

Configure the SMTP parameters if you want en email sent for each successful SSH jump. The SMTP parameters are regular environment variables except for SMTP_PASS_FILE which should be the path to a file with the SMTP password, not the password it self.

The default is `/run/secrets/smtp_pass` and should be mounted onto the container. Look at the `test/docker-compose.yml` file as an example.

### Environment variables

The jump server can be configured further with these environment variables.

#### Server parameters.
| Name               | Default | Description             |
| -------------------| :-----: | ------------------------|
| LISTEN_PORT        | 22222    | Listening port          |
| LOGLEVEL           | INFO    | Loging level         (INFO\|VERBOSE\|DEBUG)   |
| TESTING | no     | Testing (yes\|no)   |

#### SSHD [sshd_config](https://www.ssh.com/academy/ssh/sshd_config) parameters.
| Name              | Default | Description                  |
| ----------------- | :-----: | -----------------------------|
| AGENT_FORWARDING  | yes     | Permit agent forwarding      |
| GATEWAY_PORTS     | no      | Permit gateway ports         |
| PERMIT_TUNNEL     | no      | Permit tunnelling            |
| TCP_FORWARDING    | yes     | Permit TCP forwarding        |
| X11_FORWARDING    | no      | Permit X11 forwarding        |

#### Crypto parameters with hardened defaults from [sshaudit.com](https://www.sshaudit.com/hardening_guides.html#ubuntu_24_04_lts).
| Name                        | Default |
| --------------------------- | :-----: |
| CASIGNATUREALGORITHMS       |    ..   |
| CIPHERS                     |    ..   |
| GSSAPIKEXALGORITHMS         |    ..   |
| HOSTBASEDACCEPTEDALGORITHMS |    ..   |
| HOSTKEYALGORITHMS           |    ..   |
| KEXALGORITHMS               |    ..   |
| MACS                        |    ..   |
| PUBKEYACCEPTEDALGORITHMS    |    ..   |
| REQUIREDRSASIZE             |   3072  |

#### SMTP parameters.
| Name      | Default | Description           |
| --------- | :-----: | --------------------- |
| SMTP_HOST |         | SMTP hostname or IP   |
| SMTP_MAIL |         | Senders email address |
| SMTP_PORT |  587    | SMTP port             |
| SMTP_USER |         | SMTP username         |
| SMTP_PASS_FILE | /run/secrets/smtp_pass | Path to password file |


## Development

You can use the `dev.sh` script if you for some strange reason want to develop this project.

Start the server in development mode:
```bash
./dev.sh up
```

Run the tests from another shell:
```bash
./dev.sh test all
```

Execute a shell in the container:
```bash
./dev.sh exec
```
