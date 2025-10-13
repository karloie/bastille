# Builder: build a static bastille binary
FROM golang:1.24-alpine AS builder

ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_TIME

# Networking/proxy config for restricted environments
ARG GOPROXY=https://proxy.golang.org,direct
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY
# Optional DNS override inside builder (space-separated for multiple)
ARG BUILDER_DNS

# Export to environment so Go and tools pick them up
ENV GOPROXY=$GOPROXY
ENV HTTP_PROXY=$HTTP_PROXY
ENV HTTPS_PROXY=$HTTPS_PROXY
ENV NO_PROXY=$NO_PROXY
ENV http_proxy=$HTTP_PROXY
ENV https_proxy=$HTTPS_PROXY
ENV no_proxy=$NO_PROXY

# If BUILDER_DNS is set, override /etc/resolv.conf for reliable name resolution during build
RUN if [ -n "$BUILDER_DNS" ]; then \
    { for d in $BUILDER_DNS; do echo "nameserver $d"; done; } > /etc/resolv.conf; \
    fi

WORKDIR /src
COPY go.mod go.sum ./
COPY app app
RUN mkdir -p /out && CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags "-s -w \
    -X main.Version=${VERSION} \
    -X main.GitCommit=${GIT_COMMIT} \
    -X main.BuildTime=${BUILD_TIME}" \
    -o /out/bastille ./app


FROM alpine:3.23
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /out/bastille /usr/local/bin/bastille
RUN addgroup -g 10001 bastille && adduser -D -u 10001 -G bastille bastille && mkdir -p /hostkeys /home /ca && chown -R bastille:bastille /hostkeys /home /ca
USER bastille

ENV LISTEN_PORT="22222"
ENV LOGLEVEL="INFO"
ENV TESTING="no"
ENV STRICTMODES="no"

# OpenSSH-style controls (kept for compatibility; ignored by Go server)
ENV AGENT_FORWARDING="no"
ENV GATEWAY_PORTS="no"
ENV PERMIT_TUNNEL="no"
ENV TCP_FORWARDING="yes"
ENV X11_FORWARDING="no"

# Crypto hardening knobs (kept; Go server has its own, safe to pass through)
ENV CASIGNATUREALGORITHMS="sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256"
ENV CIPHERS="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr"
ENV HOSTBASEDACCEPTEDALGORITHMS="sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256"
ENV HOSTKEYALGORITHMS="sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256"
ENV KEXALGORITHMS="sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512"
ENV MACS="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com"
ENV PUBKEYACCEPTEDALGORITHMS="sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256"
ENV REQUIREDRSASIZE="3072"
ENV MODULI_MIN=""

# SMTP knobs (SMTP disabled unless SMTP_MAIL is set)
ENV SMTP_HOST=""
ENV SMTP_MAIL=""
ENV SMTP_PORT="587"
ENV SMTP_USER=""
ENV SMTP_PASS_FILE="/run/secrets/smtp_pass"

# Go-server specific locations (mount volumes at runtime as needed)
ENV AUTH_KEYS="/home/{user}/.ssh/authorized_keys,/home/{user}"
ENV CERT_KEYS="/home/{user}/.ssh/ca.pub,/ca"
ENV HOST_KEYS="/hostkeys"

EXPOSE 22222/tcp
ENTRYPOINT ["/usr/local/bin/bastille"]
