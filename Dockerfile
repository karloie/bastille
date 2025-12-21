FROM golang:1.24-alpine AS builder

ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_TIME

WORKDIR /app

COPY go.* ./
RUN go mod download

COPY app/ ./app/
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags "-s -w -X main.Version=${VERSION} -X main.GitCommit=${GIT_COMMIT} -X main.BuildTime=${BUILD_TIME}" \
    -o bastille ./app

FROM alpine:3.23

LABEL maintainer="Karl-Bjørnar Øie <karloie@gmail.com>"

RUN addgroup -g 1000 bastille && \
    adduser -D -u 1000 -G bastille bastille

COPY --from=builder /app/bastille /usr/local/bin/bastille

USER bastille

ENV LISTEN_PORT=22222 \
    LOGLEVEL=INFO \
    TESTING=no \
    STRICTMODES=no \
    AGENT_FORWARDING=no \
    GATEWAY_PORTS=no \
    PERMIT_TUNNEL=no \
    TCP_FORWARDING=yes \
    X11_FORWARDING=no \
    CASIGNATUREALGORITHMS="sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256" \
    CIPHERS="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr" \
    HOSTBASEDACCEPTEDALGORITHMS="sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256" \
    HOSTKEYALGORITHMS="sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256" \
    KEXALGORITHMS="sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512" \
    MACS="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com" \
    PUBKEYACCEPTEDALGORITHMS="sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256" \
    REQUIREDRSASIZE=3072 \
    SMTP_HOST=smtp.gmail.com \
    SMTP_MAIL="" \
    SMTP_PASS_FILE=/run/secrets/smtp_pass \
    SMTP_PORT=587 \
    SMTP_USER="" \
    AUTH_BASE=/home \
    AUTH_KEYS="{user},{user}/.ssh/authorized_keys" \
    CERT_BASE=/ca \
    CERT_KEYS="ca1.pub,ca2.pub" \
    HOST_BASE=/hostkeys \
    HOST_KEYS="ssh_host_ed25519_key,ssh_host_rsa_key" \
    DEBUG=false

EXPOSE 22222/tcp

ENTRYPOINT ["bastille"]
