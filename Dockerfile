FROM alpine:3.22.2

LABEL maintainer="Karl-Bjørnar Øie <karloie@gmail.com>"

RUN set -eux && \
    apk upgrade --no-cache && \
    apk add --no-cache \
        openssh-server-pam \
        openssh-client-common \
        msmtp

WORKDIR /usr/sbin/
COPY src/* .
RUN chmod -R 0500 *.sh && init.sh && rm init*.sh

ENV LISTEN_PORT="22222"
ENV LOGLEVEL="INFO"
ENV TESTING="no"
ENV STRICTMODES="no"

# https://linux.die.net/man/5/sshd_config
ENV AGENT_FORWARDING="no"
ENV GATEWAY_PORTS="no"
ENV PERMIT_TUNNEL="no"
ENV TCP_FORWARDING="yes"
ENV X11_FORWARDING="no"

# https://www.sshaudit.com/hardening_guides.html#ubuntu_24_04_lts
ENV CASIGNATUREALGORITHMS="sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256"
ENV CIPHERS="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-gcm@openssh.com,aes128-ctr"
ENV HOSTBASEDACCEPTEDALGORITHMS="sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256"
ENV HOSTKEYALGORITHMS="sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256"
ENV KEXALGORITHMS="sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512"
ENV MACS="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com"
ENV PUBKEYACCEPTEDALGORITHMS="sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256"
ENV REQUIREDRSASIZE="3072"

ENV SMTP_HOST=""
ENV SMTP_MAIL=""
ENV SMTP_PORT="587"
ENV SMTP_USER=""
ENV SMTP_PASS_FILE="/run/secrets/smtp_pass"

ENV MODULI_MIN=""

EXPOSE 22222/tcp

WORKDIR /tmp
ENTRYPOINT ["sshd.sh"]

ARG GIT_COMMIT=unspecified
ENV GIT_COMMIT=$GIT_COMMIT
