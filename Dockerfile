FROM alpine:3.22.2

LABEL maintainer="Karl-Bjørnar Øie <karloie@gmail.com>"

WORKDIR /root

RUN set -x && \
    apk add --no-cache openssh-server-pam msmtp

RUN find /etc -depth -type d -empty -delete && \
    find /lib -depth -type d -empty -delete && \
    find /var -not -path "*/empty*" -depth -type d -empty -delete && \
    find / -maxdepth 1 -depth -type d -empty -delete

COPY src/* .
RUN chmod -R 0500 * && \
    rm -Rf /etc/pam.d/* /etc/ssh /media /etc/fstab && \
    ln -svf /run/msmtprc /etc/msmtprc && \
    ln -svf /run/sshd.pam /etc/pam.d/sshd && \
    ln -svfb /run/group /etc/group && \
    ln -svfb /run/passwd /etc/passwd && \
    ln -svfb /run/shadow /etc/shadow && \
    ln -svf /usr/bin/msmtp /usr/bin/sendmail && \
    ln -svf /usr/bin/msmtp /usr/sbin/sendmail && \
    ln -svf /usr/sbin/sshd.pam /usr/sbin/sshd && \
    pwd

ENV LISTEN_PORT="22222"
ENV LOGLEVEL="INFO"
ENV TESTING="no"

# https://linux.die.net/man/5/sshd_config
ENV AGENT_FORWARDING="yes"
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

EXPOSE 22222/tcp

ENTRYPOINT ["./entrypoint.sh"]

ARG GIT_COMMIT=unspecified
ENV GIT_COMMIT=$GIT_COMMIT
