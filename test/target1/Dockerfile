FROM alpine:3.22.2

RUN apk add --no-cache openssh-server && ssh-keygen -A

WORKDIR /root

COPY .ssh .ssh
RUN chmod 0700 .ssh && chmod 0600 .ssh/*

CMD ["/usr/sbin/sshd", "-De4"]
