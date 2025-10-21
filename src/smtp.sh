#!/bin/sh
passfile=/run/secrets/smtp_pass
mailsend=/usr/sbin/smtp.send.sh
trustfile=/etc/ssl/certs/ca-certificates.crt

if [ -z "${SMTP_HOST}" ] ||
  [ ! -f "${SMTP_PASS_FILE:-${passfile}}" ] ||
  [ -z "${SMTP_USER}" ]; then
  echo no
  exit 0
fi

cat << EOF > /run/msmtprc
defaults
auth           on
tls            on
tls_trust_file ${trustfile}

account        notify
from           ${SMTP_MAIL:-${SMTP_USER}}
host           ${SMTP_HOST}
passwordeval   "cat ${SMTP_PASS_FILE:-${passfile}}"
port           ${SMTP_PORT:-587}
user           ${SMTP_USER}

account default : notify
EOF

cat << EOF > /run/sshd.pam
session optional pam_exec.so ${mailsend} ${SMTP_MAIL:-${SMTP_USER}}
EOF

echo yes
