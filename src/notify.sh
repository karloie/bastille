#!/bin/sh
passfile=/run/secrets/smtp_pass

if [ -z "${SMTP_HOST}" ] ||
  [ ! -f "${SMTP_PASS_FILE:-${passfile}}" ] ||
  [ -z "${SMTP_USER}" ]; then
  echo no
  exit 0
fi

cat << EOF > /run/sshd.pam
session optional pam_exec.so debug stdout /root/notify.send.sh ${SMTP_MAIL:-${SMTP_USER}}
EOF

cat << EOF > /run/msmtprc
defaults
auth           on
tls            on
tls_trust_file /etc/ssl/certs/ca-certificates.crt

account        notify
from           ${SMTP_MAIL:-${SMTP_USER}}
host           ${SMTP_HOST}
passwordeval   "cat ${SMTP_PASS_FILE:-${passfile}}"
port           ${SMTP_PORT:-587}
user           ${SMTP_USER}

account default : notify
EOF

echo yes
