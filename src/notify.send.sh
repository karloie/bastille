#!/bin/sh
SUBJECT="$(hostname) ssh jump by ${PAM_USER} - $(TZ=GST-2 date)"
BODY="SSH_CONN=${SSH_CONNECTION}
SSH_AUTH=${SSH_AUTH_INFO_0}"
if [ "${PAM_TYPE}" = "open_session" ]; then
  ( 
    printf "Subject: ${SUBJECT}\n\n${BODY}" | msmtp -a notify ${1}
  ) &
fi
exit 0
