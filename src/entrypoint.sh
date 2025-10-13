#!/bin/sh
umask 077
grp=${grp:-jmp}
cfg=/run/sshd.cfg

notify=$(./notify.sh)
users=$(./users.sh)

echo "GitCommit=$GIT_COMMIT"
echo

cat << EOF > ${cfg}
LogLevel = ${LOGLEVEL:-INFO}
Port = ${LISTEN_PORT:-22222}
StrictModes = no

AllowGroups = ${grp}
AllowUsers = ${users}
AuthorizedKeysFile = /home/%u /home/%u/authorized_keys /home/%u/.ssh/authorized_keys
ChallengeResponseAuthentication = no
#ForceCommand = /bin/false
PasswordAuthentication = no
PermitRootLogin = no
PermitTTY = no
PubkeyAuthentication = yes
UsePAM = ${notify}

AllowAgentForwarding = ${AGENT_FORWARDING:-yes}
AllowTcpForwarding = ${TCP_FORWARDING:-yes}
GatewayPorts = ${GATEWAY_PORTS:-no}
PermitTunnel = ${PERMIT_TUNNEL:-no}
X11Forwarding = ${X11_FORWARDING:-no}

EOF

./crypto.sh

if [ $TESTING = "yes" ]; then
  echo "PerSourcePenalties = no" >> ${cfg}
fi

if [ "${LOGLEVEL}" = "VERBOSE" ] || [ "${LOGLEVEL}" = "DEBUG" ]; then
  cat ${cfg}
fi

if [ "$1" = "debug" ]; then
  dbg="-ddd"
fi

exec /usr/sbin/sshd -De4f ${cfg} ${dbg}
