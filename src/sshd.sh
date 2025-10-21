#!/bin/sh -e
umask 077

cp /etc/group~ /run/group
cp /etc/passwd~ /run/passwd
cp /etc/shadow~ /run/shadow

users=$(sshd.users.sh)
notify=$(smtp.sh)

cfg=/run/sshd.cfg

cat << EOF >> ${cfg}
ChallengeResponseAuthentication = no
forcecommand = /sbin/nologin
KbdInteractiveAuthentication = no
PasswordAuthentication = no
PermitRootLogin = no
PermitTTY = no
PermitUserRC = no
PrintMotd = no
PubkeyAuthentication = yes
ChrootDirectory = none

AllowAgentForwarding = ${AGENT_FORWARDING:-no}
AllowTcpForwarding = ${TCP_FORWARDING:-yes}
GatewayPorts = ${GATEWAY_PORTS:-no}
PermitTunnel = ${PERMIT_TUNNEL:-no}
X11Forwarding = ${X11_FORWARDING:-no}

EOF

sshd.crypto.sh

cat << EOF >> ${cfg}
AllowUsers = ${users} # allow only users in /home/*
AuthorizedKeysFile = /home/%u /home/%u/authorized_keys /home/%u/.ssh/authorized_keys
StrictModes = ${STRICTMODES:-no} # strictly enforce permissions in /home/*
UsePAM = ${notify} # requires root, rootless container is recommended

LogLevel = ${LOGLEVEL:-INFO}
Port = ${LISTEN_PORT:-22222}
EOF

[ $TESTING = "yes" ] && echo "PerSourcePenalties = no # disable while testing" >> ${cfg}

dbg=""
[ "$1" = "debug" ] && dbg="-ddd"

cat ${cfg}
echo
set -x && exec /usr/sbin/sshd -De4f ${cfg} ${dbg}
