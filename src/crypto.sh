#!/bin/sh
cfg=/run/sshd.cfg

# create host keys
function hostKey() {
  key="/hostkeys/ssh_host_${1}_key"
  if [ ! -f ${key} ]; then
    ssh-keygen -t ${1} -N '' -f ${key}
  fi
  echo "HostKey = ${key}" >> ${cfg}
}

#hostKey ecdsa
hostKey ed25519
hostKey rsa
echo >> ${cfg}

# flatten yaml multiline values
function yml2opt() {
  s=$(echo "$2" | tr '\n' ',' | sed 's/,,/,/g' | sed 's/\(.*\),/\1 /' | xargs)
  if [ -n "$s" ]; then
    echo "$1 = $s" >> ${cfg}
  fi
}

yml2opt CASignatureAlgorithms "${CASIGNATUREALGORITHMS}"
yml2opt Ciphers "${CIPHERS}"
yml2opt HostbasedAcceptedAlgorithms "${HOSTBASEDACCEPTEDALGORITHMS}"
yml2opt HostKeyAlgorithms "${HOSTKEYALGORITHMS}"
yml2opt KexAlgorithms "${KEXALGORITHMS}"
yml2opt MACs "${MACS}"
yml2opt PubkeyAcceptedAlgorithms "${PUBKEYACCEPTEDALGORITHMS}"
yml2opt RequiredRSASize "${REQUIREDRSASIZE}"
echo >> ${cfg}
