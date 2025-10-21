#!/bin/sh
grp=${GRP:-jmp}
STRICTMODES=${STRICTMODES:-yes}

function getUid() {
  if [ "$STRICTMODES" = "yes" ]; then
    uid=$(stat -c "%u" /home/$1)
  else
    # random uid
    while :; do
      uid="$(shuf -i 20000-40000 -n 1)" && [ "$(getent passwd ${uid})" = "" ] && break
    done
  fi
  echo $uid
}

function getGid() {
  if [ "$STRICTMODES" = "yes" ]; then
    gid=$(stat -c "%g" /home/$1)
  else
    # random gid
    while :; do
      gid="$(shuf -i 2000-4000 -n 1)" && [ "$(getent group $gid)" = "" ] && break
    done
  fi
  echo $gid
}

# create users with random uid
users=""
[ "$(ls -A /home)" ] && for f in /home/* ; do
  usr="$(basename ${f})"
  uid=$(getUid ${usr})
  gid=$(getGid ${usr})
  addgroup ${usr} -g $gid
  adduser ${usr} -u ${uid} -G ${usr} -s /sbin/nologin -DH
  sed -i "s/${usr}:!/${usr}:*/g" /run/shadow
  users="${users=} ${usr}"
done

echo $users
