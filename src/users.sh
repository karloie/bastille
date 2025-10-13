#!/bin/sh
GRP=${GRP:-jmp}

cp /etc/group~ /run/group
cp /etc/passwd~ /run/passwd
cp /etc/shadow~ /run/shadow
chown root:shadow /run/shadow

# create group with random gid
while :; do
  gid="$(shuf -i 2000-4000 -n 1)" && [ "$(getent group $gid)" = "" ] && break
done
addgroup -g $gid ${GRP}

# create users with random uid
users=""
[ "$(ls -A /home)" ] && for f in /home/* ; do
  #[ -d "${f}" ] && continue
  usr="$(basename ${f})"
  while :; do
    uid="$(shuf -i 20000-40000 -n 1)" && [ "$(getent passwd ${uid})" = "" ] && break
  done
  adduser -u ${uid} -G ${GRP} ${usr} -s /sbin/nologin -DH
  sed -i "s/${usr}:!/${usr}:*/g" /run/shadow
  users="${users=} ${usr}"
done
echo $users
