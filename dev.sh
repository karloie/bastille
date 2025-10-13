#!/bin/bash
name=bastille
space=karloie/$name
tag=latest

builder=${builder:-docker}
composer="docker compose"
if [ $builder == "podman" ]; then
  composer="podman-compose"
fi

# set up keys for testing
keys="test/clientkeys/id_ed25519"
home="test/home"

mkdir -p test/target1/.ssh test/target2/.ssh test/clientkeys test/home test/hostkeys
if [ ! -f ${keys}_lilo ]; then
  ssh-keygen -t ed25519 -N '' -f ${keys}_lilo -C "lilo@localhost"
fi
printf 'permitopen="172.16.4.12:22",permitopen="172.16.4.13:22" ' > ${home}/lilo
cat ${keys}_lilo.pub >> ${home}/lilo
cat ${keys}_lilo.pub > test/target1/.ssh/authorized_keys
cat ${keys}_lilo.pub > test/target2/.ssh/authorized_keys
if [ ! -f ${keys}_stitch ]; then
  ssh-keygen -t ed25519 -N '' -f ${keys}_stitch -C "stitch@localhost"
fi
printf 'permitopen="172.16.4.13:22" ' > ${home}/stitch
cat ${keys}_stitch.pub >> ${home}/stitch
cat ${keys}_stitch.pub >> test/target2/.ssh/authorized_keys
if [ ! -f ${keys}_wrong ]; then
  ssh-keygen -t ed25519 -N '' -f ${keys}_wrong -C "wrong@localhost"
fi

function build_() {
  ${builder} build . --build-arg GIT_COMMIT=$(git rev-parse --short HEAD) -t $space:$1
}

function exec_() {
  ${builder} exec -ti test-$name-1 $@
}

function ssh_() {
  cmd="ssh -F test/ssh.config -Tn $@"
  {
    IFS= read -r -d '' STDERR;
    IFS= read -r -d '' EXIT;
    IFS= read -r -d '' STDOUT;
  } < <((printf '\0%s\n\0' "$($cmd; printf '\0%d' "${?}" 1>&2)" 1>&2) 2>&1)
  if [ ${EXIT} -gt 0 ]; then
    printf "[\e[31m FAIL \e[0m] ${cmd}\n";
    echo "${STDERR}"
  else
    printf "[\e[32m  OK  \e[0m] ${cmd}\n";
  fi
}

# run it
if [ "$1" == "build" ]; then
  build_ $tag
  exit 0
fi

# run it
if [ "$1" == "run" ]; then
  build_ $tag
  ${builder} rm $name --force || true
  ${builder} run --rm \
    --name $name \
    --read-only \
    --tmpfs /run \
    --tmpfs /tmp \
    -p 22222:22222 \
    -v $PWD/test/home:/home:rw \
    -v $PWD/test/hostkeys:/hostkeys:rw \
    -ti $space:$tag $2
  exit
fi

# deploy it
dcf="-f test/docker-compose.yml"
if [ "$1" == "up" ]; then
  ${composer} $dcf down $2 --remove-orphans
  ${composer} $dcf up $2 --build --remove-orphans
  exit
elif [ "$1" == "down" ]; then
  ${composer} $dcf down $2 --remove-orphans
  exit
fi

# exec it
if [ $1 = "exec" ]; then
  if [ "$2" = "" ]; then
    exec_ ash
  else
    shift
    exec_ $@
  fi
  exit
fi

# test it
if [ "$1" == "test" ]; then
  echo
  echo "Test access (should succeed):"
  echo "---------------------------------------------"
  ssh_ root@target1 -J lilo@bastille-lilo pwd
  ssh_ root@target2 -J lilo@bastille-lilo pwd
  ssh_ root@target2 -J stitch@bastille-stitch pwd
  if [ "$2" == "all" ]; then
    echo
    echo "Test access (should fail):"
    echo "---------------------------------------------"
    ssh_ lilo@bastille-lilo pwd
    ssh_ root@target1 -J lilo@bastille-pass pwd
    ssh_ root@target1 -J root@bastille-lilo pwd
    ssh_ root@target1 -J stitch@bastille-stitch pwd
    ssh_ root@target1 -J lilo@bastille-stitch pwd
    ssh_ root@target1 -J lilo@bastille-wrong pwd
    ssh_ root@target2 -J lilo@bastille-wrong pwd
    echo
    echo "Test hardening (should fail):"
    echo "---------------------------------------------"
    ssh_ root@target1 -J lilo@bastille-bad-hostkey pwd
    ssh_ root@target1 -J lilo@bastille-bad-cipher pwd
    ssh_ root@target1 -J lilo@bastille-bad-kex pwd
    ssh_ root@target1 -J lilo@bastille-bad-mac pwd
  fi
  exit
fi

# push it
if [ "$1" == "push" ]; then
  build_ $tag
  ${builder} save $space:$tag | bzip2 | ssh bastille ${builder} load
  ssh bastille srv bastille restart
  exit
fi

echo "Dev Stuff"
echo "--------------------------------------"
echo "./dev.sh run - build and run container"
echo "./dev.sh up - start test deployment"
echo "./dev.sh test - run tests"
echo "./dev.sh exec - exec in container"
echo "./dev.sh push - push container"
