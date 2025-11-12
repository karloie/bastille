#!/bin/bash -e
space=karloie/bastille
tag=latest
self=`basename $0`

builder=${builder:-docker}
composer="docker compose"
if [ "$builder" == "podman" ]; then
  composer="podman-compose"
fi

dfile="Dockerfile"
dcompose="docker-compose.yml"

[ -f test/$dfile ] && dockerfile=test/$dfile
[ -f test/$dcompose ] && composefile=test/$dcompose
if [ ! -f $composefile ] && [ ! -f $dockerfile ]; then
   echo "Uable to find Dockerfile or docker-compose.yml!"
   exit 1
fi

declare -A env git

env[arg]=${1}
env[composefile]=$composefile
env[dockerfile]=$dockerfile
env[pwd]=${PWD%}

git[branch]=`git rev-parse --abbrev-ref HEAD`
git[commit]=`git rev-parse HEAD`
git[rev]=`git rev-list --tags --max-count=1`
git[url]=`git remote get-url origin`
git[version]=`git describe --tags ${git[rev]}`

function printA() {
  local -n arr=$1
  for key in ${!arr[@]}; do
      printf "%s = %s\n" $key ${arr[$key]}
  done | sort
}

function build() {
  ${builder} build . --build-arg GIT_COMMIT=${commit} -t $space:$1
}

function exec() {
  ${builder} exec -ti test-bastille-1 $@
}

function ssh_() {
  fail="false"
  if [ "$1" == "fail" ]; then
    shift
    fail="true"
  fi
  cmd="ssh -F test/ssh.config -Tn $@"
  {
    IFS= read -r -d '' STDERR;
    IFS= read -r -d '' EXIT;
    IFS= read -r -d '' STDOUT;
  } < <((printf '\0%s\n\0' "$($cmd; printf '\0%d' "${?}" 1>&2)" 1>&2) 2>&1)
  if [ ${EXIT} -gt 0 ]; then
    printf "[\e[31m FAIL \e[0m] ${cmd}\n";
    echo "${STDERR}"
    if [ "$fail" = "false" ]; then
      exit ${EXIT}
    fi
  else
    if [ "$fail" = "true" ]; then
      printf "[\e[31m  OK  \e[0m] ${cmd}\n";
      echo "should have failed!" >&2; exit ${EXIT}
    else
      printf "[\e[32m  OK  \e[0m] ${cmd}\n";
    fi
  fi
}

function setup(){
  keys="test/clientkeys/id_ed25519"
  home="test/home"
  cadir="test/ca"

  mkdir -p test/ca test/target1/.ssh test/target2/.ssh test/clientkeys test/home test/hostkeys

  [ ! -f ${keys}_lilo ] && ssh-keygen -t ed25519 -N '' -f ${keys}_lilo -C "lilo@localhost"
  [ ! -f ${keys}_stitch ] && ssh-keygen -t ed25519 -N '' -f ${keys}_stitch -C "stitch@localhost"
  [ ! -f ${keys}_nani ] && ssh-keygen -t ed25519 -N '' -f ${keys}_nani -C "nani@localhost"
  [ ! -f ${keys}_jumba ] && ssh-keygen -t ed25519 -N '' -f ${keys}_jumba -C "jumba@localhost"
  [ ! -f ${keys}_wrong ] && ssh-keygen -t ed25519 -N '' -f ${keys}_wrong -C "wrong@localhost"

  if [ ! -f ${home}/lilo ]; then
    printf 'permitopen="172.16.4.12:22",permitopen="172.16.4.13:22" ' > ${home}/lilo
    cat ${keys}_lilo.pub >> ${home}/lilo
    cat ${keys}_lilo.pub > test/target1/.ssh/authorized_keys
    cat ${keys}_lilo.pub > test/target2/.ssh/authorized_keys
  fi

  if [ ! -f ${home}/stitch ]; then
    printf 'permitopen="172.16.4.13:22" ' > ${home}/stitch
    cat ${keys}_stitch.pub >> ${home}/stitch
    cat ${keys}_stitch.pub >> test/target2/.ssh/authorized_keys
  fi

  if [ ! -f test/ca/ca_ed25519_nani ]; then
    ssh-keygen -t ed25519 -N "" -C "Nani Pelekai" -f test/ca/ca_ed25519_nani -q
    ssh-keygen -q -s test/ca/ca_ed25519_nani \
      -I "Nani Pelekai" \
      -n nani,zone-databases \
      -V +1d \
      -z 1 \
      -O source-address='172.16.4.0/24' \
      test/clientkeys/id_ed25519_nani.pub
    ssh-keygen -Lf test/clientkeys/id_ed25519_nani-cert.pub
  fi

  if [ ! -f test/ca/ca_ed25519_jumba ]; then
    ssh-keygen -t ed25519 -N "" -C "CA Jumba Jookiba" -f test/ca/ca_ed25519_jumba -q
    ssh-keygen -q -s test/ca/ca_ed25519_jumba \
      -I "Jumba Jookiba" \
      -n jumba,zone-databases \
      -V +1d \
      -z 1 \
      -O source-address='172.16.4.0/24' \
      test/clientkeys/id_ed25519_jumba.pub
    ssh-keygen -Lf test/clientkeys/id_ed25519_jumba-cert.pub
  fi
}

function testSmoke() {
  echo "Smoke test:"
  echo
  ssh_ fail lilo@bastille-lilo pwd
  ssh_ root@target1 -J lilo@bastille-lilo pwd
  ssh_ root@target2 -J lilo@bastille-lilo pwd
  ssh_ root@target2 -J stitch@bastille-stitch pwd
  ssh_ fail root@target1 -J lilo@bastille-wrong pwd
  ssh_ fail root@target1 -J stitch@bastille-stitch pwd
  ssh_ root@target1 -J nani@bastille-nani pwd
  ssh_ fail root@target1 -J jumba@bastille-jumba pwd
  echo
}

function testAccess() {
  echo "Test access (should succeed):"
  echo
  ssh_ root@target1 -J lilo@bastille-lilo pwd
  ssh_ root@target2 -J lilo@bastille-lilo pwd
  ssh_ root@target2 -J stitch@bastille-stitch pwd
  echo
  echo "Test access (should fail):"
  echo
  ssh_ fail root@target1 -J stitch@bastille-stitch pwd
  ssh_ fail root@target1 -J lilo@bastille-pass pwd
  ssh_ fail root@target1 -J root@bastille-lilo pwd
  ssh_ fail root@target1 -J lilo@bastille-stitch pwd
  ssh_ fail root@target1 -J lilo@bastille-wrong pwd
  ssh_ fail root@target2 -J lilo@bastille-wrong pwd
  ssh_ fail lilo@bastille-lilo pwd
  echo
}

function testAlgorithms() {
  echo "Test hardening (should fail):"
  echo
#  ssh_ fail root@target1 -J lilo@bastille-bad-hostkey pwd
  ssh_ fail root@target1 -J lilo@bastille-bad-cipher pwd
  ssh_ fail root@target1 -J lilo@bastille-bad-kex pwd
  ssh_ fail root@target1 -J lilo@bastille-bad-mac pwd
}

#setup
printA env
echo
printA git
echo

if [ "$1" = "up" ]; then
  set -x
  ${composer} -f ${env[composefile]} down ${env[args]} --remove-orphans
  ${composer} -f ${env[composefile]} up ${env[args]} --build --remove-orphans
  set +x
elif [ "$1" = "down" ]; then
  set -x
  ${composer} -f ${env[composefile]} down --remove-orphans
  set +x
elif [ "$1" = "exec" ]; then
  shift
  set -x
  exec $@
elif [ "$1" = "run" ]; then
  set -x
  build $tag
  ${builder} run --rm \
    --name prod-bastille \
    -p 22222:22222 \
    -v go-build:/root/.cache/go-build:rw \
    -v $PWD/test/home:/home:ro \
    -v $PWD/test/hostkeys:/hostkeys:rw \
    -v $PWD/test/smtp_pass:/run/secrets/smtp_pass:ro \
    -ti $space:$tag
elif [ "$1" = "push" ]; then
  set -x
  build $tag
  ${builder} save $space:$tag | bzip2 | ssh ${PUSH_HOST:-bastille} ${builder} load
  ssh ${PUSH_HOST:-bastille} srv bastille restart
  set +x
elif [ "$1" == "test" ] && [ "$2" == "all" ]; then
  testSmoke
  testAccess
  testAlgorithms
  printf "[\e[32m  OK  \e[0m] all tests ok\n";
elif [ "$1" == "test" ]; then
  testSmoke
else
  printf "\nUsage:\n"
  echo "./$self up|down"
  echo "./$self test"
  echo "./$self test all"
  echo "./$self exec"
  echo "./$self push"
fi
