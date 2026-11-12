#!/bin/bash
# Stand-in for bwrap in unit tests: reads the NUL-separated argument list from
# `--args 9` like the real thing, applies --setenv, and runs the command
# unconfined. Behaviour depends on the file name:
#   fake-bwrap.sh        passes nothing (the isolation probe must reject it)
#   fake-bwrap-probe.sh  also answers the isolation probe
#   fake-bwrap-old.sh    like -probe, but rejects --disable-userns
#   fake-bwrap-noseccomp.sh  like -probe, but its --help lacks --add-seccomp-fd
# With --json-status-fd it runs the command as its child, like bwrap's sandbox,
# reports that child's pid on the descriptor, and exits with its status.
name=$(basename "$0")
if [ "$1" = "--help" ]; then
  [ "$name" = "fake-bwrap-noseccomp.sh" ] || echo "    --add-seccomp-fd FD          Load and use seccomp rules from FD (repeatable)"
  echo "    --json-status-fd FD          Write container status json to FD"
  exit 0
fi
[ "$1" = "--args" ] && [ "$3" = "--" ] || { echo "fake bwrap: expected --args N --" >&2; exit 2; }
shift 3
mode=opts
key=
status_fd=
while IFS= read -r -d '' line <&9; do
  case $mode in
    opts)
      case $line in
        --setenv) mode=setenv_k ;;
        --json-status-fd) mode=status ;;
        --disable-userns)
          if [ "$name" = "fake-bwrap-old.sh" ]; then
            echo "bwrap: Unknown option --disable-userns" >&2
            exit 1
          fi ;;
      esac ;;
    setenv_k) key=$line; mode=setenv_v ;;
    setenv_v) export "$key=$line"; mode=opts ;;
    status) status_fd=$line; mode=opts ;;
  esac
done
if [ "$name" != "fake-bwrap.sh" ] && [ "$1" = "/bin/sh" ]; then
  case $3 in *"echo isolated"*) echo isolated; exit 0 ;; esac
fi
[ -n "$status_fd" ] || exec "$@"
# The child gets stdin explicitly (a background job would get /dev/null) and
# not the status descriptor, which only this process holds, as with bwrap.
"$@" <&0 {status_fd}>&- &
child=$!
echo "{ \"child-pid\": $child }" >&"$status_fd"
wait "$child"
