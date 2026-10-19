#!/bin/sh
# A bwrap stand-in that passes the isolation probe, to unit-test probe handling
# without a real sandbox. With FAKE_BWRAP_NO_DISABLE_USERNS in the file name
# (`-old`), it rejects --disable-userns the way bubblewrap < 0.8 does.
for arg in "$@"; do
  if [ "$arg" = "--disable-userns" ] && [ "$(basename "$0")" = "fake-bwrap-old.sh" ]; then
    echo "bwrap: Unknown option --disable-userns" >&2
    exit 1
  fi
done
while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done
shift
if [ "$1" = "/bin/sh" ]; then
  echo isolated
  exit 0
fi
exec "$@"
