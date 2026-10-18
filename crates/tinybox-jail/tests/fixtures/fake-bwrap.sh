#!/bin/sh
# Stand in for bwrap in unit tests: drop every namespace/mount flag up to the
# `--` separator, then run the wrapped command unconfined.
while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do shift; done
shift
exec "$@"
