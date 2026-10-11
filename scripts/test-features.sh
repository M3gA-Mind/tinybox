#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
# macOS does not ship setsid; the Docker supervisor fixtures need its real
# process-session semantics even though they run without a Docker daemon.
case "${RUNNER_OS:-$(uname -s)}" in
  macOS|Darwin)
    brew install util-linux
    export PATH="$(brew --prefix util-linux)/bin:$PATH"
    ;;
esac
python3 scripts/test-feature-environment.py
python3 scripts/test-e2e-version.py
cargo test --locked --workspace
cargo test --locked --workspace --all-features
case "${RUNNER_OS:-$(uname -s)}" in
  Windows|MINGW*|MSYS*|CYGWIN*) ;;
  *) python3 scripts/test-package-layout.py ;;
esac
