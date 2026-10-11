#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
python3 scripts/test-e2e-version.py
cargo test --locked --workspace
cargo test --locked --workspace --all-features
