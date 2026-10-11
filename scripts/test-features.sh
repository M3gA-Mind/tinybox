#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
cargo test --locked --workspace
cargo test --locked --workspace --all-features
