#!/usr/bin/env bash
set -euo pipefail

if command -v dnf >/dev/null 2>&1; then
  dnf install -y gcc gcc-c++ cmake curl git gzip jq make openssl-devel perl tar util-linux
elif command -v pacman >/dev/null 2>&1; then
  pacman -Syu --noconfirm base-devel cmake curl git gzip jq openssl perl util-linux
else
  echo "unsupported distro package manager" >&2
  exit 2
fi
