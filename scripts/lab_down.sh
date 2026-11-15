#!/usr/bin/env bash
# Matikan seluruh lab. Pakai --wipe utk hapus volume Mongo juga.
set -euo pipefail
cd "$(dirname "$0")/.."
DC() { docker compose "$@"; }

if [[ "${1:-}" == "--wipe" ]]; then
  echo "==> Menurunkan lab + menghapus volume (Mongo direset)"
  DC down -v
else
  echo "==> Menurunkan lab (volume Mongo dipertahankan)"
  DC down
fi
echo "Selesai."
