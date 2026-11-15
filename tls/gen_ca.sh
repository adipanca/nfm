#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Fase 2b — Buat CA lab untuk mengamankan SBI (3GPP TS 33.501).
# Output: tls/ca/ca.key (rahasia) + tls/ca/ca.crt (dibagikan ke tiap NF).
# Idempoten: tak menimpa CA yang sudah ada kecuali --force.
#   ./tls/gen_ca.sh [--force]
# ─────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")"
CA_DIR="ca"; mkdir -p "$CA_DIR"
KEY="$CA_DIR/ca.key"; CRT="$CA_DIR/ca.crt"

if [[ -f "$CRT" && "${1:-}" != "--force" ]]; then
  echo "[i] CA sudah ada ($CRT). Pakai --force untuk buat ulang."; exit 0
fi

echo "==> Membuat kunci & sertifikat CA lab (RSA 4096, 3650 hari)"
openssl req -x509 -nodes -newkey rsa:4096 -days 3650 \
  -keyout "$KEY" -out "$CRT" \
  -subj "/C=ID/O=NFM-Testbed-Lab/OU=5G-Core/CN=NFM Lab Root CA"
chmod 600 "$KEY"
echo "==> CA siap:"
openssl x509 -in "$CRT" -noout -subject -issuer -dates
