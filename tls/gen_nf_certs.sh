#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Fase 2b — Terbitkan sertifikat TLS per-NF utk SBI (ditandatangani CA lab).
# SAN tiap cert = DNS:<nama-service> + IP:<ip-cp> → cocok baik diakses via
# nama (scp/nrf) maupun IP (SCP→NF). Output: tls/certs/<nf>.{key,crt} + ca.crt.
#   ./tls/gen_nf_certs.sh [--force]
# ─────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")"
CA_KEY="ca/ca.key"; CA_CRT="ca/ca.crt"
[[ -f "$CA_CRT" ]] || { echo "[!] CA belum ada. Jalankan ./tls/gen_ca.sh dulu."; exit 1; }
OUT="certs"; mkdir -p "$OUT"
cp -f "$CA_CRT" "$OUT/ca.crt"

# NF → IP control-plane (harus sama dgn docker-compose.yml)
declare -A NF_IP=(
  [nrf]=172.22.0.20 [scp]=172.22.0.21 [ausf]=172.22.0.22 [udm]=172.22.0.23
  [udr]=172.22.0.24 [pcf]=172.22.0.25 [bsf]=172.22.0.26 [nssf]=172.22.0.27
  [amf]=172.22.0.28 [smf]=172.22.0.29
)

for nf in "${!NF_IP[@]}"; do
  ip="${NF_IP[$nf]}"; key="$OUT/$nf.key"; crt="$OUT/$nf.crt"; csr="$OUT/$nf.csr"
  if [[ -f "$crt" && "${1:-}" != "--force" ]]; then echo "[i] $nf.crt ada, lewati."; continue; fi
  openssl req -nodes -newkey rsa:2048 -keyout "$key" -out "$csr" \
    -subj "/C=ID/O=NFM-Testbed-Lab/OU=5G-SBI/CN=$nf" 2>/dev/null
  openssl x509 -req -in "$csr" -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
    -days 825 -out "$crt" \
    -extfile <(printf "subjectAltName=DNS:%s,IP:%s\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\n" "$nf" "$ip") 2>/dev/null
  rm -f "$csr"; chmod 644 "$key"  # dibaca user open5gs (uid 999) di container (lab saja)
  echo "[OK] $nf  SAN=DNS:$nf,IP:$ip"
done
echo "==> Sertifikat NF siap di tls/$OUT/ (+ ca.crt)."
