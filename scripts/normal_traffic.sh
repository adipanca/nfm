#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Fase 3 — Trafik N6 NORMAL (benign) dari UE ke webserver.
# HTTP GET + ping berkala lewat uesimtun0 → GTP-U (N3) + IP (N6).
# Label dasar: benign.
#   bash scripts/normal_traffic.sh [durasi_detik] [ue1 ue2 ...]
# ─────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/.."
DX() { docker "$@"; }

DURATION="${1:-120}"
shift || true
UES=( "${@:-ue1 ue2}" )
WEB="172.24.0.10"
PATHS=( "/" "/index.html" "/?q=normal" "/404-notfound" )

echo "==> Trafik normal ${DURATION}s dari: ${UES[*]} → webserver $WEB"
END=$(( $(date +%s) + DURATION ))
reqs=0
while [[ $(date +%s) -lt $END ]]; do
  for UE in ${UES[*]}; do
    p="${PATHS[$((RANDOM % ${#PATHS[@]}))]}"
    DX exec "$UE" curl -s --interface uesimtun0 -m 5 -o /dev/null "http://$WEB$p" 2>/dev/null || true
    DX exec "$UE" ping -I uesimtun0 -c 1 -W 2 "$WEB" >/dev/null 2>&1 || true
    reqs=$((reqs+1))
  done
  sleep "0.$((RANDOM % 9 + 1))"
done
echo "==> Selesai. Total putaran request ~${reqs}."
