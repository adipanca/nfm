#!/usr/bin/env bash
# Tier 1 — GTP-U malformed (N3) dari ue-mal ke UPF. CVE-2021-45462; Trend Micro 2023.
#   bash scenarios/tier1_gtpu/run_tier1.sh [all|T1-01]
set -euo pipefail
cd "$(dirname "$0")/../.."
RS="scripts/run_scenario.sh"
UPF_N3="172.23.0.30"; SRC="172.23.0.43"   # ue-mal di net up

docker compose up -d ue-mal >/dev/null 2>&1 || docker start ue-mal >/dev/null 2>&1 || true
sleep 6

run_T1_01() { bash "$RS" 1 T1-01 gtpu_malformed "$SRC" "$UPF_N3" N3 20 -- \
  docker exec ue-mal python3 /opt/attacker/tools/gtpu_malformed.py "$UPF_N3" 15 800; }

case "${1:-all}" in
  all|T1-01) run_T1_01 ;;
  *) echo "skenario tak dikenal: $1"; exit 2 ;;
esac
echo "== Tier 1 selesai =="
