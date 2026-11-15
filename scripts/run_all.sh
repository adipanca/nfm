#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# run_all.sh — jalankan skenario serangan per Tier secara berurutan.
# Default Tier 0 saja (paling aman). Tambahkan tier lain saat siap.
#   bash scripts/run_all.sh [0] [1] [2] ...
# Catatan: jalankan capture_start.sh SEBELUM ini, capture_stop.sh SESUDAH.
# ─────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/.."
TIERS=( "${@:-0}" )

for t in "${TIERS[@]}"; do
  case "$t" in
    0) echo "###### TIER 0 (N6 dari UE) ######"; bash scenarios/tier0_n6/run_tier0.sh all ;;
    1) echo "###### TIER 1 (GTP-U) ######"; bash scenarios/tier1_gtpu/run_tier1.sh all ;;
    2) echo "###### TIER 2 (PFCP) ######"; bash scenarios/tier2_pfcp/run_tier2.sh all ;;
    3) echo "###### TIER 3 (NAS/NGAP) ######"; bash scenarios/tier3_nas_ngap/run_tier3.sh all ;;
    4) echo "###### TIER 4 (SBI) ######"; bash scenarios/tier4_sbi/run_tier4.sh all ;;
    *) echo "[!] Tier $t belum tersedia, lewati." ;;
  esac
done
echo "== run_all selesai. Ground truth: data/ground_truth.csv =="
