#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# SERANGAN_BARU_VM.md — orkestrator kedua grup serangan baru.
# Menjalankan Grup 1 (SBI/N3/N6) lalu Grup 2 (SCTP/NAS).
# WAJIB: capture_start.sh (root) sudah jalan SEBELUM skrip ini, dan
#        capture_stop.sh + label_pcap.py --all SESUDAH.
#   sg docker -c "bash scenarios/newattacks/run_new.sh"
# Env diteruskan ke batch: WINDOWS, SESSIONS.
# ─────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/../.."
echo "######################## GRUP 1 ########################"
bash scenarios/newattacks/batch_group1.sh
echo "######################## GRUP 2 ########################"
bash scenarios/newattacks/batch_group2.sh
echo "== run_new selesai. Jalankan: sudo bash scripts/capture_stop.sh; python3 scripts/label_pcap.py --all =="
