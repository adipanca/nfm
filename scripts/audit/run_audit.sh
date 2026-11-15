#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# AUDIT (baca-saja) — orkestrasi: ekstrak flow lalu jalankan pemeriksaan A–I.
# Tidak mengubah data/ (hanya menulis ke reports/audit/). Lihat audit.md.
#   bash scripts/audit/run_audit.sh [--skip-extract]
# Jalankan via grup docker agar inventaris container terbaca:
#   sg docker -c "bash scripts/audit/run_audit.sh"
# ─────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/../.."
if [[ "${1:-}" != "--skip-extract" ]]; then
  echo "==> [1/2] Ekstraksi flow (reports/audit/flows.csv)…"
  python3 scripts/audit/extract_flows.py
fi
echo "==> [2/2] Pemeriksaan A–I (reports/audit/AUDIT_REPORT.md)…"
python3 scripts/audit/run_checks.py
