#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Fase 2 — Nyalakan 5G Core + RAN (tanpa UE; UE via register_ue.sh).
# Urutan: mongo → NRF/SCP → NF SBI → AMF/SMF/UPF → webserver → gNB.
# Lalu daftarkan subscriber UE ke Mongo.
# ─────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/.."

# Docker via grup (tanpa re-login). Fallback ke 'docker' langsung bila sudah di grup.
DC() { docker compose "$@"; }

# .env wajib ada (dipakai utk versi image).
[[ -f .env ]] || { echo "==> Membuat .env dari .env.example"; cp .env.example .env; }

echo "==> Menarik image (butuh internet, sekali saja)"
DC pull --quiet mongo nrf 2>/dev/null || true

echo "==> Menyalakan core + RAN (tanpa UE)"
DC up -d mongo nrf scp ausf udm udr pcf bsf nssf amf smf upf webserver gnb

echo "==> Mendaftarkan subscriber UE ke Mongo"
bash subscribers/add_subs.sh

echo
echo "==> Status:"
DC ps
echo
echo "Core+RAN naik. Lanjut: ./scripts/register_ue.sh (UE online + cek N6)."
