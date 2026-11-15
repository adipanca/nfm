#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Fase 6 — Vulnerability scan NF 5G core (subnet cp 172.22.0.0/24).
#
# Dua mode:
#   1) GREENBONE/OpenVAS penuh (jika container 'openvas' profile scanner sudah
#      jalan & feed tersinkron): pakai gvm-cli.  → paling lengkap, tapi feed
#      sync butuh internet + ~30-60 mnt (lihat openvas_greenbone.md).
#   2) FALLBACK nmap (default, cepat, tanpa internet): deteksi service + NSE
#      'vuln' terhadap tiap NF → temuan port/service/kerentanan.
#
#   bash scripts/openvas_scan.sh            # auto: greenbone bila ada, else nmap
#   bash scripts/openvas_scan.sh --nmap     # paksa nmap
# Output mentah → reports/scan/. Ringkas via openvas_export.sh.
# ─────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="reports/scan"; mkdir -p "$OUT"
TS="$(date +%Y%m%d_%H%M%S)"
CP_SUBNET="172.22.0.0/24"
NF_IPS="172.22.0.20 172.22.0.21 172.22.0.22 172.22.0.23 172.22.0.24 172.22.0.25 172.22.0.26 172.22.0.27 172.22.0.28 172.22.0.29"

use_greenbone=false
if [[ "${1:-}" != "--nmap" ]] && docker ps --format '{{.Names}}' | grep -qx openvas; then
  use_greenbone=true
fi

if $use_greenbone; then
  echo "==> Mode Greenbone/OpenVAS (container 'openvas' terdeteksi)"
  echo "    Membuat target + task via gvm-cli (butuh feed tersinkron)..."
  # Catatan: perintah gvm bergantung image Greenbone; lihat openvas_greenbone.md.
  docker exec openvas gvm-cli --gmp-username admin --gmp-password "${OPENVAS_PASSWORD:-admin}" \
    socket --xml "<get_version/>" 2>&1 | tee "$OUT/greenbone_version_${TS}.xml" || true
  echo "    (Alur target→task→report Greenbone didokumentasikan di openvas_greenbone.md)"
  exit 0
fi

echo "==> Mode nmap (vulnerability scan NF core $CP_SUBNET)"
echo "    Scanner dijalankan dari container 'attacker' di net cp."
RAW_XML="$OUT/nf_scan_${TS}.xml"
RAW_TXT="$OUT/nf_scan_${TS}.txt"

# -sV deteksi service/versi; --script vuln (NSE) cari kerentanan umum; -sS SYN scan.
# -p gabungan port 5G SBI + umum. Hasil XML (utk export) + normal (teks).
docker run --rm --network nfm_cp -v "$PWD/$OUT:/out" nfm/attacker:latest \
  nmap -sS -sV -Pn -T4 \
    -p 7777,8805,2152,38412,80,443,27017,9090,22,53 \
    --script "banner,vuln,ssl-enum-ciphers" \
    -oX "/out/$(basename "$RAW_XML")" -oN "/out/$(basename "$RAW_TXT")" \
    $NF_IPS 2>&1 | tail -20

echo
echo "==> Scan selesai. Mentah: $RAW_XML + $RAW_TXT"
echo "    Ringkas: bash scripts/openvas_export.sh"
