#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Benign N6 BERAT & BERAGAM — agar kelas benign jadi MAYORITAS (≥ kelas serangan
# terbesar). Worker BASH di DALAM tiap UE (portable: ue1/ue2/ue-mal hanya perlu
# bash+curl). Tiap UE menjalankan CONC "sesi" konkuren (meniru banyak koneksi/app
# di satu perangkat): path acak, GET ~90% / POST kecil ~10%, User-Agent acak,
# think-time 0.1-0.6s. Tiap curl = 1 flow kanonik (handshake lengkap + respons)
# → BUKAN flood (per-flow kecil, SYN≈SYN-ACK). Low-rate per sesi, agregat tinggi
# krn konkurensi.  TANPA proses serangan nyasar.
#
#   bash scripts/normal_traffic_heavy.sh [durasi=300] [konkuren_per_ue=14] [ue...]
# ─────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/.."
DUR="${1:-300}"; shift || true
CONC="${1:-14}"; shift || true
UES=( "${@:-ue1 ue2 ue-mal}" )
WEB="172.24.0.10"

# Worker bash dijalankan di dalam UE: $1=WEB $2=DUR $3=CONC
WORKER='
WEB="$1"; DUR="$2"; CONC="$3"; IFACE="${IFACE:-uesimtun0}"
end=$(( $(date +%s) + DUR ))
paths=( / /index.html "/?q=berita" /about /kontak /img/logo.png /css/style.css /js/app.js /favicon.ico /api/v1/profil /api/v1/data /search /produk /artikel /unduh/file.pdf /404-tidak-ada /user/feed )
uas=( "Mozilla/5.0 (Windows NT 10.0)" "curl/8.5" "okhttp/4.9" "LabApp/2.1" "Chrome/120" )
work() {
  while [ "$(date +%s)" -lt "$end" ]; do
    p="${paths[$((RANDOM % ${#paths[@]}))]}"
    case "$p" in */data|*/produk|*/artikel|*/feed|*/profil) p="$p?id=$((RANDOM%9999))";; esac
    if [ $((RANDOM % 10)) -lt 1 ]; then
      head -c $(( (RANDOM%6+1)*1024 )) /dev/urandom | curl -s -o /dev/null --interface "$IFACE" -m 8 -X POST --data-binary @- "http://$WEB$p" 2>/dev/null || true
    else
      curl -s -o /dev/null --interface "$IFACE" -m 8 -A "${uas[$((RANDOM%${#uas[@]}))]}" "http://$WEB$p" 2>/dev/null || true
    fi
    sleep "0.$((RANDOM%5+1))"
  done
}
i=0; while [ "$i" -lt "$CONC" ]; do work & i=$((i+1)); done
( while [ "$(date +%s)" -lt "$end" ]; do ping -I "$IFACE" -c1 -W2 "$WEB" >/dev/null 2>&1 || true; sleep $((RANDOM%2+1)); done ) &
wait
'

echo "==> Benign BERAT ${DUR}s, konkuren=${CONC}/UE, UE: ${UES[*]} → $WEB"
for UE in "${UES[@]}"; do
  docker exec "$UE" ip route replace 172.24.0.0/24 dev uesimtun0 >/dev/null 2>&1 || true
done
pids=()
for UE in "${UES[@]}"; do
  docker exec "$UE" bash -c "$WORKER" _ "$WEB" "$DUR" "$CONC" &
  pids+=($!)
  echo "   worker $UE dimulai (PID host $!)"
done
for p in "${pids[@]}"; do wait "$p" || true; done
echo "==> Benign berat selesai."
