#!/usr/bin/env bash
# Hentikan semua tcpdump capture yang dimulai capture_start.sh.
# WAJIB root. Jalankan: sudo bash scripts/capture_stop.sh
set -euo pipefail
[[ "${EUID}" -ne 0 ]] && { echo "[!] Harus root: sudo bash scripts/capture_stop.sh"; exit 1; }
cd "$(dirname "$0")/.."
PIDFILE="data/raw/.capture_pids"
[[ -f "$PIDFILE" ]] || { echo "Tidak ada capture berjalan ($PIDFILE hilang)."; exit 0; }

while read -r pid br out; do
  [[ -z "$pid" ]] && continue
  if kill "$pid" 2>/dev/null; then
    echo "==> Dihentikan PID $pid ($br)"
  else
    echo "    PID $pid sudah mati."
  fi
done < "$PIDFILE"
rm -f "$PIDFILE"

echo
echo "==> File PCAP di data/raw:"
ls -lh data/raw/*.pcap* 2>/dev/null || echo "   (belum ada)"
