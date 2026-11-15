#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Fase 3 — Mulai capture multi-interface pada bridge Docker lab.
#   br(cp) → SBI (HTTP/2, nanti TLS)      → data/raw/cp_*.pcap
#   br(up) → N2(NGAP/SCTP) N3(GTP-U) N4(PFCP) → data/raw/up_*.pcap
#   br(dn) → N6 (trafik UE ke webserver)  → data/raw/dn_*.pcap
# Rotasi 500 MB/file. PID disimpan utk capture_stop.sh.
# WAJIB root (tcpdump pada bridge). Jalankan: sudo bash scripts/capture_start.sh
# ─────────────────────────────────────────────────────────────
set -euo pipefail
[[ "${EUID}" -ne 0 ]] && { echo "[!] Harus root: sudo bash scripts/capture_start.sh"; exit 1; }

cd "$(dirname "$0")/.."
RAW="data/raw"; mkdir -p "$RAW"
PIDFILE="$RAW/.capture_pids"; : > "$PIDFILE"
DROP_USER="${SUDO_USER:-root}"
TS="$(date +%Y%m%d_%H%M%S)"

# Pemetaan network Docker → peran capture
declare -A NETS=( [cp]=nfm_cp [up]=nfm_up [dn]=nfm_dn )

for role in cp up dn; do
  net="${NETS[$role]}"
  id="$(docker network inspect "$net" --format '{{.Id}}' 2>/dev/null || true)"
  [[ -z "$id" ]] && { echo "[!] Network $net tidak ada — lab sudah naik?"; continue; }
  br="br-${id:0:12}"
  if ! ip link show "$br" >/dev/null 2>&1; then
    echo "[!] Bridge $br ($net) tidak ditemukan, lewati."; continue
  fi
  out="$RAW/${role}_${TS}.pcap"
  echo "==> Capture $role di $br → $out (rotasi 500MB)"
  # -C 500: rotasi tiap 500MB; -Z: drop ke user; -n: tanpa resolve; -s0: full packet
  tcpdump -i "$br" -n -s 0 -C 500 -Z "$DROP_USER" -w "$out" \
      'not (tcp port 2375 or tcp port 2376)' \
      >/dev/null 2>"$RAW/${role}_${TS}.tcpdump.log" &
  pid=$!
  echo "$pid $br $out" >> "$PIDFILE"
  echo "    PID $pid"
done

sleep 1
echo
echo "Capture berjalan (PID di $PIDFILE). Hentikan dgn: sudo bash scripts/capture_stop.sh"
