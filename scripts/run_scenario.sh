#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# run_scenario.sh — MESIN penjalan skenario serangan lab.
# Tanggung jawab: guard subnet, banner+konfirmasi Tier≥2, timeout,
# dan pencatatan ground truth ke data/ground_truth.csv.
#
# Pemakaian:
#   run_scenario.sh TIER ID LABEL SRC_IP DST_IP IFACE DURATION [--i-understand-lab-only] -- CMD...
#
# Contoh (dipanggil oleh skrip skenario):
#   run_scenario.sh 0 T0-01 recon_portscan 10.45.0.4 172.24.0.10 N6 30 -- \
#       docker exec ue-mal nmap -e uesimtun0 -sS 172.24.0.10
# ─────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/.."

GT="data/ground_truth.csv"
mkdir -p data

# ── Subnet lab yang DIIZINKAN (guard keras) ──
# 172.22.0.0/24, 172.23.0.0/24, 172.24.0.0/24, 10.45.0.0/16
ip2int() { local IFS=.; read -r a b c d <<< "$1"; echo $(( (a<<24)+(b<<16)+(c<<8)+d )); }
in_lab_subnet() {
  local ip="$1" i; i=$(ip2int "$ip") || return 1
  local nets=( "172.22.0.0 24" "172.23.0.0 24" "172.24.0.0 24" "10.45.0.0 16" )
  for n in "${nets[@]}"; do
    local base mask; base=$(ip2int "${n% *}"); mask=$(( 0xffffffff << (32 - ${n#* }) & 0xffffffff ))
    (( (i & mask) == (base & mask) )) && return 0
  done
  return 1
}

# ── Parse argumen ──
TIER="$1"; ID="$2"; LABEL="$3"; SRC="$4"; DST="$5"; IFACE="$6"; DURATION="$7"; shift 7
UNDERSTAND=0
if [[ "${1:-}" == "--i-understand-lab-only" ]]; then UNDERSTAND=1; shift; fi
[[ "${1:-}" == "--" ]] && shift
CMD=( "$@" )
[[ ${#CMD[@]} -eq 0 ]] && { echo "[!] Tidak ada perintah serangan."; exit 2; }

# ── Banner peringatan utk Tier≥2 + wajib flag ──
if (( TIER >= 2 )); then
  cat >&2 <<BANNER
╔══════════════════════════════════════════════════════════════╗
║  PERINGATAN: Skenario Tier ${TIER} ($ID) menyerang NF 5G inti.        ║
║  Hanya untuk LAB TERISOLASI milik sendiri. Dilarang di jaringan ║
║  operator / SIM komersial (bisa melumpuhkan jaringan nyata &   ║
║  melanggar hukum, termasuk UU ITE).                            ║
╚══════════════════════════════════════════════════════════════╝
BANNER
  if (( UNDERSTAND == 0 )); then
    echo "[!] Tier≥2 wajib argumen --i-understand-lab-only. Berhenti." >&2
    exit 3
  fi
fi

# ── GUARD subnet: target WAJIB di dalam subnet lab ──
if ! in_lab_subnet "$DST"; then
  echo "[!!] GUARD GAGAL: target $DST di LUAR subnet lab (172.22/24,172.23/24,172.24/24,10.45/16)." >&2
  echo "     Serangan DIBATALKAN demi keamanan." >&2
  exit 4
fi
echo "[guard] target $DST ✓ di dalam subnet lab."

# ── Jalankan + catat ground truth ──
START=$(date +%s)
echo "==> [$ID/$LABEL] mulai $(date -d @$START '+%H:%M:%S') — ${CMD[*]}"
set +e
timeout "$DURATION" "${CMD[@]}"
RC=$?
set -e
END=$(date +%s)
echo "==> [$ID/$LABEL] selesai (rc=$RC, ${DURATION}s window, durasi nyata $((END-START))s)"

# Header CSV sekali
[[ -f "$GT" ]] || echo "tier,scenario_id,label,src_ip,dst_ip,iface,start_epoch,end_epoch" > "$GT"
echo "${TIER},${ID},${LABEL},${SRC},${DST},${IFACE},${START},${END}" >> "$GT"
echo "[gt] tercatat → $GT"
