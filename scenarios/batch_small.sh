#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Revisi R2 (MULTI-CLASS) — perbanyak EPISODE kelas serangan kecil agar tiap
# kelas ≥120 flow INDEPENDEN (buffer di atas ambang 100), demi evaluasi multi-
# class yang valid. Tiap episode = source port efemeral baru (5-tuple unik) +
# jitter timing & parameter → flow independen, mengurangi kebocoran train/test.
#
# 8 kelas: pfcp_session_delete/modify, pfcp_estab_flood, pfcp_rule_misconfig,
# gtpu_malformed, ngap_malformed, sbi_http2_dos, sbi_attack_over_tls.
#
# WAJIB: jalankan capture_start.sh SEBELUM & capture_stop.sh SESUDAH, lalu
#        label_pcap.py --all (gabung dgn dataset lama, jangan timpa).
# Guard subnet + --i-understand-lab-only ditegakkan run_scenario.sh (Tier≥2).
#
#   bash scenarios/batch_small.sh
# Env: SESSIONS(=50) PFCP_RUNS(=3) GTPU_RUNS(=3) NGAP_RUNS(=4) SBI_RUNS(=3)
# ─────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/.."
RS="scripts/run_scenario.sh"; OK="--i-understand-lab-only"
UPF="172.23.0.30"; AMF="172.23.0.32"; NRF="172.22.0.20"
ATT_UP="172.23.0.50"; ATT_CP="172.22.0.50"; UEMAL_N3="172.23.0.43"
SESS="${SESSIONS:-50}"
PFCP_RUNS="${PFCP_RUNS:-3}"; GTPU_RUNS="${GTPU_RUNS:-3}"
NGAP_RUNS="${NGAP_RUNS:-4}"; SBI_RUNS="${SBI_RUNS:-3}"
jit(){ sleep $((1 + RANDOM % 3)); }   # jitter 1-3 dtk antar-episode

docker compose up -d attacker ue-mal >/dev/null 2>&1 || true
sleep 4

echo "###### R2: PFCP (4 kelas × ${PFCP_RUNS} episode × ${SESS} flow) ######"
for spec in "delete:pfcp_session_delete:T2-01" "modify:pfcp_session_modify:T2-02" \
            "estab_flood:pfcp_estab_flood:T2-03" "misconfig:pfcp_rule_misconfig:T2-04"; do
  IFS=: read -r mode label base <<< "$spec"
  for i in $(seq 1 "$PFCP_RUNS"); do
    bash "$RS" 2 "${base}-e${i}" "$label" "$ATT_UP" "$UPF" N4 40 $OK -- \
      docker exec -e SESSIONS="$SESS" -e PKTS_PER_SESSION=6 attacker \
        python3 /opt/attacker/tools/pfcp_attack.py "$mode" "$UPF"
    jit
  done
done

echo "###### R2: GTP-U malformed (ue-mal → UPF N3) × ${GTPU_RUNS} episode ######"
for i in $(seq 1 "$GTPU_RUNS"); do
  bash "$RS" 1 "T1-01-e${i}" gtpu_malformed "$UEMAL_N3" "$UPF" N3 40 -- \
    docker exec -e SESSIONS="$SESS" -e PKTS_PER_SESSION=8 ue-mal \
      python3 /opt/attacker/tools/gtpu_malformed.py "$UPF"
  jit
done

echo "###### R2: NGAP malformed (attacker → AMF N2) × ${NGAP_RUNS} episode ######"
# tiap koneksi SCTP = socket baru = source port efemeral baru = flow baru
for i in $(seq 1 "$NGAP_RUNS"); do
  bash "$RS" 3 "T3-03-e${i}" ngap_malformed "$ATT_UP" "$AMF" N2 25 $OK -- \
    docker exec attacker python3 /opt/attacker/tools/ngap_attack.py malformed "$AMF" 15 120
  jit
done

echo "###### R2: SBI HTTP/2 DoS (attacker → NRF) × ${SBI_RUNS} episode ######"
# h2load -c 50 → 50 koneksi = 50 flow per episode
for i in $(seq 1 "$SBI_RUNS"); do
  bash "$RS" 4 "T4-01-e${i}" sbi_http2_dos "$ATT_CP" "$NRF" SBI 25 $OK -- \
    docker exec attacker h2load -n 60000 -c 50 -m 50 --duration=10 "https://$NRF:7777/"
  jit
done

echo "###### R2: SBI attack over TLS (attacker → NRF) × ${SBI_RUNS} episode ######"
for i in $(seq 1 "$SBI_RUNS"); do
  bash "$RS" 5 "T5-04-e${i}" sbi_attack_over_tls "$ATT_CP" "$NRF" TLS 25 $OK -- \
    docker exec attacker h2load -n 60000 -c 50 -m 50 --duration=10 "https://$NRF:7777/"
  jit
done

echo "== batch_small selesai. Jalankan capture_stop.sh lalu label_pcap.py --all =="
