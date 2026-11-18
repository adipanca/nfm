#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# SERANGAN_BARU_VM.md — Grup 2 (NAS/NGAP di atas SCTP → AMF).
# Kelas baru: nas_tamper_registration, nas_replay_n1, bidding_down.
#
# CATATAN: berjalan di SCTP — tokenisasi penuh baru jalan setelah patch SCTP di
# WSL (INGEST_TRAIN_WSL.md). Tetap DI-CAPTURE sekarang (jangan tunggu patch).
# Tiap koneksi SCTP = source port efemeral baru = 1 flow independen.
#
#   bash scenarios/newattacks/batch_group2.sh
# Env: WINDOWS(=8) SESSIONS(=20)
# ─────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/../.."
RS="scripts/run_scenario.sh"; OK="--i-understand-lab-only"

AMF_N2="172.23.0.32"; ATT_UP="172.23.0.50"
WINDOWS="${WINDOWS:-8}"; SESS="${SESSIONS:-20}"
jit(){ sleep $((1 + RANDOM % 3)); }

echo "== Grup2 (SCTP): ${WINDOWS} window × ${SESS} flow/ kelas =="
docker compose up -d attacker >/dev/null 2>&1 || true
sleep 3

# label : mode-tool : scenario-id-base : iface
for spec in "nas_tamper_registration:tamper_registration:NB2-TAMPER:N2" \
            "nas_replay_n1:replay:NB2-REPLAY:N1" \
            "bidding_down:bidding_down:NB2-BID:N2"; do
  IFS=: read -r label mode base iface <<< "$spec"
  echo "###### ${label} (attacker → AMF N2/SCTP) ######"
  for i in $(seq 1 "$WINDOWS"); do
    bash "$RS" 3 "${base}-e${i}" "$label" "$ATT_UP" "$AMF_N2" "$iface" 30 $OK -- \
      docker exec -e SESSIONS="$SESS" attacker \
        python3 /opt/attacker/tools/nas_attack.py "$mode" "$AMF_N2" 38412
    jit
  done
done

echo "== Grup2 selesai. Jalankan capture_stop.sh lalu label_pcap.py --all =="
