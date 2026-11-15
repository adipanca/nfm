#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Daftarkan IMSI UE uji ke MongoDB Open5GS (skema subscriber 2.7.x).
# Idempoten: upsert berdasarkan imsi. Dijalankan setelah 'mongo' naik.
#   bash subscribers/add_subs.sh
# Jalankan di grup docker (user biasa) atau: sg docker -c "bash subscribers/add_subs.sh"
# ─────────────────────────────────────────────────────────────
set -euo pipefail
MONGO_CONT="${MONGO_CONT:-mongo}"
K="${SUBS_K:-465B5CE8B199B49FAA5F0A2EE238A6BC}"
OPC="${SUBS_OPC:-E8ED289DEBA952E4283B54E88E6183CA}"
IMSIS=( 999700000000001 999700000000002 999700000000003 )

echo "==> Menunggu MongoDB siap di container '${MONGO_CONT}'..."
for i in $(seq 1 30); do
  if docker exec "${MONGO_CONT}" mongosh --quiet --eval 'db.runCommand({ping:1}).ok' 2>/dev/null | grep -q 1; then
    echo "    Mongo siap."; break
  fi
  sleep 2
  [[ $i -eq 30 ]] && { echo "[!] Mongo tidak siap." >&2; exit 1; }
done

for IMSI in "${IMSIS[@]}"; do
  echo "==> Upsert subscriber IMSI=${IMSI}"
  EVAL='db.subscribers.updateOne(
    { imsi: "'"${IMSI}"'" },
    { $set: {
        imsi: "'"${IMSI}"'",
        subscribed_rau_tau_timer: 12, network_access_mode: 0,
        subscriber_status: 0, access_restriction_data: 32,
        ambr: { uplink: { value: 1, unit: 3 }, downlink: { value: 1, unit: 3 } },
        slice: [ { sst: 1, default_indicator: true,
          session: [ { name: "internet", type: 3,
            qos: { index: 9, arp: { priority_level: 8, pre_emption_capability: 1, pre_emption_vulnerability: 1 } },
            ambr: { uplink: { value: 1, unit: 3 }, downlink: { value: 1, unit: 3 } } } ] } ],
        security: { k: "'"${K}"'", opc: "'"${OPC}"'", op: null, amf: "8000" },
        schema_version: 1, __v: 0
    } },
    { upsert: true }
  ); print("  -> count=" + db.subscribers.countDocuments({ imsi: "'"${IMSI}"'" }));'
  docker exec "${MONGO_CONT}" mongosh open5gs --quiet --eval "$EVAL"
done

echo "==> Total subscriber terdaftar:"
docker exec "${MONGO_CONT}" mongosh open5gs --quiet --eval 'print(db.subscribers.countDocuments({}))'
echo "Selesai."
