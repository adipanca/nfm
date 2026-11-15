#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Tier 5 — TLS (SBI terenkripsi). Acuan: 3GPP TS 33.501; testssl.sh/sslscan.
# Dua sisi:
#   (A) KERENTANAN TLS yang ditemukan scanner (tls_scan.sh):
#       T5-01 vuln_tls_cert       — cert self-signed/kedaluwarsa (endpoint nf-weak)
#       T5-02 vuln_tls_weakcipher — TLS 1.0/1.1 + cipher lemah diizinkan (nf-weak)
#       T5-03 vuln_tls_no_mtls    — SBI tanpa mutual TLS (NF asli: mtls_required=no)
#   (B) SERANGAN DI ATAS TLS yang harus dideteksi NFM meski terenkripsi:
#       T5-04 sbi_attack_over_tls — varian Tier 4 (HTTP/2 DoS) via kanal TLS
#       T5-05 tls_handshake_flood — banjir handshake + percobaan downgrade
#
#   bash scenarios/tier5_tls/run_tier5.sh [all|vuln|attack|T5-04|T5-05]
#
# Untuk T5-04/05: jalankan capture_start.sh SEBELUM & capture_stop.sh SESUDAH,
# lalu label_pcap.py --all (agar dataset lama tetap utuh).
# ─────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/../.."
RS="scripts/run_scenario.sh"
OK="--i-understand-lab-only"
NRF="172.22.0.20"; SRC="172.22.0.50"
WEAK_IP="172.22.0.60"; WEAK_NAME="nf-weak"
ATT="docker exec attacker"

ensure_attacker() {
  docker compose up -d attacker >/dev/null 2>&1 || docker start attacker >/dev/null 2>&1 || true
  sleep 3
}

# ── (A) Kerentanan TLS: nyalakan NF palsu rentan, lalu pindai ──────────────
run_vuln() {
  echo "###### Tier 5 (A) — kerentanan TLS (scanner) ######"
  # 1) Pastikan cert rentan ada (self-signed + expired).
  [[ -f tls/weak/weak.crt ]] || bash tls/make_weak_certs.sh
  # 2) Endpoint nf-weak di net cp: TLS 1.0/1.1 + cipher lemah (SECLEVEL=0),
  #    menyajikan cert self-signed yang sudah kedaluwarsa.
  docker rm -f "$WEAK_NAME" >/dev/null 2>&1 || true
  echo "==> Menyalakan $WEAK_NAME ($WEAK_IP:7777) — TLS lemah utk T5-01/02"
  docker run -d --rm --name "$WEAK_NAME" --network nfm_cp --ip "$WEAK_IP" \
    -v "$PWD/tls/weak:/weak:ro" -e OPENSSL_CONF=/weak/openssl_weak.cnf nfm/attacker:latest \
    openssl s_server -accept 7777 -cert /weak/weak.crt -key /weak/weak.key -www >/dev/null
  sleep 2
  docker ps --format '{{.Names}}' | grep -qx "$WEAK_NAME" || { echo "[!] $WEAK_NAME gagal naik"; return 1; }
  # 3) Pindai NF asli + nf-weak sekaligus (T5-03 dari NF asli, T5-01/02 dari nf-weak).
  echo "==> tls_scan.sh (NF asli + $WEAK_NAME)"
  TLS_EXTRA_TARGETS="${WEAK_NAME}:${WEAK_IP}" bash scripts/tls_scan.sh || true
  # 4) Matikan endpoint rentan (jangan dibiarkan hidup).
  docker rm -f "$WEAK_NAME" >/dev/null 2>&1 || true
  echo "==> $WEAK_NAME dimatikan. Ringkasan kerentanan ada di reports/tls/."
  echo "    T5-01 → kolom self_signed=yes / cert_expired=yes (nf-weak)"
  echo "    T5-02 → kolom weak_tls_1_0_1_1=yes (nf-weak)"
  echo "    T5-03 → kolom mtls_required=no (semua NF asli)"
}

# ── (B) Serangan di atas TLS (trafik utk NFM) ─────────────────────────────
run_T5_04() {  # HTTP/2 DoS lewat kanal TLS (varian T4-01, dilabel khusus Tier 5)
  ensure_attacker
  bash "$RS" 5 T5-04 sbi_attack_over_tls "$SRC" "$NRF" TLS 20 $OK -- \
    $ATT h2load -n 200000 -c 40 -m 100 --duration=15 "https://$NRF:7777/"
}
run_T5_05() {  # Banjir handshake TLS + percobaan downgrade
  ensure_attacker
  bash "$RS" 5 T5-05 tls_handshake_flood "$SRC" "$NRF" TLS 25 $OK -- \
    $ATT python3 /opt/attacker/tools/tls_flood.py "$NRF" 7777 20 30
}
run_attack() { run_T5_04; echo; sleep 3; run_T5_05; }

WHICH="${1:-all}"
case "$WHICH" in
  all)    run_vuln; echo; run_attack ;;
  vuln)   run_vuln ;;
  attack) run_attack ;;
  T5-04)  run_T5_04 ;;
  T5-05)  run_T5_05 ;;
  *) echo "tak dikenal: $1 (pakai: all|vuln|attack|T5-04|T5-05)"; exit 2 ;;
esac
echo "== Tier 5 selesai =="
