#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Fase 2/3 — Nyalakan UE normal (ue1, ue2) + verifikasi PDU session.
# Membuktikan kriteria selesai Fase 2:
#   - UE dapat IP dari pool 10.45.x.x (uesimtun0)
#   - ping UE → webserver (N6) BERHASIL
#   - ping UE → 8.8.8.8 GAGAL (isolasi total)
# ─────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/.."
DC() { docker compose "$@"; }
DX() { docker "$@"; }

WEB_IP="172.24.0.10"
UES=( "${@:-ue1 ue2}" )   # default ue1 ue2; bisa override: register_ue.sh ue1

echo "==> Menyalakan UE: ${UES[*]}"
DC up -d ${UES[*]}

for UE in ${UES[*]}; do
  echo
  echo "──────── $UE ────────"
  # Tunggu uesimtun0 muncul (PDU session aktif)
  IP=""
  for i in $(seq 1 30); do
    IP=$(DX exec "$UE" sh -c "ip -4 addr show uesimtun0 2>/dev/null | awk '/inet /{print \$2}' | cut -d/ -f1" 2>/dev/null || true)
    [[ -n "$IP" ]] && break
    sleep 2
  done
  if [[ -z "$IP" ]]; then
    echo "[!] $UE: uesimtun0 tidak muncul. Log:"; DX exec "$UE" sh -c "tail -5 /dev/null" 2>/dev/null || true
    DX logs "$UE" 2>&1 | tail -8 || true
    continue
  fi
  echo "[OK] $UE dapat IP PDU: $IP"
  case "$IP" in 10.45.*) echo "[OK] IP dari pool 10.45.0.0/16" ;; *) echo "[!] IP di luar pool!" ;; esac

  # N6: ping webserver lewat uesimtun0
  if DX exec "$UE" ping -I uesimtun0 -c 3 -W 2 "$WEB_IP" >/dev/null 2>&1; then
    echo "[OK] N6: ping $UE → webserver ($WEB_IP) BERHASIL"
  else
    echo "[!] N6: ping $UE → webserver GAGAL"
  fi
  # HTTP ke webserver
  if DX exec "$UE" sh -c "command -v curl >/dev/null && curl -s --interface uesimtun0 -o /dev/null -w '%{http_code}' http://$WEB_IP/ || wget -qO- --bind-address=$IP http://$WEB_IP/ >/dev/null && echo 200" 2>/dev/null | grep -q 200; then
    echo "[OK] N6: HTTP GET webserver 200"
  fi
  # Isolasi: ping internet HARUS gagal
  if DX exec "$UE" ping -I uesimtun0 -c 2 -W 2 8.8.8.8 >/dev/null 2>&1; then
    echo "[!!] ISOLASI BOCOR: $UE bisa ping 8.8.8.8 — periksa jaringan internal!"
  else
    echo "[OK] Isolasi: $UE TIDAK bisa ping 8.8.8.8 (sesuai syarat lab)"
  fi
done

echo
echo "Verifikasi UE selesai."
