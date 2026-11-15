#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Fase 6b (Tier 5) — Buat varian sertifikat TLS yang RENTAN untuk SBI.
# Dipakai oleh "NF palsu/rentan" (nf-weak) agar scanner menandai:
#   T5-01  cert self-signed / kedaluwarsa   → vuln_tls_cert
#   (T5-02 cipher lemah/TLS1.0-1.1 = konfigurasi server, lihat run_tier5.sh)
#
# CATATAN KEAMANAN: cert ini SENGAJA buruk, hanya untuk endpoint uji di net
# cp (172.22.0.60) di lab terisolasi. JANGAN dipakai NF produksi.
# Butuh openssl ≥ 3.2 di host (opsi -not_before/-not_after).
#   ./tls/make_weak_certs.sh [--force]
# ─────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")"
OUT="weak"; mkdir -p "$OUT"
FORCE="${1:-}"
WEAK_IP="172.22.0.60"   # IP endpoint nf-weak di net cp (harus sama dgn run_tier5.sh)

need() { command -v "$1" >/dev/null || { echo "[!] butuh $1"; exit 1; }; }
need openssl
if ! openssl x509 -help 2>&1 | grep -q -- '-not_after'; then
  echo "[!] openssl host tak punya -not_after (butuh ≥3.2). Versi: $(openssl version)"; exit 1
fi

gen_expired_selfsigned() {   # T5-01: self-signed DAN kedaluwarsa (2020)
  local key="$OUT/weak.key" crt="$OUT/weak.crt"
  if [[ -f "$crt" && "$FORCE" != "--force" ]]; then echo "[i] $crt ada, lewati (pakai --force)."; return; fi
  openssl req -nodes -newkey rsa:2048 -keyout "$key" -out "$OUT/weak.csr" \
    -subj "/C=ID/O=NFM-Testbed-Lab/OU=5G-SBI-WEAK/CN=nf-weak" \
    -addext "subjectAltName=DNS:nf-weak,IP:${WEAK_IP}" 2>/dev/null
  # Self-signed (issuer==subject) + rentang waktu sudah lewat → expired.
  openssl x509 -req -in "$OUT/weak.csr" -signkey "$key" \
    -not_before 20200101000000Z -not_after 20210101000000Z \
    -copy_extensions copyall -out "$crt" 2>/dev/null
  rm -f "$OUT/weak.csr"; chmod 644 "$key"
  echo "[OK] $crt  (self-signed, EXPIRED 2020-01-01..2021-01-01, SAN IP:${WEAK_IP})"
}

gen_weakkey() {              # bonus: kunci RSA-1024 lemah (self-signed), utk dokumentasi
  local key="$OUT/weakkey.key" crt="$OUT/weakkey.crt"
  if [[ -f "$crt" && "$FORCE" != "--force" ]]; then echo "[i] $crt ada, lewati."; return; fi
  openssl req -x509 -nodes -newkey rsa:1024 -keyout "$key" -out "$crt" -days 3650 \
    -subj "/C=ID/O=NFM-Testbed-Lab/OU=5G-SBI-WEAK/CN=nf-weakkey" 2>/dev/null
  chmod 644 "$key"
  echo "[OK] $crt  (RSA-1024 lemah, self-signed)"
}

gen_weak_openssl_cnf() {    # override policy sistem (Ubuntu MinProtocol=TLSv1.2)
  local cnf="$OUT/openssl_weak.cnf"
  cat > "$cnf" <<'CNF'
# Konfigurasi openssl SENGAJA lemah untuk endpoint uji nf-weak (T5-02).
# Menurunkan MinProtocol & SECLEVEL agar TLS 1.0/1.1 + cipher lemah diizinkan.
openssl_conf = default_conf
[default_conf]
ssl_conf = ssl_sect
[ssl_sect]
system_default = system_default_sect
[system_default_sect]
MinProtocol = TLSv1
MaxProtocol = TLSv1.1
CipherString = ALL:@SECLEVEL=0
CNF
  echo "[OK] $cnf  (MinProtocol=TLSv1, SECLEVEL=0)"
}

gen_expired_selfsigned
gen_weakkey
gen_weak_openssl_cnf
echo "==> Sertifikat rentan siap di tls/$OUT/ — dipakai nf-weak (run_tier5.sh vuln)."
echo "    Verifikasi: openssl x509 -in tls/weak/weak.crt -noout -subject -issuer -dates"
