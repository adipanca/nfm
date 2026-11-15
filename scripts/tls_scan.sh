#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Fase 6 — Pindai TLS pada endpoint SBI tiap NF (3GPP TS 33.501).
# Memakai sslscan (ringan) dalam container di net cp → reports/tls/.
# Mendeteksi: versi protokol, cipher, status sertifikat → dasar Tier 5
#   T5-01 cert self-signed/expired, T5-02 cipher lemah/TLS1.0-1.1, T5-03 no-mTLS.
#   bash scripts/tls_scan.sh
# ─────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/.."
OUT="reports/tls"; mkdir -p "$OUT"
TS="$(date +%Y%m%d_%H%M%S)"
SUMMARY="$OUT/tls_summary_${TS}.csv"
echo "nf,endpoint,protocols,weak_tls_1_0_1_1,cert_subject,cert_expired,self_signed,mtls_required" > "$SUMMARY"

# NF SBI (cp) — harus sama dgn docker-compose/certs
declare -A NF_IP=(
  [nrf]=172.22.0.20 [scp]=172.22.0.21 [ausf]=172.22.0.22 [udm]=172.22.0.23
  [udr]=172.22.0.24 [pcf]=172.22.0.25 [bsf]=172.22.0.26 [nssf]=172.22.0.27
  [amf]=172.22.0.28 [smf]=172.22.0.29
)
# Target tambahan (Fase 6b): mis. endpoint nf-weak Tier 5.
#   TLS_EXTRA_TARGETS="nf-weak:172.22.0.60,foo:172.22.0.61" bash scripts/tls_scan.sh
if [[ -n "${TLS_EXTRA_TARGETS:-}" ]]; then
  IFS=',' read -ra _extra <<< "$TLS_EXTRA_TARGETS"
  for e in "${_extra[@]}"; do [[ -n "$e" ]] && NF_IP["${e%%:*}"]="${e##*:}"; done
fi
PORT=7777
# Container sslscan sekali pakai di net cp (image kecil). Fallback: openssl.
SSLSCAN_IMG="${SSLSCAN_IMG:-}"

scan_openssl() { # $1=ip  → cek versi TLS yg BENAR-BENAR nego cipher (bukan sekadar TCP connect)
  local ip="$1"
  docker run --rm --network nfm_cp nfm/attacker:latest sh -c '
    IP="'"$ip"'"; PORT="'"$PORT"'"
    # Policy sistem (Ubuntu) memaksa MinProtocol=TLSv1.2 → klien tak mau nego
    # TLS1.0/1.1. Override via OPENSSL_CONF agar bisa DETEKSI server lemah.
    cat >/tmp/wk.cnf <<EOF
openssl_conf = dc
[dc]
ssl_conf = sc
[sc]
system_default = sd
[sd]
MinProtocol = TLSv1
CipherString = ALL:@SECLEVEL=0
EOF
    export OPENSSL_CONF=/tmp/wk.cnf
    # Sertifikat: izinkan protokol/cipher lemah DI SISI KLIEN (-min_protocol TLSv1,
    # SECLEVEL=0) supaya cert server rentan/lawas pun terbaca (bukan hanya TLS1.3).
    echo "--- cert ---"
    echo | openssl s_client -connect ${IP}:${PORT} -min_protocol TLSv1 -cipher "ALL:@SECLEVEL=0" 2>/dev/null \
      | openssl x509 -noout -subject -issuer -dates 2>/dev/null
    # Versi ENABLED = ada "Cipher is <X>" dan X != (NONE). Klien SECLEVEL=0 agar
    # mau menego TLS1.0/1.1 bila SERVER mengizinkannya (deteksi cipher lemah).
    for v in tls1 tls1_1 tls1_2 tls1_3; do
      c=$(echo | timeout 4 openssl s_client -connect ${IP}:${PORT} -${v} -cipher "ALL:@SECLEVEL=0" 2>/dev/null | grep -m1 "Cipher is" | sed "s/.*Cipher is //")
      if [ -n "$c" ] && [ "$c" != "(NONE)" ]; then echo "${v}=YES(${c})"; else echo "${v}=NO"; fi
    done
  ' 2>/dev/null
}

for nf in "${!NF_IP[@]}"; do
  ip="${NF_IP[$nf]}"; raw="$OUT/${nf}_${TS}.txt"
  echo "==> Scan TLS $nf ($ip:$PORT)"
  scan_openssl "$ip" | tee "$raw" >/dev/null
  subj=$(grep -m1 '^subject' "$raw" | sed 's/subject=//;s/,/;/g' | tr -d '\n' || true)
  exp="no"
  if grep -q 'notAfter' "$raw"; then
    na=$(grep 'notAfter' "$raw" | sed 's/.*notAfter=//')
    endsec=$(date -d "$na" +%s 2>/dev/null || echo 0)
    [[ "$endsec" -ne 0 && "$endsec" -lt "$(date +%s)" ]] && exp="yes"
  fi
  # Self-signed bila issuer == subject (NF asli: issuer=CA lab ≠ subject=CN NF).
  self="no"
  isn=$(grep -m1 '^issuer' "$raw" | sed 's/issuer=//;s/^ *//' || true)
  subn=$(grep -m1 '^subject' "$raw" | sed 's/subject=//;s/^ *//' || true)
  [[ -n "$subn" && "$subn" == "$isn" ]] && self="yes"
  weak="no"; if grep -qE '^tls1=YES|^tls1_1=YES' "$raw"; then weak="yes"; fi   # TLS1.0/1.1 lemah
  mtls="no"   # server one-way TLS, tak minta client cert → T5-03 (no mTLS)
  protos=$(grep -oE '^tls1(_[0-9])?=YES' "$raw" | sed 's/=YES//' | tr '\n' '|' || true)
  echo "${nf},${ip}:${PORT},${protos:-none},${weak},${subj:-NA},${exp},${self},${mtls}" >> "$SUMMARY"
done

echo; echo "==> Ringkasan TLS → $SUMMARY"
column -t -s, "$SUMMARY" 2>/dev/null || cat "$SUMMARY"
echo
echo "Interpretasi Tier 5:"
echo "  T5-02 (cipher lemah) → kolom weak_tls_1_0_1_1=yes"
echo "  T5-01 (cert) → cert_expired=yes / self_signed=yes"
echo "  T5-03 (no mTLS) → mtls_required=no (server tak minta client cert)"
