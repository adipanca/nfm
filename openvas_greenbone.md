# OpenVAS / Greenbone — scan penuh NF 5G (Fase 6)

Testbed menyediakan **dua jalur** vulnerability scanning NF core:

## 1. Scan cepat (nmap) — default, tanpa internet
```bash
bash scripts/openvas_scan.sh --nmap      # service + NSE vuln + ssl-enum thd NF cp
python3 scripts/openvas_export.sh        # → reports/scan/nf_findings_*.json/.csv
```
Hasil: port terbuka, service, cipher TLS, dan tanda CVE per NF. Cepat, cocok untuk
iterasi harian. Output di `reports/scan/`.

## 2. Scan penuh Greenbone/OpenVAS — paling lengkap
Container `openvas` (profile `scanner`) memakai image all-in-one `immauss/openvas`.

```bash
# 1) Nyalakan (first-run sinkron feed NVT: beberapa GB, BUTUH internet, ~30-60 mnt)
docker compose --profile scanner up -d openvas
docker logs -f openvas            # tunggu "Feed update ... done" / gvmd siap

# 2) Akses UI Greenbone (via Host-only VirtualBox)
#    https://<IP-VM-hostonly>:9392   user: admin  pass: $OPENVAS_PASSWORD

# 3) Buat Target = subnet NF 172.22.0.0/24 (atau daftar IP .20-.29),
#    buat Task "Full and fast", jalankan. Lalu ekspor report (XML).

# 4) Otomatis via gvm-cli (setelah feed siap):
bash scripts/openvas_scan.sh              # auto-deteksi container openvas → mode Greenbone
```

**Isolasi:** `openvas` terhubung ke net `cp` (internal) agar menjangkau NF, dan
port UI 9392 dipublish HANYA ke Host-only. Feed sync butuh internet sesaat — lakukan
saat VM punya NAT, lalu scan boleh offline. Jangan arahkan scan ke luar
`172.22.0.0/24` (kebijakan lab).

## Catatan hasil
Open5GS 2.7.5 dgn SBI over TLS relatif ketat; temuan nmap umumnya berupa
enumerasi port SBI (7777/TLS) + metrics (9090). Greenbone menambah ribuan NVT
(mis. cek TLS, HTTP/2, konfigurasi) → lebih banyak temuan untuk analisis LLM (Fase 8).
Kombinasikan dengan `scripts/tls_scan.sh` (status cert/cipher/mTLS per NF, dasar Tier 5).
