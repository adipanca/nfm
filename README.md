# NFM Testbed 5G — Deteksi Serangan & Vulnerability Scanning pada Private 5G

Testbed **private 5G** berbasis **Open5GS (5G Core) + UERANSIM (gNB/UE) di dalam Docker**, berjalan di satu VM Linux (VirtualBox). Tujuannya menghasilkan trafik 5G **normal** dan **serangan** yang terkontrol dan berlabel, untuk:

1. **Vulnerability scanning** terhadap Network Function (NF) 5G → laporan OpenVAS/Greenbone.
2. **Deteksi serangan** dengan **Network Foundation Model (NFM)**, misalnya netFound.
3. **Analisis & prioritas** hasil NFM + laporan scan dengan **LLM**.

**SBI antar-NF diamankan dengan TLS** (sesuai 3GPP TS 33.501), sehingga testbed ini juga menguji kemampuan NFM pada **trafik terenkripsi** — klaim utama netFound — dan memberi scanner "pekerjaan nyata" berupa kerentanan konfigurasi TLS.

Setiap skenario serangan di sini **dimodelkan dari paper, jurnal, atau CVE nyata** (lihat kolom "Rujukan"), bukan dikarang, agar trafiknya mendekati serangan asli dan penelitian ini berkontribusi.

> Dokumen ini juga menjadi **spesifikasi kerja untuk Claude Code CLI** — lihat [Instruksi untuk Claude Code](#instruksi-untuk-claude-code).

---

## ⚠️ Aturan Keamanan (WAJIB BACA)

- Lab ini menjalankan serangan terhadap NF 5G yang **sengaja dibuat rentan**. Jaringan harus **terisolasi total**.
- Jaringan Docker core/RAN **harus `internal: true`** — tanpa internet, tanpa port publish ke luar kecuali UI OpenVAS lewat Host-only.
- Semua serangan **hanya** ke IP di subnet lab (`10.45.0.0/16` untuk UE, `172.22.0.0/24` untuk NF). **Dilarang** mengarahkan ke IP di luar lab.
- **Jangan pernah** menjalankan skenario ini terhadap jaringan seluler operator sungguhan, kartu SIM komersial, atau perangkat yang bukan milik Anda. Beberapa serangan di sini (flooding NGAP/PFCP, crash AMF/UPF) bisa melumpuhkan jaringan nyata dan melanggar hukum (termasuk UU ITE).
- Gunakan **versi Open5GS yang sengaja rentan** (lihat Tier 2–4) hanya untuk reproduksi CVE di lab tertutup. Jangan pakai di produksi.
- Adapter VM VirtualBox: **NAT** (unduh image) + **Host-only** (akses UI). **Jangan Bridged.**

---

## Arsitektur

```
Windows (host)
 └── VirtualBox — VM Ubuntu Server 24.04 (≥ 16 GB RAM, 6 vCPU, 120 GB disk)
      └── Docker
           ├── lab-CA (step-ca/openssl) → terbitkan cert tiap NF untuk TLS SBI
           ├── net "cp" 172.22.0.0/24  (control plane, internal)
           │    ├── nrf  scp  ausf  udm  udr  pcf  bsf  nssf  amf  smf   ← SBI over TLS
           │    └── mongo (subscriber DB)
           ├── net "up" 172.23.0.0/24  (user plane N3/N4, internal)
           │    ├── upf
           │    └── gnb (UERANSIM)   ── N2→amf, N3→upf
           ├── net "ue" 10.45.0.0/16 (pool IP UE, via UPF)
           │    ├── ue1 ue2 ... (UERANSIM, trafik normal)
           │    └── ue-mal (UE jahat, sumber serangan dari sisi pelanggan)
           ├── net "dn" 172.24.0.0/24 (data network / N6)
           │    └── webserver (nginx) + dns  ← tujuan trafik UE
           ├── attacker (Kali, di net cp+up) ← serangan dari sisi jaringan inti
           ├── openvas (profile scanner)
           └── tcpdump di host VM pada br-cp / br-up / br-dn → data/raw/*.pcap
```

**Titik tangkap (capture point) yang direkam:**

| Interface | Antara | Protokol | Kenapa menarik |
|---|---|---|---|
| **N1/N2** | UE/gNB ↔ AMF | NAS, NGAP/SCTP | Signaling registrasi & mobilitas |
| **N3** | gNB ↔ UPF | GTP-U (UDP 2152) | Trafik pengguna ter-tunnel |
| **N4** | SMF ↔ UPF | PFCP (UDP 8805) | Kontrol sesi PDU |
| **N6** | UPF ↔ data network | IP biasa | Trafik keluar UE (mirip internet) |
| **SBI** | antar-NF di core | HTTP/2 **over TLS** | REST khas 5G (Nxxx services), kini terenkripsi — uji NFM pada trafik terenkripsi |

---

## Model Serangan (berbasis rujukan nyata)

Serangan disusun bertingkat (Tier). **Mulai dari Tier 0**, lalu naik sesuai kesiapan. Tier makin tinggi makin "khas 5G" dan makin tinggi nilai kebaruannya, tapi makin kompleks.

### Tier 0 — N6 / User plane (paling mudah, aman untuk tokenizer netFound)
Serangan klasik dari UE ke server di data network. Trafiknya IP biasa sehingga netFound langsung mengenalinya. **Model acuan: dataset 5G-NIDD (Samarakoon et al., 2022).**

| ID | Skenario | Label | Tool | Rujukan |
|---|---|---|---|---|
| T0-01 | SYN scan / TCP connect / UDP scan dari UE | `recon_portscan` | nmap | 5G-NIDD |
| T0-02 | SYN Flood | `dos_synflood` | hping3 | 5G-NIDD |
| T0-03 | UDP Flood | `dos_udpflood` | hping3 | 5G-NIDD |
| T0-04 | ICMP Flood | `dos_icmpflood` | hping3 | 5G-NIDD |
| T0-05 | HTTP Flood | `dos_httpflood` | locust/ab | 5G-NIDD |
| T0-06 | Slow-rate DoS (Slowloris) | `dos_slowrate` | slowhttptest | 5G-NIDD |

### Tier 1 — N3 / GTP-U anomali (user plane)
UE jahat menyusupkan paket GTP-U cacat sehingga ter-tunnel ke UPF (serangan "GTP-U in GTP-U").

| ID | Skenario | Label | Rujukan |
|---|---|---|---|
| T1-01 | GTP-U malformed (zero-length, message type 0xFF) ke UPF | `gtpu_malformed` | **CVE-2021-45462** (Open5GS UPF crash); Trend Micro, "Attacks on 5G Infrastructure From Users' Devices" (2023) |

### Tier 2 — N4 / PFCP (control plane SMF↔UPF)
**Model acuan: Amponis et al., "Threatening the 5G core via PFCP DoS attacks", EURASIP JWCN 2022** — lima serangan PFCP.

| ID | Skenario | Label | Rujukan |
|---|---|---|---|
| T2-01 | Unauthorised PFCP Session Deletion Request | `pfcp_session_delete` | Amponis et al. 2022 |
| T2-02 | Unauthorised PFCP Session Modification Request | `pfcp_session_modify` | Amponis et al. 2022 |
| T2-03 | PFCP Session Establishment Flood | `pfcp_estab_flood` | Amponis et al. 2022; **CVE-2024-51179** (Open5GS Issue #3497) |
| T2-04 | Unauthorised UPF forwarding-rule misconfig | `pfcp_rule_misconfig` | Amponis et al. 2022 |
| T2-05 | PFCP MitM (SMF↔UPF intercept/modify) | `pfcp_mitm` | Inventi Impact 2024, "MitM on PFCP" |

### Tier 3 — N1/N2 / NAS & NGAP (signaling)
**Model acuan: "5G Attacks: Realistic Scenarios and Simulations Using Open5GS", ISeCure Vol.17 No.3, 2025.**

| ID | Skenario | Label | Rujukan |
|---|---|---|---|
| T3-01 | Registration flooding (banjir UE register/dereg) | `nas_reg_flood` | ISeCure 2025; VulDB #626112/#626118 (Open5GS ≤2.7.5 AMF DoS) |
| T3-02 | AMF exhaustion via NGSetupRequest massal | `ngap_ngsetup_flood` | ISeCure 2025 |
| T3-03 | Malformed NGAP packet → crash AMF | `ngap_malformed` | **CVE-2024-24429** (RANsacked) |
| T3-04 | Tampering parameter keamanan saat registrasi UE | `nas_auth_tamper` | ISeCure 2025 |

### Tier 4 — SBI / HTTP/2 (antar-NF)
**Model acuan: Positive Technologies "5G Standalone Core Security Assessment"; dataset HTTP/2 5G SBA (Free5GC, IEEE DataPort).**

| ID | Skenario | Label | Rujukan |
|---|---|---|---|
| T4-01 | SBI DoS via HTTP/2 churn (RST_STREAM saat PDU release) | `sbi_http2_dos` | VulDB #626122 (Open5GS ≤2.7.5 SMF DoS) |
| T4-02 | NF profile enumeration / impersonation ke NRF | `sbi_nf_impersonation` | Positive Technologies |

### Tier 5 — TLS (SBI terenkripsi)
Dua sisi: **(A) kerentanan TLS** yang ditemukan scanner, dan **(B) serangan di atas TLS** yang harus dideteksi NFM meski terenkripsi. **Acuan: 3GPP TS 33.501 (TLS wajib di SBI); tool uji testssl.sh/sslscan.**

| ID | Skenario | Label | Jenis | Rujukan |
|---|---|---|---|---|
| T5-01 | NF pakai cert self-signed / kedaluwarsa | `vuln_tls_cert` | Kerentanan (scanner) | TS 33.501; testssl.sh |
| T5-02 | Cipher lemah / TLS 1.0–1.1 diizinkan | `vuln_tls_weakcipher` | Kerentanan (scanner) | TS 33.501; testssl.sh |
| T5-03 | SBI tanpa mutual TLS → NF menyamar | `vuln_tls_no_mtls` | Kerentanan (scanner) | TS 33.501; Positive Technologies |
| T5-04 | Serangan Tier 4 dijalankan **melalui kanal TLS** | `sbi_attack_over_tls` | Serangan (NFM) | — (varian T4 terenkripsi) |
| T5-05 | Handshake TLS gagal berulang / percobaan downgrade | `tls_handshake_flood` | Serangan (NFM) | — |

> **Nilai riset Tier 5:** jalankan skenario SBI (T4) dalam dua kondisi — **tanpa TLS** vs **dengan TLS** — lalu bandingkan akurasi deteksi NFM. Selisihnya menunjukkan seberapa baik NFM bekerja saat payload tak terbaca dan hanya metadata/handshake/timing yang tersisa.

> **Catatan penting tokenizer:** netFound dirancang untuk IP/TCP/UDP umum. **Tier 0–1 aman** (trafik N6 & GTP-U membungkus IP biasa). **Tier 2–4** memakai protokol khas 5G (PFCP, NGAP/SCTP, HTTP/2 SBI) yang mungkin belum dikenali tokenizer netFound. Dua jalur:
> - **Aman:** fokus Tier 0–1 dulu untuk hasil cepat.
> - **Kontribusi lebih besar:** perluas tokenizer netFound agar protocol-aware untuk PFCP/NGAP — ini bisa jadi klaim kebaruan tersendiri.
>
> Untuk **Tier 5**, payload SBI terenkripsi sehingga NFM hanya melihat metadata TLS/TCP (ukuran, arah, timing, pola handshake) — justru inilah skenario yang paling pas untuk menonjolkan keunggulan NFM dibanding metode berbasis isi.

---

## Ground Truth & Pelabelan

`run_scenario.sh` mencatat tiap skenario ke `data/ground_truth.csv`:
```csv
tier,scenario_id,label,src_ip,dst_ip,iface,start_epoch,end_epoch
2,T2-03,pfcp_estab_flood,172.22.0.x,172.23.0.x,N4,1762750000,1762750090
```
`label_pcap.py` memotong PCAP mentah berdasarkan **jendela waktu + interface + pasangan IP/port protokol**, lalu menyimpan per label ke `data/labeled/<label>/`. Trafik UE normal → `benign`. Trafik scan OpenVAS → `scan_openvas` (dipisah). Paket tak cocok → `unknown` untuk diperiksa manual.

---

## Prasyarat

- **VM:** Ubuntu Server 24.04, ≥ 16 GB RAM (Open5GS punya belasan NF + UERANSIM + Mongo), 6 vCPU, 120 GB disk.
- **Di VM:** Docker Engine + compose, `tcpdump`, `tshark`/`editcap`, `python3-venv`, `git`, Claude Code CLI.
- **GPU:** VirtualBox tidak meneruskan GPU → **fine-tuning netFound dilakukan di luar VM** (Colab/Kaggle/WSL2+CUDA). VM ini hanya menghasilkan & melabeli data.
- **Image 5G:** gunakan proyek siap pakai sebagai basis (verifikasi dulu oleh Claude Code):
  - `docker_open5gs` (herlesupreeth) — Open5GS + UERANSIM dalam compose.
  - atau `open5gs` resmi + image UERANSIM komunitas.

---

## Struktur Direktori

```
nfm-testbed-5g/
├── README.md
├── docker-compose.yml           # core + RAN + UE + DN + attacker
├── .env.example                 # PLMN/MCC/MNC, OpenVAS pass, versi image
├── configs/                     # yaml Open5GS (amf,smf,upf,...) + ueransim (gnb,ue)
├── tls/                         # CA lab + sertifikat per-NF untuk SBI
│   ├── gen_ca.sh                # buat CA lab (openssl/step-ca)
│   ├── gen_nf_certs.sh          # terbitkan cert tiap NF (SAN = nama service NRF)
│   └── make_weak_certs.sh       # varian rentan utk T5 (self-signed/expired/weak)
├── subscribers/add_subs.sh      # daftarkan IMSI UE ke Mongo (Open5GS)
├── docker/attacker/Dockerfile   # Kali + nmap,hping3,slowhttptest,scapy,gtp/pfcp tools
├── scenarios/
│   ├── tier0_n6/                # T0-01..06
│   ├── tier1_gtpu/              # T1-01
│   ├── tier2_pfcp/              # T2-01..05
│   ├── tier3_nas_ngap/          # T3-01..04
│   ├── tier4_sbi/               # T4-01..02
│   └── tier5_tls/               # T5-01..05 (vuln TLS + serangan over-TLS)
├── scripts/
│   ├── setup_vm.sh  lab_up.sh  lab_down.sh
│   ├── register_ue.sh           # nyalakan UE normal + verifikasi PDU session
│   ├── normal_traffic.sh        # trafik N6 normal dari UE
│   ├── capture_start.sh / capture_stop.sh   # tcpdump multi-interface
│   ├── run_scenario.sh / run_all.sh         # cek subnet, timeout, ground truth
│   ├── openvas_scan.sh / openvas_export.sh  # scan NF → reports/
│   ├── tls_scan.sh                          # testssl.sh/sslscan pada SBI → reports/
│   └── label_pcap.py
├── data/ raw/  labeled/  ground_truth.csv
└── reports/
```

---

## Alur Pakai (ringkas)

```bash
./scripts/setup_vm.sh
./tls/gen_ca.sh && ./tls/gen_nf_certs.sh   # CA lab + cert tiap NF (untuk TLS SBI)
docker compose build                 # butuh internet (NAT)
./scripts/lab_up.sh                  # core + RAN naik (SBI over TLS)
./scripts/register_ue.sh             # UE online, cek bisa akses webserver (N6)
./scripts/capture_start.sh           # rekam N2/N3/N4/N6 + SBI
sleep 600                            # baseline trafik normal 10 menit
./scripts/run_all.sh                 # jalankan skenario Tier 0..n berurutan
./scripts/capture_stop.sh
python3 scripts/label_pcap.py        # → data/labeled/
./scripts/lab_down.sh
```
OpenVAS (terpisah): `docker compose --profile scanner up -d openvas`, scan NF di `172.22.0.0/24`, lalu `./scripts/openvas_export.sh`.

---

## Instruksi untuk Claude Code

Jalankan `claude` dari folder `nfm-testbed-5g`, lalu minta **satu fase per sesi**.

**Aturan umum:**
- `set -euo pipefail` di semua skrip; komentar bahasa Indonesia.
- **Verifikasi nama & tag image** Open5GS/UERANSIM sebelum dipakai; jika hilang, usulkan alternatif dan tunggu konfirmasi.
- Di `run_scenario.sh` tambahkan **guard**: tolak target di luar `172.22.0.0/24`, `172.23.0.0/24`, `172.24.0.0/24`, `10.45.0.0/16`.
- Untuk Tier 2–4: setiap skrip diawali banner peringatan + argumen `--i-understand-lab-only`, dan **berhenti** bila guard subnet gagal.
- Jangan commit `data/`, `reports/`, `.env`.
- Untuk serangan yang mereproduksi CVE (T1-01, T2-03, T3-03, T4-01): pakai **versi Open5GS rentan yang ditentukan di `.env`**, dan dokumentasikan nomor CVE/issue di komentar skrip.

### Fase 1 — VM & prasyarat
Buat `setup_vm.sh`, `.gitignore`, `.env.example`. **Selesai jika:** `docker run hello-world` & `tshark -v` OK.

### Fase 2 — 5G Core + RAN naik
Buat `docker-compose.yml` + `configs/` + `subscribers/add_subs.sh`.
**Selesai jika:** semua NF Open5GS running; `ue1` dapat IP dari pool `10.45.x.x`; `ping` dari UE ke `webserver` (N6) berhasil; `ping 8.8.8.8` **gagal** (isolasi).

### Fase 2b — TLS pada SBI
Buat `tls/gen_ca.sh` + `tls/gen_nf_certs.sh`, lalu aktifkan TLS di bagian `sbi`/`tls` tiap config NF Open5GS. **Verifikasi dulu** nama kunci konfigurasi TLS pada versi Open5GS yang dipakai (dokumentasi resmi), termasuk apakah mutual TLS didukung.
**Selesai jika:** core tetap berjalan dengan TLS aktif; di PCAP SBI terlihat TLS handshake (`tshark -Y tls.handshake`); payload HTTP/2 kini terenkripsi (tidak lagi terbaca sebagai teks).

### Fase 3 — Trafik normal + capture multi-interface
Buat `register_ue.sh`, `normal_traffic.sh`, `capture_start/stop.sh` (rekam br-cp/br-up/br-dn, rotasi 500 MB, simpan PID per interface).
**Selesai jika:** PCAP berisi NGAP (N2), GTP-U (N3), PFCP (N4), dan HTTP (N6) dari UE normal — cek dengan `tshark -r ... -Y "ngap || pfcp || gtp"`.

### Fase 4 — Skenario Tier 0 (N6)
Buat `scenarios/tier0_n6/` + `run_scenario.sh` + `run_all.sh` (mulai Tier 0 saja).
**Selesai jika:** 6 skenario selesai tanpa error, `ground_truth.csv` terisi, jendela waktu tidak tumpang tindih.

### Fase 5 — Pelabelan
Buat `label_pcap.py` + ringkasan paket/flow per label.
**Selesai jika:** `data/labeled/` berisi folder per label dengan jumlah wajar; `benign` tidak kosong.

### Fase 6 — OpenVAS + pemindaian TLS
Scan NF core (OpenVAS), ekspor laporan (XML + JSON ringkas: host, port, CVE, severity). Tambah `tls_scan.sh` (testssl.sh/sslscan) terhadap endpoint SBI.
**Selesai jika:** laporan OpenVAS memuat temuan pada NF; laporan TLS mencantumkan versi protokol, cipher, dan status sertifikat tiap NF.

### Fase 6b — Skenario TLS (Tier 5)
Buat `tls/make_weak_certs.sh` + `scenarios/tier5_tls/`. Untuk T5-01..03, terbitkan ulang NF dengan cert/cipher rentan lalu pindai dengan `tls_scan.sh`. Untuk T5-04..05, jalankan ulang skenario Tier 4 melalui kanal TLS dan rekam.
**Selesai jika:** `tls_scan.sh` menandai kerentanan T5-01..03; PCAP Tier 5 berisi handshake TLS + trafik serangan terenkripsi, tercatat di ground truth.

### Fase 7 — Serangan khas 5G (Tier 1→4, bertahap)
Tambah skenario per Tier dengan guard & banner. Kerjakan **satu Tier per sesi**, uji dampaknya (mis. AMF/UPF restart) lewat `docker logs`, dan pastikan terekam di PCAP interface yang benar.
**Selesai jika:** tiap skenario punya jejak jelas di PCAP + tercatat di ground truth.

### Fase 8 (di luar VM)
Fine-tune netFound dgn `data/labeled/` → uji silang dengan **5G-NIDD** → integrasi alert NFM + laporan OpenVAS → LLM untuk analisis & prioritas.

---

## Referensi (model serangan & dataset)
- Amponis et al., *Threatening the 5G core via PFCP DoS attacks*, EURASIP JWCN 2022 — https://doi.org/10.1186/s13638-022-02204-5
- *5G Attacks: Realistic Scenarios and Simulations Using Open5GS*, ISeCure 17(3), 2025 — https://www.isecure-journal.com
- Trend Micro, *Attacks on 5G Infrastructure From Users' Devices*, 2023 (GTP-U, CVE-2021-45462)
- CVE-2021-45462 (Open5GS UPF GTP-U DoS); CVE-2024-24429 (NGAP, RANsacked); CVE-2024-51179 (PFCP flood, Issue #3497)
- VulDB #626112/#626118/#626122 — Open5GS ≤2.7.5 AMF/SMF DoS (SBI churn, HTTP/2)
- Positive Technologies, *5G Standalone Core Security Assessment* (HTTP/2 & PFCP)
- Samarakoon et al., *5G-NIDD*, 2022 — IEEE DataPort 10203 / arXiv 2212.01298
- Manca et al., *SAGE-5GC: Security-Aware Guidelines for Evaluating Anomaly Detection in 5G Core*, arXiv 2602.03596
- netFound — https://github.com/SNL-UCSB/netFound · arXiv 2310.17025
- Open5GS — https://open5gs.org · UERANSIM — https://github.com/aligungr/UERANSIM
- 3GPP TS 33.501 — *Security architecture and procedures for 5G System* (TLS wajib pada SBI)
- testssl.sh — https://testssl.sh · sslscan — https://github.com/rbsec/sslscan
- draft-irtf-nmrg-llm-nm (LLM-assisted network management)