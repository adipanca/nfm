# SERANGAN_BARU_VM.md — Bangkitkan Serangan Baru (dikerjakan DI VM)

Spesifikasi kerja untuk **Claude Code CLI yang dijalankan DI VM VirtualBox** (`~/nfm-testbed-5g`), lab 5G hidup (Open5GS + UERANSIM). Tujuan: menambah skenario serangan baru sesuai celah dari `GUIDELINE_GAP_ANALYSIS.md`, lalu capture + label — **tanpa menyentuh WSL**. Pelatihan dilakukan terpisah di WSL (lihat `INGEST_TRAIN_WSL.md`).

> **Pembagian kerja:** VM = pabrik data (tanpa GPU). WSL = pelatihan (GPU). Dokumen ini **hanya** bagian VM. Setelah selesai, serahkan data ke WSL lewat langkah §H.

---

## Aturan (WAJIB)
- Lab-only. Semua serangan **hanya** ke subnet lab (`172.22/23/24.0.0`, `10.45/16`). `run_scenario.sh` harus menolak target di luar itu; Tier ≥2 wajib `--i-understand-lab-only`.
- **≥100 episode independen per kelas baru** (pelajaran dari REVISI: kelas 1-episode tak bisa di-split dengan benar). Tiap episode: port efemeral baru + variasi timing/parameter.
- Aditif: jangan hapus data lama. Tulis ke `data/labeled/<kelas_baru>/` dan tambah baris ke `data/ground_truth.csv`.
- `set -euo pipefail`; guard subnet di setiap skrip.

---

## Serangan yang dibangkitkan

### Grup 1 — Langsung terproses NFM (UDP/TCP/N6) — kerjakan DULU
| Label | Interface | Pendekatan | Guideline | Kategori |
|---|---|---|---|---|
| `sbi_nf_impersonation` | SBI | NF palsu / access-token tak sah ke NRF (HTTP/2 over TLS) | Core-11, Core-39 | autentikasi |
| `gtpu_teid_injection` | N3 | Inject GTP-U ke sesi UE lain via TEID spoof | Core-25 | integritas user-plane |
| `n6_exfiltration` | N6 | Exfiltrasi dari `ue-mal` (DNS tunneling / bulk upload / beaconing) | Core-5, 33, 34 | kerahasiaan |

### Grup 2 — Berjalan di SCTP → butuh (b) SCTP support di WSL agar terproses
> Tetap **di-capture sekarang** di VM. Tokenisasinya baru jalan setelah patch SCTP selesai di WSL. Jadi jangan tunggu (b) untuk membangkitkannya.

| Label | Interface | Pendekatan | Guideline | Kategori |
|---|---|---|---|---|
| `nas_tamper_registration` | N1/N2 | Parameter keamanan dipalsukan saat registrasi UE | Core-6 | autentikasi |
| `nas_replay_n1` | N1 | Replay pesan NAS duplikat | Core-7 | integritas |
| `bidding_down` | Xn/negosiasi | Paksa algoritma keamanan lebih lemah (downgrade) | Core-8, Core-22, gNB-12 | integritas/autentikasi |

---

## Alur per serangan (reuse mesin yang ada)
1. `capture_start.sh` pada interface relevan (N2/N3/N4/N6/SBI).
2. `batch_<nama>.sh` → panggil `run_scenario.sh` berulang **≥100×** dengan variasi (port efemeral, timing jitter, parameter) → tiap run = episode independen, tercatat ke `ground_truth.csv`.
3. `capture_stop.sh`.
4. `label_pcap.py` → `data/labeled/<label>/`.
5. Verifikasi: tiap kelas baru **≥100 flow**; trafik benar ada di interface yang diharapkan (`tshark -Y`).

**Selesai per kelas jika:** ≥100 flow independen, label benar, ground_truth terisi, tak ada target di luar subnet lab.

---

## §H — Serah-terima ke WSL (WAJIB di akhir)
Setelah semua kelas baru selesai, buat **snapshot lengkap** data (bukan hanya yang baru) supaya WSL dapat gambaran utuh terbaru:
```bash
cd ~/nfm-testbed-5g
tar czf /tmp/labeled_latest.tgz data/labeled data/ground_truth.csv
echo "Snapshot siap: /tmp/labeled_latest.tgz"
ls -lh /tmp/labeled_latest.tgz
```
Lalu beri tahu: *"Data VM siap, jalankan `INGEST_TRAIN_WSL.md`."* WSL akan menarik snapshot ini dan melatih ulang. **Jangan latih apa pun di VM.**

---

## Catatan
- Grup 2 di-capture sekarang tapi metriknya baru muncul setelah (b) SCTP di WSL — itu normal dan sudah dijelaskan di `INGEST_TRAIN_WSL.md`.
- Kumpulkan **semua** serangan baru dulu (Grup 1 + 2) sebelum serah-terima, supaya WSL cukup satu putaran training besar, bukan berkali-kali.