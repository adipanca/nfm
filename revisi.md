# REVISI.md — Perbaikan Dataset sebelum Fase 8

Dokumen ini adalah **spesifikasi kerja untuk Claude Code CLI**, menindaklanjuti `reports/audit/AUDIT_REPORT.md` (verdikt: **GO-DENGAN-SYARAT**). Tujuannya membereskan temuan audit agar dataset layak untuk fine-tuning netFound (Fase 8).

Temuan yang ditangani:
- **F** — 107 flow bocor dari IP attacker-container ke label `benign` (perlu dibersihkan).
- **H** — 8 kelas serangan terlalu kecil (1–40 flow) untuk dilatih/diuji secara valid (perlu diperbanyak episode).
- **E/I** — IP masking netFound belum dikonfirmasi (perlu diverifikasi/dicatat).

---

## Tentukan dulu: target penelitian

Jalur revisi tergantung target deteksi:

- **BINER** (serangan vs normal): kerjakan **R0, R1, R3, R4**. **Lewati R2** (kelas kecil tak masalah karena semua serangan digabung; total serangan 55.289 flow sudah cukup).
- **MULTI-CLASS** (mengenali jenis serangan): kerjakan **semua R0–R5**. R2 **wajib**, kalau tidak 8 kelas kecil tak bisa dievaluasi dengan benar.

> Claude Code: tulis target yang dipakai di awal log, dan jalankan hanya langkah yang sesuai. Jika pengguna belum menyebut target, **tanyakan dulu** sebelum R2.

---

## Aturan untuk Claude Code (WAJIB)

- **Aditif & aman.** Jangan hapus atau timpa PCAP ronde-1 di `data/raw/`. Semua hasil baru ditulis ke file/berkas baru. `data/labeled/` boleh diregenerasi, tapi backup dulu (`data/labeled_bak_<tgl>/`).
- **Branch baru.** Kerjakan di branch git baru (mis. `fix/dataset-revisi`). `data/` & `reports/` tetap di-gitignore; hanya skrip/ground-truth yang di-commit.
- **Guard tetap.** Semua serangan hanya ke subnet lab (`172.22/23/24.0.0`, `10.45/16`). Tier ≥2 tetap butuh `--i-understand-lab-only`. `set -euo pipefail` di semua skrip.
- **Lab l-only.** Jangan pernah mengarah ke IP luar. Jangan pull jaringan luar.
- **Lapor, jangan sembunyi.** Jika sebuah langkah gagal/terlewati, catat di log + `reports/revisi/REVISI_LOG.md`. Jangan diam-diam melewati.
- Keluaran akhir: **`reports/revisi/REVISI_LOG.md`** (ringkasan sebelum/sesudah) + audit ulang (R4).

---

## R0 — Persiapan
- Buat branch `fix/dataset-revisi`.
- Backup: `cp -r data/labeled data/labeled_bak_<YYYYMMDD>` (atau catat bahwa raw cukup untuk regen).
- Pastikan lab sehat (`docker compose ps` = 18 container) bila R2 akan dijalankan.
- **Selesai jika:** branch dibuat, backup/strategi regen tercatat.

## R1 — Bersihkan kebocoran benign (temuan F)
Penyebab: trafik setup/teardown serangan SBI (Tier 4/5) dari IP container `172.22.0.50` & `172.23.0.50` sedikit di luar window ground-truth → masuk `benign`.

- Ubah `scripts/label_pcap.py`: saat membentuk label `benign`, **kecualikan flow yang salah satu endpoint-nya** ∈ `{172.22.0.50, 172.23.0.50}` (IP attacker-container). **Jangan** mengecualikan IP ue-mal (`10.45.0.9`, `172.23.0.43`) — trafik benign dari sana **sah** (UE penyerang juga browsing normal) dan penting untuk ketahanan anti-shortcut.
  - Opsi pelengkap (boleh keduanya): lebarkan trim-window benign agar paket tepi serangan tidak tercecer ke benign.
- Regenerasi label (`python3 scripts/label_pcap.py`), lalu verifikasi.
- **Selesai jika:** jumlah flow `benign` yang menyentuh `172.22.0.50`/`172.23.0.50` = **0**; jumlah flow benign dari ue-mal tetap ~53k (tidak ikut terbuang); total benign turun ~107 flow saja.

## R2 — Perbanyak episode kelas kecil (temuan H & E) — MULTI-CLASS saja
8 kelas bermasalah: `pfcp_session_delete`, `pfcp_session_modify`, `pfcp_estab_flood`, `pfcp_rule_misconfig`, `gtpu_malformed`, `ngap_malformed`, `sbi_attack_over_tls`, `sbi_http2_dos`.

Masalah inti: tiap kelas kini berasal dari **1 episode** (1–2 flow). Segmentasi burst **tidak** memperbaiki ini — sampelnya tetap dari satu rekaman dan akan bocor antar train/test. Solusi: **jalankan ulang tiap skenario banyak kali sebagai episode independen**.

- Buat `scenarios/batch_small.sh` yang untuk tiap skenario di atas menjalankan `run_scenario.sh` berulang **hingga kelas mencapai ≥120 flow** (buffer di atas ambang 100), dengan **variasi antar-run** supaya tiap episode = flow independen:
  - **Port sumber efemeral baru** tiap run (soket baru → 5-tuple kanonik berbeda). Ini syarat utama agar dihitung sebagai flow terpisah.
  - **Jitter timing** antar-run (tidur acak 1–3 dtk) dan **variasikan parameter**: rate/jumlah paket untuk flood; parameter malformasi (offset/panjang/flag) untuk `*_malformed`; jumlah sesi untuk PFCP.
  - Gunakan seed acak berbeda tiap run; catat seed/param ke ground truth (kolom tambahan bila perlu) demi reprodusibilitas.
- Alur eksekusi (reuse mesin yang ada):
  1. (opsional) biarkan trafik normal ue1/ue2 jalan sebagai latar.
  2. `capture_start.sh` pada interface yang relevan (N2/N3/N4/SBI).
  3. `batch_small.sh` — tiap run memanggil `run_scenario.sh` (guard + catat window ke `ground_truth.csv`).
  4. `capture_stop.sh`.
  5. `label_pcap.py` (dengan perbaikan R1) untuk melabeli PCAP baru; **gabungkan** dengan dataset lama (jangan timpa).
- **Selesai jika:** tiap dari 8 kelas punya **≥100 flow independen** (idealnya ≥120); window antar-episode tercatat di ground truth; tak ada episode yang mengarah ke luar subnet lab.

> Catatan kejujuran untuk laporan riset: episode berasal dari tool & parameter yang sama, jadi kemiripan antar-episode tinggi. Ini mengurangi, bukan menghapus, risiko overfit. Klaim generalisasi tetap harus diuji pada **5G-NIDD** (dataset ber-IP & ber-tool berbeda).

## R3 — Verifikasi IP masking netFound (temuan E/I)
Fine-tuning berjalan di luar VM, tetapi keputusan ini menentukan validitas 9 kelas sumber-container.

- Periksa repo/preprocessing netFound yang akan dipakai: apakah tokenizer **menganonimkan/meng-nol-kan alamat IP** (dan idealnya MAC/port yang identik-per-host) sebelum tokenisasi?
- Catat di `reports/revisi/REVISI_LOG.md`: nama file/fungsi yang melakukannya (atau konfirmasi **tidak ada** → harus ditambahkan sebelum Fase 8).
- **Selesai jika:** status IP masking terdokumentasi eksplisit (AKTIF + lokasinya, atau TIDAK ADA + rencana menambah).

## R4 — Audit ulang (fokus E, F, H)
- Jalankan ulang pemeriksaan **E, F, H** dari `AUDIT.md` pada dataset hasil revisi (ekstraksi ulang `flows.csv`).
- Hasilkan **`reports/audit/AUDIT_REPORT_v2.md`** dengan tabel sebelum→sesudah.
- **Selesai jika:**
  - F = **LULUS** (0 flow container di benign).
  - H = tiap kelas ≥100 flow (untuk jalur multi-class); untuk jalur biner, catat H sebagai N/A.
  - E = per-kelas dilaporkan ulang; status IP masking (R3) disertakan sebagai syarat.

## R5 — Commit — MULTI-CLASS saja (atau setelah semua beres)
- Commit perubahan skrip + `ground_truth.csv` di branch `fix/dataset-revisi` (data/reports tetap gitignored).
- Pesan commit ringkas (mis. `fix: bersihkan kebocoran benign (F) + perbanyak episode kelas kecil (H)`).
- **Jangan push** kecuali diminta pengguna.
- **Selesai jika:** commit bersih; `git status` tak menyertakan data/kunci.

---

## Isi `reports/revisi/REVISI_LOG.md`
1. Target (biner/multi-class) + langkah yang dijalankan.
2. Tabel **sebelum→sesudah**: flow per kelas (khusus 8 kelas + benign), jumlah flow benign-bocor (F).
3. Status IP masking netFound (R3).
4. Verdikt Fase 8 yang diperbarui (GO / GO-DENGAN-SYARAT / NO-GO) + syarat tersisa.
5. Pointer ke `AUDIT_REPORT_v2.md`.

## Cara pakai
```bash
cd ~/nfm-testbed-5g
claude
# "Baca REVISI.md. Target penelitian saya: <biner / multi-class>. Jalankan langkah yang sesuai."
```
Setelah selesai, tempelkan `reports/revisi/REVISI_LOG.md` + ringkasan `AUDIT_REPORT_v2.md` untuk ditinjau sebelum mulai Fase 8.