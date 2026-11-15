# AUDIT.md — Pemeriksaan Dataset & Testbed sebelum Fase 8 (fine-tune netFound)

Dokumen ini adalah **spesifikasi kerja untuk Claude Code CLI**. Tujuannya memastikan hasil Fase 1–7 (lab + dataset berlabel di `data/labeled/`) **sehat dan layak** sebelum dipakai fine-tuning netFound di luar VM. Fine-tuning mahal (GPU) — audit ini mencegah melatih model di atas data yang cacat atau bocor (shortcut).

> Keluaran akhir: **`reports/audit/AUDIT_REPORT.md`** berisi tabel ringkas LULUS/PERINGATAN/GAGAL + detail angka, yang akan ditinjau manusia/Claude di chat sebelum lanjut Fase 8.

---

## Aturan untuk Claude Code (WAJIB)

- **Baca-saja.** Audit **tidak boleh mengubah** apa pun di `data/`, `reports/` (kecuali menulis ke `reports/audit/`), konfigurasi, atau container. Jangan relabel, jangan hapus, jangan jalankan skenario serangan.
- **Tanpa jaringan keluar.** Jangan pull image/paket baru. Pakai tool yang sudah ada (`tshark`, `capinfos`, `editcap`, `python3` + `pandas`). Jika sebuah tool tidak ada, **catat sebagai "TIDAK BISA DIPERIKSA"** di laporan — jangan diam-diam melewati.
- **Jangan memperbaiki, hanya melaporkan.** Jika menemukan masalah, catat temuan + dampak + saran perbaikan di laporan. Perbaikan dilakukan di sesi terpisah atas persetujuan pengguna.
- **Deteksi tata letak dulu.** Gunakan pengetahuan Anda atas struktur `data/labeled/` yang Anda buat sendiri. Jika asumsi perintah di bawah tak cocok dengan tata letak nyata, **sesuaikan** dan tulis asumsi yang dipakai di awal laporan.
- **Ambang di bawah bisa disetel**; tulis nilai ambang yang dipakai di laporan agar bisa didiskusikan.
- Semua skrip bantu diletakkan di `scripts/audit/` dengan `set -euo pipefail`.

---

## Pendekatan: satu ekstraksi → banyak pemeriksaan

Agar efisien dan konsisten, lakukan **satu kali ekstraksi** semua PCAP berlabel menjadi tabel, lalu jalankan semua pemeriksaan di atas tabel itu.

1. Untuk tiap file `data/labeled/<label>/*.pcap`, pakai `tshark` mengeluarkan per-paket (field minimal):
   `frame.time_epoch, ip.src, ip.dst, ip.proto, tcp.srcport, tcp.dstport, udp.srcport, udp.dstport, frame.len, tls.handshake.type, http2` (+ `sctp` bila ada untuk NGAP).
2. Agregasi menjadi **tabel flow** (`reports/audit/flows.csv`): satu baris per `(label, 5-tuple terkanonikalisasi)`. Kanonikalisasi = urutkan pasangan (IP:port) supaya arah A→B dan B→A dihitung sebagai **satu flow bidirectional** (sesuai notasi flow netFound). Kolom: `label, proto, ip_a, ip_b, port_a, port_b, n_packets, n_bytes, t_start, t_end, has_tls_handshake, has_http2`.
3. Simpan **hanya** `flows.csv` (ringkas), **bukan** CSV per-paket (bisa jutaan baris). Semua pemeriksaan C–H dibaca dari `flows.csv` via pandas.

Catat jumlah total paket & flow yang berhasil diekstraksi vs total paket di PCAP (untuk mendeteksi paket yang gagal di-parse).

---

## Pemeriksaan

### A — Inventaris lab & repo
- Daftar container yang jalan (`docker compose ps`), cocokkan dengan ekspektasi (18 container: 10 NF + SCP, Mongo, UPF, gNB, ue1/ue2/ue-mal, attacker, webserver).
- Pastikan `data/labeled/`, `data/ground_truth.csv`, `reports/` ada. Laporkan ukuran disk (`df -h` untuk partisi terkait).
- Konfirmasi `.gitignore` menutup `data/`, `reports/`, `.env`, dan kunci TLS (`tls/{ca,certs,weak}/`, `*.key`) — tak boleh ada rahasia ter-commit.
- **LULUS jika:** semua artefak inti ada; tak ada kunci privat ter-track git (`git ls-files | grep -E '\.key$|/ca/|/certs/|/weak/'` kosong).

### B — Integritas PCAP
- Jalankan `capinfos` pada tiap PCAP; tangkap error/peringatan "truncated".
- Laporkan: jumlah file, total paket, file yang gagal dibaca / terpotong.
- **LULUS jika:** 0 file gagal/terpotong. **GAGAL jika** ada PCAP tak terbaca (data tak bisa dipercaya).

### C — Ground truth
- Validasi `ground_truth.csv`: kolom sesuai (`tier,scenario_id,label,src_ip,dst_ip,iface,start_epoch,end_epoch`), tiap `end > start`, dan **jendela waktu antar-skenario tidak tumpang tindih** (kecuali trafik benign yang memang menyertai).
- Cocokkan: tiap `label` di ground truth punya folder di `data/labeled/`, dan sebaliknya (tak ada label yatim).
- **LULUS jika:** skema valid, tak ada window serangan yang bertabrakan, pemetaan label ground-truth ↔ folder konsisten.

### D — Distribusi label (flow & paket)
- Dari `flows.csv`: tabel per label berisi **jumlah flow**, **jumlah paket**, **jumlah byte**, dan **rentang waktu**.
- Hitung ukuran bucket **`unknown`** (paket/flow yang tak cocok aturan pelabelan) sebagai **persentase dari total**.
- **LULUS jika** `unknown` < 2% paket; **PERINGATAN** 2–10%; **GAGAL** > 10% (pelabelan terlalu longgar → sinyal tercampur).

### E — Shortcut via alamat IP (PEMERIKSAAN PALING PENTING)
Risiko: semua serangan berasal dari IP tetap (attacker `172.22/23.x`, `ue-mal` di `10.45.x`). Model bisa "curang" hanya dengan menghafal IP, bukan belajar pola serangan.
- Untuk tiap label serangan, daftar himpunan **IP sumber** (dan tujuan) uniknya.
- **Uji separabilitas trivial:** buat aturan baseline *"flow dianggap SERANGAN jika salah satu endpoint ∈ {IP attacker, ue-mal}"*. Hitung akurasi/precision/recall aturan ini pada seluruh dataset (serangan vs benign).
- Laporkan pula: apakah ada kelas serangan yang **100% terpisah** dari benign hanya berdasar IP.
- **Interpretasi:** akurasi baseline-IP mendekati 100% = **shortcut berat**. Ini **tidak otomatis GAGAL**, TAPI harus ditandai **BLOKER-BERSYARAT**: Fase 8 hanya valid bila (a) preprocessing netFound **meng-anonimkan/masking IP** diaktifkan, dan/atau (b) ada rencana validasi silang ke dataset ber-IP berbeda (5G-NIDD). Laporkan status (a): apakah pipeline netFound yang akan dipakai melakukan IP masking.
- **LULUS jika:** baseline-IP jauh dari sempurna **atau** IP masking dikonfirmasi aktif; jika tidak → **PERINGATAN/BLOKER-BERSYARAT** dengan angkanya.

### F — Kemurnian benign & tumpang tindih
- Pastikan label `benign` **tidak mengandung** flow yang salah satu endpoint-nya IP attacker/ue-mal.
- Cek kebocoran silang: flow yang jatuh di dua label, atau paket serangan yang masuk ke `benign` karena window waktu.
- **LULUS jika:** 0 flow attacker/ue-mal di `benign`; tak ada flow yang terlabel ganda.

### G — Shortcut TLS & verifikasi enkripsi
Risiko halus: bila satu-satunya trafik ber-TLS adalah serangan (T5-04/05), model belajar *"ada TLS = serangan"*.
- Cek: apakah label **`benign` juga mengandung flow SBI ber-TLS** (mis. port 7777, `has_tls_handshake=1`)? Harus **ya**.
- Verifikasi serangan-atas-TLS benar terenkripsi: pada PCAP `sbi_attack_over_tls`/`tls_handshake_flood`, jumlah frame **HTTP/2 plaintext ≈ 0** dan ada TLS handshake.
- **LULUS jika:** benign punya flow TLS > 0 **dan** serangan-atas-TLS tak punya HTTP/2 plaintext.

### H — Kelayakan untuk ML (keseimbangan kelas)
- Dari tabel D (satuan **flow**): urutkan kelas dari flow paling sedikit.
- Hitung rasio ketidakseimbangan (flow kelas terbesar / terkecil).
- Tandai kelas dengan **flow < 200** sebagai berisiko (sulit dilatih/diuji; pertimbangkan digabung, ditambah ulangan, atau dipakai hanya untuk uji).
- **LULUS jika:** tiap kelas ≥ 200 flow; **PERINGATAN** bila ada kelas 50–199; **GAGAL/-perhatian** bila ada kelas < 50. Laporkan rasio ketidakseimbangan apa adanya (bukan untuk gagal, tapi untuk keputusan strategi loss/sampling).

### I — Kesiapan format netFound
- Konfirmasi data yang akan diekspor adalah **PCAP mentah per label** (bukan hanya CSV fitur), karena netFound memproses paket mentah.
- Konfirmasi rencana preprocessing: IP anonymization/masking (lihat E), pemotongan flow/burst, dan tokenizer protocol-aware. Untuk Tier 2–4 (PFCP/NGAP/SBI), catat **apakah tokenizer netFound mengenali protokol itu** atau akan diperlakukan sebagai payload generik (batasan yang harus ditulis di laporan penelitian).
- **LULUS jika:** format mentah tersedia & rencana preprocessing tercatat (ini pemeriksaan kesiapan, bukan angka).

---

## Isi `reports/audit/AUDIT_REPORT.md`

1. **Header:** tanggal, commit git (`git rev-parse --short HEAD`), asumsi tata letak yang dipakai, nilai ambang yang dipakai, daftar tool yang tersedia/tidak.
2. **Ringkasan** — tabel:

   | Kode | Pemeriksaan | Status | Catatan 1 baris |
   |---|---|---|---|
   | A | Inventaris lab & repo | LULUS/PERINGATAN/GAGAL/TIDAK BISA | … |
   | … | … | … | … |

3. **Detail per pemeriksaan A–I** dengan tabel angka (distribusi flow/paket per label, himpunan IP per label, akurasi baseline-IP, kelas < 200 flow, dll.).
4. **Daftar BLOKER** (hal yang harus dibereskan sebelum Fase 8) vs **PERINGATAN** (boleh lanjut dengan catatan).
5. **Verdikt Fase 8:** salah satu —
   - **GO** — dataset sehat, lanjut fine-tune.
   - **GO-DENGAN-SYARAT** — lanjut hanya jika syarat dipenuhi (mis. IP masking aktif + validasi silang 5G-NIDD). Sebutkan syaratnya.
   - **NO-GO** — ada bloker (mis. PCAP terpotong, `unknown` > 10%, benign tercemar). Sebutkan apa yang harus diperbaiki.
6. **Rekomendasi split Fase 8:** ingatkan bahwa pembagian train/test harus **per-flow** dan idealnya **per-waktu** (satu flow tak boleh ada di dua sisi), serta sarankan **uji akhir pada dataset eksternal 5G-NIDD** untuk menguji generalisasi.

---

## Cara pakai
```bash
cd ~/nfm-testbed-5g
claude
# lalu: "Baca AUDIT.md, jalankan audit baca-saja, hasilkan reports/audit/AUDIT_REPORT.md"
```
Setelah selesai, tempelkan isi `reports/audit/AUDIT_REPORT.md` (atau unggah) untuk ditinjau sebelum memulai Fase 8.