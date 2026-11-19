# PFCP_PAIR_INVESTIGATION.md — Selidiki `pfcp_estab_flood` vs `pfcp_rule_misconfig` (opsi 2, DI VM)

Spesifikasi kerja untuk **Claude Code CLI** (paralel, tak memblokir SCTP/training). Boleh dijalankan di **VM** (`~/nfm-testbed-5g`, punya skrip serangan **dan** pcap) — itu paling lengkap.

## Masalah
Di semua run (frozen/unfrozen, 14-kelas & interim), `pfcp_estab_flood` dan `pfcp_rule_misconfig` **bingung hanya satu sama lain** (blok 2×2 bersih di confusion matrix; ~50/50). netFound tak bisa membedakan keduanya. Perlu tahu **kenapa**: trafiknya memang mirip, atau netFound yang tak menangkap bedanya?

---

## P1 — Bandingkan skrip serangan
- Buka kedua skrip (mis. `docker/attacker/tools/*pfcp*` / `scenarios/tier2_pfcp/`).
- Catat: **jenis pesan PFCP** apa yang dikirim masing-masing, dan **IE** apa yang membedakannya?
  - `pfcp_estab_flood` → seharusnya **PFCP Session Establishment Request** (banjir).
  - `pfcp_rule_misconfig` → seharusnya memodifikasi **forwarding rule** (PDR/FAR) — idealnya pesan/IE berbeda.
- **Output:** ringkasan "apa yang secara desain membedakan keduanya?"

## P2 — Bandingkan trafik nyata (pcap)
Pakai tshark pada pcap kedua kelas (ada di `data/labeled/pfcp_estab_flood/` & `data/labeled/pfcp_rule_misconfig/`):
```bash
for c in pfcp_estab_flood pfcp_rule_misconfig; do
  echo "=== $c ==="
  f=$(ls data/labeled/$c/*.pcap | head -1)
  # distribusi jenis pesan PFCP
  tshark -r "$f" -Y pfcp -T fields -e pfcp.msg_type 2>/dev/null | sort | uniq -c
  # IE yang muncul
  tshark -r "$f" -Y pfcp -T fields -e pfcp.ie_type 2>/dev/null | tr ',' '\n' | sort | uniq -c | head -20
done
```
- Bandingkan: apakah **jenis pesan / IE / panjang payload** benar-benar berbeda antar-kelas, atau nyaris identik?

## P3 — Diagnosis (dua kemungkinan)
- **Kasus A — trafik MEMANG berbeda** (jenis pesan/IE beda jelas) tapi netFound tetap bingung → **keterbatasan tokenizer**: netFound memperlakukan payload PFCP sebagai byte generik dan tak menangkap semantik IE. → **Temuan ilmiah**. Tindakan: **pertahankan 2 kelas, laporkan sebagai limitasi** (mirip argumen SCTP: NFM butuh protocol-awareness untuk 5G control-plane).
- **Kasus B — trafik nyaris identik** (skrip menghasilkan pesan serupa) → bukan salah netFound. Tindakan: **(i)** perbaiki skrip `pfcp_rule_misconfig` agar benar-benar memodifikasi rule (pesan/IE berbeda nyata) lalu regen, **atau (ii)** gabung keduanya jadi satu kelas `pfcp_control_attack` di `label_map.json`.

## P4 — Keputusan & aksi
- Tulis `reports/pfcp_pair_investigation.md`: temuan P1–P3 + kasus (A/B) + rekomendasi.
- Jangan ubah dataset tanpa konfirmasi pengguna — laporkan dulu.

---

## Selesai jika
Laporan memuat: perbedaan desain (P1), bukti trafik (P2), diagnosis A/B (P3), dan rekomendasi (pertahankan+dokumentasikan / perbaiki skrip / gabung). Lalu tunggu keputusan sebelum mengubah apa pun.

## Cara pakai
```bash
cd ~/nfm-testbed-5g   # di VM (punya skrip + pcap)
claude
# "Baca PFCP_PAIR_INVESTIGATION.md, jalankan P1–P3, hasilkan reports/pfcp_pair_investigation.md. Jangan ubah dataset — laporkan dulu."
```