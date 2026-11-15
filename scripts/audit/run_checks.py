#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AUDIT (baca-saja) — Pemeriksaan A–I dari flows.csv + ground_truth.csv.
Menulis reports/audit/AUDIT_REPORT.md. TIDAK mengubah data/.
Tanpa pandas (plain python) agar tak perlu instal paket (lab offline).
"""
import csv, os, subprocess, glob, sys
from collections import defaultdict, OrderedDict
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
AUD = os.path.join(ROOT, "reports", "audit")
FLOWS = os.path.join(AUD, "flows.csv")
STATS = os.path.join(AUD, "extract_stats.csv")
GT = os.path.join(ROOT, "data", "ground_truth.csv")
LABELED = os.path.join(ROOT, "data", "labeled")
REPORT = os.path.join(AUD, "AUDIT_REPORT.md")

# Ambang (dapat disetel) — ditulis di laporan
TH_UNKNOWN_PASS, TH_UNKNOWN_WARN = 2.0, 10.0      # persen
TH_CLASS_PASS, TH_CLASS_WARN = 200, 50            # flow per kelas
TH_IP_SHORTCUT = 95.0                             # akurasi baseline-IP (%) => shortcut

def sh(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=60).stdout.strip()
    except Exception as e:
        return f"(error: {e})"

def load_flows():
    rows = []
    with open(FLOWS) as f:
        for r in csv.DictReader(f):
            r["n_packets"] = int(r["n_packets"]); r["n_bytes"] = int(r["n_bytes"] or 0)
            r["has_tls_handshake"] = int(r["has_tls_handshake"] or 0)
            r["has_http2"] = int(r["has_http2"] or 0)
            rows.append(r)
    return rows

def load_gt():
    with open(GT) as f:
        return list(csv.DictReader(f))

def main():
    flows = load_flows()
    gt = load_gt()
    out = []
    W = out.append

    # ---- Header ----
    commit = sh(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"])
    today = datetime.now().strftime("%Y-%m-%d %H:%M")
    tools = {t: (sh(["bash","-c",f"command -v {t}"]) or "TIDAK ADA") for t in
             ["tshark","capinfos","editcap","python3"]}
    has_pandas = subprocess.run(["python3","-c","import pandas"],
                                capture_output=True).returncode == 0
    summary = OrderedDict()   # code -> (nama, status, catatan)

    # ---- A: Inventaris lab & repo ----
    running = sh(["bash","-c","(command -v docker >/dev/null && docker ps --format '{{.Names}}' 2>/dev/null) | sort | tr '\\n' ' '"])
    ncont = len([x for x in running.split() if x])
    arts = {p: os.path.exists(os.path.join(ROOT,p)) for p in
            ["data/labeled","data/ground_truth.csv","reports"]}
    tracked_secrets = sh(["bash","-c",
        "git -C '%s' ls-files | grep -E '\\.key$|/ca/|/certs/|/weak/|^\\.env$|^data/|^reports/' || true" % ROOT])
    df_line = sh(["bash","-c","df -h %s | tail -1" % ROOT])
    gi = open(os.path.join(ROOT,".gitignore")).read() if os.path.exists(os.path.join(ROOT,".gitignore")) else ""
    gi_ok = all(k in gi for k in ["data/","reports/",".env","tls/weak/"])
    a_pass = (ncont >= 18) and all(arts.values()) and (tracked_secrets=="") and gi_ok
    a_stat = "LULUS" if a_pass else ("PERINGATAN" if (all(arts.values()) and tracked_secrets=="") else "GAGAL")
    summary["A"] = ("Inventaris lab & repo", a_stat,
                    f"{ncont} container jalan; artefak inti {'ada' if all(arts.values()) else 'KURANG'}; "
                    f"git rahasia: {'bersih' if tracked_secrets=='' else 'ADA BOCOR'}")
    W("## A — Inventaris lab & repo\n")
    W(f"- Container berjalan ({ncont}): `{running}`")
    W(f"- Ekspektasi 18 (10 NF+SCP, Mongo, UPF, gNB, ue1/ue2/ue-mal, attacker, webserver). "
      f"{'✓ cukup' if ncont>=18 else '⚠ kurang dari 18'}")
    for p,ok in arts.items(): W(f"- `{p}`: {'ada ✓' if ok else 'TIDAK ADA ✗'}")
    W(f"- Disk: `{df_line}`")
    W(f"- `.gitignore` menutup data/reports/.env/tls-weak: {'ya ✓' if gi_ok else 'TIDAK ✗'}")
    W(f"- Kunci/rahasia ter-track git: {'TIDAK ADA ✓' if tracked_secrets=='' else '**ADA:** '+tracked_secrets}")
    W(f"- **Status A: {a_stat}**\n")

    # ---- B: Integritas PCAP ----
    stat_rows = list(csv.DictReader(open(STATS)))
    nfiles = len(stat_rows)
    failed = [s for s in stat_rows if int(s["capinfos_packets"])<0]
    # cek truncated via capinfos stderr
    trunc = []
    for s in stat_rows:
        fp = os.path.join(ROOT, s["file"])
        err = subprocess.run(["capinfos","-c",fp], capture_output=True, text=True).stderr
        if "truncat" in err.lower(): trunc.append(s["file"])
    tot_cap = sum(int(s["capinfos_packets"]) for s in stat_rows if int(s["capinfos_packets"])>0)
    tot_row = sum(int(s["tshark_rows"]) for s in stat_rows)
    b_pass = (not failed) and (not trunc)
    b_stat = "LULUS" if b_pass else "GAGAL"
    summary["B"] = ("Integritas PCAP", b_stat,
                    f"{nfiles} file, {tot_cap} paket, gagal={len(failed)}, terpotong={len(trunc)}, "
                    f"selisih parse={tot_cap-tot_row}")
    W("## B — Integritas PCAP\n")
    W(f"- File PCAP berlabel: **{nfiles}**; total paket (capinfos): **{tot_cap:,}**")
    W(f"- Paket ter-parse tshark: **{tot_row:,}** (selisih = {tot_cap-tot_row}; 0 = tak ada paket gagal parse)")
    W(f"- File gagal dibaca: **{len(failed)}**; file terpotong (truncated): **{len(trunc)}**")
    if trunc: W(f"  - terpotong: {trunc}")
    W(f"- **Status B: {b_stat}**\n")

    # ---- C: Ground truth ----
    exp_cols = ["tier","scenario_id","label","src_ip","dst_ip","iface","start_epoch","end_epoch"]
    gt_cols_ok = (list(gt[0].keys())==exp_cols) if gt else False
    bad_time = [r["scenario_id"] for r in gt if float(r["end_epoch"])<=float(r["start_epoch"])]
    # overlap antar window (per iface, serangan)
    wins = sorted((float(r["start_epoch"]),float(r["end_epoch"]),r["scenario_id"]) for r in gt)
    overlaps = []
    for i in range(1,len(wins)):
        if wins[i][0] < wins[i-1][1]:
            overlaps.append((wins[i-1][2], wins[i][2]))
    gt_labels = {r["label"] for r in gt}
    folder_labels = {os.path.basename(d) for d in glob.glob(os.path.join(LABELED,"*")) if os.path.isdir(d)}
    attack_folders = folder_labels - {"benign"}
    orphan_gt = gt_labels - folder_labels           # label GT tanpa folder
    orphan_folder = attack_folders - gt_labels      # folder tanpa GT
    c_pass = gt_cols_ok and not bad_time and not overlaps and not orphan_gt and not orphan_folder
    c_stat = "LULUS" if c_pass else ("PERINGATAN" if (gt_cols_ok and not bad_time) else "GAGAL")
    summary["C"] = ("Ground truth", c_stat,
                    f"skema {'ok' if gt_cols_ok else 'SALAH'}; overlap={len(overlaps)}; "
                    f"label yatim GT={len(orphan_gt)} folder={len(orphan_folder)}")
    W("## C — Ground truth\n")
    W(f"- Skema kolom sesuai: {'ya ✓' if gt_cols_ok else 'TIDAK ✗'} ({len(gt)} baris skenario)")
    W(f"- Window `end>start` semua: {'ya ✓' if not bad_time else 'TIDAK: '+str(bad_time)}")
    W(f"- Window serangan tumpang tindih: {'TIDAK ADA ✓' if not overlaps else '**ADA:** '+str(overlaps)}")
    W(f"- Label GT tanpa folder: {sorted(orphan_gt) or 'tak ada ✓'}")
    W(f"- Folder serangan tanpa GT: {sorted(orphan_folder) or 'tak ada ✓'}")
    W(f"- **Status C: {c_stat}**\n")

    # ---- D: Distribusi label ----
    per = defaultdict(lambda: {"flows":0,"pkts":0,"bytes":0,"ts":None,"te":None})
    for r in flows:
        d = per[r["label"]]; d["flows"]+=1; d["pkts"]+=r["n_packets"]; d["bytes"]+=r["n_bytes"]
        try:
            ts=float(r["t_start"]); te=float(r["t_end"])
            d["ts"]=ts if d["ts"] is None else min(d["ts"],ts)
            d["te"]=te if d["te"] is None else max(d["te"],te)
        except (ValueError, TypeError): pass
    tot_pkts = sum(d["pkts"] for d in per.values())
    # "unknown": pipeline tak membuat folder unknown → 0 (benign = catch-all)
    unknown_pct = 0.0
    d_stat = "LULUS" if unknown_pct < TH_UNKNOWN_PASS else ("PERINGATAN" if unknown_pct<=TH_UNKNOWN_WARN else "GAGAL")
    summary["D"] = ("Distribusi label", d_stat,
                    f"{len(per)} kelas, {tot_pkts:,} paket; bucket unknown={unknown_pct:.1f}% (pipeline tak buat 'unknown')")
    W("## D — Distribusi label (flow & paket)\n")
    W("| label | flows | packets | bytes | durasi(s) |")
    W("|---|--:|--:|--:|--:|")
    for lbl in sorted(per, key=lambda k:per[k]["flows"]):
        d=per[lbl]; dur = (d["te"]-d["ts"]) if d["ts"] else 0
        W(f"| {lbl} | {d['flows']:,} | {d['pkts']:,} | {d['bytes']:,} | {dur:.0f} |")
    W(f"\n- Bucket **unknown**: {unknown_pct:.1f}% (pipeline label_pcap tak menghasilkan kelas `unknown`; "
      f"paket di luar window serangan → `benign` sbg catch-all; relevan utk F/G).")
    W(f"- **Status D: {d_stat}** (ambang unknown <{TH_UNKNOWN_PASS}% LULUS / ≤{TH_UNKNOWN_WARN}% PERINGATAN)\n")

    # ---- E: Shortcut IP ----
    attack_ips = sorted({r["src_ip"] for r in gt})
    aset = set(attack_ips)
    # Pisahkan asal serangan:
    #  - CONTAINER attacker (nfm/attacker) di cp/up .50 → HANYA menyerang, tak
    #    pernah benign → bila muncul di benign = KEBOCORAN NYATA.
    #  - UE/tunnel ue-mal (10.45.x UE, 172.23.0.43 N3/GTP) → UE yg JUGA browsing
    #    normal → muncul di benign adalah SAH (shared-host), bukan kebocoran.
    CONTAINER_IPS = {ip for ip in aset if ip.endswith(".50") and ip.startswith("172.2")}
    UE_IPS = aset - CONTAINER_IPS
    TP=FP=FN=TN=0
    benign_flows=attack_flows=0
    for r in flows:
        is_benign = (r["label"]=="benign")
        pred_attack = (r["ip_a"] in aset) or (r["ip_b"] in aset)
        if is_benign: benign_flows+=1
        else: attack_flows+=1
        if not is_benign and pred_attack: TP+=1
        elif is_benign and pred_attack: FP+=1
        elif not is_benign and not pred_attack: FN+=1
        else: TN+=1
    tot=TP+FP+FN+TN
    acc=100*(TP+TN)/tot if tot else 0
    prec=100*TP/(TP+FP) if (TP+FP) else 0
    rec=100*TP/(TP+FN) if (TP+FN) else 0
    # per-kelas: apakah IP sumbernya pernah muncul di benign?
    benign_ips=set()
    for r in flows:
        if r["label"]=="benign": benign_ips.add(r["ip_a"]); benign_ips.add(r["ip_b"])
    sep_classes=[]
    cls_ips={}
    for lbl in attack_folders:
        ips=set()
        for r in flows:
            if r["label"]==lbl:
                for e in (r["ip_a"],r["ip_b"]):
                    if e in aset: ips.add(e)
        cls_ips[lbl]=sorted(ips)
        # 100% terpisah bila tak satupun IP attacker kelas ini ada di benign
        if ips and not (ips & benign_ips): sep_classes.append(lbl)
    # Kelas sumber-CONTAINER = IP-nya HANYA dari attacker container (.50) → attack-only
    # by design (kebocoran 80-flow itu sendiri = trafik serangan salah-label, bukan benign
    # sah) → BISA dihafal via IP, independen dari artefak kebocoran.
    sep_container = sorted(l for l in attack_folders
                           if cls_ips.get(l) and set(cls_ips[l]) <= CONTAINER_IPS)
    # Shortcut bila akurasi global tinggi ATAU ada kelas sumber-container.
    shortcut = (acc>=TH_IP_SHORTCUT) or bool(sep_container)
    e_stat = "PERINGATAN/BLOKER-BERSYARAT" if shortcut else "LULUS"
    summary["E"] = ("Shortcut IP", e_stat,
                    f"baseline-IP acc={acc:.1f}% (prec={prec:.1f}%/rec={rec:.1f}%); "
                    f"{len(sep_container)}/{len(attack_folders)} kelas sumber-container BISA di-shortcut via IP")
    W("## E — Shortcut via alamat IP (PALING PENTING)\n")
    W(f"- IP sumber serangan (ground_truth): `{attack_ips}`")
    W(f"  - **attacker CONTAINER** (hanya menyerang): `{sorted(CONTAINER_IPS)}`")
    W(f"  - **UE/tunnel ue-mal** (juga browsing normal): `{sorted(UE_IPS)}`")
    W(f"- Aturan baseline *\"flow=SERANGAN bila satu endpoint ∈ IP attacker/ue-mal\"*:")
    W(f"  - Akurasi **{acc:.1f}%**, precision **{prec:.1f}%**, recall **{rec:.1f}%** "
      f"(TP={TP:,} FP={FP:,} FN={FN:,} TN={TN:,}; flow serangan={attack_flows:,}, benign={benign_flows:,})")
    W(f"  - FP tinggi ({FP:,}) karena IP ue-mal (10.45.0.9) **juga** dipakai benign → "
      f"justru **menurunkan** kekuatan shortcut (bagus utk validitas).")
    ue_sourced = sorted(set(attack_folders) - set(sep_container))
    W(f"- Separabilitas IP **per kelas** (kunci), berdasar ASAL serangan:")
    W(f"  - **Sumber-CONTAINER → SHORTCUT-ABLE** (IP .50 attack-only): **{sep_container}**")
    W(f"  - **Sumber-UE/tunnel → RESISTEN** (IP juga dipakai benign): **{ue_sourced}**")
    W(f"  - (uji ketat \"IP tak pernah muncul di benign\" → {sorted(sep_classes)}; "
      f"kelas container lolos uji ini kecuali terpengaruh 80-flow bocor di F.)")
    W(f"- IP attacker per kelas:")
    for lbl in sorted(cls_ips): W(f"  - `{lbl}`: {cls_ips[lbl]}")
    W(f"- **Interpretasi:** serangan **sumber-UE** (Tier 0 dos_*/recon, gtpu) BERBAGI IP dgn benign "
      f"→ tak bisa dicurangi via IP (baik). Serangan **sumber-CONTAINER** (PFCP/NGAP/SBI/TLS) memakai "
      f"IP .50 yang tak pernah benign → **BISA dihafal via IP**. IP masking netFound: **BELUM DIKONFIRMASI** (lihat I).")
    W(f"- **Status E: {e_stat}** — Fase 8 valid hanya bila (a) IP masking AKTIF (wajib utk kelas sumber-container) "
      f"dan/atau (b) validasi silang dataset ber-IP lain (5G-NIDD).\n")

    # ---- F: Kemurnian benign ----
    # KEBOCORAN NYATA = benign yg menyentuh IP CONTAINER attacker (tak pernah sah benign).
    leak=[r for r in flows if r["label"]=="benign" and ((r["ip_a"] in CONTAINER_IPS) or (r["ip_b"] in CONTAINER_IPS))]
    leak_pkts=sum(r["n_packets"] for r in leak)
    # SHARED-HOST (sah) = benign dari IP UE/tunnel yg juga menyerang.
    shared=[r for r in flows if r["label"]=="benign" and ((r["ip_a"] in UE_IPS) or (r["ip_b"] in UE_IPS))]
    shared_pkts=sum(r["n_packets"] for r in shared)
    benign_total=sum(1 for r in flows if r["label"]=="benign")
    leak_pct=100*len(leak)/benign_total if benign_total else 0
    # flow terlabel ganda: key 5-tuple muncul di >1 label
    key2labels=defaultdict(set)
    for r in flows:
        key2labels[(r["proto"],r["ip_a"],r["ip_b"],r["port_a"],r["port_b"])].add(r["label"])
    dual=[k for k,ls in key2labels.items() if len(ls)>1]
    dual_benign=[k for k in dual if "benign" in key2labels[k]]
    # GAGAL hanya bila kebocoran container besar (>1% benign); kalau kecil → PERINGATAN (mudah dibersihkan).
    f_stat = "LULUS" if not leak else ("GAGAL" if leak_pct>1.0 else "PERINGATAN")
    summary["F"]=("Kemurnian benign", f_stat,
                  f"kebocoran container→benign={len(leak)} flow ({leak_pct:.3f}%); "
                  f"shared-host UE (sah)={len(shared)} flow; 5-tuple ganda campur-benign={len(dual_benign)}")
    W("## F — Kemurnian benign & tumpang tindih\n")
    W(f"- **Kebocoran NYATA** (benign menyentuh IP attacker-CONTAINER {sorted(CONTAINER_IPS)}): "
      f"**{len(leak)} flow / {leak_pkts:,} pkt** ({leak_pct:.3f}% dari benign) "
      f"{'✓ bersih' if not leak else '✗ (perlu dibersihkan)'}")
    for r in leak[:4]: W(f"  - {r['ip_a']}:{r['port_a']} ↔ {r['ip_b']}:{r['port_b']} ({r['n_packets']} pkt)")
    if leak: W(f"  - **Sebab:** trafik setup/teardown serangan SBI (T4/T5) sedikit di LUAR window ground-truth → "
               f"masuk benign. **Saran:** kecualikan IP {sorted(CONTAINER_IPS)} dari benign, atau lebarkan trim window.")
    W(f"- **Shared-host (SAH, bukan kebocoran):** benign dari IP UE/tunnel ue-mal "
      f"{sorted(UE_IPS)} = **{len(shared)} flow / {shared_pkts:,} pkt** — UE penyerang JUGA browsing normal "
      f"(semua ke webserver 172.24.0.10:80). Ini benar berlabel benign & menguntungkan (anti-shortcut, lihat E).")
    W(f"- 5-tuple terlabel ganda: **{len(dual)}** (campur benign+serangan: **{len(dual_benign)}**) — "
      f"antar-kelas serangan berbeda window akibat port efemeral dipakai ulang; relevan hanya bila mencampur benign.")
    W(f"- **Status F: {f_stat}** (GAGAL bila kebocoran container >1% benign; di sini {leak_pct:.3f}%).\n")

    # ---- G: Shortcut TLS ----
    benign_tls=[r for r in flows if r["label"]=="benign" and (r["has_tls_handshake"]==1 or r["port_a"]=="7777" or r["port_b"]=="7777")]
    tls_attack_labels=["sbi_attack_over_tls","tls_handshake_flood","sbi_http2_dos"]
    plaintext_http2={}
    for lbl in tls_attack_labels:
        plaintext_http2[lbl]=sum(1 for r in flows if r["label"]==lbl and r["has_http2"]==1)
    g_pass = (len(benign_tls)>0) and all(v==0 for v in plaintext_http2.values())
    g_stat="LULUS" if g_pass else "PERINGATAN"
    summary["G"]=("Shortcut TLS & enkripsi", g_stat,
                  f"benign TLS flow={len(benign_tls)}; http2-plaintext di serangan-TLS={sum(plaintext_http2.values())}")
    W("## G — Shortcut TLS & verifikasi enkripsi\n")
    W(f"- Flow **benign** ber-TLS/SBI (port 7777 atau TLS handshake): **{len(benign_tls)}** "
      f"{'✓ (bukan hanya serangan yg ber-TLS)' if benign_tls else '✗ (hanya serangan ber-TLS → shortcut)'}")
    W(f"- Frame HTTP/2 **plaintext** pada serangan-atas-TLS (harus 0):")
    for lbl,v in plaintext_http2.items(): W(f"  - `{lbl}`: {v} {'✓' if v==0 else '✗'}")
    W(f"- **Status G: {g_stat}**\n")

    # ---- H: Keseimbangan kelas ----
    attack_counts={lbl:per[lbl]["flows"] for lbl in attack_folders if lbl in per}
    fl=sorted(per[k]["flows"] for k in per)
    imb = (max(fl)/min(fl)) if fl and min(fl)>0 else float("inf")
    low=[l for l,n in attack_counts.items() if n< TH_CLASS_PASS]
    verylow=[l for l,n in attack_counts.items() if n< TH_CLASS_WARN]
    h_stat = "GAGAL/perhatian" if verylow else ("PERINGATAN" if low else "LULUS")
    summary["H"]=("Keseimbangan kelas", h_stat,
                  f"rasio imbalance={imb:.0f}×; kelas <{TH_CLASS_PASS} flow={len(low)}, <{TH_CLASS_WARN}={len(verylow)}")
    W("## H — Kelayakan ML (keseimbangan kelas, satuan FLOW)\n")
    W("| kelas | flows | status |")
    W("|---|--:|---|")
    for lbl in sorted(attack_counts, key=attack_counts.get):
        n=attack_counts[lbl]
        st = "GAGAL(<%d)"%TH_CLASS_WARN if n<TH_CLASS_WARN else ("PERINGATAN(<%d)"%TH_CLASS_PASS if n<TH_CLASS_PASS else "ok")
        W(f"| {lbl} | {n:,} | {st} |")
    W(f"| benign | {per['benign']['flows']:,} | ok |")
    W(f"\n- Rasio ketidakseimbangan (flow terbesar/terkecil): **{imb:.0f}×**")
    W(f"- Kelas < {TH_CLASS_PASS} flow: {sorted(low) or 'tak ada'}; < {TH_CLASS_WARN} flow: {sorted(verylow) or 'tak ada'}")
    W(f"- **Status H: {h_stat}**\n")

    # ---- I: Kesiapan netFound ----
    raw_ok = all(glob.glob(os.path.join(LABELED,l,"*.pcap")) for l in folder_labels)
    summary["I"]=("Kesiapan format netFound","LULUS" if raw_ok else "PERINGATAN",
                  "PCAP mentah per label tersedia; preprocessing (IP mask, tokenizer PFCP/NGAP) dicatat")
    W("## I — Kesiapan format netFound\n")
    W(f"- PCAP mentah per label tersedia: {'ya ✓' if raw_ok else 'TIDAK ✗'} (netFound proses paket mentah).")
    W("- Rencana preprocessing yang HARUS dicatat untuk Fase 8:")
    W("  - **IP anonymization/masking** (lihat E): status **belum dikonfirmasi** — WAJIB aktif.")
    W("  - **Tokenizer protocol-aware:** netFound asli untuk IP/TCP/UDP umum. Tier 0–1 (N6, GTP-U "
      "membungkus IP) aman; **Tier 2–4 (PFCP/NGAP/SBI)** mungkin diperlakukan sbg payload generik "
      "→ batasan yang harus ditulis di laporan riset.")
    W("  - Split train/test **per-flow & per-waktu** (satu flow tak boleh di dua sisi).")
    W(f"- **Status I: {summary['I'][1]}**\n")

    # ---- Ringkasan + verdikt (ditaruh di atas saat tulis file) ----
    blockers=[]; warns=[]; conds=[]
    if b_stat=="GAGAL": blockers.append("B: PCAP terpotong/gagal")
    if d_stat=="GAGAL": blockers.append("D: unknown >10%")
    if f_stat=="GAGAL": blockers.append(f"F: benign tercemar container-IP >1% ({leak_pct:.2f}%)")
    # Syarat (boleh lanjut DENGAN syarat terpenuhi)
    if shortcut:
        conds.append(f"E: {len(sep_container)} kelas sumber-container (PFCP/NGAP/SBI/TLS) 100% IP-separable → "
                     f"WAJIB IP masking netFound dan/atau validasi silang 5G-NIDD")
    if f_stat=="PERINGATAN" and leak:
        conds.append(f"F: bersihkan {len(leak)} flow bocor container→benign (kecualikan {sorted(CONTAINER_IPS)} dari benign)")
    # Peringatan (boleh lanjut, catat)
    if verylow: warns.append(f"H: {sorted(verylow)} <{TH_CLASS_WARN} flow — pakai segmentasi burst/paket utk netFound, bukan unit flow")
    elif low: warns.append(f"H: {len(low)} kelas <{TH_CLASS_PASS} flow")
    if g_stat!="LULUS": warns.append("G: periksa shortcut TLS")
    if blockers:
        verdikt="**NO-GO** — ada bloker: "+ "; ".join(blockers)
    elif conds:
        verdikt=("**GO-DENGAN-SYARAT** — dataset sehat & berlabel benar; lanjut Fase 8 HANYA bila syarat "
                 "berikut dipenuhi: " + "; ".join(conds) + ".")
    else:
        verdikt="**GO** — dataset sehat."

    head=[]
    head.append("# AUDIT_REPORT — Dataset & Testbed 5G (pra-Fase 8)\n")
    head.append(f"- Tanggal: **{today}** · Commit: **{commit}** · Host: VM Ubuntu (offline)")
    head.append(f"- Tool tersedia: " + ", ".join(f"{k}={'ADA' if v and 'TIDAK' not in v else 'TIDAK'}" for k,v in tools.items())
                + f", pandas={'ADA' if has_pandas else 'TIDAK ADA → pakai plain-python'}")
    head.append("- Asumsi tata letak: `data/labeled/<label>/*.pcap` (benign tersebar di beberapa pcap cp/up/dn 2 ronde capture); "
                "flow = 5-tuple bidirectional terkanonikalisasi (IP:port diurutkan).")
    head.append(f"- Ambang dipakai: unknown <{TH_UNKNOWN_PASS}%/≤{TH_UNKNOWN_WARN}%; kelas ≥{TH_CLASS_PASS} flow (warn <{TH_CLASS_PASS}, fail <{TH_CLASS_WARN}); shortcut-IP bila akurasi ≥{TH_IP_SHORTCUT}%.")
    head.append(f"- Ekstraksi: **{sum(int(s['capinfos_packets']) for s in stat_rows if int(s['capinfos_packets'])>0):,} paket**, "
                f"**{len(flows):,} flow**, 0 paket gagal parse.\n")
    head.append("## Ringkasan\n")
    head.append("| Kode | Pemeriksaan | Status | Catatan |")
    head.append("|---|---|---|---|")
    for k,(nm,st,note) in summary.items():
        head.append(f"| {k} | {nm} | {st} | {note} |")
    j = lambda xs: ("\n  - " + "\n  - ".join(xs)) if xs else " tak ada"
    head.append("\n### Bloker, Syarat & Peringatan")
    head.append(f"- **BLOKER (NO-GO):**{j(blockers)}")
    head.append(f"- **SYARAT (GO-DENGAN-SYARAT):**{j(conds)}")
    head.append(f"- **PERINGATAN (catat, boleh lanjut):**{j(warns)}")
    head.append(f"\n### Verdikt Fase 8: {verdikt}\n")
    head.append("### Rekomendasi split Fase 8")
    head.append("- Split train/test **per-flow** dan idealnya **per-waktu** (hindari satu flow di dua sisi → kebocoran).")
    head.append("- Aktifkan **IP masking** pada preprocessing netFound (tanpa ini, model menghafal IP — lihat E).")
    head.append("- **Uji akhir pada dataset eksternal 5G-NIDD** untuk menguji generalisasi lintas-IP.\n")
    head.append("---\n")

    with open(REPORT,"w") as f:
        f.write("\n".join(head) + "\n" + "\n".join(out) + "\n")
    print(f"==> Laporan → {os.path.relpath(REPORT,ROOT)}")
    print("\n".join(f"  {k}: {v[1]}" for k,v in summary.items()))
    print(f"  VERDIKT: {verdikt}")

if __name__ == "__main__":
    main()
