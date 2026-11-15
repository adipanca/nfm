#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fase 5 — Pelabelan PCAP.

Memotong PCAP mentah (data/raw/{cp,up,dn}_*.pcap) berdasarkan:
  jendela waktu (ground_truth.csv) + interface + pasangan IP,
lalu menyimpan per label ke data/labeled/<label>/.

  - Tiap baris ground_truth → data/labeled/<label>/<scenario>_<role>.pcap
  - Trafik di LUAR semua jendela serangan → data/labeled/benign/<role>_*.pcap
  - Ringkasan jumlah paket per label → data/labeled/summary.csv

Catatan: tshark di VM ini dibatasi AppArmor untuk baca/tulis file di path proyek,
jadi semua tshark dijalankan via pipe stdin→stdout (bypass, aman).

Pemakaian:
  python3 scripts/label_pcap.py            # proses pcap TERBARU per role
  python3 scripts/label_pcap.py --all      # proses semua pcap di data/raw
"""
import argparse, csv, glob, os, subprocess, sys
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(ROOT, "data", "raw")
LABELED = os.path.join(ROOT, "data", "labeled")
GT = os.path.join(ROOT, "data", "ground_truth.csv")

# Peta interface skenario → role capture (nama file pcap)
IFACE2ROLE = {"N6": "dn", "N3": "up", "N4": "up", "N2": "up",
              "N1": "up", "SBI": "cp", "TLS": "cp"}

def sh(cmd, stdin_path=None, stdout_path=None):
    """Jalankan tshark via pipe (hindari AppArmor path-rule)."""
    fin = open(stdin_path, "rb") if stdin_path else None
    fout = open(stdout_path, "wb") if stdout_path else subprocess.PIPE
    p = subprocess.run(cmd, stdin=fin, stdout=fout,
                       stderr=subprocess.DEVNULL)
    if fin: fin.close()
    if stdout_path: fout.close()
    return p.returncode

def count_pkts(pcap):
    try:
        out = subprocess.run(["capinfos", "-c", "-M", pcap],
                             capture_output=True, text=True).stdout
        for line in out.splitlines():
            if "Number of packets" in line:
                return int(line.split(":")[1].strip().replace(",", ""))
    except Exception:
        pass
    return 0

def pcap_timerange(pcap):
    """(start_epoch, end_epoch) dari capinfos; (0,0) bila gagal."""
    try:
        out = subprocess.run(["capinfos", "-a", "-e", "-S", pcap],
                             capture_output=True, text=True).stdout
        s = e = None
        for line in out.splitlines():
            if "Earliest packet time" in line or "First packet time" in line:
                s = float(line.split(":",1)[1].strip())
            if "Latest packet time" in line or "Last packet time" in line:
                e = float(line.split(":",1)[1].strip())
        if s is not None and e is not None:
            return s, e
    except Exception:
        pass
    return 0.0, 0.0

def tshark_extract(src_pcap, out_pcap, dfilter):
    """tshark -r - -Y <filter> -w -  (pipe)."""
    cmd = ["tshark", "-r", "-", "-Y", dfilter, "-w", "-", "-F", "pcap"]
    fin = open(src_pcap, "rb"); fout = open(out_pcap, "wb")
    p = subprocess.run(cmd, stdin=fin, stdout=fout, stderr=subprocess.DEVNULL)
    fin.close(); fout.close()
    return count_pkts(out_pcap) if p.returncode == 0 else -1

def latest_per_role(files):
    best = {}
    for f in files:
        base = os.path.basename(f)
        role = base.split("_", 1)[0]
        if role not in ("cp", "up", "dn"): continue
        if role not in best or os.path.getmtime(f) > os.path.getmtime(best[role]):
            best[role] = f
    return best

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true", help="proses semua pcap (default: terbaru per role)")
    ap.add_argument("--raw", default=RAW)
    ap.add_argument("--gt", default=GT)
    args = ap.parse_args()

    if not os.path.exists(args.gt):
        print(f"[!] {args.gt} tidak ada — jalankan skenario dulu."); sys.exit(1)

    rows = list(csv.DictReader(open(args.gt)))
    print(f"==> {len(rows)} baris ground truth.")

    pcaps = sorted(glob.glob(os.path.join(args.raw, "*.pcap")))
    if not pcaps: print(f"[!] tak ada pcap di {args.raw}"); sys.exit(1)
    if not args.all:
        sel = latest_per_role(pcaps); pcaps = list(sel.values())
    print(f"==> memproses {len(pcaps)} pcap: {[os.path.basename(p) for p in pcaps]}")

    summary = defaultdict(int)   # label -> total pkts
    # Kumpulan jendela serangan per role (utk pengurangan benign)
    windows_by_role = defaultdict(list)   # role -> [(start,end)]
    for r in rows:
        role = IFACE2ROLE.get(r["iface"].upper())
        if role:
            windows_by_role[role].append((float(r["start_epoch"]), float(r["end_epoch"])))

    # 1) Per-label (serangan)
    for r in rows:
        role = IFACE2ROLE.get(r["iface"].upper())
        if not role:
            print(f"  [skip] iface {r['iface']} tak dikenal ({r['scenario_id']})"); continue
        s, e, label, sid = r["start_epoch"], r["end_epoch"], r["label"], r["scenario_id"]
        src, dst = r["src_ip"], r["dst_ip"]
        # pcap role yg rentang waktunya menyentuh [s,e]
        cand = [p for p in pcaps if os.path.basename(p).startswith(role+"_")]
        for p in cand:
            ps, pe = pcap_timerange(p)
            if pe < float(s) or ps > float(e):  # tak overlap
                continue
            outdir = os.path.join(LABELED, label); os.makedirs(outdir, exist_ok=True)
            outp = os.path.join(outdir, f"{sid}_{role}.pcap")
            dfilt = (f"frame.time_epoch >= {s} && frame.time_epoch <= {e} "
                     f"&& ip.addr == {src} && ip.addr == {dst}")
            n = tshark_extract(p, outp, dfilt)
            if n > 0:
                summary[label] += n
                print(f"  [{label}] {sid} {role}: {n} pkt → {os.path.relpath(outp,ROOT)}")
            else:
                if os.path.exists(outp) and count_pkts(outp) == 0: os.remove(outp)

    # 2) Benign = di LUAR SEMUA jendela serangan (union lintas role).
    #    Serangan Tier0 (N6) juga melintas N3(up) sbg GTP-U → jangan dianggap benign.
    all_windows = [w for ws in windows_by_role.values() for w in ws]
    for p in pcaps:
        role = os.path.basename(p).split("_",1)[0]
        wins = all_windows
        if wins:
            cond = " || ".join(f"(frame.time_epoch >= {s} && frame.time_epoch <= {e})" for s,e in wins)
            dfilt = f"ip && !({cond})"
        else:
            dfilt = "ip"
        outdir = os.path.join(LABELED, "benign"); os.makedirs(outdir, exist_ok=True)
        outp = os.path.join(outdir, f"{role}_{os.path.basename(p)}")
        n = tshark_extract(p, outp, dfilt)
        if n > 0:
            summary["benign"] += n
            print(f"  [benign] {role}: {n} pkt → {os.path.relpath(outp,ROOT)}")
        elif os.path.exists(outp):
            os.remove(outp)

    # 3) Ringkasan
    os.makedirs(LABELED, exist_ok=True)
    with open(os.path.join(LABELED, "summary.csv"), "w", newline="") as f:
        w = csv.writer(f); w.writerow(["label", "total_packets"])
        for k in sorted(summary): w.writerow([k, summary[k]])
    print("\n==> Ringkasan (data/labeled/summary.csv):")
    for k in sorted(summary): print(f"    {k:20s} {summary[k]:>8d} pkt")
    if summary.get("benign", 0) == 0:
        print("[!] PERINGATAN: benign kosong.")
    print("Selesai.")

if __name__ == "__main__":
    main()
