#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AUDIT (baca-saja) — Ekstraksi SATU KALI semua PCAP berlabel → tabel flow.

Untuk tiap data/labeled/<label>/*.pcap: jalankan tshark (via pipe stdin, hindari
AppArmor) ambil field per-paket, lalu agregasi menjadi flow BIDIRECTIONAL
(5-tuple terkanonikalisasi: pasangan IP:port diurutkan). Hanya flows.csv yang
disimpan (bukan per-paket). Juga menulis extract_stats.csv (paket capinfos vs
baris terekstrak → deteksi paket gagal parse).

Keluaran: reports/audit/flows.csv, reports/audit/extract_stats.csv
TIDAK mengubah apa pun di data/. Read-only.
"""
import csv, glob, os, subprocess, sys
from collections import defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LABELED = os.path.join(ROOT, "data", "labeled")
OUT = os.path.join(ROOT, "reports", "audit")
os.makedirs(OUT, exist_ok=True)

FIELDS = ["frame.time_epoch", "ip.src", "ip.dst", "ip.proto",
          "tcp.srcport", "tcp.dstport", "udp.srcport", "udp.dstport",
          "sctp.srcport", "sctp.dstport", "frame.len",
          "tls.handshake.type", "frame.protocols"]

def capinfos_count(pcap):
    try:
        out = subprocess.run(["capinfos", "-c", "-M", pcap],
                             capture_output=True, text=True).stdout
        for line in out.splitlines():
            if "Number of packets" in line:
                return int(line.split(":")[1].strip().replace(",", ""))
    except Exception:
        pass
    return -1

def tshark_rows(pcap):
    """tshark -r - (pipe) -T fields → yield list kolom per paket."""
    cmd = ["tshark", "-r", "-", "-T", "fields", "-E", "separator=\t", "-E", "occurrence=f"]
    for f in FIELDS:
        cmd += ["-e", f]
    with open(pcap, "rb") as fin:
        p = subprocess.Popen(cmd, stdin=fin, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, text=True)
        for line in p.stdout:
            yield line.rstrip("\n").split("\t")
        p.wait()

def canon(ip_a, pa, ip_b, pb):
    """Urutkan (IP,port) agar A→B dan B→A = satu flow."""
    if (ip_a, pa) <= (ip_b, pb):
        return ip_a, ip_b, pa, pb
    return ip_b, ip_a, pb, pa

def main():
    pcaps = sorted(glob.glob(os.path.join(LABELED, "*", "*.pcap")))
    if not pcaps:
        print("[!] tak ada pcap berlabel"); sys.exit(1)
    print(f"==> {len(pcaps)} pcap berlabel akan diekstrak.")

    # flow key -> agregat
    flows = defaultdict(lambda: {"n": 0, "bytes": 0, "ts": None, "te": None,
                                 "tls_hs": 0, "http2": 0, "proto": ""})
    stats = []   # (file, label, capinfos_pkts, extracted_rows, parsed_ip)

    for pcap in pcaps:
        label = os.path.basename(os.path.dirname(pcap))
        cap_n = capinfos_count(pcap)
        rows = 0; parsed = 0
        for col in tshark_rows(pcap):
            rows += 1
            col += [""] * (len(FIELDS) - len(col))
            (te, ipsrc, ipdst, proto, tsp, tdp, usp, udp_, ssp, sdp,
             flen, tlshs, protos) = col[:13]
            if not ipsrc or not ipdst:
                continue   # paket non-IP (mis. ARP) — tak masuk flow
            parsed += 1
            # pilih port sesuai protokol
            if tsp or tdp:   sp, dp = tsp, tdp
            elif usp or udp_: sp, dp = usp, udp_
            elif ssp or sdp: sp, dp = ssp, sdp
            else:            sp, dp = "0", "0"
            sp = sp or "0"; dp = dp or "0"
            ia, ib, pa, pb = canon(ipsrc, sp, ipdst, dp)
            key = (label, proto, ia, ib, pa, pb)
            f = flows[key]
            f["n"] += 1
            try: f["bytes"] += int(flen or 0)
            except ValueError: pass
            try:
                t = float(te)
                f["ts"] = t if f["ts"] is None else min(f["ts"], t)
                f["te"] = t if f["te"] is None else max(f["te"], t)
            except ValueError:
                pass
            if tlshs: f["tls_hs"] = 1
            if protos and "http2" in protos: f["http2"] = 1
            f["proto"] = proto
        stats.append((os.path.relpath(pcap, ROOT), label, cap_n, rows, parsed))
        print(f"  [{label}] {os.path.basename(pcap)}: capinfos={cap_n} rows={rows} ip={parsed} flows_so_far={len(flows)}")

    # tulis flows.csv
    fp = os.path.join(OUT, "flows.csv")
    with open(fp, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["label", "proto", "ip_a", "ip_b", "port_a", "port_b",
                    "n_packets", "n_bytes", "t_start", "t_end",
                    "has_tls_handshake", "has_http2"])
        for (label, proto, ia, ib, pa, pb), v in flows.items():
            w.writerow([label, proto, ia, ib, pa, pb, v["n"], v["bytes"],
                        f"{v['ts']:.6f}" if v["ts"] else "",
                        f"{v['te']:.6f}" if v["te"] else "",
                        v["tls_hs"], v["http2"]])
    # tulis extract_stats.csv
    sp = os.path.join(OUT, "extract_stats.csv")
    with open(sp, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["file", "label", "capinfos_packets", "tshark_rows", "ip_packets"])
        w.writerows(stats)

    tot_cap = sum(s[2] for s in stats if s[2] > 0)
    tot_row = sum(s[3] for s in stats)
    print(f"\n==> {len(flows)} flow → {os.path.relpath(fp,ROOT)}")
    print(f"==> paket capinfos={tot_cap} tshark_rows={tot_row} "
          f"(selisih={tot_cap-tot_row}) → {os.path.relpath(sp,ROOT)}")

if __name__ == "__main__":
    main()
