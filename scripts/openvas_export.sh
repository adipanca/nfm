#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fase 6 — Ekspor hasil scan NF ke ringkasan JSON (host, port, service, CVE, severity).
Membaca XML nmap terbaru di reports/scan/ → reports/scan/nf_findings_<ts>.json + .csv.
(Jika memakai Greenbone, ganti input dgn XML report GMP — struktur serupa.)

  python3 scripts/openvas_export.sh
"""
import glob, os, json, csv, sys, re
import xml.etree.ElementTree as ET
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCAN = os.path.join(ROOT, "reports", "scan")

xmls = sorted(glob.glob(os.path.join(SCAN, "nf_scan_*.xml")))
if not xmls:
    print(f"[!] Tak ada XML scan di {SCAN}. Jalankan openvas_scan.sh dulu."); sys.exit(1)
xml = xmls[-1]
print(f"==> Ekspor dari {os.path.basename(xml)}")

tree = ET.parse(xml); root = tree.getroot()
findings = []
for host in root.findall("host"):
    addr = ""
    for a in host.findall("address"):
        if a.get("addrtype") == "ipv4": addr = a.get("addr")
    for port in host.findall("./ports/port"):
        portid = port.get("portid"); proto = port.get("protocol")
        st = port.find("state")
        if st is None or st.get("state") != "open": continue
        svc = port.find("service")
        service = svc.get("name") if svc is not None else ""
        product = (svc.get("product") if svc is not None else "") or ""
        version = (svc.get("version") if svc is not None else "") or ""
        # kerentanan dari NSE script (vuln/ssl)
        vulns = []
        for scr in port.findall("script"):
            sid = scr.get("id", ""); outp = scr.get("output", "")
            cves = re.findall(r"CVE-\d{4}-\d{4,7}", outp)
            state = "VULNERABLE" if "VULNERABLE" in outp.upper() else ("info" if outp else "")
            if cves or state == "VULNERABLE":
                vulns.append({"script": sid, "cves": sorted(set(cves)), "state": state})
        findings.append({
            "host": addr, "port": int(portid), "proto": proto,
            "service": service, "product": product, "version": version,
            "severity": "high" if any(v["state"]=="VULNERABLE" for v in vulns) else ("info" if vulns else "open"),
            "vulns": vulns,
        })

ts = datetime.now().strftime("%Y%m%d_%H%M%S")
jpath = os.path.join(SCAN, f"nf_findings_{ts}.json")
cpath = os.path.join(SCAN, f"nf_findings_{ts}.csv")
json.dump({"source": os.path.basename(xml), "generated": ts, "findings": findings},
          open(jpath, "w"), indent=2)
with open(cpath, "w", newline="") as f:
    w = csv.writer(f); w.writerow(["host","port","proto","service","product","version","severity","cves"])
    for x in findings:
        cves = ";".join(sorted({c for v in x["vulns"] for c in v["cves"]}))
        w.writerow([x["host"],x["port"],x["proto"],x["service"],x["product"],x["version"],x["severity"],cves])

print(f"==> JSON: {os.path.relpath(jpath,ROOT)}")
print(f"==> CSV : {os.path.relpath(cpath,ROOT)}")
openp = sum(1 for x in findings)
vulnp = sum(1 for x in findings if x["severity"] in ("high",))
print(f"==> {openp} port terbuka, {vulnp} tanda VULNERABLE, "
      f"{len(set(x['host'] for x in findings))} NF.")
# tampilkan ringkas
print("\nhost            port/proto  service        severity")
for x in sorted(findings, key=lambda r:(r['host'],r['port'])):
    print(f"  {x['host']:15s} {x['port']}/{x['proto']:4s} {x['service']:14s} {x['severity']}")
