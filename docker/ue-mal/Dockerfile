# ue-mal — UE jahat (sumber serangan sisi pelanggan, Tier 0/1).
# Basis UERANSIM (tetap bisa bangun PDU session) + tool serangan N6/GTP-U.
# Build butuh internet (NAT); runtime di jaringan internal (isolasi).
FROM gradiant/ueransim:3.2.6

# Tool Tier 0 (5G-NIDD): nmap(recon), hping3(flood), slowhttptest(slow DoS),
# apache2-utils→ab(http flood). + scapy/python3 utk Tier 1 GTP-U malformed.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      nmap hping3 slowhttptest apache2-utils \
      iproute2 iputils-ping curl tcpdump \
      python3 python3-scapy && \
    rm -rf /var/lib/apt/lists/*

# Entrypoint UERANSIM tetap (command: ue). Serangan dijalankan via `docker exec`.
