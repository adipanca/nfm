# attacker — penyerang sisi jaringan inti (Tier 2-4).
# Di net cp + up → jangkau SBI(cp), PFCP/NGAP/GTP-U(up).
# Tooling: scapy (craft PFCP/GTP-U/NGAP), nmap, hping3, nghttp2 (h2load utk SBI HTTP/2).
# Build butuh internet; runtime di jaringan internal (isolasi).
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip python3-scapy \
      nmap hping3 nghttp2-client curl \
      iproute2 iputils-ping tcpdump netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*
# scapy.contrib.pfcp & gtp tersedia di scapy standar.
WORKDIR /opt/attacker
COPY tools/ /opt/attacker/tools/
CMD ["sleep", "infinity"]
