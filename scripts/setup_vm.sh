#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# Fase 1 — Setup prasyarat VM untuk NFM Testbed 5G.
# Memasang: Docker Engine + compose plugin, tshark/tcpdump/editcap,
#           python3-venv, git, dan util jaringan untuk capture.
# Idempoten: aman dijalankan ulang.
#
# WAJIB root (apt + grup docker). Jalankan:
#   sudo bash scripts/setup_vm.sh
#
# Selesai jika: `docker run hello-world` dan `tshark -v` berjalan OK
# (skrip ini mengujinya di akhir).
# ─────────────────────────────────────────────────────────────
set -euo pipefail

# --- Pastikan root ---
if [[ "${EUID}" -ne 0 ]]; then
  echo "[!] Harus root. Jalankan: sudo bash scripts/setup_vm.sh" >&2
  exit 1
fi

# User non-root yang akan ditambahkan ke grup docker (pemanggil sudo).
TARGET_USER="${SUDO_USER:-${USER}}"
export DEBIAN_FRONTEND=noninteractive

echo "==> [1/6] apt update"
apt-get update -y

echo "==> [2/6] Paket dasar (tshark, tcpdump, python3-venv, dll.)"
# wireshark-common menyediakan editcap/mergecap; tshark untuk analisis PCAP.
# Preseed agar tshark boleh dipakai non-root tanpa prompt interaktif.
echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections
apt-get install -y --no-install-recommends \
  ca-certificates curl gnupg lsb-release \
  tshark tcpdump \
  python3 python3-venv python3-pip \
  git jq iproute2 iputils-ping

echo "==> [3/6] Docker Engine + compose plugin (repo resmi Docker)"
if ! command -v docker >/dev/null 2>&1; then
  install -m 0755 -d /etc/apt/keyrings
  # Ubuntu 26.04 (resolute) belum tentu punya repo Docker sendiri → fallback ke 'noble' (24.04 LTS) yang stabil.
  UBU_CODENAME="$(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")"
  DOCKER_CODENAME="$UBU_CODENAME"
  if ! curl -fsSL "https://download.docker.com/linux/ubuntu/dists/${UBU_CODENAME}/Release" >/dev/null 2>&1; then
    echo "    [i] Repo Docker utk '${UBU_CODENAME}' tidak ada → pakai 'noble' (24.04 LTS)."
    DOCKER_CODENAME="noble"
  fi
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${DOCKER_CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
else
  echo "    [i] docker sudah ada: $(docker --version)"
fi

echo "==> [4/6] Aktifkan & mulai layanan docker"
systemctl enable --now docker

echo "==> [5/6] Tambahkan user '${TARGET_USER}' ke grup docker"
if ! id -nG "${TARGET_USER}" | tr ' ' '\n' | grep -qx docker; then
  usermod -aG docker "${TARGET_USER}"
  echo "    [i] '${TARGET_USER}' ditambah ke grup docker. LOGOUT/LOGIN (atau 'newgrp docker') agar berlaku."
else
  echo "    [i] '${TARGET_USER}' sudah di grup docker."
fi

echo "==> [6/6] Verifikasi (kriteria selesai Fase 1)"
echo "---- docker run hello-world ----"
docker run --rm hello-world | grep -q "Hello from Docker" && echo "[OK] docker hello-world"
echo "---- tshark -v ----"
tshark -v | head -1 && echo "[OK] tshark"
echo "---- editcap ----"
command -v editcap >/dev/null && echo "[OK] editcap: $(editcap -v 2>&1 | head -1)"
echo "---- docker compose ----"
docker compose version && echo "[OK] docker compose"

echo
echo "============================================================"
echo "Fase 1 SELESAI. Jika baru ditambah ke grup docker, jalankan:"
echo "    newgrp docker    # atau logout/login"
echo "lalu lanjut Fase 2 (docker-compose.yml + core 5G)."
echo "============================================================"
