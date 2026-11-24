#!/usr/bin/env bash
set -e
export DEBIAN_FRONTEND=noninteractive

# ---- Load box data from environment ----
BOX_NAME="${BOX_NAME:-}"
PKG_INSTALL="${PKG_INSTALL:-}"
ROUTINATOR_VERSION="${ROUTINATOR_VERSION:-}"
FORT_BUILD_FROM_SOURCE="${FORT_BUILD_FROM_SOURCE:-}"
FORT_VERSION="${FORT_VERSION:-}"

# Explicit guarantee: gnupg must exist before gpg --dearmor
if command -v apt >/dev/null 2>&1; then
  apt install -y gnupg curl wget
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y gnupg2 curl wget
fi

# ============================================================
# Routinator
# ============================================================
if command -v dnf >/dev/null 2>&1; then
  # Fedora: NLnet Labs does not publish packages for Fedora versions.
  # The CentOS 9 repository is used instead. gpgcheck=0 because the
  # official .asc key is in APT (ASCII armored) format, not RPM.
  cat > /etc/yum.repos.d/nlnetlabs.repo << 'EOF'
[nlnetlabs]
name=NLnet Labs
baseurl=https://packages.nlnetlabs.nl/linux/centos/9/main/$basearch
enabled=1
gpgcheck=0
EOF
  dnf makecache
  dnf install -y routinator
elif command -v apt >/dev/null 2>&1; then
  DISTRO_ID=$(. /etc/os-release && echo "$ID")
  if command -v lsb_release >/dev/null 2>&1; then
    CODENAME=$(lsb_release -cs)
  else
    . /etc/os-release
    CODENAME="${VERSION_CODENAME:-}"
  fi
  case "$DISTRO_ID" in
    debian|ubuntu)
      REPO_BASE="$DISTRO_ID"
      ;;
    *)
      echo "Error: unsupported distribution for the NLnet Labs APT repository: $DISTRO_ID"
      exit 1
      ;;
  esac
  if [ -z "$CODENAME" ]; then
    echo "Error: could not determine the distribution codename for the NLnet Labs APT repository."
    exit 1
  fi
  curl -fsSL https://packages.nlnetlabs.nl/aptkey.asc -o /tmp/nlnetlabs-aptkey.asc
  gpg --dearmor --yes -o /usr/share/keyrings/nlnetlabs-archive-keyring.gpg /tmp/nlnetlabs-aptkey.asc
  rm -f /tmp/nlnetlabs-aptkey.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/nlnetlabs-archive-keyring.gpg] https://packages.nlnetlabs.nl/linux/${REPO_BASE} ${CODENAME} main" | tee /etc/apt/sources.list.d/nlnetlabs.list > /dev/null
  apt update

  if [ -n "$ROUTINATOR_VERSION" ]; then
    apt install -y "routinator=${ROUTINATOR_VERSION}"
    apt-mark hold routinator
  else
    apt install -y routinator
  fi
else
  echo "Error: no supported package manager found for Routinator."
  exit 1
fi

if ! command -v routinator >/dev/null 2>&1; then
  echo "Error: Routinator installation completed, but the routinator executable was not found."
  exit 1
fi

systemctl enable --now routinator || true
systemctl status routinator --no-pager || true

# ============================================================
# Fort
# ============================================================
if [ "$FORT_BUILD_FROM_SOURCE" = "true" ]; then
  # Debian 12: compile FORT from source
  apt install -y build-essential pkg-config rsync \
    libjansson-dev libssl-dev libcurl4-openssl-dev \
    libxml2-dev libmicrohttpd-dev

  cd /opt
  rm -rf "fort-${FORT_VERSION}" "fort-${FORT_VERSION}.tar.gz"
  wget -q "https://github.com/NICMx/FORT-validator/releases/download/${FORT_VERSION}/fort-${FORT_VERSION}.tar.gz"
  tar xzf "fort-${FORT_VERSION}.tar.gz"
  cd "fort-${FORT_VERSION}"
  ./configure
  make
  make install
  cd /
  rm -rf "/opt/fort-${FORT_VERSION}" "/opt/fort-${FORT_VERSION}.tar.gz"
else
  # Other boxes: Fort 1.7.0.experimental from GitHub
  if command -v apt >/dev/null 2>&1; then
    wget -q -O /tmp/fort.deb https://github.com/NICMx/FORT-validator/releases/download/1.7.0.experimental/fort_1.7.0.experimental-1_amd64.deb
    apt install -y /tmp/fort.deb
    rm -f /tmp/fort.deb
  elif command -v dnf >/dev/null 2>&1; then
    wget -q -O /tmp/fort.rpm https://github.com/NICMx/FORT-validator/releases/download/1.7.0.experimental/fort-1.7.0.experimental-1.el9.x86_64.rpm
    dnf install -y /tmp/fort.rpm
    rm -f /tmp/fort.rpm
  else
    echo "Error: no supported package manager found for the Fort package."
    exit 1
  fi
fi

FORT_BIN="$(command -v fort || command -v fort-validator || true)"
if [ -z "$FORT_BIN" ]; then
  echo "Error: Fort package installed but its executable was not found."
  exit 1
fi

getent passwd fort || useradd --system --home-dir /var/lib/fort --create-home --shell /usr/sbin/nologin fort
install -d -o root -g fort -m 0750 /etc/fort
install -d -o fort -g fort -m 0750 /var/lib/fort/repository
install -d -o fort -g fort -m 0750 /var/lib/fort/output

# Force tal directory correction immediately before --init-tals
rm -rf /etc/fort/tal
install -d -o fort -g fort -m 0750 /etc/fort/tal

ls -ld /etc/fort/tal

if ! sudo -u fort test -w /etc/fort/tal; then
  echo "FATAL ERROR: user fort does NOT have write permission on /etc/fort/tal"
  ls -la /etc/fort/
  exit 1
fi

sudo -u fort "$FORT_BIN" --init-tals --tal /etc/fort/tal

cat > /etc/fort/config.json << 'EOF'
{
  "mode": "server",
  "tal": "/etc/fort/tal",
  "local-repository": "/var/lib/fort/repository",
  "output": {
    "roa": "/var/lib/fort/output/validated-roas.csv"
  },
  "server": {
    "address": ["127.0.0.1", "::1"],
    "port": "8323",
    "max-rtr-version": 1,
    "interval": {
      "validation": 3600,
      "refresh": 3600,
      "retry": 600,
      "expire": 7200
    }
  },
  "log": {
    "output": "console",
    "level": "info"
  }
}
EOF
chown root:fort /etc/fort/config.json
chmod 0640 /etc/fort/config.json

cat > /etc/systemd/system/fort.service << EOF
[Unit]
Description=FORT RPKI Validator
After=network.target

[Service]
Type=simple
User=fort
Group=fort
ExecStart=${FORT_BIN} --configuration-file /etc/fort/config.json
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now fort || true
systemctl status fort --no-pager || true
