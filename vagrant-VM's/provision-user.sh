#!/usr/bin/env bash
set -e
export DEBIAN_FRONTEND=noninteractive

# ---- Load box data from environment ----
BOX_NAME="${BOX_NAME:-}"
PKG_UPDATE="${PKG_UPDATE:-}"
PKG_INSTALL="${PKG_INSTALL:-}"
DEVEL_PKGS="${DEVEL_PKGS:-}"
SUDO_GROUP="${SUDO_GROUP:-}"
EXTRA_PKGS="${EXTRA_PKGS:-}"

# ---- Base packages ----
eval "$PKG_UPDATE"
eval "$PKG_INSTALL $DEVEL_PKGS $EXTRA_PKGS"

# Explicit guarantee: git and gnupg must exist before clone/gpg
if command -v apt >/dev/null 2>&1; then
  apt install -y git gnupg
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y git gnupg2
fi

usermod -aG "$SUDO_GROUP" vagrant
id vagrant

# ---- Symlinks ----
if [ -d /vagrant/mirak-app ]; then
  rm -rf /home/vagrant/mirak-app
  ln -sfn /vagrant/mirak-app /home/vagrant/mirak-app
  chown -h vagrant:vagrant /home/vagrant/mirak-app || true
  chmod +x /vagrant/mirak-app/* 2>/dev/null || true
else
  echo "Warning: /vagrant/mirak-app folder not found. Skipping symlink."
fi

if [ -f /vagrant/benchmark_script.sh ]; then
  ln -sfn /vagrant/benchmark_script.sh /home/vagrant/benchmark_script.sh
  chown -h vagrant:vagrant /home/vagrant/benchmark_script.sh || true
  chmod +x /home/vagrant/benchmark_script.sh
else
  echo "Warning: /vagrant/benchmark_script.sh not found. Skipping symlink."
fi

# ---- Trivy and Grype ----
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# ---- Go ----
wget -q https://go.dev/dl/go1.26.2.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.26.2.linux-amd64.tar.gz
rm go1.26.2.linux-amd64.tar.gz

export GOROOT=/usr/local/go
export GOPATH=/root/go
export PATH=$GOROOT/bin:$GOPATH/bin:$PATH
mkdir -p "$GOPATH"

cat > /etc/profile.d/go.sh << 'EOF'
export GOROOT=/usr/local/go
export GOPATH=/root/go
export PATH=$GOROOT/bin:$GOPATH/bin:$PATH
EOF

eval "$PKG_INSTALL sqlite3 gcc make"

if ! command -v go >/dev/null 2>&1; then
  echo "ERROR: go not found in PATH"
  exit 1
fi
go version

# ---- Vuls (defensive install) ----
rm -rf /opt/vuls-src
mkdir -p /opt/vuls-src
cd /opt/vuls-src
git clone https://github.com/future-architect/vuls.git
cd vuls

if ! make install; then
  echo "ERROR: Vuls make install failed"
  exit 1
fi

VULS_BIN=$(find /root/go /usr/local/go /opt/vuls-src -name "vuls" -type f -executable 2>/dev/null | head -1)
if [ -z "$VULS_BIN" ]; then
  echo "ERROR: Vuls binary not found after make install"
  ls -la /root/go/bin/ 2>/dev/null || echo "(directory does not exist)"
  exit 1
fi
echo "Vuls binary found at: $VULS_BIN"
install -m 0755 "$VULS_BIN" /usr/local/bin/vuls
/usr/local/bin/vuls -v || true

mkdir -p /opt/vuls/config /opt/vuls/results
chmod -R 755 /opt/vuls

cat > /home/vagrant/config.toml << 'EOF'
[servers]

[servers.localhost]
host = "localhost"
port = "local"
EOF

chown vagrant:vagrant /home/vagrant/config.toml
cd /
