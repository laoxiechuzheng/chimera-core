#!/bin/bash
# Chimera server one-command installer for Debian 12
# Interactive:  bash <(curl -fsSL https://raw.githubusercontent.com/laoxiechuzheng/chimera-core/main/install.sh)
# Unattended:   bash <(curl -fsSL https://raw.githubusercontent.com/laoxiechuzheng/chimera-core/main/install.sh) --port 9443 --sni www.bing.com
set -e

CHIMERA_DIR="/opt/chimera"
REPO="https://github.com/laoxiechuzheng/chimera-core"
BINARY_URL="$REPO/releases/latest/download/chimera-server-linux-amd64"

PORT=""
SNI=""

while [ $# -gt 0 ]; do
  case "$1" in
    -p|--port) PORT="$2"; shift 2 ;;
    -s|--sni)  SNI="$2";  shift 2 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

validate_port() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

if [ -z "$PORT" ]; then
  if [ -t 0 ]; then
    while true; do
      read -r -p "Listen port, TCP and UDP share it [8443]: " input
      candidate="${input:-8443}"
      if validate_port "$candidate"; then
        PORT="$candidate"
        break
      fi
      echo "Invalid port: $candidate (must be 1-65535)"
    done
  else
    PORT="8443"
  fi
fi
validate_port "$PORT" || { echo "Invalid --port: $PORT" >&2; exit 1; }

if [ -z "$SNI" ]; then
  if [ -t 0 ]; then
    read -r -p "SNI / REALITY target site [www.cloudflare.com]: " input
    SNI="${input:-www.cloudflare.com}"
  else
    SNI="www.cloudflare.com"
  fi
fi
SNI=$(printf '%s' "$SNI" | tr -d '[:space:]' | tr 'A-Z' 'a-z')
[ -n "$SNI" ] || { echo "SNI cannot be empty" >&2; exit 1; }

echo "=== Chimera installer for Debian 12 ==="
echo "Port: $PORT  SNI: $SNI"

systemctl stop chimera 2>/dev/null || true
umask 077

mkdir -p "$CHIMERA_DIR"
cd "$CHIMERA_DIR"

echo "[1/4] Downloading chimera-server..."
curl -fsSL -o chimera-server.new "$BINARY_URL"
chmod +x chimera-server.new
mv -f chimera-server.new chimera-server

if [ -f keys.env ]; then
  echo "[2/4] Reusing existing keys from keys.env..."
  # shellcheck disable=SC1091
  . ./keys.env
  chmod 600 keys.env
else
  echo "[2/4] Generating keys..."
  KEYS=$(./chimera-server -genkey)
  PRIV=$(echo "$KEYS" | grep 'Private Key' | awk '{print $3}')
  PUB=$(echo "$KEYS" | grep 'Public Key' | awk '{print $3}')
  SID=$(echo "$KEYS" | grep 'Short ID' | awk '{print $3}')
  cat > keys.env <<EOF
PRIV="$PRIV"
PUB="$PUB"
SID="$SID"
EOF
  chmod 600 keys.env
fi

echo "[3/4] Creating systemd service..."
cat > /etc/systemd/system/chimera.service <<EOF
[Unit]
Description=Chimera Proxy Server
After=network.target

[Service]
EnvironmentFile=$CHIMERA_DIR/keys.env
ExecStart=$CHIMERA_DIR/chimera-server -listen :$PORT -target $SNI:443 -sni $SNI -key `$PRIV -sid `$SID
Restart=on-failure
RestartSec=3
LimitNOFILE=65535
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now chimera

echo "[4/4] Done. Connection info below - SAVE THIS:"
echo ""
echo "  Server IP:  (your VPS public IP)"
echo "  TCP port:   $PORT"
echo "  QUIC port:  $PORT (same port, auto-detect)"
echo "  SNI:        $SNI"
echo "  Public Key: $PUB"
echo "  Short ID:   $SID"
