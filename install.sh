#!/bin/bash
# Chimera server one-command installer for Debian 12
# Usage: bash install.sh
set -e

CHIMERA_DIR="/opt/chimera"
REPO="https://github.com/laoxiechuzheng/chimera-core"
BINARY_URL="$REPO/releases/latest/download/chimera-server-linux-amd64"

echo "=== Chimera installer for Debian 12 ==="

mkdir -p "$CHIMERA_DIR"
cd "$CHIMERA_DIR"

echo "[1/4] Downloading chimera-server..."
curl -fsSL -o chimera-server "$BINARY_URL"
chmod +x chimera-server

echo "[2/4] Generating keys..."
KEYS=$(./chimera-server -genkey)
PRIV=$(echo "$KEYS" | grep 'Private Key' | awk '{print $3}')
PUB=$(echo "$KEYS" | grep 'Public Key' | awk '{print $3}')
SID=$(echo "$KEYS" | grep 'Short ID' | awk '{print $3}')

echo "[3/4] Creating systemd service..."
cat > /etc/systemd/system/chimera.service <<EOF
[Unit]
Description=Chimera Proxy Server
After=network.target

[Service]
ExecStart=$CHIMERA_DIR/chimera-server -listen :8443 -target www.cloudflare.com:443 -sni www.cloudflare.com -key $PRIV -sid $SID -quic-pass $SID
Restart=on-failure
RestartSec=3
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now chimera

echo "[4/4] Done. Connection info below - SAVE THIS:"
echo ""
echo "  Server IP:  (your VPS public IP)"
echo "  TCP port:   8443"
echo "  QUIC port:  8443 (same port, auto-detect)"
echo "  SNI:        www.cloudflare.com"
echo "  Public Key: $PUB"
echo "  Short ID:   $SID"
echo ""
echo "Open firewall ports if needed: ufw allow 8443/tcp && ufw allow 8443/udp"
