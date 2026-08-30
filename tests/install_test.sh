#!/bin/bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SERVER_BIN=${CHIMERA_TEST_SERVER:?CHIMERA_TEST_SERVER must point to a Linux chimera-server binary}
export CHIMERA_INSTALL_LIB_ONLY=1
# shellcheck source=../install.sh
. "$ROOT/install.sh"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

KEYS_FILE="$TMP/keys.env"
cat > "$KEYS_FILE" <<'EOF'
PRIV="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
PUB="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
SID="0102030405060708"
EOF
migrate_keys_file "$KEYS_FILE" "$SERVER_BIN"
grep -q '^CHIMERA_PRIVATE_KEY="AAAAAAAA' "$KEYS_FILE"
grep -q '^CHIMERA_PUBLIC_KEY="BBBBBBBB' "$KEYS_FILE"
grep -q '^CHIMERA_SHORT_IDS="0102030405060708"' "$KEYS_FILE"
grep -Eq '^CHIMERA_QUIC_PSK="[A-Za-z0-9_-]{43}"$' "$KEYS_FILE"
if grep -Eq '^(PRIV|PUB|SID)=' "$KEYS_FILE"; then
  echo "legacy key names remained after migration" >&2
  exit 1
fi

CHECKSUMS="$TMP/checksums-sha256.txt"
HASH=$(sha256sum "$SERVER_BIN" | awk '{print $1}')
printf '%s  chimera-server-linux-amd64\n' "$HASH" > "$CHECKSUMS"
verify_binary_checksum "$SERVER_BIN" "$CHECKSUMS" chimera-server-linux-amd64
printf '%064d  chimera-server-linux-amd64\n' 0 > "$CHECKSUMS"
if verify_binary_checksum "$SERVER_BIN" "$CHECKSUMS" chimera-server-linux-amd64; then
  echo "checksum mismatch was accepted" >&2
  exit 1
fi

UNIT="$TMP/chimera.service"
render_systemd_unit "$SERVER_BIN" "$UNIT" /opt/chimera :9443 g.alicdn.com:443 g.alicdn.com
grep -q '^EnvironmentFile=/opt/chimera/keys.env$' "$UNIT"
grep -q '^DynamicUser=true$' "$UNIT"
grep -q '^StateDirectory=chimera$' "$UNIT"
grep -q '^StateDirectoryMode=0700$' "$UNIT"
grep -q '^WorkingDirectory=/var/lib/chimera$' "$UNIT"
grep -q '^Environment=CHIMERA_QUIC_CERT=/var/lib/chimera/quic-v5-cert.pem$' "$UNIT"
grep -q '^CapabilityBoundingSet=CAP_NET_BIND_SERVICE$' "$UNIT"
grep -q '^AmbientCapabilities=CAP_NET_BIND_SERVICE$' "$UNIT"
grep -q '^RestrictAddressFamilies=AF_INET AF_INET6$' "$UNIT"
if grep -Eq -- ' -(key|sid|quic-psk)( |$)' "$UNIT"; then
  echo "secret argument leaked into systemd unit" >&2
  exit 1
fi
if command -v systemd-analyze >/dev/null 2>&1; then
  mkdir -p /opt/chimera
  cp "$SERVER_BIN" /opt/chimera/chimera-server
  : > /opt/chimera/keys.env
  systemd-analyze verify "$UNIT"
fi

STATE_DIR="$TMP/state"
mkdir -p "$STATE_DIR"
FP1=$(ensure_quic_certificate "$SERVER_BIN" "$STATE_DIR/quic-v5-cert.pem" g.alicdn.com)
FP2=$(ensure_quic_certificate "$SERVER_BIN" "$STATE_DIR/quic-v5-cert.pem" g.alicdn.com)
test "$FP1" = "$FP2"
test -s "$STATE_DIR/quic-v5-cert.pem"

CONFIG="$TMP/server.env"
write_server_config "$CONFIG" 9443 g.alicdn.com
load_saved_config "$CONFIG" "$TMP/unused.service"
test "$SAVED_PORT" = 9443
test "$SAVED_SNI" = g.alicdn.com

LEGACY_UNIT="$TMP/legacy.service"
cat > "$LEGACY_UNIT" <<'EOF'
[Service]
ExecStart=/opt/chimera/chimera-server -listen :10443 -target legacy.example:443 -sni legacy.example -key $PRIV -sid $SID
EOF
load_saved_config "$TMP/missing.env" "$LEGACY_UNIT"
test "$SAVED_PORT" = 10443
test "$SAVED_SNI" = legacy.example

E2E="$TMP/full-upgrade"
mkdir -p "$E2E/opt/chimera" "$E2E/systemd"
cat > "$E2E/opt/chimera/keys.env" <<'EOF'
PRIV="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
PUB="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
SID="0102030405060708"
EOF
cat > "$E2E/systemd/chimera.service" <<'EOF'
[Service]
ExecStart=/opt/chimera/chimera-server -listen :10443 -target legacy.example:443 -sni legacy.example -key $PRIV -sid $SID
EOF
GOOD_CHECKSUMS="$E2E/checksums-sha256.txt"
printf '%s  chimera-server-linux-amd64\n' "$HASH" > "$GOOD_CHECKSUMS"
CHIMERA_INSTALL_LIB_ONLY=0 \
CHIMERA_SKIP_SYSTEMCTL=1 \
CHIMERA_DIR="$E2E/opt/chimera" \
CHIMERA_STATE_DIR="$E2E/var/lib/chimera" \
CHIMERA_SYSTEMD_DIR="$E2E/systemd" \
CHIMERA_BINARY_URL="file://$SERVER_BIN" \
CHIMERA_CHECKSUM_URL="file://$GOOD_CHECKSUMS" \
bash "$ROOT/install.sh"

cmp "$SERVER_BIN" "$E2E/opt/chimera/chimera-server"
grep -q '^CHIMERA_PRIVATE_KEY="AAAAAAAA' "$E2E/opt/chimera/keys.env"
grep -q '^CHIMERA_PUBLIC_KEY="BBBBBBBB' "$E2E/opt/chimera/keys.env"
grep -q '^CHIMERA_SHORT_IDS="0102030405060708"' "$E2E/opt/chimera/keys.env"
grep -Eq '^CHIMERA_QUIC_PSK="[A-Za-z0-9_-]{43}"$' "$E2E/opt/chimera/keys.env"
grep -q '^CHIMERA_PORT="10443"$' "$E2E/opt/chimera/server.env"
grep -q '^CHIMERA_SNI="legacy.example"$' "$E2E/opt/chimera/server.env"
grep -q -- '-listen :10443 -target legacy.example:443 -sni legacy.example' "$E2E/systemd/chimera.service"
test -s "$E2E/var/lib/chimera/quic-v5-cert.pem"

echo "installer behavior tests passed"
