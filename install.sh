#!/bin/bash
# Chimera v0.5 installer for Debian 12.
# Interactive: bash <(curl -fsSL https://raw.githubusercontent.com/laoxiechuzheng/chimera-core/main/install.sh)
# Unattended:  bash <(curl -fsSL https://raw.githubusercontent.com/laoxiechuzheng/chimera-core/main/install.sh) --port 9443 --sni example.com
set -euo pipefail

CHIMERA_DIR=${CHIMERA_DIR:-/opt/chimera}
CHIMERA_STATE_DIR=${CHIMERA_STATE_DIR:-/var/lib/chimera}
CHIMERA_SYSTEMD_DIR=${CHIMERA_SYSTEMD_DIR:-/etc/systemd/system}
CHIMERA_REPO=${CHIMERA_REPO:-https://github.com/laoxiechuzheng/chimera-core}
CHIMERA_VERSION=${CHIMERA_VERSION:-v0.5.0}
BINARY_ASSET=chimera-server-linux-amd64
BINARY_URL=${CHIMERA_BINARY_URL:-$CHIMERA_REPO/releases/download/$CHIMERA_VERSION/$BINARY_ASSET}
CHECKSUM_URL=${CHIMERA_CHECKSUM_URL:-$CHIMERA_REPO/releases/download/$CHIMERA_VERSION/checksums-sha256.txt}
KEYS_FILE=${CHIMERA_KEYS_FILE:-$CHIMERA_DIR/keys.env}
SERVER_CONFIG=${CHIMERA_SERVER_CONFIG:-$CHIMERA_DIR/server.env}
UNIT_FILE=${CHIMERA_UNIT_FILE:-$CHIMERA_SYSTEMD_DIR/chimera.service}
CERT_FILE=${CHIMERA_CERT_FILE:-$CHIMERA_STATE_DIR/quic-v5-cert.pem}

validate_port() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

normalize_sni() {
  local value
  value=$(printf '%s' "$1" | tr 'A-Z' 'a-z')
  case "$value" in
    ''|.*|*.|*..*|*[!a-z0-9.-]*|*[[:space:]]*) return 1 ;;
  esac
  printf '%s\n' "$value"
}

verify_binary_checksum() {
  local binary=$1 checksums=$2 asset=$3 expected actual
  expected=$(awk -v asset="$asset" '$2 == asset { print tolower($1); exit }' "$checksums")
  actual=$(sha256sum "$binary" | awk '{ print tolower($1) }')
  case "$expected" in
    ''|*[!0-9a-f]*) return 1 ;;
  esac
  [ "${#expected}" -eq 64 ] && [ "$actual" = "$expected" ]
}

validate_sid_list() {
  local item
  local -a sid_items
  IFS=',' read -r -a sid_items <<< "$1"
  [ "${#sid_items[@]}" -gt 0 ] || return 1
  for item in "${sid_items[@]}"; do
    case "$item" in
      ''|*[!0-9a-fA-F]*) return 1 ;;
    esac
    [ $(( ${#item} % 2 )) -eq 0 ] || return 1
    [ "${#item}" -ge 2 ] && [ "${#item}" -le 16 ] || return 1
  done
}

migrate_keys_file() {
  local keys_file=$1 server_bin=$2 generated tmp
  CHIMERA_PRIVATE_KEY=
  CHIMERA_PUBLIC_KEY=
  CHIMERA_SHORT_IDS=
  CHIMERA_QUIC_PSK=
  PRIV=
  PUB=
  SID=
  if [ -f "$keys_file" ]; then
    # Root-owned mode-0600 file created by this installer.
    # shellcheck disable=SC1090
    . "$keys_file"
    CHIMERA_PRIVATE_KEY=${CHIMERA_PRIVATE_KEY:-$PRIV}
    CHIMERA_PUBLIC_KEY=${CHIMERA_PUBLIC_KEY:-$PUB}
    CHIMERA_SHORT_IDS=${CHIMERA_SHORT_IDS:-$SID}
  fi
  if [ -z "$CHIMERA_PRIVATE_KEY" ] || [ -z "$CHIMERA_PUBLIC_KEY" ] || [ -z "$CHIMERA_SHORT_IDS" ]; then
    generated=$($server_bin -genkey)
    CHIMERA_PRIVATE_KEY=$(printf '%s\n' "$generated" | awk '/^Private Key:/ { print $3; exit }')
    CHIMERA_PUBLIC_KEY=$(printf '%s\n' "$generated" | awk '/^Public Key:/ { print $3; exit }')
    CHIMERA_SHORT_IDS=$(printf '%s\n' "$generated" | awk '/^Short ID:/ { print $3; exit }')
    CHIMERA_QUIC_PSK=$(printf '%s\n' "$generated" | awk '/^QUIC PSK:/ { print $3; exit }')
  fi
  if [ -z "$CHIMERA_QUIC_PSK" ]; then
    generated=$($server_bin -genpsk)
    CHIMERA_QUIC_PSK=$(printf '%s\n' "$generated" | awk '/^QUIC PSK:/ { print $3; exit }')
  fi
  [[ "$CHIMERA_PRIVATE_KEY" =~ ^[A-Za-z0-9_-]{43}$ ]] || { echo "invalid REALITY private key" >&2; return 1; }
  [[ "$CHIMERA_PUBLIC_KEY" =~ ^[A-Za-z0-9_-]{43}$ ]] || { echo "invalid REALITY public key" >&2; return 1; }
  validate_sid_list "$CHIMERA_SHORT_IDS" || { echo "invalid short ID list" >&2; return 1; }
  [[ "$CHIMERA_QUIC_PSK" =~ ^[A-Za-z0-9_-]{43}$ ]] || { echo "invalid QUIC PSK" >&2; return 1; }
  tmp=${keys_file}.new
  umask 077
  {
    printf 'CHIMERA_PRIVATE_KEY="%s"\n' "$CHIMERA_PRIVATE_KEY"
    printf 'CHIMERA_PUBLIC_KEY="%s"\n' "$CHIMERA_PUBLIC_KEY"
    printf 'CHIMERA_SHORT_IDS="%s"\n' "$CHIMERA_SHORT_IDS"
    printf 'CHIMERA_QUIC_PSK="%s"\n' "$CHIMERA_QUIC_PSK"
  } > "$tmp"
  chmod 600 "$tmp"
  mv -f "$tmp" "$keys_file"
}

render_systemd_unit() {
  local server_bin=$1 output=$2 install_dir=$3 listen=$4 target=$5 sni=$6 tmp
  tmp=${output}.new
  "$server_bin" -systemd-unit -install-dir "$install_dir" -listen "$listen" -target "$target" -sni "$sni" > "$tmp"
  chmod 644 "$tmp"
  mv -f "$tmp" "$output"
}

ensure_quic_certificate() {
  local server_bin=$1 cert_path=$2 sni=$3 output fingerprint
  output=$(CHIMERA_QUIC_CERT="$cert_path" "$server_bin" -quic-cert-info -sni "$sni")
  fingerprint=$(printf '%s\n' "$output" | awk '/^QUIC Fingerprint:/ { print $3; exit }')
  [[ "$fingerprint" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n' "$fingerprint"
}

write_server_config() {
  local file=$1 port=$2 sni=$3 tmp=${1}.new
  validate_port "$port" || return 1
  sni=$(normalize_sni "$sni") || return 1
  umask 077
  {
    printf 'CHIMERA_PORT="%s"\n' "$port"
    printf 'CHIMERA_SNI="%s"\n' "$sni"
  } > "$tmp"
  chmod 600 "$tmp"
  mv -f "$tmp" "$file"
}

load_saved_config() {
  local file=$1 legacy_unit=${2:-} line
  SAVED_PORT=
  SAVED_SNI=
  CHIMERA_PORT=
  CHIMERA_SNI=
  if [ -f "$file" ]; then
    # shellcheck disable=SC1090
    . "$file"
    SAVED_PORT=${CHIMERA_PORT:-}
    SAVED_SNI=${CHIMERA_SNI:-}
  elif [ -n "$legacy_unit" ] && [ -f "$legacy_unit" ]; then
    line=$(grep -m1 '^ExecStart=' "$legacy_unit" || true)
    SAVED_PORT=$(printf '%s\n' "$line" | sed -nE 's/.* -listen [^ ]*:([0-9]+).*/\1/p')
    SAVED_SNI=$(printf '%s\n' "$line" | sed -nE 's/.* -sni ([^ ]+).*/\1/p')
    validate_port "$SAVED_PORT" || SAVED_PORT=
    SAVED_SNI=$(normalize_sni "$SAVED_SNI") || SAVED_SNI=
  fi
}

main() {
  local requested_port= requested_sni= port_default sni_default input download checksums fingerprint
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -p|--port) requested_port=${2:?missing port}; shift 2 ;;
      -s|--sni) requested_sni=${2:?missing SNI}; shift 2 ;;
      *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
  done

  load_saved_config "$SERVER_CONFIG" "$UNIT_FILE"
  port_default=${SAVED_PORT:-8443}
  sni_default=${SAVED_SNI:-www.cloudflare.com}
  if [ -n "$requested_port" ]; then
    PORT=$requested_port
  elif [ -t 0 ]; then
    while true; do
      read -r -p "Listen port, TCP and UDP share it [$port_default]: " input
      PORT=${input:-$port_default}
      validate_port "$PORT" && break
      echo "Invalid port: $PORT (must be 1-65535)"
    done
  else
    PORT=$port_default
  fi
  validate_port "$PORT" || { echo "Invalid port: $PORT" >&2; exit 1; }

  if [ -n "$requested_sni" ]; then
    SNI=$requested_sni
  elif [ -t 0 ]; then
    read -r -p "SNI / REALITY target site [$sni_default]: " input
    SNI=${input:-$sni_default}
  else
    SNI=$sni_default
  fi
  SNI=$(normalize_sni "$SNI") || { echo "Invalid SNI: $SNI" >&2; exit 1; }

  echo "=== Chimera $CHIMERA_VERSION installer for Debian 12 ==="
  echo "Port: $PORT  SNI: $SNI"
  umask 077
  mkdir -p "$CHIMERA_DIR" "$CHIMERA_STATE_DIR" "$CHIMERA_SYSTEMD_DIR"
  chmod 700 "$CHIMERA_STATE_DIR"

  download=$(mktemp "$CHIMERA_DIR/.chimera-server.XXXXXX")
  checksums=$(mktemp "$CHIMERA_DIR/.checksums.XXXXXX")
  trap 'rm -f "$download" "$checksums"' EXIT
  echo "[1/5] Downloading and verifying $BINARY_ASSET..."
  curl -fsSL -o "$download" "$BINARY_URL"
  curl -fsSL -o "$checksums" "$CHECKSUM_URL"
  chmod +x "$download"
  verify_binary_checksum "$download" "$checksums" "$BINARY_ASSET" || { echo "SHA-256 verification failed" >&2; exit 1; }

  if [ "${CHIMERA_SKIP_SYSTEMCTL:-0}" != 1 ]; then
    systemctl stop chimera 2>/dev/null || true
  fi
  mv -f "$download" "$CHIMERA_DIR/chimera-server"
  chmod 755 "$CHIMERA_DIR/chimera-server"
  rm -f "$checksums"
  trap - EXIT

  echo "[2/5] Preserving/migrating credentials..."
  migrate_keys_file "$KEYS_FILE" "$CHIMERA_DIR/chimera-server"
  write_server_config "$SERVER_CONFIG" "$PORT" "$SNI"

  echo "[3/5] Creating persistent QUIC certificate..."
  fingerprint=$(ensure_quic_certificate "$CHIMERA_DIR/chimera-server" "$CERT_FILE" "$SNI")

  echo "[4/5] Installing hardened systemd unit..."
  render_systemd_unit "$CHIMERA_DIR/chimera-server" "$UNIT_FILE" "$CHIMERA_DIR" ":$PORT" "$SNI:443" "$SNI"
  if [ "${CHIMERA_SKIP_SYSTEMCTL:-0}" != 1 ]; then
    systemctl daemon-reload
    systemctl enable --now chimera
  fi

  echo "[5/5] Done. Save these client values:"
  echo ""
  echo "  Server IP:       (your VPS public IP)"
  echo "  TCP/UDP port:    $PORT"
  echo "  SNI:             $SNI"
  echo "  Public Key:      $CHIMERA_PUBLIC_KEY"
  echo "  Short ID(s):     $CHIMERA_SHORT_IDS"
  echo "  QUIC PSK:        $CHIMERA_QUIC_PSK"
  echo "  QUIC Fingerprint: $fingerprint"
  echo ""
  echo "TCP/REALITY remains compatible. QUIC v0.5 requires a matching v0.5 client."
}

if [ "${CHIMERA_INSTALL_LIB_ONLY:-0}" != 1 ]; then
  main "$@"
fi
