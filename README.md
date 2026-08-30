# Chimera v0.5

Chimera is a TCP proxy with two selectable carriers:

- `tcp`: REALITY with an SNI whitelist and the existing Chimera padding stream.
- `quic`: a standards-valid HTTP/3 basic CONNECT tunnel with an independent PSK and mandatory certificate pinning.
- `auto`: try QUIC for a bounded period, then lazily fall back to TCP/REALITY.

v0.5 replaces the old raw `CHIM`-over-QUIC prototype. Its QUIC carrier is intentionally incompatible with v0.3/v0.4; TCP/REALITY remains compatible.

## What it does and does not do

- TCP/REALITY provides the strongest active-probe fallback in this project: a non-authenticated TLS client is sent to the configured real site.
- QUIC is real HTTP/3, not HTTP/1.1 bytes hidden behind an `h3` ALPN. Ordinary H3 requests receive a cached, bounded decoy response.
- QUIC uses UDP on the wire but currently carries TCP CONNECT streams. Chimera does **not** implement SOCKS UDP ASSOCIATE, CONNECT-UDP, or arbitrary UDP relay.
- The self-signed QUIC certificate is securely pinned by authorized clients, but it is not equivalent to REALITY camouflage. A domain and CA-signed certificate you control can reduce that distinction.
- Chimera does not promise anonymity, immunity from DPI/QoS/blocking, or protection from a malicious server. Sensitive applications should still use HTTPS, SSH, or application-level end-to-end encryption.

## Debian 12 server install

Interactive install (asks for one shared TCP/UDP port and the SNI):

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/laoxiechuzheng/chimera-core/main/install.sh)
```

Non-interactive example:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/laoxiechuzheng/chimera-core/main/install.sh) --port 9443 --sni g.alicdn.com
```

The installer does not change firewall rules. It:

- verifies the release binary with `checksums-sha256.txt`;
- preserves existing REALITY keys, short IDs, port, and SNI;
- generates an independent 32-byte `QUIC_PSK` only when missing;
- stores secrets in `/opt/chimera/keys.env` with mode `0600`;
- persists the QUIC certificate in `/var/lib/chimera/quic-v5-cert.pem`;
- runs the service as a restricted dynamic systemd user;
- prints the public key, SID, QUIC PSK, and certificate fingerprint needed by clients.

Existing installations use the same command to upgrade. QUIC clients and the server must both be upgraded to v0.5 before selecting `quic` or `auto`.

Useful checks:

```bash
systemctl status chimera --no-pager
journalctl -u chimera -n 100 --no-pager
```

## Native mihomo configuration

Use the matching Chimera-enabled mihomo release:

```yaml
proxies:
  - name: chimera
    type: chimera
    server: YOUR_VPS_IP
    port: 9443
    sni: g.alicdn.com
    public-key: YOUR_REALITY_PUBLIC_KEY
    short-id: YOUR_SHORT_ID
    client-fingerprint: chrome
    mode: auto                 # tcp | quic | auto
    quic-psk: YOUR_QUIC_PSK
    quic-fp: YOUR_QUIC_CERT_SHA256
    auto-quic-timeout: 1200    # milliseconds; auto mode only
```

Mode behavior is deterministic:

- `tcp` opens TCP/REALITY only. `quic-psk` and `quic-fp` are not required.
- `quic` opens UDP/HTTP3 only. A blocked TCP port does not prevent the attempt.
- `auto` attempts QUIC for `auto-quic-timeout`, then opens TCP only if QUIC failed. QUIC success creates no TCP socket.

The Chimera-enabled mihomo remains a normal mihomo kernel and retains standard VLESS/REALITY, VMess, Trojan, Hysteria2, TUIC, AnyTLS, TUN, DNS, and rule support from its upstream tree. Chimera itself currently advertises TCP streams only; setting `udp: true` does not add a UDP relay.

## Standalone client

TCP only:

```bash
chimera-client \
  -socks 127.0.0.1:1080 \
  -server YOUR_VPS_IP:9443 \
  -sni g.alicdn.com \
  -pub YOUR_REALITY_PUBLIC_KEY \
  -sid YOUR_SHORT_ID \
  -fp chrome
```

Auto mode:

```bash
chimera-client \
  -socks 127.0.0.1:1080 \
  -server YOUR_VPS_IP:9443 \
  -sni g.alicdn.com \
  -pub YOUR_REALITY_PUBLIC_KEY \
  -sid YOUR_SHORT_ID \
  -fp chrome \
  -auto \
  -quic-psk YOUR_QUIC_PSK \
  -quic-fp YOUR_QUIC_CERT_SHA256 \
  -auto-quic-timeout 1200ms
```

Use `-quic` instead of `-auto` to prohibit TCP fallback.

## Manual server start

Secrets may be supplied through environment variables so they do not appear in the process command line:

```bash
export CHIMERA_PRIVATE_KEY='YOUR_PRIVATE_KEY'
export CHIMERA_SHORT_IDS='YOUR_SHORT_ID'
export CHIMERA_QUIC_PSK='YOUR_QUIC_PSK'
export CHIMERA_QUIC_CERT='/var/lib/chimera/quic-v5-cert.pem'

chimera-server \
  -listen :9443 \
  -target g.alicdn.com:443 \
  -sni g.alicdn.com
```

Use `-no-quic` for TCP-only service. Multiple comma-separated SIDs are supported; each SID derives its own H3 auth key from the same independent PSK.

## Security controls in v0.5

- H3 auth key: HKDF-SHA256 over the independent PSK, REALITY public key, and SID.
- Per-request timestamp, 16-byte random nonce, HMAC-SHA256, and a hard-bounded replay cache.
- Mandatory SHA-256 leaf-certificate pinning for QUIC clients.
- DNS resolution followed by public-IP validation, then dialing the validated IP literal to reduce SSRF and DNS-rebinding risk.
- Cached decoy responses, a 256 KiB body cap, no request-triggered origin fetch, bounded tracked IPs, and concurrency/rate limits.
- SOCKS defaults to `127.0.0.1:1080` and rejects clients that do not offer no-auth rather than silently accepting an unsupported method.

See [chimera-spec.md](chimera-spec.md) for the wire contract and limits.

## Build

Go 1.25.13 or newer in the Go 1.25 series is required for the release build:

```bash
go build -trimpath -o chimera-server ./cmd/chimera-server
go build -trimpath -o chimera-client ./cmd/chimera-client
```

Releases include SHA-256 checksums and must be built from a clean tagged checkout with `vcs.modified=false`.

## License

MIT. See [LICENSE](LICENSE). REALITY, uTLS, quic-go, and other dependencies retain their own licenses.
