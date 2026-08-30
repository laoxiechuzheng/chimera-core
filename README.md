# Chimera Protocol

Debian 12 one-command server install. Interactive mode asks for the port and SNI;
press Enter to accept the defaults:

    bash <(curl -fsSL https://raw.githubusercontent.com/laoxiechuzheng/chimera-core/main/install.sh)

Non-interactive install with a custom port and SNI:

    bash <(curl -fsSL https://raw.githubusercontent.com/laoxiechuzheng/chimera-core/main/install.sh) --port 9443 --sni www.bing.com

Upgrades reuse /opt/chimera/keys.env, so existing client keys remain valid.

Releases: https://github.com/laoxiechuzheng/chimera-core/releases
Native mihomo kernel: https://github.com/laoxiechuzheng/mihomo/releases/tag/v1.19-chimera.4

Chimera is a hybrid proxy protocol combining:
- REALITY handshake (SNI whitelist + borrowed real-site cert, active-probing resistant)
- Session padding (AnyTLS-inspired, reduced-strength traffic-analysis resistance)
- Application bytes relayed unmodified inside the REALITY TLS session.
  NOTE: if the proxied app itself uses TLS, TLS-in-TLS signatures remain
  possible - this is NOT a Vision replacement.
- QUIC fast path v2: HMAC-SHA256 auth with random nonce + replay cache,
  mandatory certificate fingerprint pinning, dial-result confirmation
- QUIC v0.4 h3 camouflage: standard ALPN h3 handshake; active probes are
  reverse-proxied to the REALITY target site (they see the real website)

Full spec: chimera-spec.md

## Build

    go build -o chimera-server ./cmd/chimera-server
    go build -o chimera-client ./cmd/chimera-client

Requires Go 1.24+. First build downloads deps from network.

## Generate Keys

    chimera-server -genkey

Outputs Private Key (server), Public Key (client), Short ID (both).

## Server Start

    chimera-server -listen :8443 -target www.cloudflare.com:443 -sni www.cloudflare.com -key PRIVATE_KEY -sid SHORT_ID

- target: borrowed real site (prefer TLS1.3+H2, short cert chain, IP close to server)
- sni: whitelist; client SNI must be in this list
- QUIC shares the same UDP port automatically; the auth password is derived
  from the public key + short ID on both sides (no extra config)
- use -no-quic for TCP-only mode (no UDP listener)

NOTE: avoid targets whose TLS handshake exceeds 8KB (e.g. www.microsoft.com) with upstream
REALITY lib. Our fork raised the limit to 64KB but short-chain sites are still recommended.
Good targets: www.cloudflare.com, www.bing.com, dl.google.com.

## Client Start (TCP/REALITY mimic mode)

    chimera-client -socks :1080 -server SERVER_IP:8443 -sni www.cloudflare.com -pub PUBLIC_KEY -sid SHORT_ID -fp chrome

## Client Start (QUIC speed mode, needs server -quic)

The server prints its QUIC cert fingerprint at startup; pass it via -quic-fp
(mandatory - the client refuses QUIC without pinning):

    chimera-client -socks :1080 -server SERVER_IP:8443 -sni www.cloudflare.com -pub PUBLIC_KEY -sid SHORT_ID -quic -quic-fp FINGERPRINT

The QUIC auth password is derived automatically from -sid/-pub. Both TCP and
QUIC clients now wait for a dial-confirmation frame, so a SOCKS5 success reply
means the target is actually connected.

## mihomo Integration

Use the native outbound directly (v1.19-chimera.3+ kernels):

    proxies:
      - name: chimera
        type: chimera
        server: SERVER_IP
        port: 8443
        sni: www.cloudflare.com
        public-key: PUBLIC_KEY
        short-id: SHORT_ID
        client-fingerprint: chrome

Both modes verified working end-to-end. Our client's REALITY handshake also completes
against reference Xray-core VLESS+REALITY inbound (protocol-compatible with REALITY spec).

## Security Properties

1. Non-whitelisted SNI transparently falls back to the real site
2. Certificate chain is the real target's - no cert-chain attack possible
3. Session-level random padding breaks payload-length signatures
4. QUIC v2: per-stream random nonce + HMAC auth, replay cache, pinned certs
5. QUIC has no default password; credentials derive from REALITY keys on both sides
6. QUIC v0.4: ALPN is standard "h3"; unauthenticated connections are answered
   with the borrowed site's real content instead of an error

## Known Limitations

- No UDP associate in TCP mode yet (planned for QUIC mode)
- No stream multiplexing yet (one connection per request; smux planned)
- TCP mode remains detectable as TLS-in-TLS when the proxied app uses TLS
- QUIC mode serves a self-signed cert (pinned client-side); the camouflage
  relies on h3 ALPN + real-site reverse proxy for probes. It does not mimic
  the target's certificate chain - that would require the target's private key.
