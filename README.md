# Chimera Protocol

Chimera is a hybrid proxy protocol combining:
- REALITY handshake (SNI whitelist + borrowed real-site cert, active-probing resistant)
- AnyTLS-style session padding (traffic-analysis resistant)
- Vision-style raw payload relay (no TLS-in-TLS signature)
- TUIC/Hysteria2-style QUIC fast path

Full spec: chimera-spec.md

## Build

    go build -o chimera-server ./cmd/chimera-server
    go build -o chimera-client ./cmd/chimera-client

Requires Go 1.24+. First build downloads deps from network.

## Generate Keys

    chimera-server -genkey

Outputs Private Key (server), Public Key (client), Short ID (both).

## Server Start

    chimera-server -listen :8443 -target www.cloudflare.com:443 -sni www.cloudflare.com -key PRIVATE_KEY -sid SHORT_ID -quic :8445 -quic-pass PASSWORD

- target: borrowed real site (prefer TLS1.3+H2, short cert chain, IP close to server)
- sni: whitelist; client SNI must be in this list
- quic/quic-pass: optional QUIC fast mode over UDP

NOTE: avoid targets whose TLS handshake exceeds 8KB (e.g. www.microsoft.com) with upstream
REALITY lib. Our fork raised the limit to 64KB but short-chain sites are still recommended.
Good targets: www.cloudflare.com, www.bing.com, dl.google.com.

## Client Start (TCP/REALITY mimic mode)

    chimera-client -socks :1080 -server SERVER_IP:8443 -sni www.cloudflare.com -pub PUBLIC_KEY -sid SHORT_ID -fp chrome

## Client Start (QUIC speed mode, needs server -quic)

    chimera-client -socks :1085 -server SERVER_IP:8445 -sni www.cloudflare.com -pub PUBLIC_KEY -sid SHORT_ID -quic

Optional: -quic-obfs PASSWORD for length-preserving UDP obfuscation.

## mihomo Integration

Run chimera-client locally (SOCKS5), then in mihomo:

    proxies:
      - name: chimera-tcp
        type: socks5
        server: 127.0.0.1
        port: 1080
      - name: chimera-quic
        type: socks5
        server: 127.0.0.1
        port: 1085

Both modes verified working end-to-end. Our client's REALITY handshake also completes
against reference Xray-core VLESS+REALITY inbound (protocol-compatible with REALITY spec).

## Security Properties

1. Non-whitelisted SNI transparently falls back to the real site
2. Certificate chain is the real target's - no cert-chain attack possible
3. Session-level random padding breaks payload-length signatures
4. Raw payload relay (no TLS-in-TLS signature)
5. QUIC mode: cert fingerprint pinning + optional length-preserving obfuscation
6. Per-stream HMAC token auth (QUIC mode)

## Known Limitations

- No UDP associate in TCP mode yet (planned for QUIC mode)
- No stream multiplexing yet (one connection per request; smux planned)
- QUIC obfuscation uses fixed-nonce keystream (obfuscation only; security from QUIC layer)
