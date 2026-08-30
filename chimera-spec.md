# Chimera Protocol Specification v0.5

## 1. Scope

Chimera proxies TCP application streams over one of two carriers:

- TCP/REALITY with the Chimera v1 session and padding frames.
- QUIC with a standards-valid HTTP/3 basic CONNECT request.

The v0.5 H3 carrier is a breaking replacement for the v0.3/v0.4 raw QUIC protocol. TCP/REALITY is unchanged at the wire level. v0.5 does not define SOCKS UDP ASSOCIATE, CONNECT-UDP, IP tunneling, or arbitrary UDP target relay.

## 2. TCP/REALITY carrier

### 2.1 Handshake

The client performs a REALITY handshake using an allowed SNI, server public key, SID, and selected uTLS fingerprint. Non-authenticated TLS connections follow the REALITY target-site fallback behavior supplied by the XTLS/REALITY library.

After REALITY authentication, the client sends a 32-byte Chimera session header:

```text
[0..3]   43 48 49 4d ("CHIM")
[4]      version = 01
[5]      flags
[6..7]   reserved = 00 00
[8..31]  ignored padding
```

The server replies:

```text
[0..3]   43 48 49 4d
[4]      version = 01
[5]      status (00 = OK)
[6..7]   reserved
```

### 2.2 Target request

Inside the padding stream:

```text
[0]      command (01 = TCP CONNECT)
[1]      address type (01 IPv4, 03 domain, 04 IPv6)
[...]    address
[...]    port, uint16 big-endian
```

The server resolves domains, rejects forbidden destinations, dials a validated IP literal, then sends a Chimera session response with status `00` only after the target TCP connection succeeds.

### 2.3 Padding frame

```text
[0]      frame type (00 padding-only, 01 data+padding, 02 data)
[1..2]   payload length, uint16 big-endian
[3..4]   padding length, uint16 big-endian
[...]    random padding
[...]    payload
```

The current default applies up to 255 bytes of padding to the first eight frames and up to 64 bytes afterward. This is limited traffic-analysis resistance; it is not AnyTLS wire compatibility and does not eliminate TLS-in-TLS characteristics when the proxied application also uses TLS.

## 3. HTTP/3 CONNECT carrier

### 3.1 QUIC and TLS

- QUIC version: implementation-supported QUIC v1.
- ALPN: standard `h3` through the HTTP/3 library.
- TLS minimum: TLS 1.3.
- Client authentication of the server: mandatory SHA-256 pin of the leaf certificate DER.
- Default certificate mode: persisted self-signed ECDSA P-256 certificate whose SAN/CN is the configured server name.
- Preferred certificate mode: a CA-signed certificate and private key for a domain controlled by the operator.

The pinned self-signed mode protects the authorized client from an on-path certificate substitution. It does not reproduce REALITY's borrowed-certificate behavior and must not be described as REALITY-equivalent camouflage.

### 3.2 Key derivation

The installer generates an independent, random 32-byte `QUIC_PSK`. For each REALITY SID, the H3 authentication key is:

```text
HKDF-SHA256(
  ikm  = QUIC_PSK,
  salt = REALITY_PUBLIC_KEY || SHORT_ID,
  info = "chimera-h3-auth-v1",
  len  = 32
)
```

The PSK is not derived from public information. PSK, public key, and SID length validation is fail-closed.

### 3.3 CONNECT request

Each target TCP connection uses one HTTP/3 basic CONNECT request:

```text
:method    = CONNECT
:authority = host:port
authorization = Bearer <base64url token>
user-agent = browser-like static value
```

The authority uses brackets for IPv6. The HTTP/3 implementation supplies SETTINGS, QPACK, HEADERS, and DATA framing; Chimera does not write raw HTTP/1.1 bytes or custom stream magic.

### 3.4 Authorization token

Decoded token bytes:

```text
[0]       version = 05
[1..8]    Unix timestamp, uint64 big-endian
[9..24]   nonce, 16 random bytes
[25..56]  HMAC-SHA256(auth_key, canonical_input)
```

The HTTP header is:

```text
Authorization: Bearer base64url(token_without_padding)
```

Canonical HMAC input:

```text
version(1)
|| timestamp(8)
|| nonce(16)
|| uint16(len(upper(method))) || upper(method)
|| uint16(len(lower(trim(authority)))) || lower(trim(authority))
|| uint16(len(lower(trim(server_name)))) || lower(trim(server_name))
```

The server accepts a maximum default clock skew of 60 seconds. It compares the token against every configured SID-derived key, inserts the nonce only after a valid MAC, and stores accepted nonces in a hard-bounded replay cache (default capacity 4096).

### 3.5 Response and stream

- `2xx`: target dial succeeded; request and response HTTP/3 DATA frames become the bidirectional TCP byte stream.
- Non-`2xx`: no proxy stream is returned to the client.
- The client drains at most 4 KiB of an error body before closing the failed request.
- Closing the returned mihomo connection closes both the request stream and its one-per-target parent H3/QUIC connection exactly once.

## 4. Decoy and active-probe behavior

The H3 server accepts ordinary standards-valid HTTP/3 requests. Missing, malformed, expired, replayed, or wrong-key CONNECT authentication follows the same bounded unauthenticated response class; no raw `CHIM` classification branch exists.

The decoy snapshot:

- is fetched at startup and refreshed no more than once per ten minutes;
- uses a five-second timeout and no redirects;
- validates the resolved origin address before dialing it;
- has a 256 KiB maximum body;
- retains only a small safe header allowlist;
- is served from memory for individual probes;
- falls back to a bounded built-in body if origin refresh fails.

Global concurrency, per-IP unauthenticated burst limits, maximum tracked IPs, QUIC stream limits, handshake timeout, and idle timeout are bounded. Authenticated tunnels retain the global concurrency limit but are not incorrectly charged against the unauthenticated probe bucket.

## 5. Target safety

Both carriers parse `host:port`, reject zero/invalid ports, resolve domains on the server, and reject the entire DNS result if any answer is loopback, private, link-local, multicast, unspecified, CGNAT, documentation, benchmark, reserved, or metadata-relevant space. The server dials a selected validated IP literal rather than resolving the original hostname again.

This policy is designed to prevent a leaked client credential from turning the proxy into a server-side LAN or metadata springboard. Operators should still apply host-level egress controls where practical.

## 6. Client mode selection

- `tcp`: create TCP/REALITY only.
- `quic`: create QUIC/H3 only; TCP reachability is irrelevant.
- `auto`: attempt QUIC with a default 1200 ms selection budget, then lazily create TCP only if QUIC failed.

Successful QUIC selection does not create or retain a TCP socket. All partial or losing connections are closed. `auto-quic-timeout` is configured in milliseconds in mihomo and as a Go duration in the standalone client.

## 7. Privacy and observability

A passive ISP or Wi-Fi observer sees encrypted TLS/REALITY TCP traffic in TCP mode or encrypted QUIC/H3 UDP traffic in QUIC mode, plus metadata such as server IP, port, timing, packet sizes, and volume. The Chimera server can observe target addresses and traffic metadata; it can read plaintext applications. HTTPS/SSH content remains protected by the application's own end-to-end encryption.

Chimera does not provide anonymity, endpoint security, malicious-server protection, or guaranteed resistance to DPI, blocking, traffic analysis, or QoS. QUIC and TCP may perform differently on a given path, which is why the explicit and bounded modes exist.

## 8. Compatibility

- v0.5 TCP/REALITY: compatible with the previous Chimera TCP carrier.
- v0.5 H3: incompatible with v0.3/v0.4 raw QUIC clients and servers.
- v0.5 QUIC requires the independent PSK and certificate fingerprint.
- A v0.5 server and matching v0.5 core/mihomo client must be deployed together before using `quic` or `auto`.

## 9. Release requirements

Release gates include formatting, full tests, Linux race tests, vet, source vulnerability scanning, Debian 12 installer upgrade behavior, Windows/Linux builds, end-to-end TCP/H3/auto tests, certificate persistence, invalid-auth/replay/SSRF tests, clean VCS metadata, and SHA-256 checksums.

## 10. License

Chimera core is MIT licensed. Dependencies and the mihomo fork retain their own licenses, including mihomo's GPL-3.0 terms.
