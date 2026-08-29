# Chimera Protocol Specification v1

## Overview

Chimera is a hybrid proxy protocol combining:
- **REALITY** handshake for SNI whitelist camouflage (borrowed real-site TLS 1.3)
- **AnyTLS-inspired** session-level padding (defeats traffic analysis)
- **Vision-style** raw payload relay (avoids TLS-in-TLS fingerprinting)
- **TUIC/Hysteria2-inspired** QUIC/UDP fast path (speed mode)

## Modes

### Mode T (TCP/REALITY - Mimic Mode)

Priority: camouflage. Uses REALITY handshake with SNI whitelist.

### Mode U (QUIC - Speed Mode)

Priority: throughput. Uses QUIC v1 with certificate pinning + optional obfuscation.

## Mode T Wire Format

### Handshake

Standard REALITY handshake (borrowed real-site TLS 1.3). After REALITY verify succeeds:

#### Client -> Server: Session Header (32 bytes)

    [0-3]   magic 0x43 0x48 0x49 0x4D ("CHIM")
    [4]     version 0x01
    [5]     flags
            bit 0: padding enabled
            bit 1: multiplexing enabled
            bit 2-7: reserved
    [6-7]   reserved (zero)
    [8-31]  padding (random, discarded)

#### Server -> Client: Session Response (8 bytes)

    [0-3]   magic 0x43 0x48 0x49 0x4D
    [4]     version 0x01
    [5]     status (0x00 = OK, 0x01 = version mismatch)
    [6-7]   reserved

### Target Connect (within padding stream)

    [0]     command (0x01 = TCP connect, 0x03 = UDP associate)
    [1]     addr type (0x01 = IPv4, 0x03 = domain, 0x04 = IPv6)
    [..]    address
            IPv4: 4 bytes
            domain: 1 byte length + domain bytes
            IPv6: 16 bytes
    [..]    port (2 bytes big-endian)

### Padding Stream Frame

All post-handshake data is wrapped in frames:

    [0]     frame type (0x00 = padding only, 0x01 = data with padding, 0x02 = data no padding)
    [1-2]   payload length (big-endian uint16, 0-65535)
    [3-4]   padding length (big-endian uint16, 0-65535)
    [..]    padding bytes (random)
    [..]    payload

### Padding Policy (AnyTLS-inspired)

- First 8 frames after handshake: padding length = random(0, 255) applied to client requests
- Subsequent frames: padding length = random(0, max_padding) where max_padding is configurable
- Random 20% chance of sending a padding-only frame (0x00) to break timing patterns

## Mode U Wire Format (QUIC)

### Transport

QUIC v1 over UDP. Server presents self-signed ECDSA P-256 certificate.
Client pins server via SHA-256 fingerprint of the leaf certificate.

### Optional Obfuscation (Salamander-style)

When enabled, each UDP datagram payload is XOR'd with an AES-CTR keystream
before QUIC processing. This is length-preserving. The obfuscation key is
derived from a user-provided password via HKDF-SHA256.

### Authentication

First stream on each QUIC connection sends:

    [0-3]   magic "CHIM"
    [4]     version
    [5-12]  nonce (8 random bytes)
    [13-44] HMAC-SHA256(auth_password, nonce)

Server verifies HMAC. On failure, connection is closed silently.

### Target Connect (per QUIC stream)

Same as Mode T Target Connect format (without outer padding stream,
QUIC handles stream multiplexing natively).

### UDP Relay

Client opens a dedicated bidirectional stream for UDP relay. Packets are
framed as:

    Client -> Server:
    [0-7]   session ID (uint64 big-endian, client-assigned)
    [1-2]   addr type + addr + port (same as Target Connect)
    [..]    payload

    Server -> Client:
    [0-7]   session ID
    [..]    payload

## Security Properties

1. **SNI whitelist**: Only configured server names are accepted; mismatch falls back to real site
2. **Certificate forgery immunity**: REALITY borrows real cert chain from target site
3. **Active probing resistance**: Non-authenticated connections are transparently proxied to the real site
4. **Traffic analysis resistance**: AnyTLS-style padding breaks payload-length signatures
5. **TLS-in-TLS avoidance**: Payload is relayed raw inside the outer TLS (no nested TLS wrapping)
6. **Forward secrecy**: Standard TLS 1.3 forward secrecy from REALITY handshake
7. **Replay resistance (Mode U)**: Per-session nonce + HMAC verification

## Dependencies

- github.com/xtls/reality (REALITY TLS fork)
- github.com/refraction-networking/utls (uTLS for client fingerprinting)
- github.com/quic-go/quic-go (QUIC implementation)

## License

MIT. Chimera is a derivative work inspired by VLESS/REALITY (XTLS), AnyTLS,
TUIC v5, and Hysteria2. Those projects' licenses apply to their respective code.
