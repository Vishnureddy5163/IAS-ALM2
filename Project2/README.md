# Project 2: "SecureTunnel" - Transport Layer Security (TLS/SSH) Visualizer

## Overview
**SecureTunnel** is an interactive educational tool and cryptographic engine that simulates and visualizes the handshake mechanics of secure transport layer protocols (TLS/SSL and SSH), as well as IPsec Encapsulating Security Payload (ESP) packet encapsulation modes.

## Core Topics Covered
1. **Transport Level Security**: Secure socket layer architecture, authenticated key exchange, and record protocol.
2. **TLS/SSL Handshake Simulation**:
   - **Step 1: Client Hello**: Client random (32 bytes), supported cipher suites, TLS version.
   - **Step 2: Server Hello & Certificate**: Server random, selected cipher suite, server X.509 certificate with RSA public key.
   - **Step 3: Client Key Exchange**: Client verifies certificate validity, creates random 48-byte pre-master secret, encrypts it with server's RSA public key, and transmits it.
   - **Step 4: Session Key Generation**: Both parties independently run the TLS Pseudo-Random Function (PRF / HMAC-SHA256) to derive Master Secret and 4 symmetric session keys (`client_write_key`, `server_write_key`, IVs).
   - **Step 5: Finished Verification**: Mutual exchange of encrypted Finished HMAC verification messages to confirm handshake integrity.
   - **Encrypted Transmission**: Live AES-128-GCM symmetric application data transmission over the established tunnel.
3. **SSH (Secure Shell) Connection Simulation**:
   - **Step 1: Protocol Version Exchange**: Version string negotiation (`SSH-2.0`).
   - **Step 2: Key Exchange**: Diffie-Hellman Group Exchange yielding shared secret $K$ and exchange hash $H$.
   - **Step 3: Server Authentication**: Server signs exchange hash $H$ with host private key; client verifies host key fingerprint.
   - **Step 4: User Authentication**: User credential verification (`ssh-userauth`).
   - **Step 5: Secure Channel Established**: Encrypted PTY shell allocation.
4. **IP Security (IPsec) ESP Packet Encapsulation**:
   - **Transport Mode**: Host-to-host protection; encrypts transport payload (TCP/UDP) while preserving original IP header.
   - **Tunnel Mode (VPN)**: Gateway-to-gateway; encapsulates and encrypts the entire original IP datagram under a new gateway IP header.
   - Color-coded visual breakdown of plaintext headers, ESP headers, encrypted payloads, trailers, and Integrity Check Value (ICV) authentication data.

## Technical Architecture & Backend Endpoints
- **Runtime**: Python 3.14+ / Flask 3.0+ on `http://localhost:5002`
- **Crypto Library**: `cryptography.hazmat` (RSA, AES-GCM, AES-CBC, HMAC-SHA256)

### API Specification
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/tls/init` | Initializes stateful TLS session with ephemeral server certificate |
| `POST` | `/api/tls/step/<1-5>` | Advances through Client Hello, Server Hello, Key Exchange, PRF Derivation, Finished |
| `POST` | `/api/tls/send-data` | Symmetrically encrypts payload using derived `client_write_key` via AES-128-GCM |
| `POST` | `/api/ssh/init` | Initializes stateful SSH connection session |
| `POST` | `/api/ssh/step/<1-5>` | Advances through Version Exchange, DH KEX, Server Auth, User Auth, and PTY Shell |
| `POST` | `/api/ipsec/analyze` | Generates structured ESP datagram breakdown for Transport vs Tunnel Mode |

## Running Project 2
```bash
python app.py
```
To run unit tests:
```bash
python test_project2.py
```
