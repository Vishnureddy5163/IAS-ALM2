# Project 1: "CryptoVault" - Public-Key Cryptography & Digital Signature Toolkit

## Overview
**CryptoVault** is an interactive web application and cryptographic toolkit serving as a visual learning environment and practical utility for core public-key cryptography principles, as specified in the KL University ALM-2 curriculum.

## Core Topics Covered
1. **Public-Key Cryptography Principles**: Asymmetric key separation, public key distribution, private key protection.
2. **RSA Algorithm**: 2048-bit key generation, OAEP (Optimal Asymmetric Encryption Padding) with SHA-256, PSS (Probabilistic Signature Scheme) digital signatures.
3. **Diffie-Hellman Key Exchange**: Step-by-step modular exponentiation key exchange between Alice and Bob over insecure channels ($A = g^a \pmod p, B = g^b \pmod p, s = B^a = A^b \pmod p$).
4. **Elgamal Digital Signature Scheme**: Asymmetric signature scheme based on the Discrete Logarithm problem, utilizing SHA-512 digests and ephemeral key $k$.
5. **Hash Functions (SHA-512)**: High-security 512-bit message digests demonstrating why hashing before signing prevents existential forgery and optimizes performance.
6. **Distribution of Public Keys & X.509 Certificates**: Public Key Infrastructure (PKI) simulation where the server acts as a Certificate Authority (CA), binding user identities to public keys with downloadable `.crt` files.

## Technical Architecture & Backend Endpoints
- **Runtime**: Python 3.14+ / Flask 3.0+ on `http://localhost:5001`
- **Crypto Library**: `cryptography.hazmat` & `hashlib`
- **Database**: SQLite (`crypto_vault.db`)

### API Specification
| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/auth/register` | Registers user, generates RSA-2048 keypair, stores public key, issues self-signed X.509 cert |
| `POST` | `/api/auth/login` | Authenticates user and retrieves certificate and public keys |
| `GET` | `/api/pki/download-cert/<user>` | Downloads user's X.509 CA certificate as `.crt` file |
| `GET` | `/api/rsa/generate` | Generates on-demand RSA-2048 key pair in PEM format |
| `POST` | `/api/rsa/encrypt` | RSA-OAEP encryption with SHA-256 |
| `POST` | `/api/rsa/decrypt` | RSA-OAEP decryption with SHA-256 |
| `POST` | `/api/rsa/sign` | Digital signing via RSA-PSS with SHA-256 |
| `POST` | `/api/rsa/verify` | Signature verification using RSA public key |
| `POST` | `/api/dh/calculate-step` | Executes steps 1-4 of Diffie-Hellman with intermediate values |
| `GET` | `/api/elgamal/keygen` | Generates Elgamal domain parameters ($p, g, x, y$) |
| `POST` | `/api/elgamal/hash` | Computes 512-bit SHA-512 digest |
| `POST` | `/api/elgamal/sign` | Signs SHA-512 hash using Elgamal private key $x$ |
| `POST` | `/api/elgamal/verify` | Verifies Elgamal signature ($g^H \equiv y^r r^s \pmod p$) |

## Running Project 1
```bash
python app.py
```
To run unit tests:
```bash
python test_project1.py
```
