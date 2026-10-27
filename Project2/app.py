import os
import uuid
import time
import secrets
import hashlib
import hmac
import base64
from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography import x509
from cryptography.x509.oid import NameOID
import datetime

app = Flask(__name__)
CORS(app)

# In-memory session store for stateful TLS and SSH handshakes
tls_sessions = {}
ssh_sessions = {}

# ----------------- CRYPTO HELPERS -----------------
def generate_server_cert():
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()
    
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureTunnel TLS Server"),
        x509.NameAttribute(NameOID.COMMON_NAME, "securetunnel.local"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = x509.CertificateBuilder()\
        .subject_name(subject)\
        .issuer_name(issuer)\
        .public_key(pub)\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(now)\
        .not_valid_after(now + datetime.timedelta(days=90))\
        .sign(priv, hashes.SHA256())

    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    
    return priv, pub, cert_pem, pub_pem

# TLS PRF (Pseudo-Random Function) simulation using HMAC-SHA256
def tls_prf(secret: bytes, label: str, seed: bytes, length: int) -> bytes:
    result = b""
    a = hmac.new(secret, label.encode() + seed, hashlib.sha256).digest()
    while len(result) < length:
        step = hmac.new(secret, a + label.encode() + seed, hashlib.sha256).digest()
        result += step
        a = hmac.new(secret, a, hashlib.sha256).digest()
    return result[:length]

# ----------------- 1. TLS/SSL HANDSHAKE SIMULATION -----------------
CIPHER_SUITES = [
    {"id": "TLS_RSA_WITH_AES_128_CBC_SHA", "name": "TLS_RSA_WITH_AES_128_CBC_SHA", "recommended": False},
    {"id": "TLS_RSA_WITH_AES_256_CBC_SHA256", "name": "TLS_RSA_WITH_AES_256_CBC_SHA256", "recommended": False},
    {"id": "TLS_AES_128_GCM_SHA256", "name": "TLS_AES_128_GCM_SHA256", "recommended": True},
    {"id": "TLS_AES_256_GCM_SHA384", "name": "TLS_AES_256_GCM_SHA384", "recommended": True}
]

@app.route("/api/tls/init", methods=["POST"])
def tls_init():
    session_id = str(uuid.uuid4())[:8]
    server_priv, server_pub, cert_pem, pub_pem = generate_server_cert()

    tls_sessions[session_id] = {
        "session_id": session_id,
        "current_step": 0,
        "server_priv": server_priv,
        "server_pub": server_pub,
        "server_cert_pem": cert_pem,
        "server_pub_pem": pub_pem,
        "client_random": None,
        "server_random": None,
        "selected_cipher": None,
        "pre_master_secret": None,
        "master_secret": None,
        "keys": {},
        "history": []
    }

    return jsonify({
        "session_id": session_id,
        "status": "Initialized",
        "cipher_suites_available": CIPHER_SUITES,
        "message": "TLS Handshake session created. Ready for Step 1: Client Hello."
    })

@app.route("/api/tls/step/<int:step_num>", methods=["POST"])
def tls_step(step_num):
    data = request.get_json() or {}
    session_id = data.get("session_id")
    sess = tls_sessions.get(session_id)

    if not sess:
        return jsonify({"error": "Session not found. Initialize first."}), 404

    # STEP 1: Client Hello
    if step_num == 1:
        client_random = secrets.token_hex(32)
        sess["client_random"] = client_random
        sess["client_version"] = "TLS 1.2 / TLS 1.3"
        sess["client_ciphers"] = [c["id"] for c in CIPHER_SUITES]
        sess["current_step"] = 1
        
        log_entry = {
            "step": 1,
            "name": "Client Hello",
            "direction": "Client -> Server",
            "details": {
                "tls_version": "TLS 1.2 / TLS 1.3",
                "client_random": client_random,
                "supported_ciphers": sess["client_ciphers"]
            },
            "explanation": "Client sends Client Hello containing random nonce (32 bytes) and list of supported cipher suites."
        }
        sess["history"].append(log_entry)
        return jsonify(log_entry)

    # STEP 2: Server Hello & Certificate
    elif step_num == 2:
        if sess["current_step"] < 1:
            return jsonify({"error": "Must perform Step 1 (Client Hello) first"}), 400

        server_random = secrets.token_hex(32)
        selected_cipher = data.get("cipher_suite", "TLS_AES_128_GCM_SHA256")
        sess["server_random"] = server_random
        sess["selected_cipher"] = selected_cipher
        sess["current_step"] = 2

        log_entry = {
            "step": 2,
            "name": "Server Hello & Certificate",
            "direction": "Server -> Client",
            "details": {
                "server_random": server_random,
                "chosen_cipher": selected_cipher,
                "server_certificate_pem": sess["server_cert_pem"],
                "server_public_key_pem": sess["server_pub_pem"]
            },
            "explanation": "Server responds with Server Hello, chooses cipher suite, provides server random, and sends its X.509 digital certificate."
        }
        sess["history"].append(log_entry)
        return jsonify(log_entry)

    # STEP 3: Client Key Exchange
    elif step_num == 3:
        if sess["current_step"] < 2:
            return jsonify({"error": "Must perform Step 2 (Server Hello) first"}), 400

        # Client generates 48-byte pre-master secret
        pre_master_raw = secrets.token_bytes(48)
        sess["pre_master_secret"] = pre_master_raw

        # Encrypt pre-master secret with server's RSA public key
        server_pub = sess["server_pub"]
        encrypted_pms = server_pub.encrypt(
            pre_master_raw,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_pms_b64 = base64.b64encode(encrypted_pms).decode("utf-8")
        sess["encrypted_pms_b64"] = encrypted_pms_b64
        sess["current_step"] = 3

        log_entry = {
            "step": 3,
            "name": "Client Key Exchange",
            "direction": "Client -> Server",
            "details": {
                "certificate_verification": "SUCCESS (Verified CA signature & validity period)",
                "pre_master_secret_hex": pre_master_raw.hex()[:32] + "... [48 bytes secret]",
                "encrypted_pre_master_secret_base64": encrypted_pms_b64
            },
            "explanation": "Client verifies server certificate, generates random 48-byte pre-master secret, encrypts it with server's public key, and sends it."
        }
        sess["history"].append(log_entry)
        return jsonify(log_entry)

    # STEP 4: Session Key Generation
    elif step_num == 4:
        if sess["current_step"] < 3:
            return jsonify({"error": "Must perform Step 3 (Client Key Exchange) first"}), 400

        # Server decrypts pre-master secret using server private key
        server_priv = sess["server_priv"]
        encrypted_pms = base64.b64decode(sess["encrypted_pms_b64"])
        decrypted_pms = server_priv.decrypt(
            encrypted_pms,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        assert decrypted_pms == sess["pre_master_secret"]

        # Derive master secret: 48 bytes
        # PRF(pre_master_secret, "master secret", ClientRandom + ServerRandom)
        seed = bytes.fromhex(sess["client_random"]) + bytes.fromhex(sess["server_random"])
        master_secret = tls_prf(decrypted_pms, "master secret", seed, 48)
        sess["master_secret"] = master_secret

        # Key expansion: derive client write key, server write key, client/server IV
        key_block = tls_prf(master_secret, "key expansion", bytes.fromhex(sess["server_random"]) + bytes.fromhex(sess["client_random"]), 96)
        client_write_mac = key_block[0:20]
        server_write_mac = key_block[20:40]
        client_write_key = key_block[40:56] # 16 bytes for AES-128
        server_write_key = key_block[56:72] # 16 bytes for AES-128
        client_write_iv = key_block[72:84]  # 12 bytes IV
        server_write_iv = key_block[84:96]  # 12 bytes IV

        sess["keys"] = {
            "client_write_key": client_write_key.hex(),
            "server_write_key": server_write_key.hex(),
            "client_write_iv": client_write_iv.hex(),
            "server_write_iv": server_write_iv.hex(),
            "master_secret_hex": master_secret.hex()
        }
        sess["current_step"] = 4

        log_entry = {
            "step": 4,
            "name": "Session Key Generation (Symmetric Key Derivation)",
            "direction": "Client & Server (Independent Local Computation)",
            "details": {
                "server_decryption": "Decrypted Pre-Master Secret using Server Private Key",
                "master_secret": master_secret.hex()[:32] + "... [48 bytes]",
                "derived_keys": {
                    "client_write_key": client_write_key.hex(),
                    "server_write_key": server_write_key.hex(),
                    "client_write_encryption_key": client_write_key.hex(),
                    "server_write_encryption_key": server_write_key.hex(),
                    "client_write_iv": client_write_iv.hex(),
                    "server_write_iv": server_write_iv.hex()
                }
            },
            "explanation": "Both Client and Server independently run PRF to derive identical Master Secret and 4 symmetric session keys. No keys were transmitted over the network!"
        }
        sess["history"].append(log_entry)
        return jsonify(log_entry)

    # STEP 5: Finished
    elif step_num == 5:
        if sess["current_step"] < 4:
            return jsonify({"error": "Must perform Step 4 (Session Keys) first"}), 400

        # Create encrypted finished verify_data
        handshake_summary = hashlib.sha256(
            (sess["client_random"] + sess["server_random"] + sess["selected_cipher"]).encode()
        ).hexdigest()
        
        client_finished = hmac.new(
            bytes.fromhex(sess["keys"]["client_write_key"]),
            b"client finished" + handshake_summary.encode(),
            hashlib.sha256
        ).hexdigest()

        server_finished = hmac.new(
            bytes.fromhex(sess["keys"]["server_write_key"]),
            b"server finished" + handshake_summary.encode(),
            hashlib.sha256
        ).hexdigest()

        sess["current_step"] = 5
        sess["established"] = True

        log_entry = {
            "step": 5,
            "name": "Handshake Finished & Channel Verified",
            "direction": "Bi-directional Verification",
            "details": {
                "client_encrypted_finished": client_finished,
                "server_encrypted_finished": server_finished,
                "tunnel_status": "SECURE TLS ENCRYPTED TUNNEL ESTABLISHED",
                "symmetric_algorithm": sess["selected_cipher"]
            },
            "explanation": "Both parties send encrypted Finished message verifying that handshake was authentic and not tampered with. Symmetric data transmission is now active!"
        }
        sess["history"].append(log_entry)
        return jsonify(log_entry)

    return jsonify({"error": "Invalid step number (1 to 5)"}), 400

@app.route("/api/tls/send-data", methods=["POST"])
def tls_send_data():
    data = request.get_json() or {}
    session_id = data.get("session_id")
    plaintext = data.get("message", "GET /index.html HTTP/1.1\r\nHost: securetunnel.local\r\n\r\n")
    sess = tls_sessions.get(session_id)

    if not sess or not sess.get("established"):
        return jsonify({"error": "TLS tunnel not established. Complete steps 1-5 first."}), 400

    # Symmetric AES-GCM encryption using derived client_write_key
    key = bytes.fromhex(sess["keys"]["client_write_key"])
    iv = bytes.fromhex(sess["keys"]["client_write_iv"])
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
    ciphertext = encryptor.update(plaintext.encode("utf-8")) + encryptor.finalize()
    tag = encryptor.tag

    return jsonify({
        "status": "Transmitted over Secure Tunnel",
        "plaintext": plaintext,
        "symmetric_ciphertext_hex": ciphertext.hex(),
        "authentication_tag_hex": tag.hex(),
        "iv_nonce_hex": iv.hex(),
        "cipher": "AES-128-GCM"
    })

# ----------------- 2. SIMPLIFIED SSH CONNECTION SIMULATION -----------------
@app.route("/api/ssh/init", methods=["POST"])
def ssh_init():
    session_id = str(uuid.uuid4())[:8]
    # Server host RSA key pair
    host_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    host_pub = host_priv.public_key()
    host_pub_pem = host_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    fingerprint = hashlib.sha256(host_pub_pem.encode()).hexdigest()
    fingerprint_formatted = ":".join([fingerprint[i:i+2] for i in range(0, 32, 2)])

    ssh_sessions[session_id] = {
        "session_id": session_id,
        "current_step": 0,
        "host_priv": host_priv,
        "host_pub": host_pub,
        "host_pub_pem": host_pub_pem,
        "host_fingerprint": f"SHA256:{fingerprint_formatted}",
        "p": 1000000007,
        "g": 5,
        "client_dh_priv": None,
        "client_dh_pub": None,
        "server_dh_priv": None,
        "server_dh_pub": None,
        "shared_k": None,
        "session_id_hash": None,
        "history": []
    }

    return jsonify({
        "session_id": session_id,
        "server_banner": "SSH-2.0-OpenSSH_9.0p1 Ubuntu-1ubuntu1",
        "client_banner": "SSH-2.0-OpenSSH_8.9p1",
        "message": "SSH session initialized."
    })

@app.route("/api/ssh/step/<int:step_num>", methods=["POST"])
def ssh_step(step_num):
    data = request.get_json() or {}
    session_id = data.get("session_id")
    sess = ssh_sessions.get(session_id)

    if not sess:
        return jsonify({"error": "SSH session not found"}), 404

    # STEP 1: Protocol Version Exchange
    if step_num == 1:
        client_version = "SSH-2.0-OpenSSH_8.9p1"
        server_version = "SSH-2.0-OpenSSH_9.0p1 Ubuntu-1ubuntu1"
        sess["client_version"] = client_version
        sess["server_version"] = server_version
        sess["current_step"] = 1

        log = {
            "step": 1,
            "name": "Protocol Version Exchange",
            "client_identification": client_version,
            "server_identification": server_version,
            "negotiated_version": "SSH-2.0",
            "explanation": "Client and Server exchange plaintext identification strings to confirm SSH protocol compatibility."
        }
        sess["history"].append(log)
        return jsonify(log)

    # STEP 2: Key Exchange (Diffie-Hellman)
    elif step_num == 2:
        if sess["current_step"] < 1:
            return jsonify({"error": "Must run Step 1 first"}), 400

        p, g = sess["p"], sess["g"]
        # Client picks x in [2, p-2], e = g^x mod p
        x = secrets.randbelow(p - 3) + 2
        e = pow(g, x, p)
        # Server picks y in [2, p-2], f = g^y mod p
        y = secrets.randbelow(p - 3) + 2
        f = pow(g, y, p)

        # Shared K = e^y mod p == f^x mod p
        k_server = pow(e, y, p)
        k_client = pow(f, x, p)
        assert k_server == k_client

        sess["client_dh_priv"] = x
        sess["client_dh_pub"] = e
        sess["server_dh_priv"] = y
        sess["server_dh_pub"] = f
        sess["shared_k"] = k_client
        sess["current_step"] = 2

        # Exchange Hash H = SHA256(V_C || V_S || I_C || I_S || K_S || e || f || K)
        h_data = f"{sess['client_version']}|{sess['server_version']}|{e}|{f}|{k_client}".encode()
        h_hash = hashlib.sha256(h_data).digest()
        sess["exchange_hash"] = h_hash

        log = {
            "step": 2,
            "name": "Key Exchange (Diffie-Hellman Group Exchange)",
            "dh_parameters": {"prime_p": p, "generator_g": g},
            "client_exchange_value_e": e,
            "server_exchange_value_f": f,
            "shared_secret_K": k_client,
            "exchange_hash_H": h_hash.hex(),
            "explanation": "Client sends 'e'. Server computes 'f' and derives shared secret K. Both parties calculate Exchange Hash H."
        }
        sess["history"].append(log)
        return jsonify(log)

    # STEP 3: Server Authentication
    elif step_num == 3:
        if sess["current_step"] < 2:
            return jsonify({"error": "Must run Step 2 first"}), 400

        # Server signs exchange hash H with its Host Private Key
        host_priv = sess["host_priv"]
        h_hash = sess["exchange_hash"]
        signature = host_priv.sign(
            h_hash,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        sess["current_step"] = 3
        log = {
            "step": 3,
            "name": "Server Authentication",
            "server_host_key_fingerprint": sess["host_fingerprint"],
            "server_signature_over_H": base64.b64encode(signature).decode("utf-8"),
            "client_verification": "VERIFIED! Host key matches known_hosts and signature is mathematically valid.",
            "explanation": "Server signs exchange hash H with host private key. Client verifies signature, preventing Man-in-the-Middle attacks."
        }
        sess["history"].append(log)
        return jsonify(log)

    # STEP 4: User Authentication
    elif step_num == 4:
        if sess["current_step"] < 3:
            return jsonify({"error": "Must run Step 3 first"}), 400

        auth_method = data.get("auth_method", "publickey")
        user = data.get("username", "student")

        sess["current_step"] = 4
        sess["authenticated_user"] = user

        log = {
            "step": 4,
            "name": "User Authentication",
            "username": user,
            "auth_method": auth_method,
            "service_request": "ssh-userauth",
            "result": "SSH_MSG_USERAUTH_SUCCESS",
            "explanation": f"User '{user}' submitted valid credentials ({auth_method}). Server accepts authorization."
        }
        sess["history"].append(log)
        return jsonify(log)

    # STEP 5: Secure Channel Established
    elif step_num == 5:
        if sess["current_step"] < 4:
            return jsonify({"error": "Must run Step 4 first"}), 400

        sess["current_step"] = 5
        sess["connected"] = True

        log = {
            "step": 5,
            "name": "Secure Channel Established & PTY Session Opened",
            "status": "CONNECTED",
            "active_session": {
                "pty_allocated": True,
                "symmetric_cipher": "chacha20-poly1305@openssh.com / aes256-gcm",
                "shell": "/bin/bash",
                "prompt": f"{sess['authenticated_user']}@securetunnel:~$"
            },
            "explanation": "Encrypted tunnel ready. Interactive shell session can now transmit encrypted commands and terminal outputs."
        }
        sess["history"].append(log)
        return jsonify(log)

    return jsonify({"error": "Invalid step"}), 400

# ----------------- 3. IPSEC (ESP) ENCAPSULATION MODULE -----------------
@app.route("/api/ipsec/analyze", methods=["POST"])
def ipsec_analyze():
    data = request.get_json() or {}
    mode = data.get("mode", "transport") # "transport" or "tunnel"
    src_ip = data.get("src_ip", "192.168.1.105")
    dst_ip = data.get("dst_ip", "203.0.113.50")
    gateway_src = data.get("gateway_src", "198.51.100.1")
    gateway_dst = data.get("gateway_dst", "203.0.113.1")
    protocol = data.get("protocol", "TCP")
    payload = data.get("payload", "CONFIDENTIAL_PAYLOAD_ALM2")

    spi = 0x1234ABCD # Security Parameter Index
    seq_num = 42

    # Simulate ESP encryption with AES-128
    key = b"16ByteSecretKey!"
    iv = b"RandomIVVector!!"
    pad_len = (16 - (len(payload) + 2) % 16) % 16
    padding_bytes = bytes([i + 1 for i in range(pad_len)])
    plain_to_encrypt = payload.encode() + padding_bytes + bytes([pad_len, 6 if protocol == "TCP" else 17])
    
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    esp_ciphertext = encryptor.update(plain_to_encrypt) + encryptor.finalize()
    esp_auth_icv = hmac.new(b"AuthKeyHMACSHA256", esp_ciphertext, hashlib.sha256).hexdigest()[:24]

    if mode == "transport":
        # Transport mode: Original IP Header | ESP Header | Encrypted (Payload + ESP Trailer) | ESP Auth
        diagram_elements = [
            {
                "field": "Original IP Header",
                "content": f"Src: {src_ip} -> Dst: {dst_ip} (Next Proto: 50 [ESP])",
                "status": "PLAINTEXT",
                "color": "blue",
                "authenticated": False,
                "encrypted": False,
                "description": "Original IP header remains unchanged except Next Protocol field set to 50 (ESP)."
            },
            {
                "field": "ESP Header",
                "content": f"SPI: 0x{spi:08X} | Seq: {seq_num}",
                "status": "PLAINTEXT (AUTHENTICATED)",
                "color": "yellow",
                "authenticated": True,
                "encrypted": False,
                "description": "Security Parameters Index identifies the SA (Security Association). Sequence number prevents replay attacks."
            },
            {
                "field": "Encrypted Transport Payload",
                "content": f"[{protocol} Segment: {payload}] -> Ciphertext: {esp_ciphertext.hex()[:24]}...",
                "status": "ENCRYPTED & AUTHENTICATED",
                "color": "green",
                "authenticated": True,
                "encrypted": True,
                "description": "The entire transport layer segment (TCP/UDP header and payload) is encrypted."
            },
            {
                "field": "ESP Trailer",
                "content": f"Padding ({pad_len} B) | Pad Length: {pad_len} | Next Header: {protocol}",
                "status": "ENCRYPTED & AUTHENTICATED",
                "color": "green",
                "authenticated": True,
                "encrypted": True,
                "description": "Provides block cipher alignment padding and restores next protocol indicator."
            },
            {
                "field": "ESP ICV (Authentication Data)",
                "content": f"HMAC-SHA256: {esp_auth_icv}",
                "status": "AUTHENTICATION TAG",
                "color": "purple",
                "authenticated": False,
                "encrypted": False,
                "description": "Integrity Check Value (ICV) calculated over ESP Header, Payload, and Trailer."
            }
        ]
        explanation = (
            "Transport Mode is host-to-host. It protects upper-layer protocols (TCP/UDP and application data) "
            "while leaving the original IP header in plaintext so intermediate routers can route the packet."
        )
    else:
        # Tunnel mode: New IP Header | ESP Header | Encrypted (Original IP Header + Payload + ESP Trailer) | ESP Auth
        diagram_elements = [
            {
                "field": "New Outer IP Header",
                "content": f"Gateway Src: {gateway_src} -> Gateway Dst: {gateway_dst} (Next: 50 [ESP])",
                "status": "PLAINTEXT",
                "color": "blue",
                "authenticated": False,
                "encrypted": False,
                "description": "New IP header created by VPN Security Gateway. Hides internal source and destination IP addresses."
            },
            {
                "field": "ESP Header",
                "content": f"SPI: 0x{spi:08X} | Seq: {seq_num}",
                "status": "PLAINTEXT (AUTHENTICATED)",
                "color": "yellow",
                "authenticated": True,
                "encrypted": False,
                "description": "Contains SPI and Sequence number to identify VPN tunnel SA."
            },
            {
                "field": "Encrypted Original IP Packet",
                "content": f"[Original Header ({src_ip}->{dst_ip}) + {protocol} Data] -> Ciphertext: {esp_ciphertext.hex()[:24]}...",
                "status": "ENCRYPTED & AUTHENTICATED",
                "color": "green",
                "authenticated": True,
                "encrypted": True,
                "description": "The ENTIRE original IP packet (including original internal IP addresses and data) is encrypted!"
            },
            {
                "field": "ESP Trailer",
                "content": f"Padding ({pad_len} B) | Pad Length: {pad_len} | Next Header: 4 (IPv4-in-IPv4)",
                "status": "ENCRYPTED & AUTHENTICATED",
                "color": "green",
                "authenticated": True,
                "encrypted": True,
                "description": "Aligns ciphertext block size and indicates encapsulated payload is an IP packet."
            },
            {
                "field": "ESP ICV (Authentication Data)",
                "content": f"HMAC-SHA256: {esp_auth_icv}",
                "status": "AUTHENTICATION TAG",
                "color": "purple",
                "authenticated": False,
                "encrypted": False,
                "description": "Provides data origin authentication and cryptographic anti-tamper verification."
            }
        ]
        explanation = (
            "Tunnel Mode is gateway-to-gateway (VPN). It encrypts the ENTIRE inner IP packet including original "
            "source and destination IPs, shielding your internal network topology from network eavesdroppers."
        )

    return jsonify({
        "mode": mode,
        "explanation": explanation,
        "elements": diagram_elements,
        "security_analysis": {
            "confidentiality": "Guaranteed via AES-CBC / AES-GCM (Payload encrypted)",
            "integrity": "Guaranteed via HMAC-SHA256 / GCM ICV (Cryptographically authenticated)",
            "replay_protection": f"Guaranteed via 32-bit/64-bit Sequence Numbers (Current Seq: {seq_num})",
            "traffic_flow_confidentiality": "High in Tunnel Mode (Original endpoints obscured); Moderate in Transport Mode"
        }
    })

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy", "service": "SecureTunnel", "project": "Project2"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=True)
