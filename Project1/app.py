import os
import sqlite3
import datetime
import random
import hashlib
import base64
from flask import Flask, request, jsonify, send_file, Response
from flask_cors import CORS
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID

app = Flask(__name__)
CORS(app)

DB_PATH = os.path.join(os.path.dirname(__file__), "crypto_vault.db")

# ----------------- DATABASE SETUP -----------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        public_key_pem TEXT NOT NULL,
        private_key_pem TEXT NOT NULL,
        x509_certificate_pem TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.commit()
    conn.close()

init_db()

# ----------------- PKI & RSA HELPERS -----------------
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    
    return private_key, public_key, private_pem, public_pem

def generate_x509_cert(private_key, public_key, common_name, org="CryptoVault CA"):
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Telangana"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Hyderabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = x509.CertificateBuilder()\
        .subject_name(subject)\
        .issuer_name(issuer)\
        .public_key(public_key)\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(now)\
        .not_valid_after(now + datetime.timedelta(days=365))\
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )\
        .sign(private_key, hashes.SHA256())
    
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    return cert_pem

# ----------------- 1. AUTHENTICATION & KEY MANAGEMENT -----------------
@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    org = data.get("organization", "CryptoVault PKI")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    password_hash = hashlib.sha256(password.encode()).hexdigest()

    try:
        priv_key, pub_key, priv_pem, pub_pem = generate_rsa_keypair()
        cert_pem = generate_x509_cert(priv_key, pub_key, common_name=username, org=org)

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (username, password_hash, public_key_pem, private_key_pem, x509_certificate_pem)
            VALUES (?, ?, ?, ?, ?)
        """, (username, password_hash, pub_pem, priv_pem, cert_pem))
        conn.commit()
        conn.close()

        return jsonify({
            "message": "User registered successfully",
            "username": username,
            "public_key_pem": pub_pem,
            "private_key_pem": priv_pem,
            "x509_certificate_pem": cert_pem,
            "pki_note": "Application generated RSA-2048 keypair and issued self-signed X.509 Certificate acting as CA."
        }), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    password_hash = hashlib.sha256(password.encode()).hexdigest()

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? AND password_hash = ?", (username, password_hash))
    user = cursor.fetchone()
    conn.close()

    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    return jsonify({
        "message": "Login successful",
        "username": user["username"],
        "public_key_pem": user["public_key_pem"],
        "private_key_pem": user["private_key_pem"],
        "x509_certificate_pem": user["x509_certificate_pem"]
    })

@app.route("/api/users/list", methods=["GET"])
def list_users():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, public_key_pem, x509_certificate_pem, created_at FROM users")
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return jsonify({"users": users})

@app.route("/api/pki/download-cert/<username>", methods=["GET"])
def download_cert(username):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT x509_certificate_pem FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()

    if not row or not row["x509_certificate_pem"]:
        return jsonify({"error": "Certificate not found for user"}), 404

    return Response(
        row["x509_certificate_pem"],
        mimetype="application/x-x509-ca-cert",
        headers={"Content-Disposition": f"attachment;filename={username}_cert.crt"}
    )

# ----------------- 2. INTERACTIVE RSA MODULE -----------------
@app.route("/api/rsa/generate", methods=["GET"])
def rsa_generate():
    _, _, priv_pem, pub_pem = generate_rsa_keypair()
    return jsonify({
        "public_key_pem": pub_pem,
        "private_key_pem": priv_pem
    })

@app.route("/api/rsa/encrypt", methods=["POST"])
def rsa_encrypt():
    data = request.get_json() or {}
    public_key_pem = data.get("public_key_pem", "")
    plaintext = data.get("plaintext", "")

    if not public_key_pem or not plaintext:
        return jsonify({"error": "Public key and plaintext are required"}), 400

    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        ciphertext_bytes = public_key.encrypt(
            plaintext.encode("utf-8"),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return jsonify({
            "ciphertext_base64": base64.b64encode(ciphertext_bytes).decode("utf-8"),
            "ciphertext_hex": ciphertext_bytes.hex(),
            "byte_length": len(ciphertext_bytes),
            "algorithm": "RSA-OAEP-SHA256"
        })
    except Exception as e:
        return jsonify({"error": f"Encryption failed: {str(e)}"}), 400

@app.route("/api/rsa/decrypt", methods=["POST"])
def rsa_decrypt():
    data = request.get_json() or {}
    private_key_pem = data.get("private_key_pem", "")
    ciphertext_base64 = data.get("ciphertext_base64", "")

    if not private_key_pem or not ciphertext_base64:
        return jsonify({"error": "Private key and ciphertext are required"}), 400

    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"),
            password=None
        )
        ciphertext_bytes = base64.b64decode(ciphertext_base64)
        plaintext_bytes = private_key.decrypt(
            ciphertext_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return jsonify({
            "plaintext": plaintext_bytes.decode("utf-8"),
            "algorithm": "RSA-OAEP-SHA256"
        })
    except Exception as e:
        return jsonify({"error": f"Decryption failed: {str(e)}"}), 400

@app.route("/api/rsa/sign", methods=["POST"])
def rsa_sign():
    data = request.get_json() or {}
    private_key_pem = data.get("private_key_pem", "")
    message = data.get("message", "")

    if not private_key_pem or not message:
        return jsonify({"error": "Private key and message are required"}), 400

    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode("utf-8"),
            password=None
        )
        signature = private_key.sign(
            message.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return jsonify({
            "signature_base64": base64.b64encode(signature).decode("utf-8"),
            "signature_hex": signature.hex(),
            "message": message,
            "algorithm": "RSA-PSS-SHA256"
        })
    except Exception as e:
        return jsonify({"error": f"Signing failed: {str(e)}"}), 400

@app.route("/api/rsa/verify", methods=["POST"])
def rsa_verify():
    data = request.get_json() or {}
    public_key_pem = data.get("public_key_pem", "")
    message = data.get("message", "")
    signature_base64 = data.get("signature_base64", "")

    if not public_key_pem or not message or not signature_base64:
        return jsonify({"error": "Public key, message, and signature are required"}), 400

    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        signature_bytes = base64.b64decode(signature_base64)
        public_key.verify(
            signature_bytes,
            message.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return jsonify({
            "is_valid": True,
            "status": "VALID",
            "message": "Signature verified successfully using public key."
        })
    except Exception as e:
        return jsonify({
            "is_valid": False,
            "status": "INVALID",
            "error": f"Verification failed: {str(e)}"
        })

# ----------------- 3. DIFFIE-HELLMAN KEY EXCHANGE -----------------
# Standard pedagogical prime & generator or custom selection
DH_DEFAULTS = {
    "small": {"p": 353, "g": 3},
    "medium": {"p": 7919, "g": 7},
    "rfc3526": {
        "p": 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF,
        "g": 2
    }
}

@app.route("/api/dh/setup", methods=["POST"])
def dh_setup():
    data = request.get_json() or {}
    mode = data.get("mode", "small")
    
    if mode == "custom":
        p = int(data.get("p", 353))
        g = int(data.get("g", 3))
    elif mode in DH_DEFAULTS:
        p = DH_DEFAULTS[mode]["p"]
        g = DH_DEFAULTS[mode]["g"]
    else:
        p, g = 353, 3

    # Generate random private keys for Alice and Bob
    alice_private = random.randint(2, min(p - 2, 200) if p > 1000 else p - 2)
    bob_private = random.randint(2, min(p - 2, 200) if p > 1000 else p - 2)

    return jsonify({
        "p": str(p),
        "g": str(g),
        "alice_private_suggested": alice_private,
        "bob_private_suggested": bob_private
    })

@app.route("/api/dh/calculate-step", methods=["POST"])
def dh_calculate_step():
    data = request.get_json() or {}
    step = data.get("step", 1)
    p = int(data.get("p", 353))
    g = int(data.get("g", 3))
    a = int(data.get("alice_private", 97))
    b = int(data.get("bob_private", 233))

    # Step 1: Pick private keys
    if step == 1:
        return jsonify({
            "step": 1,
            "title": "Private Keys Selected",
            "alice": {"private_key": a, "note": f"Alice chooses secret a = {a}"},
            "bob": {"private_key": b, "note": f"Bob chooses secret b = {b}"},
            "public_params": {"p": p, "g": g}
        })

    # Step 2: Compute Public Keys: A = g^a mod p, B = g^b mod p
    A = pow(g, a, p)
    B = pow(g, b, p)

    if step == 2:
        return jsonify({
            "step": 2,
            "title": "Public Keys Computed",
            "alice": {
                "private_key": a,
                "public_key": A,
                "formula": f"A = {g}^{a} mod {p} = {A}"
            },
            "bob": {
                "private_key": b,
                "public_key": B,
                "formula": f"B = {g}^{b} mod {p} = {B}"
            }
        })

    # Step 3: Public Keys Exchanged over insecure channel
    if step == 3:
        return jsonify({
            "step": 3,
            "title": "Public Keys Exchanged",
            "channel_transmission": {
                "alice_to_bob": f"Alice sends Public Key A = {A} to Bob",
                "bob_to_alice": f"Bob sends Public Key B = {B} to Alice",
                "eavesdropper_sees": {"p": p, "g": g, "A": A, "B": B},
                "eavesdropper_does_not_see": ["Alice's secret 'a'", "Bob's secret 'b'"]
            }
        })

    # Step 4: Compute Shared Secret: s = B^a mod p == A^b mod p
    alice_secret = pow(B, a, p)
    bob_secret = pow(A, b, p)
    secrets_match = (alice_secret == bob_secret)

    return jsonify({
        "step": 4,
        "title": "Shared Secret Computed",
        "alice_computation": {
            "formula": f"s = B^a mod p = ({B})^{a} mod {p}",
            "shared_secret": alice_secret
        },
        "bob_computation": {
            "formula": f"s = A^b mod p = ({A})^{b} mod {p}",
            "shared_secret": bob_secret
        },
        "match": secrets_match,
        "explanation": "Both parties now share the identical secret key without transmitting it across the network!"
    })

# ----------------- 4. ELGAMAL DIGITAL SIGNATURE & SHA-512 -----------------
# Pedagogical prime and generator for Elgamal or medium-large prime
ELGAMAL_P = 1000000007 # Large prime
ELGAMAL_G = 5          # Generator

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return x % m

@app.route("/api/elgamal/keygen", methods=["GET"])
def elgamal_keygen():
    p = ELGAMAL_P
    g = ELGAMAL_G
    # Private key x: 1 < x < p - 1
    x = random.randint(2, p - 2)
    # Public key y = g^x mod p
    y = pow(g, x, p)

    return jsonify({
        "p": p,
        "g": g,
        "private_key_x": x,
        "public_key_y": y,
        "domain_info": "Prime p = 1,000,000,007, Generator g = 5"
    })

@app.route("/api/elgamal/hash", methods=["POST"])
def compute_hash():
    data = request.get_json() or {}
    message = data.get("message", "")
    sha512_hash = hashlib.sha512(message.encode("utf-8")).hexdigest()
    # Also convert hash to integer for modular operations
    hash_int = int(sha512_hash, 16) % (ELGAMAL_P - 1)
    
    return jsonify({
        "message": message,
        "sha512_hex": sha512_hash,
        "sha512_bits": 512,
        "hash_reduced_mod_p_minus_1": hash_int
    })

@app.route("/api/elgamal/sign", methods=["POST"])
def elgamal_sign():
    data = request.get_json() or {}
    message = data.get("message", "")
    private_key_x = int(data.get("private_key_x", 0))
    p = int(data.get("p", ELGAMAL_P))
    g = int(data.get("g", ELGAMAL_G))

    if not message or not private_key_x:
        return jsonify({"error": "Message and private key x are required"}), 400

    # 1. Compute SHA-512 Hash
    sha512_hex = hashlib.sha512(message.encode("utf-8")).hexdigest()
    m_int = int(sha512_hex, 16) % (p - 1)
    if m_int == 0:
        m_int = 1

    # 2. Pick ephemeral key k such that gcd(k, p-1) == 1
    while True:
        k = random.randint(2, p - 2)
        g_val, _, _ = egcd(k, p - 1)
        if g_val == 1:
            break

    # 3. Compute r = g^k mod p
    r = pow(g, k, p)

    # 4. Compute s = (m - x * r) * k^(-1) mod (p - 1)
    k_inv = modinv(k, p - 1)
    s = ((m_int - private_key_x * r) * k_inv) % (p - 1)

    return jsonify({
        "message": message,
        "sha512_hex": sha512_hex,
        "hash_value_m": m_int,
        "ephemeral_k": k,
        "signature_r": r,
        "signature_s": s,
        "explanation": f"r = g^k mod p = {r}, s = (H(m) - x*r)*k^-1 mod (p-1) = {s}"
    })

@app.route("/api/elgamal/verify", methods=["POST"])
def elgamal_verify():
    data = request.get_json() or {}
    message = data.get("message", "")
    r = int(data.get("signature_r", 0))
    s = int(data.get("signature_s", 0))
    public_key_y = int(data.get("public_key_y", 0))
    p = int(data.get("p", ELGAMAL_P))
    g = int(data.get("g", ELGAMAL_G))

    if not message or not r or not s or not public_key_y:
        return jsonify({"error": "Message, signature (r, s), and public key y required"}), 400

    if not (0 < r < p) or not (0 < s < p - 1):
        return jsonify({
            "is_valid": False,
            "status": "INVALID",
            "reason": "Signature components out of bounds: 0 < r < p and 0 < s < p-1"
        })

    # Compute SHA-512 hash
    sha512_hex = hashlib.sha512(message.encode("utf-8")).hexdigest()
    m_int = int(sha512_hex, 16) % (p - 1)
    if m_int == 0:
        m_int = 1

    # Verify: g^(H(m)) mod p == (y^r * r^s) mod p
    v1 = pow(g, m_int, p)
    v2 = (pow(public_key_y, r, p) * pow(r, s, p)) % p

    is_valid = (v1 == v2)

    return jsonify({
        "is_valid": is_valid,
        "status": "VALID" if is_valid else "INVALID",
        "sha512_hex": sha512_hex,
        "v1_left_hand_side": f"g^H(m) mod p = {v1}",
        "v2_right_hand_side": f"(y^r * r^s) mod p = {v2}",
        "comparison": f"{v1} == {v2}"
    })

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy", "service": "CryptoVault", "project": "Project1"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)
