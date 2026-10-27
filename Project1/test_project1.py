import unittest
import json
import base64
from app import app, init_db

class TestCryptoVault(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        init_db()

    def test_health(self):
        res = self.client.get('/health')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "healthy")

    def test_auth_and_pki(self):
        # Register
        reg_payload = {"username": "alice_test", "password": "SecretPassword123"}
        res = self.client.post('/api/auth/register', json=reg_payload)
        self.assertIn(res.status_code, [201, 409])
        
        # Login
        login_res = self.client.post('/api/auth/login', json=reg_payload)
        self.assertEqual(login_res.status_code, 200)
        data = login_res.get_json()
        self.assertIn("BEGIN CERTIFICATE", data["x509_certificate_pem"])
        self.assertIn("BEGIN PUBLIC KEY", data["public_key_pem"])
        self.assertIn("BEGIN PRIVATE KEY", data["private_key_pem"])

        # Download Cert
        cert_res = self.client.get('/api/pki/download-cert/alice_test')
        self.assertEqual(cert_res.status_code, 200)
        self.assertIn(b"BEGIN CERTIFICATE", cert_res.data)

    def test_rsa_encryption_and_signing(self):
        # Generate new keys
        keys_res = self.client.get('/api/rsa/generate')
        keys = keys_res.get_json()
        pub_pem = keys["public_key_pem"]
        priv_pem = keys["private_key_pem"]

        # Encrypt
        message = "Active Learning Management RSA Test!"
        enc_res = self.client.post('/api/rsa/encrypt', json={
            "public_key_pem": pub_pem,
            "plaintext": message
        })
        self.assertEqual(enc_res.status_code, 200)
        ciphertext = enc_res.get_json()["ciphertext_base64"]

        # Decrypt
        dec_res = self.client.post('/api/rsa/decrypt', json={
            "private_key_pem": priv_pem,
            "ciphertext_base64": ciphertext
        })
        self.assertEqual(dec_res.status_code, 200)
        self.assertEqual(dec_res.get_json()["plaintext"], message)

        # Sign
        sign_res = self.client.post('/api/rsa/sign', json={
            "private_key_pem": priv_pem,
            "message": message
        })
        self.assertEqual(sign_res.status_code, 200)
        sig_b64 = sign_res.get_json()["signature_base64"]

        # Verify
        verify_res = self.client.post('/api/rsa/verify', json={
            "public_key_pem": pub_pem,
            "message": message,
            "signature_base64": sig_b64
        })
        self.assertEqual(verify_res.status_code, 200)
        self.assertTrue(verify_res.get_json()["is_valid"])

    def test_diffie_hellman(self):
        setup_res = self.client.post('/api/dh/setup', json={"mode": "small"})
        self.assertEqual(setup_res.status_code, 200)
        
        # Test step 4 computation
        calc_res = self.client.post('/api/dh/calculate-step', json={
            "step": 4,
            "p": 353,
            "g": 3,
            "alice_private": 97,
            "bob_private": 233
        })
        self.assertEqual(calc_res.status_code, 200)
        data = calc_res.get_json()
        self.assertTrue(data["match"])
        self.assertEqual(data["alice_computation"]["shared_secret"], data["bob_computation"]["shared_secret"])

    def test_elgamal_signature(self):
        # Keygen
        keygen_res = self.client.get('/api/elgamal/keygen')
        self.assertEqual(keygen_res.status_code, 200)
        keys = keygen_res.get_json()

        # Sign
        msg = "Secure Financial Transaction $10,000"
        sign_res = self.client.post('/api/elgamal/sign', json={
            "message": msg,
            "private_key_x": keys["private_key_x"],
            "p": keys["p"],
            "g": keys["g"]
        })
        self.assertEqual(sign_res.status_code, 200)
        sig_data = sign_res.get_json()

        # Verify
        verify_res = self.client.post('/api/elgamal/verify', json={
            "message": msg,
            "signature_r": sig_data["signature_r"],
            "signature_s": sig_data["signature_s"],
            "public_key_y": keys["public_key_y"],
            "p": keys["p"],
            "g": keys["g"]
        })
        self.assertEqual(verify_res.status_code, 200)
        self.assertTrue(verify_res.get_json()["is_valid"])

if __name__ == "__main__":
    unittest.main()
