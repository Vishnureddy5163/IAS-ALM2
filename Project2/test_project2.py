import unittest
from app import app

class TestSecureTunnel(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_health(self):
        res = self.client.get('/health')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["service"], "SecureTunnel")

    def test_tls_handshake_flow(self):
        # 0. Init
        init_res = self.client.post('/api/tls/init')
        self.assertEqual(init_res.status_code, 200)
        sess_id = init_res.get_json()["session_id"]

        # Step 1: Client Hello
        s1 = self.client.post('/api/tls/step/1', json={"session_id": sess_id})
        self.assertEqual(s1.status_code, 200)
        self.assertEqual(s1.get_json()["step"], 1)

        # Step 2: Server Hello
        s2 = self.client.post('/api/tls/step/2', json={
            "session_id": sess_id,
            "cipher_suite": "TLS_AES_128_GCM_SHA256"
        })
        self.assertEqual(s2.status_code, 200)
        self.assertEqual(s2.get_json()["step"], 2)

        # Step 3: Client Key Exchange
        s3 = self.client.post('/api/tls/step/3', json={"session_id": sess_id})
        self.assertEqual(s3.status_code, 200)
        self.assertEqual(s3.get_json()["step"], 3)

        # Step 4: Session Keys
        s4 = self.client.post('/api/tls/step/4', json={"session_id": sess_id})
        self.assertEqual(s4.status_code, 200)
        self.assertEqual(s4.get_json()["step"], 4)
        self.assertIn("client_write_key", s4.get_json()["details"]["derived_keys"])

        # Step 5: Finished
        s5 = self.client.post('/api/tls/step/5', json={"session_id": sess_id})
        self.assertEqual(s5.status_code, 200)
        self.assertEqual(s5.get_json()["step"], 5)

        # Test symmetric data transfer
        send_res = self.client.post('/api/tls/send-data', json={
            "session_id": sess_id,
            "message": "Top Secret Data via TLS"
        })
        self.assertEqual(send_res.status_code, 200)
        self.assertIn("symmetric_ciphertext_hex", send_res.get_json())

    def test_ssh_handshake_flow(self):
        init_res = self.client.post('/api/ssh/init')
        self.assertEqual(init_res.status_code, 200)
        sess_id = init_res.get_json()["session_id"]

        for step in range(1, 6):
            res = self.client.post(f'/api/ssh/step/{step}', json={"session_id": sess_id})
            self.assertEqual(res.status_code, 200, f"Failed at SSH step {step}")
            self.assertEqual(res.get_json()["step"], step)

    def test_ipsec_analysis(self):
        # Transport mode
        trans_res = self.client.post('/api/ipsec/analyze', json={"mode": "transport"})
        self.assertEqual(trans_res.status_code, 200)
        self.assertEqual(len(trans_res.get_json()["elements"]), 5)

        # Tunnel mode
        tunnel_res = self.client.post('/api/ipsec/analyze', json={"mode": "tunnel"})
        self.assertEqual(tunnel_res.status_code, 200)
        self.assertEqual(tunnel_res.get_json()["elements"][0]["field"], "New Outer IP Header")

if __name__ == "__main__":
    unittest.main()
