import unittest
from app import app, init_db

class TestSentinel(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        init_db()

    def test_health(self):
        res = self.client.get('/health')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["service"], "Sentinel")

    def test_firewall_rules_crud(self):
        # List rules
        res = self.client.get('/api/firewall/rules')
        self.assertEqual(res.status_code, 200)
        initial_count = len(res.get_json()["rules"])
        self.assertGreater(initial_count, 0)

        # Add rule
        new_rule = {
            "name": "Test Drop FTP",
            "source_ip": "ANY",
            "dest_ip": "ANY",
            "protocol": "TCP",
            "port": 21,
            "action": "BLOCK",
            "priority": 15
        }
        add_res = self.client.post('/api/firewall/rules', json=new_rule)
        self.assertEqual(add_res.status_code, 201)
        rule_id = add_res.get_json()["rule_id"]

        # Inspect packet matching rule
        inspect_res = self.client.post('/api/firewall/inspect', json={
            "source_ip": "1.2.3.4",
            "dest_ip": "10.0.0.5",
            "protocol": "TCP",
            "port": 21
        })
        self.assertEqual(inspect_res.status_code, 200)
        self.assertEqual(inspect_res.get_json()["decision"], "BLOCK")

        # Delete rule
        del_res = self.client.delete(f'/api/firewall/rules/{rule_id}')
        self.assertEqual(del_res.status_code, 200)

    def test_ids_traffic_and_alerts(self):
        # 1. Clear alerts
        self.client.delete('/api/ids/alerts')

        # 2. Trigger SSH Brute Force
        bf_res = self.client.post('/api/ids/traffic/generate', json={"scenario": "ssh_bruteforce"})
        self.assertEqual(bf_res.status_code, 200)
        self.assertGreater(len(bf_res.get_json()["alerts_triggered"]), 0)

        # 3. Trigger Insecure Telnet
        tel_res = self.client.post('/api/ids/traffic/generate', json={"scenario": "telnet_insecure"})
        self.assertEqual(tel_res.status_code, 200)

        # 4. Trigger Port Scan
        scan_res = self.client.post('/api/ids/traffic/generate', json={"scenario": "port_scan"})
        self.assertEqual(scan_res.status_code, 200)

        # 5. Trigger SYN Flood (Statistical Anomaly)
        syn_res = self.client.post('/api/ids/traffic/generate', json={"scenario": "syn_flood"})
        self.assertEqual(syn_res.status_code, 200)
        self.assertTrue(syn_res.get_json()["metrics"]["is_anomaly"])

        # Check alerts list
        alerts_res = self.client.get('/api/ids/alerts')
        self.assertEqual(alerts_res.status_code, 200)
        alerts = alerts_res.get_json()["alerts"]
        self.assertGreaterEqual(len(alerts), 3)

    def test_threat_encyclopedia(self):
        res = self.client.get('/api/threats')
        self.assertEqual(res.status_code, 200)
        threats = res.get_json()["threats"]
        self.assertGreater(len(threats), 3)

if __name__ == "__main__":
    unittest.main()
