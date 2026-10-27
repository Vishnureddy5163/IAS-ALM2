import os
import sqlite3
import time
import math
import random
from collections import deque
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from flask_cors import CORS
import numpy as np
import pandas as pd

app = Flask(__name__)
CORS(app)

DB_PATH = os.path.join(os.path.dirname(__file__), "sentinel.db")

# ----------------- DATABASE SETUP -----------------
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    # Firewall Rules Table
    c.execute("""
    CREATE TABLE IF NOT EXISTS firewall_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        direction TEXT DEFAULT 'INBOUND', -- INBOUND or OUTBOUND
        source_ip TEXT NOT NULL,           -- e.g. '192.168.1.100' or 'ANY'
        dest_ip TEXT NOT NULL,             -- e.g. '10.0.0.5' or 'ANY'
        protocol TEXT NOT NULL,            -- 'TCP', 'UDP', 'ICMP', 'ANY'
        port INTEGER,                      -- NULL for ANY, or 80, 22, 23, etc.
        action TEXT NOT NULL,              -- 'ALLOW' or 'BLOCK'
        priority INTEGER DEFAULT 100,      -- Lower number = higher priority
        is_bastion_rule INTEGER DEFAULT 0, -- 1 if rule is for Bastion Host
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)

    # IDS Alerts Table
    c.execute("""
    CREATE TABLE IF NOT EXISTS ids_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        alert_type TEXT NOT NULL, -- 'RULE_BASED' or 'STATISTICAL_ANOMALY'
        severity TEXT NOT NULL,   -- 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
        source_ip TEXT NOT NULL,
        dest_ip TEXT NOT NULL,
        port INTEGER,
        protocol TEXT,
        rule_name TEXT,
        message TEXT NOT NULL,
        details TEXT
    )
    """)

    # Seed default firewall rules if empty
    c.execute("SELECT COUNT(*) as count FROM firewall_rules")
    if c.fetchone()["count"] == 0:
        default_rules = [
            ("Block Malicious IP", "INBOUND", "198.51.100.44", "ANY", "ANY", None, "BLOCK", 10, 0),
            ("Block Telnet (Insecure)", "INBOUND", "ANY", "ANY", "TCP", 23, "BLOCK", 20, 0),
            ("Allow Bastion Host SSH", "INBOUND", "192.168.1.0/24", "10.0.0.5", "TCP", 22, "ALLOW", 30, 1),
            ("Block Direct Server SSH (Non-Bastion)", "INBOUND", "ANY", "10.0.0.10", "TCP", 22, "BLOCK", 40, 0),
            ("Allow Web HTTP", "INBOUND", "ANY", "ANY", "TCP", 80, "ALLOW", 50, 0),
            ("Allow Web HTTPS", "INBOUND", "ANY", "ANY", "TCP", 443, "ALLOW", 60, 0),
            ("Default Inbound Drop", "INBOUND", "ANY", "ANY", "ANY", None, "BLOCK", 999, 0),
        ]
        c.executemany("""
            INSERT INTO firewall_rules (name, direction, source_ip, dest_ip, protocol, port, action, priority, is_bastion_rule)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, default_rules)
    conn.commit()
    conn.close()

init_db()

# ----------------- IN-MEMORY IDS TRAFFIC & METRIC BUFFERS -----------------
traffic_history = deque(maxlen=200)
failed_logins = {} # {ip: [timestamps]}
port_scans = {}    # {ip: {port: timestamp}}
packet_rate_history = deque(maxlen=60) # list of float packets/sec

# Pre-populate with typical baseline traffic metrics (average 12 pkts/sec, std dev ~2.5)
np.random.seed(42)
baseline_rates = list(np.random.normal(loc=12.0, scale=2.5, size=45))
for r in baseline_rates:
    packet_rate_history.append(max(2.0, round(float(r), 1)))

# Bastion host configuration
bastion_config = {
    "enabled": True,
    "ip": "10.0.0.5",
    "name": "SecOps-Bastion-01",
    "allowed_management_subnet": "192.168.1.0/24",
    "monitored_ports": [22, 443]
}

# ----------------- 1. FIREWALL RULE MANAGER -----------------
@app.route("/api/firewall/rules", methods=["GET"])
def get_rules():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM firewall_rules ORDER BY priority ASC, id ASC")
    rules = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify({"rules": rules, "bastion": bastion_config})

@app.route("/api/firewall/rules", methods=["POST"])
def add_rule():
    data = request.get_json() or {}
    name = data.get("name", "Custom Rule")
    direction = data.get("direction", "INBOUND").upper()
    source_ip = data.get("source_ip", "ANY").strip()
    dest_ip = data.get("dest_ip", "ANY").strip()
    protocol = data.get("protocol", "TCP").upper()
    port = data.get("port")
    port = int(port) if port is not None and str(port).isdigit() else None
    action = data.get("action", "BLOCK").upper()
    priority = int(data.get("priority", 50))
    is_bastion = 1 if data.get("is_bastion_rule") else 0

    conn = get_db()
    c = conn.cursor()
    c.execute("""
        INSERT INTO firewall_rules (name, direction, source_ip, dest_ip, protocol, port, action, priority, is_bastion_rule)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (name, direction, source_ip, dest_ip, protocol, port, action, priority, is_bastion))
    new_id = c.lastrowid
    conn.commit()
    conn.close()

    return jsonify({"message": "Firewall rule created", "rule_id": new_id}), 201

@app.route("/api/firewall/rules/<int:rule_id>", methods=["PUT"])
def update_rule(rule_id):
    data = request.get_json() or {}
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        UPDATE firewall_rules SET
            name = COALESCE(?, name),
            source_ip = COALESCE(?, source_ip),
            dest_ip = COALESCE(?, dest_ip),
            protocol = COALESCE(?, protocol),
            port = ?,
            action = COALESCE(?, action),
            priority = COALESCE(?, priority),
            is_bastion_rule = COALESCE(?, is_bastion_rule)
        WHERE id = ?
    """, (
        data.get("name"),
        data.get("source_ip"),
        data.get("dest_ip"),
        data.get("protocol"),
        int(data.get("port")) if data.get("port") else None,
        data.get("action"),
        data.get("priority"),
        data.get("is_bastion_rule"),
        rule_id
    ))
    conn.commit()
    conn.close()
    return jsonify({"message": f"Rule {rule_id} updated"})

@app.route("/api/firewall/rules/<int:rule_id>", methods=["DELETE"])
def delete_rule(rule_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM firewall_rules WHERE id = ?", (rule_id,))
    conn.commit()
    conn.close()
    return jsonify({"message": f"Rule {rule_id} deleted"})

@app.route("/api/firewall/bastion", methods=["POST"])
def configure_bastion():
    data = request.get_json() or {}
    bastion_config["ip"] = data.get("ip", bastion_config["ip"])
    bastion_config["name"] = data.get("name", bastion_config["name"])
    bastion_config["enabled"] = bool(data.get("enabled", True))
    bastion_config["allowed_management_subnet"] = data.get("allowed_management_subnet", bastion_config["allowed_management_subnet"])
    return jsonify({"message": "Bastion host configuration updated", "bastion": bastion_config})

def match_ip(rule_ip, packet_ip):
    if rule_ip == "ANY" or packet_ip == "ANY":
        return True
    if "/" in rule_ip:
        # Simple subnet prefix match
        prefix = rule_ip.split("/")[0].rsplit(".", 1)[0]
        return packet_ip.startswith(prefix)
    return rule_ip == packet_ip

@app.route("/api/firewall/inspect", methods=["POST"])
def inspect_packet():
    data = request.get_json() or {}
    src_ip = data.get("source_ip", "192.168.1.50")
    dst_ip = data.get("dest_ip", "10.0.0.5")
    protocol = data.get("protocol", "TCP").upper()
    port = int(data.get("port", 80))
    direction = data.get("direction", "INBOUND").upper()

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM firewall_rules ORDER BY priority ASC, id ASC")
    rules = [dict(row) for row in c.fetchall()]
    conn.close()

    matched_rule = None
    action = "BLOCK" # default fallback
    reason = "Default Policy Deny"

    for r in rules:
        # Match direction
        if r["direction"] != direction and r["direction"] != "ANY":
            continue
        # Match Protocol
        if r["protocol"] != "ANY" and r["protocol"] != protocol:
            continue
        # Match Port
        if r["port"] is not None and r["port"] != port:
            continue
        # Match Source IP
        if not match_ip(r["source_ip"], src_ip):
            continue
        # Match Dest IP
        if not match_ip(r["dest_ip"], dst_ip):
            continue

        matched_rule = r
        action = r["action"]
        reason = f"Matched Rule #{r['id']} [{r['name']}] (Priority: {r['priority']})"
        break

    is_bastion_targeted = (dst_ip == bastion_config["ip"])

    return jsonify({
        "packet": {
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "protocol": protocol,
            "port": port,
            "direction": direction
        },
        "decision": action,
        "is_bastion_targeted": is_bastion_targeted,
        "matched_rule": matched_rule,
        "reason": reason
    })

# ----------------- 2. IDS ENGINE (RULE-BASED & STATISTICAL ANOMALY) -----------------
def record_alert(alert_type, severity, src_ip, dst_ip, port, protocol, rule_name, message, details=""):
    conn = get_db()
    c = conn.cursor()
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""
        INSERT INTO ids_alerts (timestamp, alert_type, severity, source_ip, dest_ip, port, protocol, rule_name, message, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (now_str, alert_type, severity, src_ip, dst_ip, port, protocol, rule_name, message, details))
    conn.commit()
    conn.close()

@app.route("/api/ids/alerts", methods=["GET"])
def get_alerts():
    limit = int(request.args.get("limit", 50))
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM ids_alerts ORDER BY id DESC LIMIT ?", (limit,))
    alerts = [dict(row) for row in c.fetchall()]
    conn.close()
    return jsonify({"alerts": alerts, "total": len(alerts)})

@app.route("/api/ids/alerts", methods=["DELETE"])
def clear_alerts():
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM ids_alerts")
    conn.commit()
    conn.close()
    return jsonify({"message": "Alerts cleared"})

@app.route("/api/ids/traffic/generate", methods=["POST"])
def generate_traffic():
    data = request.get_json() or {}
    attack_type = data.get("scenario", "normal") # normal, ssh_bruteforce, telnet_scan, port_scan, syn_flood
    src_ip = data.get("source_ip", f"192.168.1.{random.randint(10, 250)}")
    dst_ip = data.get("dest_ip", "10.0.0.5")

    current_time = time.time()
    generated_packets = []
    alerts_triggered = []

    if attack_type == "normal":
        # Generate ordinary HTTP/HTTPS requests
        for _ in range(5):
            port = random.choice([80, 443])
            pkt = {
                "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                "source_ip": src_ip,
                "dest_ip": dst_ip,
                "protocol": "TCP",
                "port": port,
                "payload": "GET /api/v1/resource HTTP/1.1",
                "status": "NORMAL"
            }
            generated_packets.append(pkt)
            traffic_history.append(pkt)
        packet_rate_history.append(round(random.uniform(9.0, 14.0), 1))

    elif attack_type == "ssh_bruteforce":
        # 5+ failed SSH logins in 1 minute
        if src_ip not in failed_logins:
            failed_logins[src_ip] = []
        
        for i in range(6):
            failed_logins[src_ip].append(current_time)
            pkt = {
                "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                "source_ip": src_ip,
                "dest_ip": dst_ip,
                "protocol": "TCP",
                "port": 22,
                "payload": f"SSH-2.0 auth failure: invalid password attempt #{i+1} for root",
                "status": "SUSPICIOUS"
            }
            generated_packets.append(pkt)
            traffic_history.append(pkt)

        # Rule check: >= 5 failed SSH logins in 60s
        recent_failures = [t for t in failed_logins[src_ip] if current_time - t <= 60]
        if len(recent_failures) >= 5:
            msg = f"Rule Alert: {len(recent_failures)} failed SSH login attempts in <60s from {src_ip}"
            record_alert(
                alert_type="RULE_BASED",
                severity="HIGH",
                src_ip=src_ip,
                dst_ip=dst_ip,
                port=22,
                protocol="TCP",
                rule_name="SSH Brute-Force Detection",
                message=msg,
                details=f"Threshold exceeded (5 attempts). Source IP: {src_ip} targeting SSH port 22."
            )
            alerts_triggered.append(msg)
        packet_rate_history.append(round(random.uniform(14.0, 18.0), 1))

    elif attack_type == "telnet_insecure":
        # Telnet on port 23
        pkt = {
            "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "protocol": "TCP",
            "port": 23,
            "payload": "TELNET IAC DO TERMINAL-TYPE",
            "status": "INSECURE"
        }
        generated_packets.append(pkt)
        traffic_history.append(pkt)

        msg = f"Rule Alert: Cleartext Telnet connection attempted on port 23 from {src_ip}"
        record_alert(
            alert_type="RULE_BASED",
            severity="MEDIUM",
            src_ip=src_ip,
            dst_ip=dst_ip,
            port=23,
            protocol="TCP",
            rule_name="Suspicious Insecure Protocol (Telnet)",
            message=msg,
            details="Telnet transmits passwords in plaintext and is disallowed by policy."
        )
        alerts_triggered.append(msg)

    elif attack_type == "port_scan":
        # Scanning multiple target ports in quick succession
        scanned_ports = [21, 22, 23, 25, 80, 443, 3389, 8080]
        for p in scanned_ports:
            pkt = {
                "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                "source_ip": src_ip,
                "dest_ip": dst_ip,
                "protocol": "TCP",
                "port": p,
                "payload": "SYN Stealth Scan Probe [Flags: S]",
                "status": "RECONNAISSANCE"
            }
            generated_packets.append(pkt)
            traffic_history.append(pkt)

        msg = f"Rule Alert: Reconnaissance Port Scan detected from {src_ip} ({len(scanned_ports)} ports probed)"
        record_alert(
            alert_type="RULE_BASED",
            severity="HIGH",
            src_ip=src_ip,
            dst_ip=dst_ip,
            port=None,
            protocol="TCP",
            rule_name="Port Reconnaissance Scan",
            message=msg,
            details=f"Ports scanned: {scanned_ports}. Likely automated scanner (e.g. Nmap)."
        )
        alerts_triggered.append(msg)
        packet_rate_history.append(round(random.uniform(22.0, 26.0), 1))

    elif attack_type == "syn_flood":
        # Volumetric traffic anomaly (> 3 standard deviations)
        burst_rate = 55.0 # extreme surge compared to normal mean ~12.0
        for _ in range(12):
            pkt = {
                "timestamp": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                "source_ip": src_ip,
                "dest_ip": dst_ip,
                "protocol": "TCP",
                "port": 80,
                "payload": "SYN Flood Request [Flags: S, Seq: random]",
                "status": "ANOMALY"
            }
            generated_packets.append(pkt)
            traffic_history.append(pkt)
        packet_rate_history.append(burst_rate)

    # ---------------- Statistical Anomaly Check (Using numpy & pandas) ----------------
    rates_series = pd.Series(list(packet_rate_history))
    mean_val = float(rates_series.mean())
    std_val = float(rates_series.std()) if len(rates_series) > 1 else 1.0
    latest_val = float(packet_rate_history[-1]) if packet_rate_history else mean_val
    threshold_3sigma = mean_val + 3.0 * std_val

    is_anomaly = (latest_val > threshold_3sigma and std_val > 0)
    z_score = round((latest_val - mean_val) / (std_val if std_val > 0 else 1.0), 2)

    if is_anomaly:
        msg = f"Statistical Anomaly Alert: Packet rate {latest_val} pkts/sec exceeds 3-sigma threshold ({round(threshold_3sigma, 2)}) [Z-Score = {z_score}]"
        record_alert(
            alert_type="STATISTICAL_ANOMALY",
            severity="CRITICAL",
            src_ip=src_ip,
            dst_ip=dst_ip,
            port=80,
            protocol="TCP",
            rule_name="Statistical Anomaly Engine (3-Sigma Deviation)",
            message=msg,
            details=f"Observed rate {latest_val} pkts/s vs Baseline mean {round(mean_val, 2)} pkts/s (std: {round(std_val, 2)}). Z-score: {z_score}."
        )
        alerts_triggered.append(msg)

    return jsonify({
        "scenario": attack_type,
        "packets_generated": generated_packets,
        "alerts_triggered": alerts_triggered,
        "metrics": {
            "latest_rate": latest_val,
            "mean": round(mean_val, 2),
            "std_dev": round(std_val, 2),
            "threshold_3sigma": round(threshold_3sigma, 2),
            "z_score": z_score,
            "is_anomaly": is_anomaly
        }
    })

@app.route("/api/ids/metrics", methods=["GET"])
def get_metrics():
    rates_series = pd.Series(list(packet_rate_history))
    mean_val = float(rates_series.mean()) if len(rates_series) > 0 else 12.0
    std_val = float(rates_series.std()) if len(rates_series) > 1 else 2.5
    threshold = round(mean_val + 3.0 * std_val, 2)

    history_points = [
        {"index": i + 1, "rate": round(r, 1), "threshold": threshold, "mean": round(mean_val, 1)}
        for i, r in enumerate(packet_rate_history)
    ]

    return jsonify({
        "current_mean": round(mean_val, 2),
        "current_std": round(std_val, 2),
        "threshold_3sigma": threshold,
        "total_packets_recorded": len(traffic_history),
        "history": history_points,
        "recent_traffic": list(traffic_history)[-10:]
    })

# ----------------- 3. THREAT ENCYCLOPEDIA (CONCEPTUAL MODULE) -----------------
ENCYCLOPEDIA = [
    {
        "id": "file-infector",
        "category": "Viruses",
        "title": "File Infector Viruses",
        "summary": "Viruses that attach themselves to executable files (.exe, .com, .dll).",
        "mechanism": "When the infected host program is executed, the virus code runs first, loads into memory, and seeks other executable binaries to infect before returning control to the host.",
        "historical_examples": ["Jerusalem Virus (1987)", "Cascade Virus", "CIH / Chernobyl (1998)"],
        "countermeasures": [
            "Signature-based antivirus file scanning",
            "Cryptographic file integrity checksums (SHA-256)",
            "Application whitelisting and code signing enforcement"
        ]
    },
    {
        "id": "boot-sector",
        "category": "Viruses",
        "title": "Boot Sector Viruses",
        "summary": "Infects the Master Boot Record (MBR) or partition boot record of storage drives.",
        "mechanism": "Executes before the operating system boots up. The virus moves original MBR to another sector and executes itself at boot time, gaining hyper-privileged system control.",
        "historical_examples": ["Brain Virus (1986 - First PC virus)", "Stoned", "Michelangelo"],
        "countermeasures": [
            "UEFI Secure Boot with cryptographically signed bootloaders",
            "Write protection on firmware/BIOS",
            "Disabling legacy boot from external USB drives in UEFI settings"
        ]
    },
    {
        "id": "macro-viruses",
        "category": "Viruses",
        "title": "Macro Viruses",
        "summary": "Viruses written in application scripting languages (e.g., VBA in Microsoft Word/Excel).",
        "mechanism": "Embedded inside document templates. When the user opens the document, malicious macros execute automatically to infect default template files.",
        "historical_examples": ["Concept (1995)", "Melissa Virus (1999)"],
        "countermeasures": [
            "Default blocking of macros from internet-downloaded files (Mark-of-the-Web)",
            "Mandatory cryptographic digital signatures on internal enterprise macros"
        ]
    },
    {
        "id": "email-worms",
        "category": "Worms",
        "title": "Email Worms",
        "summary": "Self-replicating malware that spreads autonomously through email systems.",
        "mechanism": "Scans local address books, harvesting contact emails, and leverages its own SMTP engine to send infected attachments or phishing links to all contacts.",
        "historical_examples": ["ILOVEYOU (Love Bug, 2000)", "Mydoom (2004)", "Storm Worm"],
        "countermeasures": [
            "Secure Email Gateways (SEG) with attachment sandboxing",
            "Outbound rate limiting on SMTP servers",
            "User security awareness and anti-phishing training"
        ]
    },
    {
        "id": "network-worms",
        "category": "Worms",
        "title": "Network & Exploitation Worms",
        "summary": "Worms that autonomously spread across networks by exploiting unpatched OS/service vulnerabilities without any human interaction.",
        "mechanism": "Scans IP address ranges for open ports, sends crafted exploit payloads (buffer overflows), and injects a shellcode listener to download and run the worm binary.",
        "historical_examples": ["Morris Worm (1988)", "Code Red (2001)", "SQL Slammer (2003)", "WannaCry (2017 - EternalBlue)"],
        "countermeasures": [
            "Rapid automated patch management for critical CVEs",
            "Network perimeter firewalls blocking unused incoming ports",
            "Intrusion Prevention Systems (IPS) with deep packet inspection"
        ]
    },
    {
        "id": "bastion-host-architecture",
        "category": "Firewalls",
        "title": "Bastion Host & DMZ Security",
        "summary": "A hardened, dedicated public-facing server that serves as the single gateway into an internal network.",
        "mechanism": "All administrative traffic (e.g. SSH, RDP) must traverse the Bastion Host. The Bastion host enforces multi-factor authentication, audit logging, and strict firewall packet rules.",
        "historical_examples": ["Dual-homed gateways", "Screened host architectures", "AWS Bastion Jumpboxes"],
        "countermeasures": [
            "Disable all unnecessary services and daemons",
            "Strict ingress firewall rules: only specific management IPs allowed",
            "Immutable session recording and audit trails"
        ]
    }
]

@app.route("/api/threats", methods=["GET"])
def get_threats():
    category = request.args.get("category")
    if category:
        filtered = [t for t in ENCYCLOPEDIA if t["category"].lower() == category.lower()]
        return jsonify({"threats": filtered})
    return jsonify({"threats": ENCYCLOPEDIA})

@app.route("/api/threats/<threat_id>", methods=["GET"])
def get_threat_detail(threat_id):
    for t in ENCYCLOPEDIA:
        if t["id"] == threat_id:
            return jsonify(t)
    return jsonify({"error": "Threat not found"}), 404

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy", "service": "Sentinel", "project": "Project3"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5003, debug=True)
