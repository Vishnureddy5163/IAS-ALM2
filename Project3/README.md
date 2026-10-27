# Project 3: "Sentinel" - Intrusion Detection & Firewall Simulator

## Overview
**Sentinel** is a full-stack security application simulating enterprise perimeter defense, packet filtering engines, network intrusion detection systems (both signature/rule-based and statistical anomaly-based), Bastion Host management, and comprehensive threat intelligence.

## Core Topics Covered
1. **Firewall Rule Manager & Bastion Host**:
   - Admin control panel for granular rule management (Source IP, Destination IP, Port, Protocol, Action: ALLOW / BLOCK, Priority).
   - Dedicated Bastion Host configuration (`10.0.0.5`) with restricted management subnets (`192.168.1.0/24`) and monitored ports (22, 443).
   - Real-time packet evaluation engine matching incoming packets top-down by priority with default deny fallback.
2. **Rule-Based Intrusion Detection System (Signature IDS)**:
   - Evaluates security policies against traffic feeds in real time.
   - Detects:
     * $\ge 5$ failed SSH logins in 1 minute from the same source IP $\to$ High Severity Alert ("SSH Brute Force").
     * Traffic on unencrypted Port 23 $\to$ Medium Severity Alert ("Suspicious Insecure Telnet").
     * Multi-port sequential probing $\to$ High Severity Alert ("Port Reconnaissance Scan").
3. **Statistical Anomaly Intrusion Detection System (3-Sigma Gaussian Model)**:
   - Dynamic baseline tracking using NumPy and Pandas.
   - Computes rolling mean ($\mu$) and standard deviation ($\sigma$) of packet rates.
   - Flags volumetric traffic bursts (e.g., SYN Flood) exceeding $\mu + 3\sigma$ with exact Z-score computation.
4. **Traffic Generator**:
   - Injects simulated traffic vectors: Normal HTTP/HTTPS, SSH Brute Force, Telnet Insecure, Port Scans, and SYN Floods.
5. **Threat Encyclopedia**:
   - Theoretical background on Viruses (File Infector, Boot Sector, Macro, Polymorphic), Worms (Email worms, Network worms, Morris worm, WannaCry), and Bastion Host defense countermeasures.

## Technical Architecture & Backend Endpoints
- **Runtime**: Python 3.14+ / Flask 3.0+ on `http://localhost:5003`
- **Analytics**: `numpy` and `pandas`
- **Database**: SQLite (`sentinel.db`)

### API Specification
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/firewall/rules` | Lists all firewall rules and Bastion Host configuration |
| `POST` | `/api/firewall/rules` | Creates a new firewall rule with custom priority and action |
| `DELETE` | `/api/firewall/rules/<id>` | Deletes an existing rule |
| `POST` | `/api/firewall/inspect` | Evaluates simulated packet against rules in priority order |
| `POST` | `/api/firewall/bastion` | Updates Bastion Host configuration parameters |
| `POST` | `/api/ids/traffic/generate`| Generates traffic scenario and updates metrics and alerts |
| `GET` | `/api/ids/alerts` | Returns live feed of rule-based and anomaly alerts |
| `DELETE` | `/api/ids/alerts` | Clears alert feed |
| `GET` | `/api/ids/metrics` | Returns 3-sigma baseline statistics and recent traffic rates |
| `GET` | `/api/threats` | Retrieves articles from Threat Encyclopedia |

## Running Project 3
```bash
python app.py
```
To run unit tests:
```bash
python test_project3.py
```
