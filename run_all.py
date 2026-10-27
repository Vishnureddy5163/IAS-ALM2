import os
import sys
import subprocess
import time
import signal

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def start_services():
    print("=" * 70)
    print("   KLH ALM-2: Advanced CyberSecurity & Cryptography Suite")
    print("   Launching All 3 Projects & Unified React Dashboard...")
    print("=" * 70)

    processes = []

    # 1. Start Project 1 (Port 5001)
    p1_dir = os.path.join(BASE_DIR, "Project1")
    print("\n[+] Starting Project 1 (CryptoVault) on http://localhost:5001 ...")
    p1 = subprocess.Popen([sys.executable, "app.py"], cwd=p1_dir)
    processes.append(("Project 1 (CryptoVault)", p1))

    # 2. Start Project 2 (Port 5002)
    p2_dir = os.path.join(BASE_DIR, "Project2")
    print("[+] Starting Project 2 (SecureTunnel) on http://localhost:5002 ...")
    p2 = subprocess.Popen([sys.executable, "app.py"], cwd=p2_dir)
    processes.append(("Project 2 (SecureTunnel)", p2))

    # 3. Start Project 3 (Port 5003)
    p3_dir = os.path.join(BASE_DIR, "Project3")
    print("[+] Starting Project 3 (Sentinel) on http://localhost:5003 ...")
    p3 = subprocess.Popen([sys.executable, "app.py"], cwd=p3_dir)
    processes.append(("Project 3 (Sentinel)", p3))

    # 4. Start Unified Dashboard (Port 3000)
    dash_dir = os.path.join(BASE_DIR, "dashboard")
    print("[+] Starting Unified Master Dashboard on http://localhost:3000 ...")
    npm_cmd = "npm.cmd" if os.name == "nt" else "npm"
    p_ui = subprocess.Popen([npm_cmd, "run", "dev"], cwd=dash_dir)
    processes.append(("Unified Dashboard UI", p_ui))

    time.sleep(3)
    print("\n" + "=" * 70)
    print("   ALL SERVICES RUNNING SUCCESSFULLY!")
    print("   -> Unified Dashboard: http://localhost:3000")
    print("   -> Project 1 API:     http://localhost:5001")
    print("   -> Project 2 API:     http://localhost:5002")
    print("   -> Project 3 API:     http://localhost:5003")
    print("=" * 70)
    print("Press Ctrl+C to terminate all services.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down all services gracefully...")
        for name, p in processes:
            print(f"    Stopping {name}...")
            p.terminate()
            p.wait()
        print("[✓] All services stopped.")

if __name__ == "__main__":
    start_services()
