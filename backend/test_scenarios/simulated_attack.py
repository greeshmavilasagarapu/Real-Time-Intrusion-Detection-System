#!/usr/bin/env python3
"""
Simulated Attack Generator
Generates realistic network traffic patterns that match CICIDS2017 attack signatures.
This works because the MLP model was trained on CICIDS2017 flow features.

SAFE: Only generates synthetic traffic on localhost.
"""

import socket
import time
import threading
import sys


def port_scan_attack():
    """Simulate port scanning traffic pattern."""
    print("[ATTACK] Starting Port Scan simulation...")
    target = "127.0.0.1"
    ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
             993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443,
             33060, 54321, 27017, 6379, 9200, 11211]
    
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.3)
            s.connect((target, port))
            s.close()
        except:
            pass
    print(f"[ATTACK] Port scan completed: {len(ports)} ports probed")


def dos_attack():
    """Simulate DoS/DDoS traffic pattern (many short connections)."""
    print("[ATTACK] Starting DoS simulation...")
    target = "127.0.0.1"
    port = 8080  # Any open port
    
    # First open a listener
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((target, port))
    server.listen(100)
    server.settimeout(0.1)
    
    # Send burst of connections
    for i in range(200):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect((target, port))
            s.send(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
            s.close()
        except:
            pass
    
    server.close()
    print(f"[ATTACK] DoS simulation completed: 200 rapid connections")


def brute_force_network():
    """Simulate brute force network traffic pattern."""
    print("[ATTACK] Starting Brute Force network simulation...")
    target = "127.0.0.1"
    
    # Many connections to SSH-like port with short duration
    for i in range(50):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            s.connect((target, 22))  # SSH port
            s.send(b"SSH-2.0-OpenSSH_test\r\n")
            s.close()
        except:
            pass
    print(f"[ATTACK] Brute Force simulation completed: 50 connection attempts")


def web_attack():
    """Simulate web attack traffic pattern."""
    print("[ATTACK] Starting Web Attack simulation...")
    target = "127.0.0.1"
    port = 8080
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((target, port))
    server.listen(50)
    server.settimeout(0.1)
    
    # Send HTTP requests with attack-like patterns
    attack_payloads = [
        b"GET /admin HTTP/1.1\r\nHost: test\r\n\r\n",
        b"GET /wp-login.php HTTP/1.1\r\nHost: test\r\n\r\n",
        b"POST /login HTTP/1.1\r\nHost: test\r\nContent-Length: 50\r\n\r\nuser=admin&pass=admin'or'1'='1",
        b"GET /../../../etc/passwd HTTP/1.1\r\nHost: test\r\n\r\n",
        b"GET /shell?cmd=id HTTP/1.1\r\nHost: test\r\n\r\n",
    ]
    
    for i in range(30):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            s.connect((target, port))
            s.send(attack_payloads[i % len(attack_payloads)])
            s.close()
        except:
            pass
    
    server.close()
    print(f"[ATTACK] Web Attack simulation completed: 30 malicious requests")


def generate_log_anomaly():
    """Generate suspicious log entries via syslog."""
    print("[ATTACK] Generating suspicious log entries...")
    
    suspicious_logs = [
        "Failed password for root from 10.0.0.100 port 44444 ssh2",
        "Failed password for admin from 10.0.0.100 port 44445 ssh2",
        "Failed password for user from 10.0.0.100 port 44446 ssh2",
        "Invalid user test from 10.0.0.100",
        "Connection closed by 10.0.0.100 port 44447 [preauth]",
        "PAM: Authentication failure for root from 10.0.0.100",
        "Kernel: iptables DROP IN=eth0 SRC=10.0.0.100 DST=192.168.1.1",
        "sshd: excessive authentication failures from 10.0.0.100",
    ]
    
    for log in suspicious_logs:
        try:
            import subprocess
            subprocess.run(['logger', '-p', 'auth.warning', log],
                         capture_output=True, timeout=2)
        except:
            pass
        time.sleep(0.3)
    
    print(f"[ATTACK] Generated {len(suspicious_logs)} suspicious log entries")


if __name__ == "__main__":
    attacks = {
        '1': ('Port Scan', port_scan_attack),
        '2': ('DoS/DDoS', dos_attack),
        '3': ('Brute Force', brute_force_network),
        '4': ('Web Attack', web_attack),
        '5': ('Log Anomaly', generate_log_anomaly),
    }
    
    print("=" * 50)
    print("  SIMULATED ATTACK GENERATOR")
    print("=" * 50)
    print("Choose attack type:")
    for key, (name, _) in attacks.items():
        print(f"  {key}. {name}")
    print()
    
    choice = sys.argv[1] if len(sys.argv) > 1 else input("Enter choice: ")
    
    if choice == 'all':
        for name, func in attacks.values():
            func()
            time.sleep(2)
    elif choice in attacks:
        attacks[choice][1]()
    else:
        print("Invalid choice")
