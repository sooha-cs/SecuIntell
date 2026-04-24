"""
Secuintell — Log Simulator
Generates realistic security log events and fires them at the FastAPI backend.

Usage:
    python simulator.py                  # send 20 random logs
    python simulator.py --count 100      # send 100 logs
    python simulator.py --burst          # bulk-send 200 logs in one request
    python simulator.py --loop           # stream logs every 2 seconds forever
"""

import requests
import random
import time
import argparse
from datetime import datetime

BACKEND_URL = "http://127.0.0.1:8000"

# ── Fake data pools ───────────────────────────────────────────────────────────

LEVELS = ["INFO", "INFO", "INFO", "WARNING", "WARNING", "ERROR", "CRITICAL"]

EVENT_TYPES = [
    "AUTH_FAILURE", "AUTH_SUCCESS", "PORT_SCAN", "MALWARE_DETECTED",
    "FIREWALL_BLOCK", "PRIVILEGE_ESCALATION", "DATA_EXFILTRATION",
    "BRUTE_FORCE", "LATERAL_MOVEMENT", "DNS_ANOMALY",
]

MESSAGES = {
    "AUTH_FAILURE":         "Failed login attempt for user '{user}' from {src}",
    "AUTH_SUCCESS":         "Successful login for user '{user}' from {src}",
    "PORT_SCAN":            "Port scan detected from {src} targeting {dst}",
    "MALWARE_DETECTED":     "Malware signature matched on {host} — file quarantined",
    "FIREWALL_BLOCK":       "Inbound connection from {src} blocked on port {port}",
    "PRIVILEGE_ESCALATION": "User '{user}' escalated privileges on {host}",
    "DATA_EXFILTRATION":    "Unusual outbound data volume from {host} to {dst}",
    "BRUTE_FORCE":          "Brute-force attack detected from {src} — {count} attempts",
    "LATERAL_MOVEMENT":     "Lateral movement detected: {src} → {dst}",
    "DNS_ANOMALY":          "Suspicious DNS query from {host} to unknown resolver {dst}",
}

USERNAMES = ["root", "admin", "ubuntu", "deploy", "svc_account", "backup_user"]
HOSTNAMES = ["prod-server-01", "db-master", "vpn-gateway", "dev-box-07", "k8s-node-03"]

def _rand_ip():
    return f"{random.randint(10,192)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def generate_log() -> dict:
    event = random.choice(EVENT_TYPES)
    level = "CRITICAL" if event in ("MALWARE_DETECTED", "PRIVILEGE_ESCALATION", "DATA_EXFILTRATION") \
            else random.choice(LEVELS)

    src  = _rand_ip()
    dst  = _rand_ip()
    user = random.choice(USERNAMES)
    host = random.choice(HOSTNAMES)
    port = random.choice([22, 443, 3306, 6379, 27017, 8080])

    message = MESSAGES[event].format(
        src=src, dst=dst, user=user, host=host,
        port=port, count=random.randint(50, 500)
    )

    return {
        "message": message,
        "level": level,
        "source_ip": src,
        "destination_ip": dst,
        "event_type": event,
        "hostname": host,
        "user": user,
        "extra": {"port": port, "simulated": True},
    }


# ── Sender helpers ────────────────────────────────────────────────────────────

def send_one(log: dict):
    try:
        r = requests.post(f"{BACKEND_URL}/logs/", json=log, timeout=5)
        r.raise_for_status()
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] ✅ {log['level']:8s} | {log['event_type']:25s} | {log['source_ip']}")
    except Exception as e:
        print(f"❌ Failed to send log: {e}")


def send_bulk(logs: list[dict]):
    try:
        r = requests.post(f"{BACKEND_URL}/logs/bulk", json=logs, timeout=10)
        r.raise_for_status()
        print(f"✅ Bulk insert: {r.json()['inserted']} logs stored.")
    except Exception as e:
        print(f"❌ Bulk send failed: {e}")


# ── CLI entrypoint ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secuintell log simulator")
    parser.add_argument("--count",  type=int, default=20, help="Number of logs to send")
    parser.add_argument("--burst",  action="store_true",  help="Send all logs in one bulk request")
    parser.add_argument("--loop",   action="store_true",  help="Stream one log every 2s forever")
    args = parser.parse_args()

    print(f"\n🛡️  Secuintell Log Simulator → {BACKEND_URL}\n")

    if args.loop:
        print("Streaming mode — Ctrl+C to stop\n")
        while True:
            send_one(generate_log())
            time.sleep(2)
    elif args.burst:
        logs = [generate_log() for _ in range(args.count)]
        print(f"Sending {len(logs)} logs in bulk…")
        send_bulk(logs)
    else:
        for _ in range(args.count):
            send_one(generate_log())
            time.sleep(0.15)

    print("\nDone.")
