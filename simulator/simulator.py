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
    "BRUTE_FORCE", "LATERAL_MOVEMENT", "DNS_ANOMALY", "FILE_TAMPER",
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
    "FILE_TAMPER":          "File integrity violation on {host} — {file} hash mismatch detected",
}

# Sensitive files targeted in attack scenarios
SENSITIVE_FILES = [
    "/etc/passwd", "/etc/sudoers", "/etc/ssh/sshd_config",
    "/usr/bin/sudo", "/etc/crontab", "/var/log/auth.log",
]

USERNAMES = ["root", "admin", "ubuntu", "deploy", "svc_account", "backup_user"]
HOSTNAMES = ["prod-server-01", "db-master", "vpn-gateway", "dev-box-07", "k8s-node-03"]

def _rand_ip():
    return f"{random.randint(10,192)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def generate_log() -> dict:
    event = random.choice(EVENT_TYPES)
    level = "CRITICAL" if event in ("MALWARE_DETECTED", "PRIVILEGE_ESCALATION", "DATA_EXFILTRATION", "FILE_TAMPER") \
            else random.choice(LEVELS)

    src  = _rand_ip()
    dst  = _rand_ip()
    user = random.choice(USERNAMES)
    host = random.choice(HOSTNAMES)
    port = random.choice([22, 443, 3306, 6379, 27017, 8080])
    file = random.choice(SENSITIVE_FILES)

    message = MESSAGES[event].format(
        src=src, dst=dst, user=user, host=host,
        port=port, count=random.randint(50, 500), file=file,
    )

    return {
        "message":        message,
        "level":          level,
        "source_ip":      src,
        "destination_ip": dst,
        "event_type":     event,
        "hostname":       host,
        "user":           user,
        "extra":          {"port": port, "simulated": True},
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


# ── Attack scenario engine ────────────────────────────────────────────────────

SCENARIO_SPEEDS = {
    "fast":     {"phase": 1,  "event": 0.3},   # quick demo
    "normal":   {"phase": 3,  "event": 0.8},   # realistic
    "slow":     {"phase": 6,  "event": 1.5},   # walkthrough/presentation
}

def _divider(char="─", width=60):
    print(char * width)

def _phase(number, title, description, color="\033[93m"):
    reset = "\033[0m"
    _divider()
    print(f"{color}  PHASE {number}: {title}{reset}")
    print(f"  {description}")
    _divider()


def _make_event(event_type, level, src, host, user, extra_msg="", **kwargs) -> dict:
    """Build a structured log event for the scenario."""
    file = kwargs.get("file", random.choice(SENSITIVE_FILES))
    dst  = kwargs.get("dst", _rand_ip())
    port = kwargs.get("port", 22)
    msg  = MESSAGES[event_type].format(
        src=src, dst=dst, user=user, host=host,
        port=port, count=kwargs.get("count", 0), file=file,
    )
    if extra_msg:
        msg += f" — {extra_msg}"
    return {
        "message":        msg,
        "level":          level,
        "source_ip":      src,
        "destination_ip": dst,
        "event_type":     event_type,
        "hostname":       host,
        "user":           user,
        "extra":          {"simulated": True, "scenario": "brute_force_chain", **kwargs},
    }


def run_scenario(speed: str = "normal"):
    """
    Scripted attack chain:
      Phase 1 — Reconnaissance  : port scan from attacker IP
      Phase 2 — Brute Force     : repeated AUTH_FAILURE bursts
      Phase 3 — Initial Access  : AUTH_SUCCESS (credentials compromised)
      Phase 4 — Privilege Esc.  : sudo escalation to root
      Phase 5 — File Tamper     : critical system file modifications
      Phase 6 — Exfiltration    : data sent to external IP
    """
    timing   = SCENARIO_SPEEDS.get(speed, SCENARIO_SPEEDS["normal"])
    p_delay  = timing["phase"]     # seconds between phases
    e_delay  = timing["event"]     # seconds between individual events

    # Fixed attacker IP and target for narrative consistency
    attacker = f"185.{random.randint(10,99)}.{random.randint(10,99)}.{random.randint(10,99)}"
    target   = "prod-server-01"
    user     = "root"
    c2_ip    = f"91.{random.randint(100,200)}.{random.randint(10,99)}.{random.randint(10,99)}"

    red    = "\033[91m"
    yellow = "\033[93m"
    green  = "\033[92m"
    cyan   = "\033[96m"
    reset  = "\033[0m"

    print(f"\n{red}{'█' * 60}")
    print(f"  🔴  SECUINTELL — LIVE ATTACK SCENARIO")
    print(f"  Attacker IP : {attacker}")
    print(f"  Target Host : {target}")
    print(f"  Speed       : {speed}")
    print(f"{'█' * 60}{reset}\n")
    time.sleep(1)

    # ── Phase 1: Reconnaissance ───────────────────────────────────────────────
    _phase(1, "RECONNAISSANCE", f"Attacker {attacker} probes {target} for open ports", yellow)
    for port in [22, 80, 443, 3306, 8080]:
        log = _make_event("PORT_SCAN", "WARNING", attacker, target, "unknown", port=port)
        send_one(log)
        time.sleep(e_delay)

    print(f"\n  {cyan}→ Port scan complete. Attacker identifies SSH (22) as open.{reset}\n")
    time.sleep(p_delay)

    # ── Phase 2: Brute Force ──────────────────────────────────────────────────
    _phase(2, "BRUTE FORCE", f"SSH credential stuffing from {attacker} — {random.randint(300,800)} attempts", red)
    for attempt in range(1, 9):
        count = random.randint(40, 120)
        log = _make_event(
            "BRUTE_FORCE", "CRITICAL", attacker, target, user,
            count=count,
            extra_msg=f"attempt burst #{attempt}"
        )
        send_one(log)
        time.sleep(e_delay)
        # Sprinkle auth failures between bursts
        if attempt % 2 == 0:
            fail_log = _make_event("AUTH_FAILURE", "ERROR", attacker, target, user)
            send_one(fail_log)
            time.sleep(e_delay * 0.5)

    print(f"\n  {cyan}→ Account lockout bypassed. Weak password found.{reset}\n")
    time.sleep(p_delay)

    # ── Phase 3: Initial Access ───────────────────────────────────────────────
    _phase(3, "INITIAL ACCESS", f"Successful SSH login — credentials compromised", red)
    success_log = _make_event(
        "AUTH_SUCCESS", "CRITICAL", attacker, target, user,
        extra_msg="SSH login with compromised credentials"
    )
    send_one(success_log)
    time.sleep(e_delay * 2)

    print(f"\n  {red}⚠  CRITICAL: Attacker now has shell access on {target}{reset}\n")
    time.sleep(p_delay)

    # ── Phase 4: Privilege Escalation ─────────────────────────────────────────
    _phase(4, "PRIVILEGE ESCALATION", f"Attacker escalates to root via sudo exploit", red)
    priv_log = _make_event(
        "PRIVILEGE_ESCALATION", "CRITICAL", attacker, target, user,
        extra_msg="sudo -l enumeration → CVE-2023-22809 exploit attempted"
    )
    send_one(priv_log)
    time.sleep(e_delay)

    # Also fire a lateral movement attempt
    lateral_target = random.choice([h for h in HOSTNAMES if h != target])
    lateral_log = _make_event(
        "LATERAL_MOVEMENT", "CRITICAL", attacker, lateral_target, user,
        dst=f"10.0.0.{random.randint(2,50)}",
        extra_msg="root pivot via SSH key"
    )
    send_one(lateral_log)
    time.sleep(e_delay)

    print(f"\n  {red}⚠  CRITICAL: Root shell obtained. Lateral movement to {lateral_target}.{reset}\n")
    time.sleep(p_delay)

    # ── Phase 5: File Tampering ───────────────────────────────────────────────
    _phase(5, "FILE INTEGRITY VIOLATION", "Attacker modifies critical system files", red)
    tamper_targets = ["/etc/passwd", "/etc/sudoers", "/etc/ssh/sshd_config"]
    for filepath in tamper_targets:
        tamper_log = _make_event(
            "FILE_TAMPER", "CRITICAL", attacker, target, user,
            file=filepath,
            extra_msg="hash mismatch — unauthorized modification"
        )
        send_one(tamper_log)
        time.sleep(e_delay)

    print(f"\n  {red}⚠  CRITICAL: Persistence established via modified sudoers + sshd_config{reset}\n")
    time.sleep(p_delay)

    # ── Phase 6: Exfiltration ─────────────────────────────────────────────────
    _phase(6, "DATA EXFILTRATION", f"Sensitive data being sent to C2 at {c2_ip}", red)
    for i in range(3):
        exfil_log = _make_event(
            "DATA_EXFILTRATION", "CRITICAL", target, target, user,
            dst=c2_ip,
            extra_msg=f"batch {i+1}/3 — encrypted stream to C2"
        )
        send_one(exfil_log)
        time.sleep(e_delay)

    # Final DNS anomaly — C2 beacon
    dns_log = _make_event(
        "DNS_ANOMALY", "ERROR", target, target, user,
        dst=c2_ip,
        extra_msg="beaconing to C2 domain — DGA pattern detected"
    )
    send_one(dns_log)

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n{red}{'█' * 60}")
    print(f"  ✅  SCENARIO COMPLETE")
    print(f"{'─' * 60}")
    print(f"  Attacker IP  : {attacker}")
    print(f"  C2 Server    : {c2_ip}")
    print(f"  Target Host  : {target}")
    print(f"  Attack Chain : Recon → Brute Force → Initial Access")
    print(f"                 → Privilege Escalation → File Tamper → Exfil")
    print(f"  MITRE Tactics: Discovery, Credential Access, Initial Access,")
    print(f"                 Privilege Escalation, Defense Evasion, Exfiltration")
    print(f"{'█' * 60}{reset}\n")


# ── CLI entrypoint ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secuintell log simulator")
    parser.add_argument("--count",    type=int, default=20,       help="Number of logs to send")
    parser.add_argument("--burst",    action="store_true",        help="Send all logs in one bulk request")
    parser.add_argument("--loop",     action="store_true",        help="Stream one log every 2s forever")
    parser.add_argument("--scenario", action="store_true",        help="Run scripted brute-force → success → file tamper chain")
    parser.add_argument("--speed",    default="normal",           help="Scenario speed: fast | normal | slow  (default: normal)",
                        choices=["fast", "normal", "slow"])
    args = parser.parse_args()

    print(f"\n🛡️  Secuintell Log Simulator → {BACKEND_URL}\n")

    if args.scenario:
        run_scenario(speed=args.speed)
    elif args.loop:
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
