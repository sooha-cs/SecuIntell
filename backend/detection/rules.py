"""
Rule-Based Detection Engine
────────────────────────────
Each DetectionRule carries:
  • One or more Conditions  (field matcher OR regex on message)
  • A severity tier         LOW | MEDIUM | HIGH | CRITICAL
  • A MITRE ATT&CK tactic  for context
  • match_mode              ALL  → every condition must pass
                            ANY  → at least one condition must pass

Rules are evaluated in priority order (highest first).  A log can trigger
multiple rules; each produces a separate RuleMatch.
"""

from __future__ import annotations
import re
from typing import Callable, Literal, Optional
from dataclasses import dataclass, field as dc_field

# ── Severity tier ─────────────────────────────────────────────────────────────

SEVERITY_SCORE: dict[str, int] = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


# ── Single condition ──────────────────────────────────────────────────────────

@dataclass
class Condition:
    """
    field=None  → match against log['message']
    field='level' / 'event_type' / 'source_ip' / … → match that field
    """
    pattern: str                          # regex pattern
    field: Optional[str] = None           # None means 'message'
    negate: bool = False                  # True → condition passes when pattern does NOT match
    _compiled: re.Pattern = dc_field(default=None, init=False, repr=False)

    def __post_init__(self):
        self._compiled = re.compile(self.pattern, re.IGNORECASE)

    def evaluate(self, log: dict) -> bool:
        value = str(log.get(self.field or "message", "") or "")
        matched = bool(self._compiled.search(value))
        return (not matched) if self.negate else matched


# ── Rule definition ───────────────────────────────────────────────────────────

@dataclass
class DetectionRule:
    id: str
    name: str
    description: str
    severity: Severity
    conditions: list[Condition]
    tactic: str = "Unknown"               # MITRE ATT&CK tactic label
    technique: str = ""                   # e.g. T1110
    match_mode: Literal["ALL", "ANY"] = "ALL"
    priority: int = 50                    # higher → evaluated first

    def evaluate(self, log: dict) -> bool:
        if self.match_mode == "ALL":
            return all(c.evaluate(log) for c in self.conditions)
        return any(c.evaluate(log) for c in self.conditions)


# ── Match result ──────────────────────────────────────────────────────────────

@dataclass
class RuleMatch:
    rule_id: str
    rule_name: str
    severity: Severity
    severity_score: int
    tactic: str
    technique: str
    description: str


# ── Rule registry ─────────────────────────────────────────────────────────────

RULES: list[DetectionRule] = [

    # ── CRITICAL ──────────────────────────────────────────────────────────────

    DetectionRule(
        id="R001",
        name="Root Login Detected",
        description="Direct root login observed — privileged access without sudo trail.",
        severity="CRITICAL",
        tactic="Privilege Escalation",
        technique="T1078",
        priority=100,
        conditions=[
            Condition(pattern=r"\broot\b", field="user"),
            Condition(pattern=r"(login|auth|session)", field="message"),
        ],
    ),

    DetectionRule(
        id="R002",
        name="Malware Signature Detected",
        description="Known malware pattern matched in log event.",
        severity="CRITICAL",
        tactic="Execution",
        technique="T1204",
        priority=100,
        conditions=[Condition(pattern=r"malware|ransomware|trojan|rootkit|exploit|shellcode", field="message")],
    ),

    DetectionRule(
        id="R003",
        name="Data Exfiltration Attempt",
        description="Large outbound transfer or exfil keywords detected.",
        severity="CRITICAL",
        tactic="Exfiltration",
        technique="T1041",
        priority=100,
        match_mode="ANY",
        conditions=[
            Condition(pattern=r"exfiltrat|data.{0,15}(transfer|leak|dump|export)|outbound.{0,20}(volume|data|traffic)", field="message"),
            Condition(pattern=r"DATA_EXFILTRATION", field="event_type"),
        ],
    ),

    DetectionRule(
        id="R004",
        name="Privilege Escalation via SUDO/SETUID",
        description="Suspicious privilege escalation pattern in log.",
        severity="CRITICAL",
        tactic="Privilege Escalation",
        technique="T1548",
        priority=95,
        match_mode="ANY",
        conditions=[
            # Covers "privilege escalation" AND "escalated privileges" (both word orders)
            Condition(pattern=r"privilege.{0,15}escalat|escalat.{0,15}privilege|sudo.{0,15}(fail|error|denied)|setuid|setgid|suid", field="message"),
            Condition(pattern=r"PRIVILEGE_ESCALATION", field="event_type"),
        ],
    ),

    # ── HIGH ──────────────────────────────────────────────────────────────────

    DetectionRule(
        id="R005",
        name="Brute Force Attack",
        description="Repeated authentication failures suggest brute-force.",
        severity="HIGH",
        tactic="Credential Access",
        technique="T1110",
        priority=85,
        match_mode="ANY",
        conditions=[
            Condition(pattern=r"brute.?force|multiple.{0,10}fail|repeated.{0,10}(login|auth)", field="message"),
            Condition(pattern=r"BRUTE_FORCE", field="event_type"),
        ],
    ),

    DetectionRule(
        id="R006",
        name="Port Scan Detected",
        description="Sequential port probing activity identified.",
        severity="HIGH",
        tactic="Discovery",
        technique="T1046",
        priority=85,
        conditions=[Condition(pattern=r"port.?scan|nmap|masscan|zmap|host.{0,10}discover", field="message")],
    ),

    DetectionRule(
        id="R007",
        name="Lateral Movement Detected",
        description="Inter-host movement pattern detected.",
        severity="HIGH",
        tactic="Lateral Movement",
        technique="T1021",
        priority=80,
        match_mode="ANY",
        conditions=[
            Condition(pattern=r"lateral.{0,10}move|psexec|wmiexec|pass.?the.?hash|impacket|smb.{0,10}(login|connect)", field="message"),
            Condition(pattern=r"LATERAL_MOVEMENT", field="event_type"),
        ],
    ),

    DetectionRule(
        id="R008",
        name="Suspicious DNS Query",
        description="DNS request to unknown or suspicious resolver.",
        severity="HIGH",
        tactic="Command and Control",
        technique="T1071.004",
        priority=75,
        conditions=[
            Condition(pattern=r"(dns|resolver|lookup)", field="message"),
            Condition(pattern=r"(unknown|suspicious|anomal|unusual)", field="message"),
        ],
        match_mode="ANY",
    ),

    DetectionRule(
        id="R009",
        name="Critical-Level Log from Production Host",
        description="CRITICAL severity log from a production system.",
        severity="HIGH",
        tactic="Impact",
        technique="T1499",
        priority=70,
        conditions=[
            Condition(pattern=r"CRITICAL", field="level"),
            Condition(pattern=r"prod|production|prd", field="hostname"),
        ],
    ),

    # ── MEDIUM ────────────────────────────────────────────────────────────────

    DetectionRule(
        id="R010",
        name="Authentication Failure",
        description="Single authentication failure event.",
        severity="MEDIUM",
        tactic="Credential Access",
        technique="T1110.001",
        priority=60,
        conditions=[
            Condition(pattern=r"fail(ed)?|denied|invalid|incorrect|wrong", field="message"),
            Condition(pattern=r"(login|auth|password|credential|ssh|rdp)", field="message"),
        ],
    ),

    DetectionRule(
        id="R011",
        name="Firewall Rule Triggered",
        description="Firewall blocked a connection attempt.",
        severity="MEDIUM",
        tactic="Defense Evasion",
        technique="T1562.004",
        priority=55,
        conditions=[Condition(pattern=r"firewall.{0,10}(block|drop|deny|reject)|iptables|nftables", field="message")],
    ),

    DetectionRule(
        id="R012",
        name="Service Account Activity",
        description="Privileged service account performing actions.",
        severity="MEDIUM",
        tactic="Privilege Escalation",
        technique="T1078.003",
        priority=50,
        conditions=[
            Condition(pattern=r"svc_|service.?account|sa_|system.?account", field="user"),
        ],
    ),

    DetectionRule(
        id="R013",
        name="Off-Hours Access",
        description="System access occurring outside business hours.",
        severity="MEDIUM",
        tactic="Initial Access",
        technique="T1078",
        priority=45,
        conditions=[Condition(pattern=r"(01|02|03|04|05):\d{2}:\d{2}", field="message")],
    ),

    DetectionRule(
        id="R016",
        name="File Integrity Violation",
        description="Critical system file modified, deleted, or permission changed by unauthorised actor.",
        severity="CRITICAL",
        tactic="Defense Evasion",
        technique="T1565.001",
        priority=98,
        match_mode="ANY",
        conditions=[
            Condition(pattern=r"file.{0,20}(integrity|tamper|hash.{0,10}mismatch|modif)", field="message"),
            Condition(pattern=r"FILE_TAMPER", field="event_type"),
        ],
    ),

    DetectionRule(
        id="R017",
        name="Suspicious Successful Authentication",
        description="AUTH_SUCCESS following brute-force or from unusual source — possible credential compromise.",
        severity="HIGH",
        tactic="Initial Access",
        technique="T1078",
        priority=88,
        match_mode="ANY",
        conditions=[
            Condition(pattern=r"compromised.{0,20}credential|ssh.{0,15}login.{0,15}(attacker|unusual|foreign)", field="message"),
            Condition(pattern=r"AUTH_SUCCESS", field="event_type"),
        ],
    ),

    # ── LOW ───────────────────────────────────────────────────────────────────

    DetectionRule(
        id="R014",
        name="Successful Root Authentication",
        description="Root login succeeded — note for audit trail.",
        severity="LOW",
        tactic="Initial Access",
        technique="T1078.003",
        priority=30,
        match_mode="ALL",
        conditions=[
            Condition(pattern=r"\broot\b", field="user"),
            Condition(pattern=r"success|accepted|granted", field="message"),
        ],
    ),

    DetectionRule(
        id="R015",
        name="Backup User Activity",
        description="Backup account performing operations — verify schedule.",
        severity="LOW",
        tactic="Collection",
        technique="T1005",
        priority=20,
        conditions=[Condition(pattern=r"backup|bkp", field="user")],
    ),
]

# Sort by priority descending once at import time
RULES.sort(key=lambda r: r.priority, reverse=True)


# ── Engine ────────────────────────────────────────────────────────────────────

class RuleEngine:
    """Evaluate all rules against a log document and return every match."""

    def __init__(self, rules: list[DetectionRule] = RULES):
        self.rules = rules

    def evaluate(self, log: dict) -> list[RuleMatch]:
        matches: list[RuleMatch] = []
        for rule in self.rules:
            if rule.evaluate(log):
                matches.append(RuleMatch(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    severity_score=SEVERITY_SCORE[rule.severity],
                    tactic=rule.tactic,
                    technique=rule.technique,
                    description=rule.description,
                ))
        return matches

    def max_severity(self, matches: list[RuleMatch]) -> Optional[Severity]:
        if not matches:
            return None
        return max(matches, key=lambda m: m.severity_score).severity
