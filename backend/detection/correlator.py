"""
Correlation Engine
───────────────────
Chains individual alert events into Incidents using two strategies:

  1. IP-based time-window correlation
     ─ All alerts from the same source_ip within WINDOW_SECONDS are grouped.
     ─ When a group reaches THRESHOLD_ALERTS alerts, an Incident is created/updated.

  2. Sequence-based correlation (attack chain matching)
     ─ Recognises known multi-stage attack patterns (MITRE ATT&CK kill-chain).
     ─ If a sequence of event_types from the same source_ip is observed within
       CHAIN_WINDOW_SECONDS, an Incident is escalated with a named tactic chain.

Incidents are stored in MongoDB collection "incidents".

Public API
───────────
  correlator.process(alert_doc)     dict → IncidentUpdate | None
  correlator.get_or_create_incident(…) → str (incident_id)
"""

from __future__ import annotations
import uuid
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

# ── Config ────────────────────────────────────────────────────────────────────

WINDOW_SECONDS       = 300    # 5-minute sliding window for IP grouping
CHAIN_WINDOW_SECONDS = 600    # 10-minute window for sequence matching
THRESHOLD_ALERTS     = 3      # alerts from same IP before incident fires


# ── Attack chain definitions ──────────────────────────────────────────────────
# Each chain is: (ordered sequence of event_types, incident_title, tactic, severity)
# The sequence doesn't have to be strictly ordered — a sliding set check is used.

@dataclass
class AttackChain:
    name: str
    event_sequence: list[str]     # event_types that must ALL appear
    incident_title: str
    tactic: str
    severity: str                  # override severity for the incident
    require_order: bool = False    # if True, events must appear in listed order


ATTACK_CHAINS: list[AttackChain] = [

    AttackChain(
        name="Reconnaissance → Exploitation",
        event_sequence=["PORT_SCAN", "AUTH_FAILURE"],
        incident_title="Reconnaissance followed by Authentication Attack",
        tactic="Initial Access",
        severity="HIGH",
    ),

    AttackChain(
        name="Credential Brute-Force → Lateral Movement",
        event_sequence=["BRUTE_FORCE", "AUTH_SUCCESS", "LATERAL_MOVEMENT"],
        incident_title="Brute-Force Leading to Lateral Movement",
        tactic="Lateral Movement",
        severity="CRITICAL",
        require_order=True,
    ),

    AttackChain(
        name="Privilege Escalation → Exfiltration",
        event_sequence=["PRIVILEGE_ESCALATION", "DATA_EXFILTRATION"],
        incident_title="Privilege Escalation Followed by Data Exfiltration",
        tactic="Exfiltration",
        severity="CRITICAL",
        require_order=True,
    ),

    AttackChain(
        name="Malware → C2",
        event_sequence=["MALWARE_DETECTED", "DNS_ANOMALY"],
        incident_title="Malware Detected with Suspected C2 Channel",
        tactic="Command and Control",
        severity="CRITICAL",
    ),

    AttackChain(
        name="Scanning Storm",
        event_sequence=["PORT_SCAN", "PORT_SCAN", "PORT_SCAN"],
        incident_title="Sustained Port Scanning Campaign",
        tactic="Discovery",
        severity="HIGH",
    ),

    AttackChain(
        name="Authentication Storm",
        event_sequence=["AUTH_FAILURE", "AUTH_FAILURE", "AUTH_FAILURE"],
        incident_title="Brute-Force Credential Attack",
        tactic="Credential Access",
        severity="HIGH",
    ),
]


# ── In-memory sliding window per source_ip ────────────────────────────────────

@dataclass
class IPContext:
    """Track recent alerts and event_types for a given source_ip."""
    alerts:      deque = field(default_factory=lambda: deque(maxlen=200))
    event_times: deque = field(default_factory=lambda: deque(maxlen=200))
    # (timestamp, event_type) pairs for sequence matching


class _WindowStore:
    """Thread-safe-ish sliding window keyed by source_ip."""

    def __init__(self):
        self._store: dict[str, IPContext] = defaultdict(IPContext)

    def add(self, source_ip: str, alert_doc: dict):
        ctx = self._store[source_ip]
        now = datetime.now(timezone.utc)
        ctx.alerts.append((now, alert_doc))
        et = alert_doc.get("event_type") or alert_doc.get("rule_id", "UNKNOWN")
        ctx.event_times.append((now, et))

    def recent_alerts(self, source_ip: str) -> list[dict]:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=WINDOW_SECONDS)
        ctx = self._store.get(source_ip)
        if not ctx:
            return []
        return [a for ts, a in ctx.alerts if ts >= cutoff]

    def recent_events(self, source_ip: str) -> list[tuple[datetime, str]]:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=CHAIN_WINDOW_SECONDS)
        ctx = self._store.get(source_ip)
        if not ctx:
            return []
        return [(ts, et) for ts, et in ctx.event_times if ts >= cutoff]

    def clear_old(self):
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=CHAIN_WINDOW_SECONDS * 2)
        for ip, ctx in list(self._store.items()):
            while ctx.alerts and ctx.alerts[0][0] < cutoff:
                ctx.alerts.popleft()
            while ctx.event_times and ctx.event_times[0][0] < cutoff:
                ctx.event_times.popleft()


# ── Incident / IncidentUpdate DTOs ────────────────────────────────────────────

@dataclass
class IncidentUpdate:
    incident_id: str
    title: str
    severity: str
    tactic: str
    source_ip: str
    alert_count: int
    chain_name: Optional[str]
    status: str       # "new" | "updated"
    alert_ids: list[str]
    first_seen: datetime
    last_seen: datetime


# ── Correlator ────────────────────────────────────────────────────────────────

class CorrelationEngine:

    def __init__(self):
        self._window = _WindowStore()
        # Track active incidents per source_ip to avoid duplicates
        self._active_incidents: dict[str, str] = {}   # source_ip → incident_id

    # ── Main entry point ──────────────────────────────────────────────────────

    def process(self, alert_doc: dict) -> Optional[IncidentUpdate]:
        """
        Receive a single alert and return an IncidentUpdate if a correlation
        rule fires, or None if the alert is isolated.
        """
        source_ip = alert_doc.get("source_ip") or "UNKNOWN"
        self._window.add(source_ip, alert_doc)
        self._window.clear_old()

        # 1. Check sequence-based attack chains first (higher signal)
        chain_result = self._check_chains(source_ip, alert_doc)
        if chain_result:
            return chain_result

        # 2. Threshold-based: enough alerts from same IP in window?
        threshold_result = self._check_threshold(source_ip, alert_doc)
        return threshold_result

    # ── Chain matching ────────────────────────────────────────────────────────

    def _check_chains(self, source_ip: str, alert_doc: dict) -> Optional[IncidentUpdate]:
        recent = self.recent_events(source_ip)
        event_list = [et for _, et in recent]

        for chain in ATTACK_CHAINS:
            if self._chain_matches(chain, event_list):
                inc_key = f"{source_ip}:{chain.name}"
                incident_id = self._active_incidents.get(inc_key) or str(uuid.uuid4())
                status = "updated" if inc_key in self._active_incidents else "new"
                self._active_incidents[inc_key] = incident_id

                recent_alerts = self._window.recent_alerts(source_ip)
                alert_ids = [a.get("id", a.get("_id", "")) for a in recent_alerts]

                return IncidentUpdate(
                    incident_id=incident_id,
                    title=chain.incident_title,
                    severity=chain.severity,
                    tactic=chain.tactic,
                    source_ip=source_ip,
                    alert_count=len(recent_alerts),
                    chain_name=chain.name,
                    status=status,
                    alert_ids=[str(a) for a in alert_ids if a],
                    first_seen=recent[0][0] if recent else datetime.now(timezone.utc),
                    last_seen=recent[-1][0] if recent else datetime.now(timezone.utc),
                )
        return None

    @staticmethod
    def _chain_matches(chain: AttackChain, event_list: list[str]) -> bool:
        seq = chain.event_sequence
        if chain.require_order:
            # Subsequence check (order-preserving)
            it = iter(event_list)
            return all(et in it for et in seq)
        else:
            # Multiset check: every event in seq must appear at least that many times
            from collections import Counter
            needed  = Counter(seq)
            present = Counter(event_list)
            return all(present[et] >= count for et, count in needed.items())

    # ── Threshold matching ────────────────────────────────────────────────────

    def _check_threshold(self, source_ip: str, alert_doc: dict) -> Optional[IncidentUpdate]:
        recent_alerts = self._window.recent_alerts(source_ip)
        if len(recent_alerts) < THRESHOLD_ALERTS:
            return None

        inc_key = f"{source_ip}:threshold"
        incident_id = self._active_incidents.get(inc_key) or str(uuid.uuid4())
        status = "updated" if inc_key in self._active_incidents else "new"
        self._active_incidents[inc_key] = incident_id

        # Determine severity from the most severe alert in the window
        sev_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        max_sev = max(
            (a.get("severity", "LOW") for a in recent_alerts),
            key=lambda s: sev_order.get(s, 0),
            default="MEDIUM",
        )

        alert_ids = [str(a.get("id", a.get("_id", ""))) for a in recent_alerts]
        times = [a.get("timestamp") or datetime.now(timezone.utc) for a in recent_alerts]
        times = [t if isinstance(t, datetime) else datetime.now(timezone.utc) for t in times]

        return IncidentUpdate(
            incident_id=incident_id,
            title=f"Multiple Alerts from {source_ip} ({len(recent_alerts)} in 5 min)",
            severity=max_sev,
            tactic="Multi-Stage Attack",
            source_ip=source_ip,
            alert_count=len(recent_alerts),
            chain_name=None,
            status=status,
            alert_ids=[a for a in alert_ids if a],
            first_seen=min(times),
            last_seen=max(times),
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    def recent_events(self, source_ip: str) -> list[tuple[datetime, str]]:
        return self._window.recent_events(source_ip)

    def active_incident_count(self) -> int:
        return len(self._active_incidents)


# ── Singleton ─────────────────────────────────────────────────────────────────

correlator = CorrelationEngine()
