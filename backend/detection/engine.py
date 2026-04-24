"""
Secuintell Detection Engine
============================
Three-layer security intelligence pipeline:
  1. Rule-Based Detection  — pattern matching → severity tiers
  2. Anomaly Detection     — Isolation Forest (scikit-learn)
  3. Correlation Engine    — chains related events into incidents
"""

from __future__ import annotations

import re
import uuid
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)s]  %(name)s — %(message)s",
)
log = logging.getLogger("secuintell")


# ===========================================================================
# SHARED DATA MODELS
# ===========================================================================

class Severity(str, Enum):
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def score(self) -> int:
        return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}[self.value]


@dataclass
class LogEvent:
    """Normalised representation of a single log line."""
    raw: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    source_ip: str = "0.0.0.0"
    dest_ip: str = "0.0.0.0"
    user: str = ""
    event_type: str = "generic"
    # Filled in by the pipeline stages
    rule_matches: list[str] = field(default_factory=list)
    severity: Severity = Severity.INFO
    anomaly_score: float = 0.0
    is_anomaly: bool = False
    incident_id: str | None = None

    @property
    def event_id(self) -> str:
        digest = hashlib.md5(
            f"{self.timestamp}{self.raw}{self.source_ip}".encode()
        ).hexdigest()[:12]
        return f"EVT-{digest.upper()}"


@dataclass
class Incident:
    """A cluster of correlated events that together describe a security incident."""
    incident_id: str = field(default_factory=lambda: f"INC-{uuid.uuid4().hex[:8].upper()}")
    title: str = ""
    severity: Severity = Severity.INFO
    events: list[LogEvent] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    tags: list[str] = field(default_factory=list)
    summary: str = ""

    @property
    def event_count(self) -> int:
        return len(self.events)

    @property
    def source_ips(self) -> set[str]:
        return {e.source_ip for e in self.events}

    @property
    def affected_users(self) -> set[str]:
        return {e.user for e in self.events if e.user}

    def upgrade_severity(self, new_sev: Severity) -> None:
        if new_sev.score > self.severity.score:
            self.severity = new_sev
            self.updated_at = datetime.utcnow()


# ===========================================================================
# STAGE 1 — RULE-BASED DETECTION
# ===========================================================================

@dataclass
class DetectionRule:
    name: str
    pattern: re.Pattern
    severity: Severity
    event_type: str
    tags: list[str] = field(default_factory=list)
    description: str = ""


# Master rule catalogue  ─────────────────────────────────────────────────────
_RULE_DEFINITIONS: list[tuple] = [
    # (name, regex_pattern, severity, event_type, tags, description)

    # ── CRITICAL ──────────────────────────────────────────────────────────
    ("SQL_INJECTION",
     r"(?i)(\bunion\b.+\bselect\b|select.+from.+where|drop\s+table|insert\s+into|exec\s*\(|xp_cmdshell)",
     Severity.CRITICAL, "web_attack",
     ["injection", "database"],
     "SQL injection attempt detected in request"),

    ("REMOTE_CODE_EXEC",
     r"(?i)(cmd\.exe|/bin/sh|/bin/bash|powershell|wget\s+http|curl\s+http.*\|\s*sh|eval\(base64)",
     Severity.CRITICAL, "rce",
     ["rce", "command_execution"],
     "Remote code execution pattern detected"),

    ("PRIVILEGE_ESCALATION",
     r"(?i)(sudo\s+su|sudo\s+-i|chmod\s+[74][74][74]|chown\s+root|passwd\s+root|visudo)",
     Severity.CRITICAL, "privilege_escalation",
     ["privesc", "lateral_movement"],
     "Privilege escalation attempt"),

    ("DATA_EXFILTRATION",
     r"(?i)(SELECT.{0,50}INTO\s+OUTFILE|mysqldump|pg_dump|exfil|base64.*\|\s*nc\s)",
     Severity.CRITICAL, "data_exfiltration",
     ["exfiltration", "data_loss"],
     "Possible data exfiltration in progress"),

    ("RANSOMWARE_INDICATOR",
     r"(?i)(\.encrypt|vssadmin\s+delete|bcdedit\s+\/set|wbadmin\s+delete|shadow\s+copy|ransom)",
     Severity.CRITICAL, "ransomware",
     ["ransomware", "malware"],
     "Ransomware behavioural indicator"),

    # ── HIGH ──────────────────────────────────────────────────────────────
    ("BRUTE_FORCE_SSH",
     r"(?i)(failed\s+password|authentication\s+failure|invalid\s+user).{0,80}(ssh|sshd)",
     Severity.HIGH, "brute_force",
     ["brute_force", "ssh"],
     "SSH brute-force attempt"),

    ("BRUTE_FORCE_WEB",
     r"(?i)(failed\s+login|invalid\s+credentials|too\s+many\s+attempts|account\s+locked)",
     Severity.HIGH, "brute_force",
     ["brute_force", "web"],
     "Web application brute-force attempt"),

    ("PORT_SCAN",
     r"(?i)(nmap|masscan|port\s+scan|syn\s+scan|connect\s+scan|SYN_SENT.{0,30}\d{1,5}\s+ports?)",
     Severity.HIGH, "reconnaissance",
     ["recon", "port_scan"],
     "Port scanning activity detected"),

    ("XSS_ATTACK",
     r"(?i)(<script[\s>]|javascript:|on(load|error|click|mouseover)\s*=|alert\s*\(|document\.cookie)",
     Severity.HIGH, "web_attack",
     ["xss", "injection"],
     "Cross-site scripting (XSS) attempt"),

    ("MALWARE_BEACON",
     r"(?i)(c2\s|command.and.control|beaconing|reverse\s+shell|meterpreter|cobalt\s+strike)",
     Severity.HIGH, "malware",
     ["c2", "malware"],
     "Malware C2 beaconing indicator"),

    ("DIRECTORY_TRAVERSAL",
     r"(?i)(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%252e%252e%252f)",
     Severity.HIGH, "web_attack",
     ["traversal", "lfi"],
     "Directory traversal attempt"),

    # ── MEDIUM ────────────────────────────────────────────────────────────
    ("SUSPICIOUS_USER_AGENT",
     r"(?i)(sqlmap|nikto|nessus|burpsuite|metasploit|w3af|acunetix|nmap|zgrab|python-requests/2\.)",
     Severity.MEDIUM, "reconnaissance",
     ["recon", "scanner"],
     "Known security scanner user-agent"),

    ("LARGE_OUTBOUND_TRANSFER",
     r"(?i)(bytes_sent\s*[=:]\s*[1-9]\d{6,}|transferred\s+\d{7,}\s+bytes|upload.{0,20}\d{3,}\s*[MG]B)",
     Severity.MEDIUM, "data_loss",
     ["exfiltration", "bandwidth"],
     "Unusually large outbound data transfer"),

    ("CONFIG_FILE_ACCESS",
     r"(?i)(\/etc\/passwd|\/etc\/shadow|web\.config|\.env\b|id_rsa|\.htpasswd|credentials\.json)",
     Severity.MEDIUM, "file_access",
     ["sensitive_file", "credential_access"],
     "Access to sensitive configuration file"),

    ("NEW_ADMIN_ACCOUNT",
     r"(?i)(useradd|adduser|net\s+user\s+\S+\s+\/add|New-LocalUser|created\s+admin\s+account)",
     Severity.MEDIUM, "account_manipulation",
     ["persistence", "account_creation"],
     "New administrative account created"),

    ("TOR_EXIT_NODE",
     r"(?i)(tor\s+exit|\.onion|torproject|tor2web)",
     Severity.MEDIUM, "network",
     ["anonymisation", "tor"],
     "Traffic via Tor exit node detected"),

    # ── LOW ───────────────────────────────────────────────────────────────
    ("AUTH_SUCCESS_OFF_HOURS",
     r"(?i)(accepted\s+password|login\s+successful|session\s+opened).{0,120}"
     r"(0[01]\d:\d\d|2[2-3]\d:\d\d)",
     Severity.LOW, "authentication",
     ["off_hours", "anomalous_login"],
     "Successful auth outside business hours"),

    ("FIREWALL_DENY",
     r"(?i)(firewall\s+deny|acl\s+deny|packet\s+dropped|connection\s+refused\s+by\s+policy)",
     Severity.LOW, "network",
     ["firewall"],
     "Firewall deny rule triggered"),

    ("SERVICE_RESTART",
     r"(?i)(service\s+restart|systemctl\s+restart|service\s+\S+\s+stop|killed\s+process)",
     Severity.LOW, "system",
     ["availability"],
     "Unexpected service restart"),

    # ── INFO ──────────────────────────────────────────────────────────────
    ("USER_LOGOUT",
     r"(?i)(logout|log\s*out|session\s+closed|disconnected\s+from)",
     Severity.INFO, "authentication",
     ["normal"],
     "Normal user logout"),

    ("HEALTH_CHECK",
     r"(?i)(health.?check|keep.?alive|ping|uptime\s+check)",
     Severity.INFO, "monitoring",
     ["normal"],
     "Monitoring health-check"),
]


class RuleBasedDetector:
    """
    Compiles regex rules and matches them against raw log lines.
    Assigns the *highest* matching severity tier to the event.
    Multiple rules may match; all are recorded in ``event.rule_matches``.
    """

    def __init__(self, extra_rules: list[DetectionRule] | None = None):
        self.rules: list[DetectionRule] = []
        for name, pat, sev, etype, tags, desc in _RULE_DEFINITIONS:
            self.rules.append(DetectionRule(
                name=name,
                pattern=re.compile(pat),
                severity=sev,
                event_type=etype,
                tags=tags,
                description=desc,
            ))
        if extra_rules:
            self.rules.extend(extra_rules)
        log.info("RuleBasedDetector: loaded %d rules", len(self.rules))

    def analyze(self, event: LogEvent) -> LogEvent:
        """Mutates *event* in place; returns the same object for chaining."""
        matched_severity = Severity.INFO
        for rule in self.rules:
            if rule.pattern.search(event.raw):
                event.rule_matches.append(rule.name)
                if rule.severity.score > matched_severity.score:
                    matched_severity = rule.severity
                    event.event_type = rule.event_type
        event.severity = matched_severity
        return event

    def analyze_batch(self, events: list[LogEvent]) -> list[LogEvent]:
        return [self.analyze(e) for e in events]


# ===========================================================================
# STAGE 2 — ISOLATION FOREST ANOMALY DETECTION
# ===========================================================================

def _extract_features(event: LogEvent) -> list[float]:
    """
    Turn a LogEvent into a numeric feature vector:
      [0] hour of day (0–23)
      [1] log message length
      [2] number of digits in raw log
      [3] number of '/' path separators
      [4] number of special chars (!@#$%^&*;|<>)
      [5] HTTP status code bucket (0=none, 1=2xx, 2=3xx, 3=4xx, 4=5xx)
      [6] byte count extracted from log (0 if absent)
      [7] number of dots in IP-like patterns
      [8] rule severity score (0–4)
      [9] number of rule matches
    """
    raw = event.raw
    hour  = event.timestamp.hour
    length = len(raw)
    digits = sum(c.isdigit() for c in raw)
    slashes = raw.count("/")
    specials = sum(raw.count(c) for c in "!@#$%^&*;|<>")

    status_bucket = 0
    m = re.search(r"\b([2-5]\d{2})\b", raw)
    if m:
        code = int(m.group(1))
        if 200 <= code < 300:   status_bucket = 1
        elif 300 <= code < 400: status_bucket = 2
        elif 400 <= code < 500: status_bucket = 3
        else:                   status_bucket = 4

    byte_count = 0.0
    bm = re.search(r"(\d+)\s*bytes?", raw, re.IGNORECASE)
    if bm:
        byte_count = float(bm.group(1))

    dots = raw.count(".")
    rule_score  = event.severity.score
    rule_count  = len(event.rule_matches)

    return [hour, length, digits, slashes, specials,
            status_bucket, byte_count, dots, rule_score, rule_count]


class AnomalyDetector:
    """
    Wraps scikit-learn's IsolationForest.
    Call ``fit()`` once on a representative baseline corpus,
    then ``score_batch()`` on new events.
    """

    FEATURE_NAMES = [
        "hour_of_day", "log_length", "digit_count", "slash_count",
        "special_char_count", "http_status_bucket", "byte_count",
        "dot_count", "rule_severity_score", "rule_match_count",
    ]

    def __init__(
        self,
        contamination: float = 0.05,
        n_estimators: int = 200,
        random_state: int = 42,
    ):
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
        )
        self.scaler = StandardScaler()
        self._fitted = False

    def fit(self, events: list[LogEvent]) -> "AnomalyDetector":
        if not events:
            raise ValueError("Cannot fit on an empty event list.")
        X = np.array([_extract_features(e) for e in events])
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self._fitted = True
        log.info(
            "AnomalyDetector: fitted on %d events  (contamination=%.2f)",
            len(events), self.model.contamination,
        )
        return self

    def score_batch(self, events: list[LogEvent]) -> list[LogEvent]:
        """
        Annotates events with:
          - ``anomaly_score``  (−1 = most anomalous, +1 = most normal)
          - ``is_anomaly``     (True when IF predicts −1)
        """
        if not self._fitted:
            raise RuntimeError("Call fit() before score_batch().")
        if not events:
            return events

        X = np.array([_extract_features(e) for e in events])
        X_scaled = self.scaler.transform(X)
        scores    = self.model.decision_function(X_scaled)   # raw IF scores
        preds     = self.model.predict(X_scaled)             # +1 or -1

        for event, score, pred in zip(events, scores, preds):
            event.anomaly_score = float(round(score, 4))
            event.is_anomaly    = bool(pred == -1)
            # Promote severity when IF flags anomaly + rule says ≥ HIGH
            if event.is_anomaly and event.severity.score >= Severity.HIGH.score:
                event.severity = Severity.CRITICAL
        return events


# ===========================================================================
# STAGE 3 — CORRELATION ENGINE
# ===========================================================================

class CorrelationEngine:
    """
    Groups related events into Incidents using three correlation strategies:

    1. **IP-based grouping**     — events sharing a source IP within a time window
    2. **Attack-chain chaining** — events whose rule tags suggest a MITRE-style
                                   attack progression (recon → exploit → exfil)
    3. **Anomaly clustering**    — flagged anomalies that fire within a tight window
                                   are coalesced into a single incident regardless of IP

    Configuration
    -------------
    ip_window_minutes       : max time gap between events for IP correlation
    chain_window_minutes    : max time gap for attack-chain correlation
    anomaly_window_seconds  : max time gap for anomaly clustering
    min_events_for_incident : events needed before an IP group becomes an incident
    """

    # MITRE ATT&CK-inspired progression chains
    # A sequence is a list of tag-sets; each element matches ≥ 1 tag.
    ATTACK_CHAINS: list[tuple[str, list[set[str]]]] = [
        ("Recon-to-Compromise",
         [{"recon", "port_scan"}, {"brute_force", "web_attack"}, {"rce", "injection"}]),

        ("Credential-Stuffing-to-Lateral-Movement",
         [{"brute_force"}, {"credential_access", "sensitive_file"}, {"lateral_movement", "privesc"}]),

        ("Exfiltration-Campaign",
         [{"recon"}, {"data_loss", "exfiltration"}, {"bandwidth", "exfiltration"}]),

        ("Ransomware-Kill-Chain",
         [{"recon"}, {"brute_force", "rce"}, {"persistence", "account_creation"}, {"ransomware"}]),
    ]

    def __init__(
        self,
        ip_window_minutes: int = 15,
        chain_window_minutes: int = 60,
        anomaly_window_seconds: int = 120,
        min_events_for_incident: int = 2,
    ):
        self.ip_window     = timedelta(minutes=ip_window_minutes)
        self.chain_window  = timedelta(minutes=chain_window_minutes)
        self.anomaly_window = timedelta(seconds=anomaly_window_seconds)
        self.min_events    = min_events_for_incident
        self._open_incidents: dict[str, Incident] = {}

    # ── helpers ──────────────────────────────────────────────────────────

    def _tags_for(self, event: LogEvent) -> set[str]:
        rule_map: dict[str, list[str]] = {r.name: r.tags for r in []}
        # Use the global rule catalogue tags via rule_matches
        all_tags: set[str] = set()
        for rule_def in _RULE_DEFINITIONS:
            name, _, _, _, tags, _ = rule_def
            if name in event.rule_matches:
                all_tags.update(tags)
        return all_tags

    def _best_severity(self, events: list[LogEvent]) -> Severity:
        best = Severity.INFO
        for e in events:
            if e.severity.score > best.score:
                best = e.severity
        return best

    def _make_incident(
        self,
        events: list[LogEvent],
        title: str,
        tags: list[str],
        summary: str,
    ) -> Incident:
        sev = self._best_severity(events)
        inc = Incident(
            title=title,
            severity=sev,
            events=list(events),
            tags=tags,
            summary=summary,
        )
        for e in events:
            e.incident_id = inc.incident_id
        return inc

    # ── strategy 1 : IP-based grouping ───────────────────────────────────

    def _correlate_by_ip(self, events: list[LogEvent]) -> list[Incident]:
        incidents: list[Incident] = []
        by_ip: dict[str, list[LogEvent]] = {}
        for e in events:
            by_ip.setdefault(e.source_ip, []).append(e)

        for ip, ip_events in by_ip.items():
            if ip in ("0.0.0.0", "127.0.0.1"):
                continue
            ip_events.sort(key=lambda e: e.timestamp)
            # Slide a time window
            window: list[LogEvent] = []
            for e in ip_events:
                if window and (e.timestamp - window[0].timestamp) > self.ip_window:
                    if len(window) >= self.min_events:
                        incidents.append(self._make_incident(
                            window,
                            title=f"Multi-event activity from {ip}",
                            tags=["ip_correlation"],
                            summary=(
                                f"{len(window)} events from {ip} within "
                                f"{self.ip_window.seconds // 60} min window."
                            ),
                        ))
                    window = []
                window.append(e)
            if len(window) >= self.min_events:
                incidents.append(self._make_incident(
                    window,
                    title=f"Multi-event activity from {ip}",
                    tags=["ip_correlation"],
                    summary=(
                        f"{len(window)} events from {ip} within "
                        f"{self.ip_window.seconds // 60} min window."
                    ),
                ))
        return incidents

    # ── strategy 2 : attack-chain chaining ───────────────────────────────

    def _correlate_attack_chains(self, events: list[LogEvent]) -> list[Incident]:
        incidents: list[Incident] = []
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        for chain_name, stage_tags in self.ATTACK_CHAINS:
            matched_stages: list[list[LogEvent]] = [[] for _ in stage_tags]

            for event in sorted_events:
                etags = self._tags_for(event)
                for i, required_tags in enumerate(stage_tags):
                    if etags & required_tags:
                        matched_stages[i].append(event)

            # Require all stages to have ≥ 1 match
            if not all(matched_stages):
                continue

            # Flatten events in chronological order; check they span ≤ chain_window
            chain_events = [e for stage in matched_stages for e in stage]
            chain_events.sort(key=lambda e: e.timestamp)
            span = chain_events[-1].timestamp - chain_events[0].timestamp
            if span > self.chain_window:
                continue

            incidents.append(self._make_incident(
                chain_events,
                title=chain_name,
                tags=["attack_chain", chain_name.lower().replace(" ", "_")],
                summary=(
                    f"Attack chain '{chain_name}' detected across {len(chain_events)} "
                    f"events spanning {int(span.total_seconds())}s."
                ),
            ))

        return incidents

    # ── strategy 3 : anomaly clustering ──────────────────────────────────

    def _correlate_anomalies(self, events: list[LogEvent]) -> list[Incident]:
        incidents: list[Incident] = []
        anomalies = sorted(
            [e for e in events if e.is_anomaly],
            key=lambda e: e.timestamp,
        )
        if len(anomalies) < self.min_events:
            return incidents

        cluster: list[LogEvent] = [anomalies[0]]
        for e in anomalies[1:]:
            if (e.timestamp - cluster[-1].timestamp) <= self.anomaly_window:
                cluster.append(e)
            else:
                if len(cluster) >= self.min_events:
                    incidents.append(self._make_incident(
                        cluster,
                        title="Anomaly Burst",
                        tags=["anomaly", "isolation_forest"],
                        summary=(
                            f"Cluster of {len(cluster)} anomalous events within "
                            f"{self.anomaly_window.seconds}s window."
                        ),
                    ))
                cluster = [e]

        if len(cluster) >= self.min_events:
            incidents.append(self._make_incident(
                cluster,
                title="Anomaly Burst",
                tags=["anomaly", "isolation_forest"],
                summary=(
                    f"Cluster of {len(cluster)} anomalous events within "
                    f"{self.anomaly_window.seconds}s window."
                ),
            ))

        return incidents

    # ── public API ────────────────────────────────────────────────────────

    def correlate(self, events: list[LogEvent]) -> list[Incident]:
        """
        Run all three correlation strategies.
        De-duplicates events that appear in multiple incidents by
        keeping only the first assignment (earliest incident wins).
        """
        all_incidents: list[Incident] = []
        all_incidents += self._correlate_by_ip(events)
        all_incidents += self._correlate_attack_chains(events)
        all_incidents += self._correlate_anomalies(events)

        # De-duplicate: each event can only belong to ONE incident
        seen_event_ids: set[str] = set()
        deduped: list[Incident] = []
        for inc in sorted(all_incidents, key=lambda i: i.severity.score, reverse=True):
            unique_events = [e for e in inc.events if e.event_id not in seen_event_ids]
            if not unique_events:
                continue
            seen_event_ids.update(e.event_id for e in unique_events)
            inc.events = unique_events
            deduped.append(inc)

        log.info("CorrelationEngine: generated %d incidents from %d events",
                 len(deduped), len(events))
        return deduped


# ===========================================================================
# PIPELINE ORCHESTRATOR
# ===========================================================================

class SecuintellPipeline:
    """
    Drives all three stages end-to-end.

    Usage
    -----
    pipeline = SecuintellPipeline()
    pipeline.fit_anomaly_detector(baseline_events)
    incidents = pipeline.run(new_events)
    """

    def __init__(
        self,
        extra_rules: list[DetectionRule] | None = None,
        contamination: float = 0.05,
        ip_window_minutes: int = 15,
        chain_window_minutes: int = 60,
        anomaly_window_seconds: int = 120,
        min_events_for_incident: int = 2,
    ):
        self.rule_detector = RuleBasedDetector(extra_rules=extra_rules)
        self.anomaly_detector = AnomalyDetector(contamination=contamination)
        self.correlation_engine = CorrelationEngine(
            ip_window_minutes=ip_window_minutes,
            chain_window_minutes=chain_window_minutes,
            anomaly_window_seconds=anomaly_window_seconds,
            min_events_for_incident=min_events_for_incident,
        )
        self._baseline_fitted = False

    def fit_anomaly_detector(self, baseline_events: list[LogEvent]) -> "SecuintellPipeline":
        # Run rules first so features include rule context
        self.rule_detector.analyze_batch(baseline_events)
        self.anomaly_detector.fit(baseline_events)
        self._baseline_fitted = True
        return self

    def run(
        self,
        events: list[LogEvent],
        auto_fit: bool = True,
    ) -> tuple[list[LogEvent], list[Incident]]:
        """
        Full three-stage pipeline.

        Parameters
        ----------
        events    : raw ``LogEvent`` objects (only ``.raw`` and ``.timestamp``
                    need to be populated; the rest is filled in)
        auto_fit  : if True and the anomaly detector is not yet fitted,
                    fit it on the incoming batch (useful for first run)

        Returns
        -------
        (enriched_events, incidents)
        """
        # Stage 1 — rule-based detection
        log.info("Stage 1 — Rule-based detection on %d events", len(events))
        events = self.rule_detector.analyze_batch(events)

        # Stage 2 — anomaly detection
        if not self._baseline_fitted:
            if auto_fit:
                log.warning(
                    "Anomaly detector not fitted; fitting on current batch "
                    "(contamination=%.2f). Provide a baseline for best results.",
                    self.anomaly_detector.model.contamination,
                )
                self.anomaly_detector.fit(events)
                self._baseline_fitted = True
            else:
                log.warning("Anomaly detector not fitted; skipping Stage 2.")
        if self._baseline_fitted:
            log.info("Stage 2 — Anomaly scoring on %d events", len(events))
            events = self.anomaly_detector.score_batch(events)

        # Stage 3 — correlation
        log.info("Stage 3 — Correlating events into incidents")
        incidents = self.correlation_engine.correlate(events)

        return events, incidents


# ===========================================================================
# DETECTION ENGINE — API adapter (glue between pipeline and FastAPI routes)
# ===========================================================================

from dataclasses import dataclass as _dc, field as _field
from datetime import timezone as _tz
from bson import ObjectId as _ObjId


@_dc
class AnalysisResult:
    """Return value of DetectionEngine.analyze()."""
    log_id:           str
    rule_matches:     list
    top_severity:     str | None
    is_anomalous:     bool
    anomaly_score:    float
    anomaly_pct:      float
    anomaly_features: dict
    incident:         object | None   # has .incident_id and .title if set
    alert_id:         str | None
    processed_at:     datetime


class DetectionEngine:
    """
    High-level façade used by routes/detection.py.
    Wraps RuleBasedDetector + AnomalyDetector + CorrelationEngine.
    """

    def __init__(self):
        self._rules   = RuleBasedDetector()
        self._anomaly = AnomalyDetector()
        self._corr    = CorrelationEngine()
        self._fitted  = False

    # ── helpers ──────────────────────────────────────────────────────────────

    @staticmethod
    def _log_to_event(log: dict) -> LogEvent:
        """Convert a MongoDB log document to a LogEvent."""
        return LogEvent(
            raw=log.get("message", ""),
            timestamp=log.get("timestamp", datetime.utcnow()),
            source_ip=log.get("source_ip", "0.0.0.0"),
            dest_ip=log.get("destination_ip", "0.0.0.0"),
            user=log.get("user", ""),
            event_type=log.get("event_type", "generic"),
        )

    # ── public API ───────────────────────────────────────────────────────────

    def analyze(self, log: dict, *, db) -> AnalysisResult:
        """
        Run the full 3-stage pipeline on a single log document and
        persist the resulting alert (and any incident) to MongoDB.
        """
        now = datetime.now(_tz.utc)
        log_id = str(log.get("_id", ""))

        # Stage 1 — rule matching
        event = self._log_to_event(log)
        self._rules.analyze(event)

        # Stage 2 — anomaly scoring (skip gracefully if not fitted)
        anomaly_score   = 0.0
        anomaly_pct     = 0.0
        anomaly_features: dict = {}
        is_anomalous    = False
        if self._fitted:
            scored = self._anomaly.score_batch([event])
            event  = scored[0]
            anomaly_score = getattr(event, "anomaly_score", 0.0)
            is_anomalous  = getattr(event, "is_anomaly",    False)
            anomaly_pct   = round(max(0.0, min(1.0, (anomaly_score + 0.5))), 4)

        # Stage 3 — correlation (incident chaining)
        incidents = self._corr.correlate([event])
        incident  = incidents[0] if incidents else None

        # Persist alert to MongoDB
        top_sev = event.severity.value if event.severity else None
        alert_doc = {
            "log_id":           log_id,
            "source_ip":        log.get("source_ip"),
            "hostname":         log.get("hostname"),
            "user":             log.get("user"),
            "event_type":       log.get("event_type"),
            "message":          log.get("message", ""),
            "timestamp":        log.get("timestamp", now),
            "severity":         top_sev,
            "rule_matches":     [{"rule_id": r, "rule_name": r, "severity": top_sev,
                                  "tactic": "unknown", "technique": "unknown"}
                                 for r in event.rule_matches],
            "is_anomalous":     is_anomalous,
            "anomaly_score":    anomaly_score,
            "anomaly_pct":      anomaly_pct,
            "anomaly_features": anomaly_features,
            "status":           "open",
            "created_at":       now,
        }
        inserted = db["alerts"].insert_one(alert_doc)
        alert_id = str(inserted.inserted_id)

        # Persist incident if one was produced
        if incident:
            inc_doc = {
                "incident_id":  incident.incident_id,
                "title":        incident.title,
                "severity":     incident.severity.value if incident.severity else top_sev,
                "tactic":       getattr(incident, "tactic", "unknown"),
                "source_ip":    incident.source_ips.pop() if incident.source_ips else log.get("source_ip", ""),
                "alert_count":  incident.event_count,
                "chain_name":   getattr(incident, "chain_name", None),
                "status":       "open",
                "alert_ids":    [alert_id],
                "first_seen":   incident.first_seen,
                "last_seen":    incident.last_seen,
                "created_at":   now,
            }
            db["incidents"].update_one(
                {"incident_id": incident.incident_id},
                {"$set": inc_doc, "$addToSet": {"alert_ids": alert_id}},
                upsert=True,
            )

        return AnalysisResult(
            log_id=log_id,
            rule_matches=event.rule_matches,
            top_severity=top_sev,
            is_anomalous=is_anomalous,
            anomaly_score=anomaly_score,
            anomaly_pct=anomaly_pct,
            anomaly_features=anomaly_features,
            incident=incident,
            alert_id=alert_id,
            processed_at=now,
        )

    def train_anomaly_model(self, db) -> dict:
        """Load all logs from MongoDB and (re)train the Isolation Forest."""
        logs = list(db["logs"].find({}, {"_id": 0}))
        if len(logs) < 50:
            return {
                "status": "skipped",
                "reason": f"Need ≥ 50 logs to train; only {len(logs)} found.",
                "samples": len(logs),
            }
        events = [self._log_to_event(l) for l in logs]
        self._anomaly.fit(events)
        self._fitted = True
        return {"status": "trained", "samples": len(events)}


# Module-level singleton used by routes/detection.py
detection_engine = DetectionEngine()
