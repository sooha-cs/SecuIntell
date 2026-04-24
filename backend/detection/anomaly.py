"""
Anomaly Detection — Isolation Forest
──────────────────────────────────────
Feature vector extracted from each log:

  [0] hour_of_day          0-23
  [1] day_of_week          0-6  (Mon=0)
  [2] level_score          INFO=0 WARNING=1 ERROR=2 CRITICAL=3
  [3] src_ip_first_octet   0-255 (0 if absent)
  [4] src_ip_last_octet    0-255
  [5] is_privileged_user   1 if root/admin/svc account, else 0
  [6] event_type_encoded   ordinal mapping of event_type
  [7] message_length       len(message) normalised to 0-1 (÷2000)
  [8] has_ip_in_message    1 if IPv4 pattern found in message
  [9] port_flag            1 if a common attack port (22,3389,445…) is mentioned

The model is trained on demand when ≥ MIN_TRAIN_SAMPLES logs exist in MongoDB.
It is persisted to disk so it survives restarts.

Public API
──────────
  anomaly_detector.train(logs)         list[dict] → trains & saves model
  anomaly_detector.score(log)          dict → AnomalyResult
  anomaly_detector.is_ready            bool
"""

from __future__ import annotations
import os
import re
import math
import logging
import joblib
import numpy as np
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Optional

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

MODEL_PATH  = os.path.join(os.path.dirname(__file__), "..", "core", "iso_forest.joblib")
SCALER_PATH = os.path.join(os.path.dirname(__file__), "..", "core", "iso_scaler.joblib")

MIN_TRAIN_SAMPLES = 50        # won't train below this
CONTAMINATION     = 0.08      # expected fraction of anomalies ≈ 8 %
ANOMALY_THRESHOLD = -0.05     # decision_function score below this → anomalous

LEVEL_MAP = {"INFO": 0, "WARNING": 1, "ERROR": 2, "CRITICAL": 3}

EVENT_TYPE_MAP = {
    "AUTH_SUCCESS": 0, "AUTH_FAILURE": 1, "PORT_SCAN": 2,
    "MALWARE_DETECTED": 3, "FIREWALL_BLOCK": 4,
    "PRIVILEGE_ESCALATION": 5, "DATA_EXFILTRATION": 6,
    "BRUTE_FORCE": 7, "LATERAL_MOVEMENT": 8, "DNS_ANOMALY": 9,
}

ATTACK_PORTS = {22, 23, 25, 445, 1433, 1521, 3306, 3389, 4444, 5432, 6379, 27017}
PRIVILEGED_USERS = {"root", "admin", "administrator", "system", "svc_account"}
PRIV_RE = re.compile(r"\b(root|admin|svc_|service.?account)\b", re.I)
IP_RE   = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
PORT_RE = re.compile(r"\b(\d{2,5})\b")


# ── Feature extraction ────────────────────────────────────────────────────────

def _parse_ip_octets(ip: Optional[str]) -> tuple[int, int]:
    if not ip:
        return 0, 0
    try:
        parts = ip.strip().split(".")
        return int(parts[0]), int(parts[-1])
    except Exception:
        return 0, 0


def extract_features(log: dict) -> np.ndarray:
    ts: datetime = log.get("timestamp", datetime.now(timezone.utc))
    if isinstance(ts, str):
        try:
            ts = datetime.fromisoformat(ts)
        except Exception:
            ts = datetime.now(timezone.utc)

    hour        = ts.hour
    dow         = ts.weekday()
    level_score = LEVEL_MAP.get(str(log.get("level", "INFO")).upper(), 0)
    first_oct, last_oct = _parse_ip_octets(log.get("source_ip"))
    user        = str(log.get("user", "") or "").lower()
    is_priv     = 1 if (user in PRIVILEGED_USERS or PRIV_RE.search(user)) else 0
    et          = str(log.get("event_type", "") or "")
    et_enc      = EVENT_TYPE_MAP.get(et, len(EVENT_TYPE_MAP))
    msg         = str(log.get("message", "") or "")
    msg_len     = min(len(msg), 2000) / 2000.0
    has_ip      = 1 if IP_RE.search(msg) else 0

    # check if any found port is an attack-relevant port
    port_flag = 0
    for m in PORT_RE.finditer(msg):
        try:
            if int(m.group()) in ATTACK_PORTS:
                port_flag = 1
                break
        except ValueError:
            pass

    return np.array([
        hour, dow, level_score, first_oct, last_oct,
        is_priv, et_enc, msg_len, has_ip, port_flag,
    ], dtype=float)


def extract_feature_matrix(logs: list[dict]) -> np.ndarray:
    return np.vstack([extract_features(log) for log in logs])


# ── Result ────────────────────────────────────────────────────────────────────

@dataclass
class AnomalyResult:
    is_anomalous: bool
    anomaly_score: float          # raw decision_function output (lower = more anomalous)
    anomaly_percentile: float     # 0-100, higher = more abnormal among training data
    features: dict                # named feature values for explainability


FEATURE_NAMES = [
    "hour_of_day", "day_of_week", "level_score",
    "src_ip_first_octet", "src_ip_last_octet",
    "is_privileged_user", "event_type_encoded",
    "message_length_norm", "has_ip_in_message", "attack_port_flag",
]


# ── Detector class ────────────────────────────────────────────────────────────

class AnomalyDetector:
    def __init__(self):
        self._model:  Optional[IsolationForest] = None
        self._scaler: Optional[StandardScaler]  = None
        self._training_scores: Optional[np.ndarray] = None
        self._load()

    # ── Persistence ───────────────────────────────────────────────────────────

    def _save(self):
        joblib.dump(self._model,           MODEL_PATH)
        joblib.dump(self._scaler,          SCALER_PATH)
        logger.info("Anomaly model saved to disk.")

    def _load(self):
        try:
            if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
                self._model  = joblib.load(MODEL_PATH)
                self._scaler = joblib.load(SCALER_PATH)
                logger.info("Anomaly model loaded from disk.")
        except Exception as e:
            logger.warning(f"Could not load saved model: {e}")

    # ── Training ──────────────────────────────────────────────────────────────

    def train(self, logs: list[dict]) -> dict:
        if len(logs) < MIN_TRAIN_SAMPLES:
            return {
                "status": "skipped",
                "reason": f"Need ≥ {MIN_TRAIN_SAMPLES} logs, got {len(logs)}.",
                "samples": len(logs),
            }

        X = extract_feature_matrix(logs)

        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X)

        self._model = IsolationForest(
            n_estimators=200,
            contamination=CONTAMINATION,
            max_samples="auto",
            random_state=42,
            n_jobs=-1,
        )
        self._model.fit(X_scaled)

        # Store training scores for percentile calculation
        self._training_scores = self._model.decision_function(X_scaled)

        self._save()
        logger.info(f"Anomaly model trained on {len(logs)} samples.")
        return {
            "status": "trained",
            "samples": len(logs),
            "contamination": CONTAMINATION,
            "features": FEATURE_NAMES,
        }

    # ── Scoring ───────────────────────────────────────────────────────────────

    def score(self, log: dict) -> AnomalyResult:
        fv = extract_features(log)
        named = dict(zip(FEATURE_NAMES, fv.tolist()))

        if not self.is_ready:
            # Model not trained yet: use a simple heuristic
            heuristic_score = _heuristic_score(log, fv)
            return AnomalyResult(
                is_anomalous=heuristic_score < ANOMALY_THRESHOLD,
                anomaly_score=float(heuristic_score),
                anomaly_percentile=0.0,
                features=named,
            )

        X_scaled = self._scaler.transform(fv.reshape(1, -1))
        raw_score = float(self._model.decision_function(X_scaled)[0])

        # Percentile: what fraction of training points score LOWER (more anomalous)
        pct = 0.0
        if self._training_scores is not None:
            pct = float(np.mean(self._training_scores < raw_score) * 100)

        return AnomalyResult(
            is_anomalous=raw_score < ANOMALY_THRESHOLD,
            anomaly_score=round(raw_score, 4),
            anomaly_percentile=round(pct, 1),
            features=named,
        )

    @property
    def is_ready(self) -> bool:
        return self._model is not None and self._scaler is not None


# ── Heuristic fallback (no trained model) ────────────────────────────────────

def _heuristic_score(log: dict, fv: np.ndarray) -> float:
    """
    Simple rule-of-thumb score when no model is trained yet.
    Returns a value in roughly the same range as IF decision_function.
    """
    score = 0.1                          # baseline "normal"
    if fv[2] >= 3:  score -= 0.15       # CRITICAL level
    if fv[5] == 1:  score -= 0.10       # privileged user
    if fv[9] == 1:  score -= 0.08       # attack port
    if fv[6] >= 5:  score -= 0.12       # high-risk event type
    if fv[0] <= 5:  score -= 0.05       # off-hours (midnight–5am)
    return score


# ── Singleton ─────────────────────────────────────────────────────────────────

anomaly_detector = AnomalyDetector()
