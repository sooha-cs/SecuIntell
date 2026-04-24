from pydantic import BaseModel, Field
from typing import Optional, Literal
from datetime import datetime


# ── Rule match (embedded in alert) ───────────────────────────────────────────

class RuleMatchSchema(BaseModel):
    rule_id:   str
    rule_name: str
    severity:  str
    tactic:    str
    technique: str


# ── Alert ─────────────────────────────────────────────────────────────────────

class AlertResponse(BaseModel):
    id:               str
    log_id:           str
    source_ip:        Optional[str] = None
    hostname:         Optional[str] = None
    user:             Optional[str] = None
    event_type:       Optional[str] = None
    message:          str
    timestamp:        datetime
    severity:         str
    rule_matches:     list[RuleMatchSchema] = []
    is_anomalous:     bool = False
    anomaly_score:    float = 0.0
    anomaly_pct:      float = 0.0
    anomaly_features: dict = {}
    status:           Literal["open", "investigating", "resolved"] = "open"
    created_at:       datetime


class PaginatedAlerts(BaseModel):
    total:     int
    page:      int
    page_size: int
    alerts:    list[AlertResponse]


# ── Incident ──────────────────────────────────────────────────────────────────

class IncidentResponse(BaseModel):
    id:           str
    incident_id:  str
    title:        str
    severity:     str
    tactic:       str
    source_ip:    str
    alert_count:  int
    chain_name:   Optional[str] = None
    status:       Literal["open", "investigating", "resolved"] = "open"
    alert_ids:    list[str] = []
    first_seen:   datetime
    last_seen:    datetime
    created_at:   datetime


class PaginatedIncidents(BaseModel):
    total:     int
    page:      int
    page_size: int
    incidents: list[IncidentResponse]


# ── Analysis result (returned from POST /detect) ──────────────────────────────

class AnalysisResponse(BaseModel):
    log_id:           str
    rules_fired:      int
    top_severity:     Optional[str]
    is_anomalous:     bool
    anomaly_score:    float
    anomaly_pct:      float
    anomaly_features: dict
    incident_id:      Optional[str]
    incident_title:   Optional[str]
    alert_id:         Optional[str]
    processed_at:     datetime


# ── Model training response ───────────────────────────────────────────────────

class TrainResponse(BaseModel):
    status:  str
    message: str
    detail:  dict


# ── Detection stats ───────────────────────────────────────────────────────────

class DetectionStats(BaseModel):
    total_alerts:    int
    open_alerts:     int
    total_incidents: int
    open_incidents:  int
    by_severity:     dict
    by_tactic:       dict
    anomaly_rate:    float    # fraction of alerts that are anomalous
