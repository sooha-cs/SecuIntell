from fastapi import Body
from groq import Groq
import os, json, re
from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from bson import ObjectId

from core.database import get_db
from detection.engine import detection_engine
from detection.rules import RULES
from schemas.detection_schema import (
    AnalysisResponse, AlertResponse, PaginatedAlerts,
    IncidentResponse, PaginatedIncidents,
    TrainResponse, DetectionStats,
)
from models.detection_model import (
    get_alerts, get_alert_by_id, update_alert_status,
    get_incidents, get_incident_by_id, update_incident_status,
    get_detection_stats,
)
from models.log_model import get_log_by_id

router = APIRouter(tags=["Detection"])


# ════════════════════════════════════════════════════════
#  ANALYSIS
# ════════════════════════════════════════════════════════

@router.post("/detect/{log_id}", response_model=AnalysisResponse, status_code=201)
def analyze_log(log_id: str):
    """
    Run the full detection pipeline on a stored log:
      1. Rule-based pattern matching (15 rules, severity tiers)
      2. Isolation Forest anomaly scoring
      3. Correlation engine (incident chaining)

    Returns the analysis result and stores any Alert/Incident in MongoDB.
    """
    log = get_log_by_id(log_id)
    if not log:
        raise HTTPException(status_code=404, detail=f"Log '{log_id}' not found.")

    db = get_db()
    result = detection_engine.analyze(log, db=db)

    return AnalysisResponse(
        log_id=result.log_id,
        rules_fired=len(result.rule_matches),
        top_severity=result.top_severity,
        is_anomalous=result.is_anomalous,
        anomaly_score=result.anomaly_score,
        anomaly_pct=result.anomaly_pct,
        anomaly_features=result.anomaly_features,
        incident_id=result.incident.incident_id if result.incident else None,
        incident_title=result.incident.title if result.incident else None,
        alert_id=result.alert_id,
        processed_at=result.processed_at,
    )


@router.post("/detect/batch", status_code=200)
def analyze_batch(log_ids: list[str], background_tasks: BackgroundTasks):
    """
    Queue detection for a list of log IDs.
    Processing happens in the background; returns immediately.
    """
    if len(log_ids) > 200:
        raise HTTPException(status_code=400, detail="Max 200 log IDs per batch.")

    def _run_batch(ids: list[str]):
        db = get_db()
        for lid in ids:
            log = get_log_by_id(lid)
            if log:
                detection_engine.analyze(log, db=db)

    background_tasks.add_task(_run_batch, log_ids)
    return {"status": "queued", "count": len(log_ids)}


# ════════════════════════════════════════════════════════
#  MODEL TRAINING
# ════════════════════════════════════════════════════════

@router.post("/detect/train", response_model=TrainResponse)
def train_anomaly_model():
    """
    (Re)train the Isolation Forest on all logs in MongoDB.
    Needs ≥ 50 logs. Model is persisted to disk after training.
    """
    db = get_db()
    result = detection_engine.train_anomaly_model(db)
    msg = (
        f"Model trained on {result['samples']} samples."
        if result["status"] == "trained"
        else result.get("reason", "Skipped.")
    )
    return TrainResponse(status=result["status"], message=msg, detail=result)


# ════════════════════════════════════════════════════════
#  RULES
# ════════════════════════════════════════════════════════

@router.get("/rules", tags=["Detection"])
def list_rules():
    """Return all loaded detection rules with their metadata."""
    return [
        {
            "id":          r.id,
            "name":        r.name,
            "description": r.description,
            "severity":    r.severity,
            "tactic":      r.tactic,
            "technique":   r.technique,
            "match_mode":  r.match_mode,
            "priority":    r.priority,
            "conditions":  len(r.conditions),
        }
        for r in RULES
    ]


# ════════════════════════════════════════════════════════
#  ALERTS
# ════════════════════════════════════════════════════════

@router.get("/alerts", response_model=PaginatedAlerts)
def list_alerts(
    page:         int   = Query(1, ge=1),
    page_size:    int   = Query(50, ge=1, le=200),
    severity:     str   = Query(None),
    is_anomalous: bool  = Query(None),
    status:       str   = Query(None),
    source_ip:    str   = Query(None),
):
    """Paginated alerts with optional filters."""
    alerts, total = get_alerts(page, page_size, severity, is_anomalous, status, source_ip)
    return PaginatedAlerts(total=total, page=page, page_size=page_size, alerts=alerts)


@router.get("/alerts/stats", response_model=DetectionStats)
def detection_stats():
    """Aggregate counts for the detection dashboard."""
    return get_detection_stats()


@router.get("/alerts/{alert_id}", response_model=AlertResponse)
def get_alert(alert_id: str):
    alert = get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
    return alert


@router.patch("/alerts/{alert_id}/status")
def set_alert_status(alert_id: str, status: str = Query(..., pattern="^(open|investigating|resolved)$")):
    """Update alert triage status."""
    ok = update_alert_status(alert_id, status)
    if not ok:
        raise HTTPException(status_code=404, detail="Alert not found or not modified.")
    return {"status": "updated", "alert_id": alert_id, "new_status": status}


# ════════════════════════════════════════════════════════
#  INCIDENTS
# ════════════════════════════════════════════════════════

@router.get("/incidents", response_model=PaginatedIncidents)
def list_incidents(
    page:      int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity:  str = Query(None),
    status:    str = Query(None),
):
    """Paginated correlated incidents."""
    incidents, total = get_incidents(page, page_size, severity, status)
    return PaginatedIncidents(total=total, page=page, page_size=page_size, incidents=incidents)


@router.get("/incidents/{incident_id}", response_model=IncidentResponse)
def get_incident(incident_id: str):
    inc = get_incident_by_id(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    return inc


@router.patch("/incidents/{incident_id}/status")
def set_incident_status(incident_id: str, status: str = Query(..., pattern="^(open|investigating|resolved)$")):
    """Update incident triage status."""
    ok = update_incident_status(incident_id, status)
    if not ok:
        raise HTTPException(status_code=404, detail="Incident not found or not modified.")
    return {"status": "updated", "incident_id": incident_id, "new_status": status}


@router.post("/explain/{alert_id}")
def explain_alert(alert_id: str, alert: dict = Body(default=None)):
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise HTTPException(status_code=503, detail="No AI provider configured.")
    
    client = Groq(api_key=api_key)
    prompt = f"""You are a cybersecurity analyst. Explain this security alert in JSON only, no markdown:
    Alert: {json.dumps(alert)}
    Return exactly this JSON structure:
    {{"what_happened":"...","why_it_matters":"...","attack_stage":"...","llm_provider":"groq","llm_actions":["action1","action2"],"analyst_notes":"...","risk_score":75,"false_positive_pct":10,"techniques":[{{"id":"T1234","name":"...","tactic":"..."}}]}}"""
    
    response = client.chat.completions.create(
        model="llama-3.3-70b-versatile",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=1024
    )
    text = re.sub(r"```json|```", "", response.choices[0].message.content).strip()
    return json.loads(text)
