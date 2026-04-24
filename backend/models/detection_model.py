from datetime import datetime, timezone
from bson import ObjectId
from core.database import get_db


def _ser(doc: dict) -> dict:
    doc["id"] = str(doc.pop("_id"))
    return doc


# ── Alerts ────────────────────────────────────────────────────────────────────

def get_alerts(
    page: int = 1,
    page_size: int = 50,
    severity: str = None,
    is_anomalous: bool = None,
    status: str = None,
    source_ip: str = None,
) -> tuple[list[dict], int]:
    db = get_db()
    query = {}
    if severity:
        query["severity"] = severity
    if is_anomalous is not None:
        query["is_anomalous"] = is_anomalous
    if status:
        query["status"] = status
    if source_ip:
        query["source_ip"] = source_ip

    total = db["alerts"].count_documents(query)
    cursor = (
        db["alerts"]
        .find(query)
        .sort("created_at", -1)
        .skip((page - 1) * page_size)
        .limit(page_size)
    )
    return [_ser(doc) for doc in cursor], total


def get_alert_by_id(alert_id: str) -> dict | None:
    db = get_db()
    try:
        doc = db["alerts"].find_one({"_id": ObjectId(alert_id)})
        if doc:
            return _ser(doc)
    except Exception:
        pass
    # Fallback: search by log_id field
    doc = db["alerts"].find_one({"log_id": alert_id})
    return _ser(doc) if doc else None


def update_alert_status(alert_id: str, status: str) -> bool:
    db = get_db()
    try:
        result = db["alerts"].update_one(
            {"_id": ObjectId(alert_id)},
            {"$set": {"status": status, "updated_at": datetime.now(timezone.utc)}},
        )
        return result.modified_count > 0
    except Exception:
        return False


# ── Incidents ─────────────────────────────────────────────────────────────────

def get_incidents(
    page: int = 1,
    page_size: int = 50,
    severity: str = None,
    status: str = None,
) -> tuple[list[dict], int]:
    db = get_db()
    query = {}
    if severity:
        query["severity"] = severity
    if status:
        query["status"] = status

    total = db["incidents"].count_documents(query)
    cursor = (
        db["incidents"]
        .find(query)
        .sort("last_seen", -1)
        .skip((page - 1) * page_size)
        .limit(page_size)
    )
    return [_ser(doc) for doc in cursor], total


def get_incident_by_id(incident_id: str) -> dict | None:
    db = get_db()
    try:
        doc = db["incidents"].find_one({"_id": ObjectId(incident_id)})
        return _ser(doc) if doc else None
    except Exception:
        return None


def update_incident_status(incident_id: str, status: str) -> bool:
    db = get_db()
    try:
        result = db["incidents"].update_one(
            {"_id": ObjectId(incident_id)},
            {"$set": {"status": status, "updated_at": datetime.now(timezone.utc)}},
        )
        return result.modified_count > 0
    except Exception:
        return False


# ── Stats ─────────────────────────────────────────────────────────────────────

def get_detection_stats() -> dict:
    db = get_db()

    total_alerts = db["alerts"].count_documents({})
    open_alerts  = db["alerts"].count_documents({"status": "open"})

    total_incidents = db["incidents"].count_documents({})
    open_incidents  = db["incidents"].count_documents({"status": "open"})

    by_severity = {
        item["_id"]: item["count"]
        for item in db["alerts"].aggregate([
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}}
        ])
    }

    by_tactic = {
        item["_id"]: item["count"]
        for item in db["alerts"].aggregate([
            {"$unwind": "$rule_matches"},
            {"$group": {"_id": "$rule_matches.tactic", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10},
        ])
    }

    anomaly_count = db["alerts"].count_documents({"is_anomalous": True})
    anomaly_rate  = round(anomaly_count / total_alerts, 4) if total_alerts else 0.0

    return {
        "total_alerts":    total_alerts,
        "open_alerts":     open_alerts,
        "total_incidents": total_incidents,
        "open_incidents":  open_incidents,
        "by_severity":     by_severity,
        "by_tactic":       by_tactic,
        "anomaly_rate":    anomaly_rate,
    }
