from datetime import datetime, timezone, timedelta
from bson import ObjectId
from core.database import get_db
from schemas.log_schema import LogCreate


def _serialize(doc: dict) -> dict:
    """Convert MongoDB _id to string 'id' field."""
    doc["id"] = str(doc.pop("_id"))
    return doc


# ── Write ─────────────────────────────────────────────────────────────────────

def insert_log(log: LogCreate) -> dict:
    db = get_db()
    payload = log.model_dump()
    payload["timestamp"] = datetime.now(timezone.utc)
    result = db["logs"].insert_one(payload)
    payload["_id"] = result.inserted_id
    return _serialize(payload)


def insert_bulk_logs(logs: list[LogCreate]) -> int:
    """Insert many logs at once — used by the simulator."""
    db = get_db()
    docs = []
    for log in logs:
        d = log.model_dump()
        d["timestamp"] = datetime.now(timezone.utc)
        docs.append(d)
    result = db["logs"].insert_many(docs)
    return len(result.inserted_ids)


# ── Read ──────────────────────────────────────────────────────────────────────

def get_logs(
    page: int = 1,
    page_size: int = 50,
    level: str = None,
    event_type: str = None,
    source_ip: str = None,
) -> tuple[list[dict], int]:
    db = get_db()
    query = {}
    if level:
        query["level"] = level
    if event_type:
        query["event_type"] = event_type
    if source_ip:
        query["source_ip"] = source_ip

    total = db["logs"].count_documents(query)
    cursor = (
        db["logs"]
        .find(query)
        .sort("timestamp", -1)
        .skip((page - 1) * page_size)
        .limit(page_size)
    )
    return [_serialize(doc) for doc in cursor], total


def get_log_by_id(log_id: str) -> dict | None:
    db = get_db()
    try:
        doc = db["logs"].find_one({"_id": ObjectId(log_id)})
        return _serialize(doc) if doc else None
    except Exception:
        return None


# ── Stats ─────────────────────────────────────────────────────────────────────

def get_stats() -> dict:
    db = get_db()
    total = db["logs"].count_documents({})

    # Aggregate by level
    by_level = {
        item["_id"]: item["count"]
        for item in db["logs"].aggregate([
            {"$group": {"_id": "$level", "count": {"$sum": 1}}}
        ])
    }

    # Aggregate by event_type (top 10)
    by_event = {
        item["_id"]: item["count"]
        for item in db["logs"].aggregate([
            {"$match": {"event_type": {"$ne": None}}},
            {"$group": {"_id": "$event_type", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$limit": 10},
        ])
    }

    # Recent CRITICAL logs in last 60 minutes
    one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
    recent_critical = db["logs"].count_documents({
        "level": "CRITICAL",
        "timestamp": {"$gte": one_hour_ago}
    })

    return {
        "total_logs": total,
        "by_level": by_level,
        "by_event_type": by_event,
        "recent_critical": recent_critical,
    }
