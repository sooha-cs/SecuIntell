from fastapi import APIRouter, HTTPException, Query, BackgroundTasks
from schemas.log_schema import LogCreate, LogResponse, PaginatedLogs, LogStats
from models.log_model import (
    insert_log,
    insert_bulk_logs,
    get_logs,
    get_log_by_id,
    get_stats,
)
from detection.engine import detection_engine
from core.database import get_db

router = APIRouter(prefix="/logs", tags=["Logs"])


# ── Detection bridge ──────────────────────────────────────────────────────────
def _run_detection(log: dict):
    """Run the full detection pipeline on a stored log (called in background)."""
    try:
        db = get_db()
        detection_engine.analyze(log, db=db)
    except Exception as e:
        print(f"⚠️  Detection error for log {log.get('id','?')}: {e}")


# ── POST /logs  — ingest a single log ────────────────────────────────────────
@router.post("/", response_model=LogResponse, status_code=201)
def create_log(log: LogCreate, background_tasks: BackgroundTasks):
    """
    Ingest a single log event.
    Automatically runs detection pipeline in background → populates alerts + incidents.
    """
    stored = insert_log(log)
    background_tasks.add_task(_run_detection, stored)
    return stored


# ── POST /logs/bulk  — ingest many logs at once ───────────────────────────────
@router.post("/bulk", status_code=201)
def create_logs_bulk(logs: list[LogCreate], background_tasks: BackgroundTasks):
    """Batch-ingest up to 500 log events. Detection runs in background for each."""
    if len(logs) > 500:
        raise HTTPException(status_code=400, detail="Maximum 500 logs per bulk request.")
    count = insert_bulk_logs(logs)

    def _run_bulk_detection(log_list: list[LogCreate]):
        db = get_db()
        for log in log_list:
            try:
                detection_engine.analyze(log, db=db)
            except Exception as e:
                print(f"⚠️  Bulk detection error: {e}")

    background_tasks.add_task(_run_bulk_detection, logs)
    return {"status": "ok", "inserted": count}


# ── GET /logs  — paginated list with filters ──────────────────────────────────
@router.get("/", response_model=PaginatedLogs)
def list_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    level: str = Query(None, description="Filter by level: INFO | WARNING | ERROR | CRITICAL"),
    event_type: str = Query(None, description="Filter by event type, e.g. AUTH_FAILURE"),
    source_ip: str = Query(None, description="Filter by source IP"),
):
    """Return paginated logs, newest first, with optional filters."""
    logs, total = get_logs(page, page_size, level, event_type, source_ip)
    return PaginatedLogs(total=total, page=page, page_size=page_size, logs=logs)


# ── GET /logs/stats  — dashboard summary ─────────────────────────────────────
@router.get("/stats", response_model=LogStats)
def log_stats():
    """Aggregate counts for the frontend dashboard."""
    return get_stats()


# ── GET /logs/{id}  — single log detail ──────────────────────────────────────
@router.get("/{log_id}", response_model=LogResponse)
def get_log(log_id: str):
    """Fetch a single log by its MongoDB ObjectId."""
    log = get_log_by_id(log_id)
    if not log:
        raise HTTPException(status_code=404, detail=f"Log '{log_id}' not found.")
    return log
