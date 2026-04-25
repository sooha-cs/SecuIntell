from zipfile import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from pymongo import ASCENDING, DESCENDING

from core.database import connect_db, disconnect_db, get_db
from routes.logs import router as logs_router
from routes.detection import router as detection_router
from dotenv import load_dotenv
from pathlib import Path
load_dotenv(dotenv_path=Path(__file__).parent / ".env")

# ── Lifespan: connect / disconnect DB around app lifetime ────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    connect_db()
    _ensure_detection_indexes()
    yield
    disconnect_db()


def _ensure_detection_indexes():
    """Create indexes for alerts and incidents collections."""
    try:
        db = get_db()
        db["alerts"].create_index([("created_at", DESCENDING)])
        db["alerts"].create_index([("severity", ASCENDING)])
        db["alerts"].create_index([("source_ip", ASCENDING)])
        db["alerts"].create_index([("status", ASCENDING)])
        db["alerts"].create_index([("is_anomalous", ASCENDING)])
        db["incidents"].create_index([("last_seen", DESCENDING)])
        db["incidents"].create_index([("severity", ASCENDING)])
        db["incidents"].create_index([("source_ip", ASCENDING)])
        db["incidents"].create_index([("incident_id", ASCENDING)], unique=True)
        print("✅ Detection indexes ready.")
    except Exception as e:
        print(f"⚠️  Index creation warning: {e}")


# ── App factory ───────────────────────────────────────────────────────────────
app = FastAPI(
    title="Secuintell SIEM API",
    description=(
        "Security Information & Event Management\n\n"
        "**Detection Engine:** Rule-based (15 rules) · Isolation Forest · Correlation\n\n"
        "**Collections:** logs · alerts · incidents"
    ),
    version="2.0.0",
    lifespan=lifespan,
)

# Allow the React frontend (Vite dev server) and simulator to call the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",   # Vite dev server  ← FIXED (was 3000)
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(logs_router)
app.include_router(detection_router)


# ── Root health-check ─────────────────────────────────────────────────────────
@app.get("/", tags=["Health"])
def health():
    return {
        "project": "Secuintell",
        "version": "2.0.0",
        "status":  "SIEM backend running 🛡️",
        "engine":  {
            "rule_based":   "15 rules across 4 severity tiers",
            "anomaly":      "Isolation Forest (scikit-learn)",
            "correlation":  "Sliding-window + 6 attack chains",
        },
        "docs": "/docs",
    }
