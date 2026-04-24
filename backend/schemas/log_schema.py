from pydantic import BaseModel, Field
from typing import Optional, Literal
from datetime import datetime
import uuid


# ── Inbound (what the simulator / agents POST) ──────────────────────────────

class LogCreate(BaseModel):
    message: str = Field(..., min_length=1, max_length=2000, description="Human-readable log message")
    level: Literal["INFO", "WARNING", "ERROR", "CRITICAL"] = Field(..., description="Severity level")
    source_ip: Optional[str] = Field(None, description="Originating IP address")
    destination_ip: Optional[str] = Field(None, description="Target IP address")
    event_type: Optional[str] = Field(None, description="e.g. AUTH_FAILURE, PORT_SCAN, MALWARE")
    hostname: Optional[str] = Field(None, description="Host that generated the log")
    user: Optional[str] = Field(None, description="Associated username if applicable")
    extra: Optional[dict] = Field(default_factory=dict, description="Any extra key-value metadata")

    model_config = {
        "json_schema_extra": {
            "example": {
                "message": "Failed SSH login attempt from hide",
                "level": "WARNING",
                "source_ip": "hidden",
                "destination_ip": "10.0.0.1",
                "event_type": "AUTH_FAILURE",
                "hostname": "prod-server-01",
                "user": "root",
                "extra": {"port": 22, "protocol": "SSH"}
            }
        }
    }


# ── Stored (what comes back out of MongoDB) ──────────────────────────────────

class LogResponse(BaseModel):
    id: str = Field(..., description="Unique log ID")
    message: str
    level: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    event_type: Optional[str] = None
    hostname: Optional[str] = None
    user: Optional[str] = None
    extra: Optional[dict] = {}
    timestamp: datetime

    model_config = {"from_attributes": True}


# ── Pagination wrapper ────────────────────────────────────────────────────────

class PaginatedLogs(BaseModel):
    total: int
    page: int
    page_size: int
    logs: list[LogResponse]


# ── Stats / dashboard summary ─────────────────────────────────────────────────

class LogStats(BaseModel):
    total_logs: int
    by_level: dict
    by_event_type: dict
    recent_critical: int  # last 60 minutes
