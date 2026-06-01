import base64
import csv
import hashlib
import hmac
import io
import json
import logging
import os
import re
import secrets
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from zoneinfo import ZoneInfo
from logging.handlers import RotatingFileHandler

import joblib
from fastapi import Depends, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from sqlalchemy import func, inspect, text
from sqlalchemy.orm import Session

from database import SessionLocal, engine, print_db_info
from detection import calculate_risk_score, decode_base64_command
from models import Agent, Base, ResponseAction, Telemetry, IncidentTimeline
from schemas import (
    AgentRegister,
    DashboardAuthResponse,
    DashboardLoginRequest,
    DecodeCommandRequest,
    DecodeCommandResponse,
    IncidentStatusUpdate,
    LiveEventCreate,
    PdfHealthResponse,
    ResponseActionCreate,
    ResponseActionResultUpdate,
    TelemetryCreate,
    
)

# ============================================================
# OPTIONAL AI MODEL SUPPORT
# ============================================================

AGENT_ONLINE_WINDOW_SECONDS = 30
BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "model.joblib"
BACKEND_LOG_DIR = BASE_DIR.parent / "data" / "logs"
BACKEND_LOG_PATH = BACKEND_LOG_DIR / "backend.log"


def setup_backend_logging() -> logging.Logger:
    BACKEND_LOG_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("mini_edr.backend")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if not logger.handlers:
        handler = RotatingFileHandler(
            BACKEND_LOG_PATH,
            maxBytes=1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        handler.setFormatter(
            logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        )
        logger.addHandler(handler)

    return logger


backend_logger = setup_backend_logging()
backend_logger.info("Backend logging initialized at %s", BACKEND_LOG_PATH)

DASHBOARD_AUTH_USERNAME = os.getenv("DASHBOARD_USERNAME", "admin")
DASHBOARD_AUTH_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "admin123")
DASHBOARD_TOKEN_SECRET = os.getenv("DASHBOARD_TOKEN_SECRET") or secrets.token_urlsafe(32)

try:
    DASHBOARD_TOKEN_TTL_SECONDS = max(
        300, int(os.getenv("DASHBOARD_TOKEN_TTL_SECONDS", "28800"))
    )
except ValueError:
    DASHBOARD_TOKEN_TTL_SECONDS = 28800

model = None
if MODEL_PATH.exists():
    try:
        model = joblib.load(MODEL_PATH)
    except Exception as e:
        backend_logger.warning("model.joblib could not be loaded: %s", e)


def build_features(data: dict):
    """Build simple ML features from Agent flags."""
    is_powershell = int(data.get("powershell_flag", 0) or 0)
    temp_exec = int(data.get("temp_execution", 0) or 0)
    suspicious_port = int(data.get("suspicious_port", 0) or 0)

    has_encoded = 1 if is_powershell == 1 else 0
    office_spawn = 0
    cmd_length = 200 if is_powershell else 10

    return [
        [
            is_powershell,
            has_encoded,
            office_spawn,
            temp_exec,
            suspicious_port,
            cmd_length,
        ]
    ]


def save_to_dataset(data: dict):
    """Optional dataset logging for later AI training."""
    dataset_path = BASE_DIR / "dataset.csv"
    with dataset_path.open("a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                data.get("cpu_percent"),
                data.get("memory_percent"),
                data.get("process_count"),
                data.get("connections_count"),
                data.get("suspicious_port"),
                data.get("powershell_flag"),
                data.get("temp_execution"),
                0,
            ]
        )


# ============================================================
# PDF SUPPORT
# ============================================================

PDF_AVAILABLE = True
PDF_IMPORT_ERROR = None

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )
except Exception as e:
    PDF_AVAILABLE = False
    PDF_IMPORT_ERROR = str(e)
# ============================================================
# INIT
# ============================================================

print_db_info()
Base.metadata.create_all(bind=engine)


def ensure_telemetry_schema():
    """SQLite helper: add new telemetry columns if an old edr.db already exists."""
    required_columns = {
        "connections_count": "INTEGER DEFAULT 0",
        "powershell_flag": "INTEGER DEFAULT 0",
        "temp_execution": "INTEGER DEFAULT 0",
        "suspicious_port": "INTEGER DEFAULT 0",
        "decoded_command": "TEXT",
        "decode_method": "VARCHAR(100)",
        "decode_layers": "TEXT",
        "decoded_suspicious_keywords": "TEXT",
        "decoded_mitre_technique": "VARCHAR(100)",
        "decoded_mitre_tactic": "VARCHAR(100)",
        "attack_intent": "TEXT",
        "attack_summary": "TEXT",
        "ai_attack_explanation": "TEXT",
        "ai_attack_category": "VARCHAR(100)",
        "ai_confidence_level": "VARCHAR(50)",
        "recommended_action": "TEXT",
    }

    try:
        inspector = inspect(engine)
        if "telemetry" not in inspector.get_table_names():
            return

        existing_columns = {col["name"] for col in inspector.get_columns("telemetry")}

        with engine.begin() as conn:
            for column_name, column_type in required_columns.items():
                if column_name not in existing_columns:
                    conn.execute(text(f"ALTER TABLE telemetry ADD COLUMN {column_name} {column_type}"))
                    print(f"DB MIGRATION: added telemetry.{column_name}")
    except Exception as e:
        print(f"WARNING: telemetry schema check failed: {e}")


ensure_telemetry_schema()

app = FastAPI(title="Mini EDR Telemetry API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Lab mode. Restrict this in production.
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# GLOBALS
# ============================================================

def resolve_local_timezone():
    try:
        return ZoneInfo("Asia/Amman")
    except Exception as e:
        print(
            "WARNING: timezone Asia/Amman is unavailable "
            f"({e}); falling back to UTC+03:00. Install tzdata for full support."
        )
        return timezone(timedelta(hours=3))


LOCAL_TIMEZONE = resolve_local_timezone()
LIVE_EVENTS_LIMIT = 300
live_events_buffer = deque(maxlen=LIVE_EVENTS_LIMIT)

ALLOWED_INCIDENT_STATUSES = {"New", "Investigating", "Resolved", "False Positive"}
ALLOWED_RESPONSE_ACTIONS = {
    "collect_diagnostics",
    "mark_host_for_isolation_review",
    "blocklisted_ip_review",
    "kill_process_request",
}
ALLOWED_RESPONSE_RESULTS = {"pending", "in_progress", "executed", "failed"}
# Telemetry ingestion policy:
# Store every telemetry payload as a new row. No deduplication/merge.
# This keeps the Telemetry page append-only so every agent heartbeat/event appears.


# ============================================================
# WEBSOCKET MANAGER
# ============================================================


class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast_json(self, payload: dict):
        if not self.active_connections:
            return

        disconnected = []

        for connection in self.active_connections:
            try:
                await connection.send_json(payload)
            except Exception:
                disconnected.append(connection)

        for connection in disconnected:
            self.disconnect(connection)


manager = ConnectionManager()


# ============================================================
# DB DEPENDENCY
# ============================================================


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ============================================================
# DASHBOARD AUTH
# ============================================================


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def create_dashboard_token(username: str) -> str:
    expires_at = int(datetime.now(timezone.utc).timestamp()) + DASHBOARD_TOKEN_TTL_SECONDS
    payload = json.dumps(
        {"sub": username, "exp": expires_at},
        separators=(",", ":"),
    ).encode("utf-8")
    body = _b64url_encode(payload)
    signature = hmac.new(
        DASHBOARD_TOKEN_SECRET.encode("utf-8"),
        body.encode("ascii"),
        hashlib.sha256,
    ).digest()
    return f"{body}.{_b64url_encode(signature)}"


def verify_dashboard_token(token: str | None) -> str:
    if not token:
        raise HTTPException(status_code=401, detail="Dashboard login required")

    try:
        body, signature = token.split(".", 1)
        expected_signature = hmac.new(
            DASHBOARD_TOKEN_SECRET.encode("utf-8"),
            body.encode("ascii"),
            hashlib.sha256,
        ).digest()

        if not hmac.compare_digest(_b64url_decode(signature), expected_signature):
            raise ValueError("invalid signature")

        payload = json.loads(_b64url_decode(body).decode("utf-8"))
        username = str(payload.get("sub") or "")
        expires_at = int(payload.get("exp") or 0)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid dashboard session")

    if username != DASHBOARD_AUTH_USERNAME:
        raise HTTPException(status_code=401, detail="Invalid dashboard session")

    if expires_at < int(datetime.now(timezone.utc).timestamp()):
        raise HTTPException(status_code=401, detail="Dashboard session expired")

    return username


def require_dashboard_auth(authorization: str | None = Header(default=None)) -> str:
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Dashboard login required")
    return verify_dashboard_token(token)


# ============================================================
# TIME HELPERS
# ============================================================


def now_local() -> datetime:
    return datetime.now(LOCAL_TIMEZONE)


def now_local_naive() -> datetime:
    return now_local().replace(tzinfo=None)


def parse_client_timestamp(value) -> datetime | None:
    if not value:
        return None

    try:
        if isinstance(value, datetime):
            dt = value
        else:
            text = str(value).strip()
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            dt = datetime.fromisoformat(text)

        if dt.tzinfo is not None:
            dt = dt.astimezone(LOCAL_TIMEZONE).replace(tzinfo=None)

        return dt
    except Exception:
        return None


def format_local_timestamp(value: datetime | None) -> str | None:
    if not value:
        return None

    try:
        if value.tzinfo is not None:
            return value.astimezone(LOCAL_TIMEZONE).isoformat()

        return value.replace(tzinfo=LOCAL_TIMEZONE).isoformat()
    except Exception:
        return value.isoformat()


def correct_legacy_timeline_timestamp(
    value: datetime | None, telemetry_timestamp: datetime | None
) -> datetime | None:
    if not value or not telemetry_timestamp or value.tzinfo is not None:
        return value

    try:
        offset = value.replace(tzinfo=LOCAL_TIMEZONE).utcoffset() or timedelta()
        if offset.total_seconds() <= 0:
            return value

        shifted = value + offset
        near_telemetry_start = telemetry_timestamp - timedelta(minutes=5)
        original_gap = abs((telemetry_timestamp - value).total_seconds())
        shifted_gap = abs((telemetry_timestamp - shifted).total_seconds())

        if value < near_telemetry_start and shifted >= near_telemetry_start:
            return shifted

        if shifted_gap + 60 < original_gap:
            return shifted

    except Exception:
        return value

    return value


def get_agent_online_status(last_seen: datetime | None) -> str:
    if not last_seen:
        return "Offline"

    now = now_local_naive()
    diff_seconds = (now - last_seen).total_seconds()

    return "Online" if diff_seconds <= AGENT_ONLINE_WINDOW_SECONDS else "Offline"
# ============================================================
# GENERIC HELPERS
# ============================================================


def risk_level_from_score(score: int) -> str:
    score = int(score or 0)
    if score >= 70:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


def infer_detection_source(rule_score: int, ai_score: int) -> str:
    rule_score = int(rule_score or 0)
    ai_score = int(ai_score or 0)

    if rule_score > 0 and ai_score > 0:
        return "Hybrid"
    if rule_score > 0:
        return "Rule-Based"
    if ai_score > 0:
        return "AI-Based"
    return "Informational"


def infer_severity_from_score(score: int) -> str:
    score = int(score or 0)
    if score >= 85:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


def infer_event_category(
    alert_type: str | None, fallback: str | None = None
) -> str | None:
    if fallback:
        return fallback

    text = str(alert_type or "").lower()

    if any(k in text for k in ["cpu", "memory", "process count", "spike"]):
        return "system_resource"

    if any(
        k in text
        for k in [
            "powershell",
            "command",
            "script",
            "execution",
            "mshta",
            "rundll32",
            "regsvr32",
            "wmi",
        ]
    ):
        return "process_execution"

    if any(k in text for k in ["credential", "mimikatz", "dumping"]):
        return "credential_access"

    if any(
        k in text
        for k in ["port", "connection", "c2", "tool transfer", "command and control"]
    ):
        return "network_connection"

    return "general_detection"


def parse_risk_reasons(value):
    if not value:
        return []

    if isinstance(value, list):
        return value

    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except Exception:
            return []

    return []


def safe_json_load(value):
    if not value:
        return []

    if isinstance(value, list):
        return value

    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, list) else []
        except Exception:
            return []

    return []


def serialize_json_field(value):
    if value is None:
        return None
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return None


def clamp_score(value: int, min_value: int = 0, max_value: int = 100) -> int:
    try:
        value = int(value)
    except Exception:
        value = 0
    return max(min_value, min(value, max_value))




def choose_top_reason(
    detection_result: dict, fallback: str = "No specific reason"
) -> str:
    top_reason = detection_result.get("top_reason")
    if top_reason:
        return str(top_reason)

    reasons = detection_result.get("risk_reasons") or []
    if isinstance(reasons, list) and reasons:
        return str(reasons[0])

    return fallback


def _parse_json_object(value):
    if not value:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    return {}


def _extract_after_label(text_value: str | None, label: str) -> str | None:
    text_value = str(text_value or "")
    if not text_value:
        return None

    try:
        pattern = re.escape(label) + r"\s*:?\s*([^.;\n]+)"
        match = re.search(pattern, text_value, flags=re.IGNORECASE)
        if match:
            value = match.group(1).strip()
            return value or None
    except Exception:
        return None

    return None


def normalize_ai_confidence(value: str | None) -> str | None:
    if not value:
        return None

    raw = str(value).strip()
    if not raw:
        return None

    lowered = raw.lower().replace("_", " ")

    if "very high" in lowered:
        return "Very High confidence"
    if lowered == "high" or " high" in lowered or lowered.startswith("high"):
        return "High confidence"
    if "medium" in lowered:
        return "Medium confidence"
    if "low" in lowered:
        return "Low confidence"
    if "informational" in lowered:
        return "Informational confidence"

    return raw


def resolve_ai_attack_category(detection_result: dict, event_category: str | None = None) -> str:
    details = _parse_json_object(detection_result.get("ai_model_details"))

    direct_value = (
        detection_result.get("ai_attack_category")
        or detection_result.get("attack_category")
        or details.get("attack_category")
        or details.get("ai_attack_category")
        or _extract_after_label(detection_result.get("ai_attack_explanation"), "Predicted attack category")
        or _extract_after_label(detection_result.get("attack_summary"), "Attack category")
    )

    if direct_value:
        return str(direct_value).strip()

    event_category_text = str(event_category or detection_result.get("event_category") or "").lower()

    if "credential" in event_category_text:
        return "Credential Access"
    if "network" in event_category_text:
        return "Command and Control"
    if "process" in event_category_text or "execution" in event_category_text:
        return "Execution"
    if "system_resource" in event_category_text:
        return "Benign / Informational"

    return "Benign / Informational"


def resolve_ai_confidence_level(
    detection_result: dict,
    risk_score: int = 0,
    ai_score: int = 0,
) -> str:
    details = _parse_json_object(detection_result.get("ai_model_details"))

    direct_value = (
        detection_result.get("ai_confidence_level")
        or detection_result.get("confidence_level")
        or detection_result.get("attack_confidence")
        or details.get("confidence_level")
        or details.get("ai_confidence_level")
    )

    normalized = normalize_ai_confidence(direct_value)
    if normalized:
        return normalized

    # Fallback based on final evidence when the AI layer did not return text.
    if int(ai_score or 0) > 0 and int(risk_score or 0) >= 70:
        return "High confidence"
    if int(ai_score or 0) > 0 and int(risk_score or 0) >= 30:
        return "Medium confidence"
    if int(risk_score or 0) >= 30:
        return "Low confidence"

    return "Informational confidence"


def add_timeline_event(db: Session, telemetry_id: int, event_type: str, message: str):
    item = IncidentTimeline(
        telemetry_id=telemetry_id,
        event_type=event_type,
        message=message,
        created_at=now_local_naive(),
    )
    db.add(item)



# ============================================================
# AGENT HELPERS
# ============================================================


def upsert_agent_from_registration(
    db: Session,
    payload: AgentRegister | TelemetryCreate | LiveEventCreate,
    last_seen: datetime,
):
    existing_agent = db.query(Agent).filter(Agent.agent_id == payload.agent_id).first()

    if existing_agent:
        existing_agent.hostname = payload.hostname
        existing_agent.ip_address = payload.ip_address
        existing_agent.public_ip = payload.public_ip
        existing_agent.os = payload.os
        existing_agent.country = payload.country
        existing_agent.city = payload.city
        existing_agent.isp = payload.isp
        existing_agent.last_seen = last_seen
        db.commit()
        db.refresh(existing_agent)
        return existing_agent, False

    new_agent = Agent(
        agent_id=payload.agent_id,
        hostname=payload.hostname,
        ip_address=payload.ip_address,
        public_ip=payload.public_ip,
        os=payload.os,
        country=payload.country,
        city=payload.city,
        isp=payload.isp,
        created_at=last_seen,
        last_seen=last_seen,
    )
    db.add(new_agent)
    db.commit()
    db.refresh(new_agent)
    return new_agent, True


# ============================================================
# HOST RISK SUMMARY
# ============================================================


def calculate_host_risk_summary(events: list[Telemetry]) -> dict:
    if not events:
        return {
            "latest_risk": 0,
            "average_risk": 0,
            "high_events_count": 0,
            "host_status": "Unknown",
        }

    latest_events = events[:10]
    risks = [int(item.risk_score or 0) for item in latest_events]

    latest_risk = risks[0] if risks else 0
    average_risk = round(sum(risks) / len(risks), 2) if risks else 0
    high_events_count = sum(1 for r in risks if r >= 70)

    if latest_risk >= 70 or high_events_count >= 3 or average_risk >= 60:
        host_status = "Critical"
    elif latest_risk >= 30 or average_risk >= 30:
        host_status = "Warning"
    else:
        host_status = "Healthy"

    return {
        "latest_risk": latest_risk,
        "average_risk": average_risk,
        "high_events_count": high_events_count,
        "host_status": host_status,
    }


# ============================================================
# SERIALIZERS
# ============================================================


def serialize_telemetry(item: Telemetry, db: Session) -> dict:
    parsed_reasons = parse_risk_reasons(item.risk_reasons)
    top_reason = item.top_reason or (
        parsed_reasons[0] if parsed_reasons else "No specific reason"
    )

    actions_count = (
        db.query(func.count(ResponseAction.id))
        .filter(ResponseAction.telemetry_id == item.id)
        .scalar()
    ) or 0

    return {
        "id": item.id,
        "agent_id": item.agent_id,
        "hostname": item.hostname,
        "ip_address": item.ip_address,
        "public_ip": item.public_ip,
        "os": item.os,
        "country": item.country,
        "city": item.city,
        "isp": item.isp,
        "cpu_percent": item.cpu_percent,
        "memory_percent": item.memory_percent,
        "process_count": item.process_count,
        # 🔥 NEW FLAGS (المهم)
        "connections_count": int(getattr(item, "connections_count", 0) or 0),
        "powershell_flag": int(getattr(item, "powershell_flag", 0) or 0),
        "temp_execution": int(getattr(item, "temp_execution", 0) or 0),
        "suspicious_port": int(getattr(item, "suspicious_port", 0) or 0),
        "decoded_command": getattr(item, "decoded_command", None),
        "decode_method": getattr(item, "decode_method", None),
        "decode_layers": safe_json_load(getattr(item, "decode_layers", None)),
        "decoded_suspicious_keywords": safe_json_load(getattr(item, "decoded_suspicious_keywords", None)),
        "decoded_mitre_technique": getattr(item, "decoded_mitre_technique", None),
        "decoded_mitre_tactic": getattr(item, "decoded_mitre_tactic", None),
        "attack_intent": safe_json_load(getattr(item, "attack_intent", None)),
        "attack_summary": getattr(item, "attack_summary", None),
        "ai_attack_explanation": getattr(item, "ai_attack_explanation", None),

        "ai_attack_category": getattr(item, "ai_attack_category", None),
        "ai_confidence_level": getattr(item, "ai_confidence_level", None),

        "recommended_action": getattr(item, "recommended_action", None),
        "top_cpu_processes": safe_json_load(item.top_cpu_processes),
        "network_connections": safe_json_load(item.network_connections),
        "process_name": item.process_name,
        "command_line": item.command_line,
        "file_path": item.file_path,
        "parent_process": item.parent_process,
        "destination_ip": item.destination_ip,
        "destination_port": item.destination_port,
        "risk_score": int(item.risk_score or 0),
        "rule_score": int(item.rule_score or 0),
        "ai_score": int(item.ai_score or 0),
        "risk_level": risk_level_from_score(int(item.risk_score or 0)),
        "risk_reasons": parsed_reasons,
        "top_reason": top_reason,
        "alert_type": item.alert_type,
        "mitre_technique": item.mitre_technique,
        "mitre_tactic": item.mitre_tactic,
        "detection_source": item.detection_source
        or infer_detection_source(item.rule_score, item.ai_score),
        "event_category": item.event_category or infer_event_category(item.alert_type),
        "severity": item.severity
        or infer_severity_from_score(int(item.risk_score or 0)),
        "incident_status": item.incident_status or "New",
        "response_actions_count": actions_count,
        "timestamp": format_local_timestamp(item.timestamp),
    }


def serialize_response_action(item: ResponseAction) -> dict:
    return {
        "id": item.id,
        "telemetry_id": item.telemetry_id,
        "agent_id": item.agent_id,
        "hostname": item.hostname,
        "action_type": item.action_type,
        "target_value": item.target_value,
        "note": item.note,
        "status": item.status,
        "requested_at": format_local_timestamp(item.requested_at),
        "executed_at": format_local_timestamp(item.executed_at),
        "result_message": item.result_message,
    }


def resolve_response_target(action_type: str, telemetry: Telemetry, requested_target: str | None) -> str | None:
    """Auto-fill a safe target from the telemetry event when the analyst leaves it empty."""
    target = (requested_target or "").strip()
    if target:
        return target

    if action_type == "blocklisted_ip_review":
        return telemetry.destination_ip or telemetry.public_ip or None

    if action_type == "kill_process_request":
        return telemetry.process_name or None

    return None


def validate_response_target(action_type: str, target_value: str | None):
    """Keep response actions safe and clear for lab/demo usage."""
    target = (target_value or "").strip()

    if action_type == "collect_diagnostics":
        return

    if action_type == "mark_host_for_isolation_review":
        return

    if action_type == "blocklisted_ip_review" and not target:
        raise HTTPException(
            status_code=400,
            detail="blocklisted_ip_review requires a target IP. Open an event with destination_ip or enter the IP manually.",
        )

    if action_type == "kill_process_request" and not target:
        raise HTTPException(
            status_code=400,
            detail="kill_process_request requires a process name. Open an event with process_name or enter the process manually.",
        )


def serialize_live_event(item: dict) -> dict:
    event = dict(item)
    ts = event.get("timestamp")
    parsed = parse_client_timestamp(ts)
    event["timestamp"] = format_local_timestamp(parsed or now_local_naive())
    event["received_at"] = event.get("received_at") or format_local_timestamp(
        now_local_naive()
    )
    return event


def push_live_event(item: dict):
    live_events_buffer.appendleft(serialize_live_event(item))


# ============================================================
# STATS
# ============================================================


def build_stats(db: Session) -> dict:
    connected_hosts = db.query(func.count(Agent.id)).scalar() or 0
    total_events = db.query(func.count(Telemetry.id)).scalar() or 0

    avg_cpu = db.query(func.avg(Telemetry.cpu_percent)).scalar()
    avg_ram = db.query(func.avg(Telemetry.memory_percent)).scalar()
    max_risk = db.query(func.max(Telemetry.risk_score)).scalar()
    critical_alerts = (
        db.query(func.count(Telemetry.id)).filter(Telemetry.risk_score >= 70).scalar()
        or 0
    )
    low_alerts = (
        db.query(func.count(Telemetry.id)).filter(Telemetry.risk_score < 30).scalar()
        or 0
    )

    new_incidents = (
        db.query(func.count(Telemetry.id))
        .filter(Telemetry.incident_status == "New")
        .scalar()
        or 0
    )
    investigating_incidents = (
        db.query(func.count(Telemetry.id))
        .filter(Telemetry.incident_status == "Investigating")
        .scalar()
        or 0
    )
    resolved_incidents = (
        db.query(func.count(Telemetry.id))
        .filter(Telemetry.incident_status == "Resolved")
        .scalar()
        or 0
    )
    false_positive_incidents = (
        db.query(func.count(Telemetry.id))
        .filter(Telemetry.incident_status == "False Positive")
        .scalar()
        or 0
    )

    pending_actions = (
        db.query(func.count(ResponseAction.id))
        .filter(ResponseAction.status == "pending")
        .scalar()
        or 0
    )
    executed_actions = (
        db.query(func.count(ResponseAction.id))
        .filter(ResponseAction.status == "executed")
        .scalar()
        or 0
    )
    failed_actions = (
        db.query(func.count(ResponseAction.id))
        .filter(ResponseAction.status == "failed")
        .scalar()
        or 0
    )

    critical_hosts = 0
    warning_hosts = 0
    healthy_hosts = 0

    agents = db.query(Agent.id, Agent.hostname).all()
    for agent in agents:
        host_events = (
            db.query(Telemetry)
            .filter(Telemetry.hostname == agent.hostname)
            .order_by(Telemetry.timestamp.desc())
            .limit(10)
            .all()
        )
        host_summary = calculate_host_risk_summary(host_events)

        if host_summary["host_status"] == "Critical":
            critical_hosts += 1
        elif host_summary["host_status"] == "Warning":
            warning_hosts += 1
        elif host_summary["host_status"] == "Healthy":
            healthy_hosts += 1

    return {
        "connected_hosts": connected_hosts,
        "total_events": total_events,
        "avg_cpu": round(avg_cpu or 0, 2),
        "avg_ram": round(avg_ram or 0, 2),
        "max_risk": int(max_risk or 0),
        "critical_alerts": critical_alerts,
        "low_alerts": low_alerts,
        "new_incidents": new_incidents,
        "investigating_incidents": investigating_incidents,
        "resolved_incidents": resolved_incidents,
        "false_positive_incidents": false_positive_incidents,
        "critical_hosts": critical_hosts,
        "warning_hosts": warning_hosts,
        "healthy_hosts": healthy_hosts,
        "pending_actions": pending_actions,
        "executed_actions": executed_actions,
        "failed_actions": failed_actions,
        "live_events_count": len(live_events_buffer),
        "server_time": format_local_timestamp(now_local_naive()),
    }


# ============================================================
# WEBSOCKET
# ============================================================


@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    try:
        verify_dashboard_token(websocket.query_params.get("token"))
    except HTTPException:
        await websocket.close(code=1008)
        return

    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


# ============================================================
# ROOT / HEALTH
# ============================================================


@app.get("/")
def root():
    return {"message": "Mini EDR backend is running"}


@app.get("/health", response_model=PdfHealthResponse)
def health():
    return {
        "status": "ok",
        "pdf_available": PDF_AVAILABLE,
        "pdf_import_error": PDF_IMPORT_ERROR,
    }


@app.post("/auth/login", response_model=DashboardAuthResponse)
def dashboard_login(payload: DashboardLoginRequest):
    username = payload.username
    password = payload.password

    username_ok = hmac.compare_digest(username, DASHBOARD_AUTH_USERNAME)
    password_ok = hmac.compare_digest(password, DASHBOARD_AUTH_PASSWORD)

    if not (username_ok and password_ok):
        backend_logger.warning("Failed dashboard login for username=%s", username)
        raise HTTPException(status_code=401, detail="Invalid username or password")

    return {
        "access_token": create_dashboard_token(username),
        "token_type": "bearer",
        "username": username,
        "expires_in": DASHBOARD_TOKEN_TTL_SECONDS,
    }


@app.post("/decode-command", response_model=DecodeCommandResponse)
def decode_command(
    payload: DecodeCommandRequest,
    _username: str = Depends(require_dashboard_auth),
):
    return decode_base64_command(payload.command)


# ============================================================
# REGISTER
# ============================================================


@app.post("/register")
async def register_agent(payload: AgentRegister, db: Session = Depends(get_db)):
    agent, created = upsert_agent_from_registration(
        db=db,
        payload=payload,
        last_seen=now_local_naive(),
    )

    return {
        "message": "Agent registered" if created else "Agent updated",
        "agent_id": agent.agent_id,
    }


# ============================================================
# LIVE EVENTS
# ============================================================


@app.post("/events/live")
async def create_live_event(payload: LiveEventCreate, db: Session = Depends(get_db)):
    agent_id = str(payload.agent_id or "").strip()
    hostname = str(payload.hostname or "").strip()

    if not agent_id or not hostname:
        raise HTTPException(
            status_code=400, detail="agent_id and hostname are required"
        )

    event_timestamp = parse_client_timestamp(payload.timestamp) or now_local_naive()

    upsert_agent_from_registration(
        db=db,
        payload=payload,
        last_seen=event_timestamp,
    )

    event = {
        "agent_id": agent_id,
        "hostname": hostname,
        "ip_address": payload.ip_address,
        "public_ip": payload.public_ip,
        "os": payload.os,
        "country": payload.country,
        "city": payload.city,
        "isp": payload.isp,
        "event_type": payload.event_type,
        "event_title": payload.event_title or "Live Event",
        "event_category": payload.event_category,
        "severity": payload.severity or "Medium",
        "process_name": payload.process_name,
        "pid": payload.pid,
        "command_line": payload.command_line,
        "file_path": payload.file_path,
        "parent_process": payload.parent_process,
        "destination_ip": payload.destination_ip,
        "destination_port": payload.destination_port,
        "connection_status": payload.connection_status,
        "reason": payload.reason,
        "reason_details": payload.reason_details or [],
        "timestamp": format_local_timestamp(event_timestamp),
        "received_at": format_local_timestamp(now_local_naive()),
    }

    push_live_event(event)

    stats_data = build_stats(db)

    await manager.broadcast_json({"type": "live_event_created", "data": event})
    await manager.broadcast_json({"type": "stats_updated", "data": stats_data})

    return {
        "message": "Live event received",
        "timestamp": event["timestamp"],
        "event_title": event["event_title"],
    }


@app.get("/events/live")
def get_live_events(
    limit: int = 100,
    _username: str = Depends(require_dashboard_auth),
):
    limit = max(1, min(limit, LIVE_EVENTS_LIMIT))
    return list(live_events_buffer)[:limit]


# ============================================================
# TELEMETRY
# ============================================================


@app.post("/telemetry")
async def create_telemetry(payload: dict, db: Session = Depends(get_db)):
    """
    Main telemetry ingestion endpoint.

    Important engineering choices:
    - Accept raw dict instead of TelemetryCreate so new Agent fields are not dropped by Pydantic.
    - Normalize JSON strings from Agent before detection.
    - Never let optional dataset logging or detection errors crash the endpoint.
    - Filter DB kwargs by actual Telemetry model columns to avoid 500 if the model/DB is older.
    - Always INSERT security-relevant telemetry. Merge only low-risk duplicate
      heartbeat rows in a short window to keep log management usable.
    """

    raw_payload = dict(payload or {})

    def as_int(value, default=0):
        try:
            if value is None or value == "":
                return default
            return int(value)
        except Exception:
            return default

    def as_float(value, default=0.0):
        try:
            if value is None or value == "":
                return default
            return float(value)
        except Exception:
            return default

    def normalize_json_list(value):
        if value is None or value == "":
            return []
        if isinstance(value, list):
            return value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                return parsed if isinstance(parsed, list) else []
            except Exception:
                return []
        return []

    # Build event for detection as lists, not raw JSON strings.
    event = dict(raw_payload)
    event["top_cpu_processes"] = normalize_json_list(event.get("top_cpu_processes"))
    event["network_connections"] = normalize_json_list(event.get("network_connections"))

    # Force numeric fields to safe values.
    event["cpu_percent"] = as_float(event.get("cpu_percent"), 0.0)
    event["memory_percent"] = as_float(event.get("memory_percent"), 0.0)
    event["process_count"] = as_int(event.get("process_count"), 0)
    event["connections_count"] = as_int(event.get("connections_count"), 0)
    event["powershell_flag"] = as_int(event.get("powershell_flag"), 0)
    event["temp_execution"] = as_int(event.get("temp_execution"), 0)
    event["suspicious_port"] = as_int(event.get("suspicious_port"), 0)

    # Optional dataset logging. It must never break telemetry.
    try:
        save_to_dataset(event)
    except Exception as e:
        backend_logger.warning("dataset logging failed: %s", e)

    try:
        detection_result = calculate_risk_score(event)
        if not isinstance(detection_result, dict):
            detection_result = {}
    except Exception as e:
        backend_logger.exception("calculate_risk_score failed")
        detection_result = {
            "risk_score": 10,
            "rule_score": 0,
            "ai_score": 0,
            "risk_reasons": [f"Detection engine error: {e}"],
            "top_reason": "Detection engine error; telemetry stored safely",
            "alert_type": "Detection Engine Error",
            "mitre_technique": None,
            "mitre_tactic": None,
            "detection_source": "Backend",
            "event_category": "system_error",
            "severity": "Low",
            "powershell_flag": event["powershell_flag"],
            "temp_execution": event["temp_execution"],
            "suspicious_port": event["suspicious_port"],
            "connections_count": event["connections_count"],
            "decoded_command": None,
            "decode_method": None,
            "decode_layers": [],
            "decoded_suspicious_keywords": [],
            "decoded_mitre_technique": None,
            "decoded_mitre_tactic": None,
            "attack_intent": [],
            "attack_summary": None,
            "ai_attack_explanation": None,
            "ai_attack_category": "Benign / Informational",
            "ai_confidence_level": "Informational confidence",
            "recommended_action": "No immediate response required. Continue monitoring.",
            "debug_extracted": {},
        }

    telemetry_timestamp = parse_client_timestamp(raw_payload.get("timestamp")) or now_local_naive()

    rule_score = clamp_score(detection_result.get("rule_score", 0), 0, 100)
    ai_score = clamp_score(detection_result.get("ai_score", 0), 0, 100)
    risk_score = clamp_score(detection_result.get("risk_score", 0), 0, 100)

    detection_source = (
        raw_payload.get("detection_source")
        or detection_result.get("detection_source")
        or infer_detection_source(rule_score, ai_score)
    )

    event_category = (
        raw_payload.get("event_category")
        or detection_result.get("event_category")
        or infer_event_category(detection_result.get("alert_type"))
    )

    severity = (
        detection_result.get("severity")
        or raw_payload.get("severity")
        or infer_severity_from_score(risk_score)
    )

    severity_map = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }
    severity = severity_map.get(str(severity).lower(), str(severity))

    risk_reasons = detection_result.get("risk_reasons") or []
    if not isinstance(risk_reasons, list):
        risk_reasons = [str(risk_reasons)]

    top_reason = choose_top_reason(detection_result)

    ai_attack_category = resolve_ai_attack_category(detection_result, event_category)
    ai_confidence_level = resolve_ai_confidence_level(
        detection_result=detection_result,
        risk_score=risk_score,
        ai_score=ai_score,
    )

    extracted = detection_result.get("debug_extracted") or {}

    final_process_name = raw_payload.get("process_name") or extracted.get("process_name")
    final_command_line = raw_payload.get("command_line") or extracted.get("command_line")
    final_file_path = raw_payload.get("file_path") or extracted.get("file_path")
    final_parent_process = raw_payload.get("parent_process") or extracted.get("parent_process")
    final_destination_ip = raw_payload.get("destination_ip") or extracted.get("destination_ip")
    final_destination_port = raw_payload.get("destination_port") or extracted.get("destination_port")

    # Preserve raw JSON strings for DB storage. If Agent sent lists, serialize them.
    top_cpu_for_db = raw_payload.get("top_cpu_processes")
    if not isinstance(top_cpu_for_db, str):
        top_cpu_for_db = json.dumps(event.get("top_cpu_processes", []), ensure_ascii=False)

    network_for_db = raw_payload.get("network_connections")
    if not isinstance(network_for_db, str):
        network_for_db = json.dumps(event.get("network_connections", []), ensure_ascii=False)

    telemetry_data = {
        "agent_id": raw_payload.get("agent_id"),
        "hostname": raw_payload.get("hostname"),
        "ip_address": raw_payload.get("ip_address"),
        "public_ip": raw_payload.get("public_ip"),
        "os": raw_payload.get("os"),
        "country": raw_payload.get("country"),
        "city": raw_payload.get("city"),
        "isp": raw_payload.get("isp"),
        "cpu_percent": event["cpu_percent"],
        "memory_percent": event["memory_percent"],
        "process_count": event["process_count"],
        "connections_count": detection_result.get("connections_count", event["connections_count"]) or 0,
        "powershell_flag": detection_result.get("powershell_flag", event["powershell_flag"]) or 0,
        "temp_execution": detection_result.get("temp_execution", event["temp_execution"]) or 0,
        "suspicious_port": detection_result.get("suspicious_port", event["suspicious_port"]) or 0,
        "decoded_command": detection_result.get("decoded_command"),
        "decode_method": detection_result.get("decode_method"),
        "decode_layers": json.dumps(detection_result.get("decode_layers") or [], ensure_ascii=False),
        "decoded_suspicious_keywords": json.dumps(detection_result.get("decoded_suspicious_keywords") or [], ensure_ascii=False),
        "decoded_mitre_technique": detection_result.get("decoded_mitre_technique"),
        "decoded_mitre_tactic": detection_result.get("decoded_mitre_tactic"),
        "attack_intent": json.dumps(detection_result.get("attack_intent") or [], ensure_ascii=False),
        "attack_summary": detection_result.get("attack_summary"),
        "ai_attack_explanation": detection_result.get("ai_attack_explanation"),

        "ai_attack_category": ai_attack_category,
        "ai_confidence_level": ai_confidence_level,

        "recommended_action": detection_result.get("recommended_action"),
        "top_cpu_processes": top_cpu_for_db,
        "network_connections": network_for_db,
        "process_name": final_process_name,
        "command_line": final_command_line,
        "file_path": final_file_path,
        "parent_process": final_parent_process,
        "destination_ip": final_destination_ip,
        "destination_port": final_destination_port,
        "risk_score": risk_score,
        "rule_score": rule_score,
        "ai_score": ai_score,
        "risk_reasons": json.dumps(risk_reasons, ensure_ascii=False),
        "top_reason": top_reason,
        "alert_type": detection_result.get("alert_type"),
        "mitre_technique": detection_result.get("mitre_technique"),
        "mitre_tactic": detection_result.get("mitre_tactic"),
        "detection_source": detection_source,
        "event_category": event_category,
        "severity": severity,
        "incident_status": raw_payload.get("incident_status") or "New",
        "timestamp": telemetry_timestamp,
        
    }

    # Prevent SQLAlchemy invalid keyword errors if models.py is behind main.py.
    valid_columns = {column.name for column in Telemetry.__table__.columns}
    telemetry_data = {k: v for k, v in telemetry_data.items() if k in valid_columns}

    try:
        agent_payload = SimpleNamespace(
            agent_id=raw_payload.get("agent_id"),
            hostname=raw_payload.get("hostname"),
            ip_address=raw_payload.get("ip_address"),
            public_ip=raw_payload.get("public_ip"),
            os=raw_payload.get("os"),
            country=raw_payload.get("country"),
            city=raw_payload.get("city"),
            isp=raw_payload.get("isp"),
        )

        upsert_agent_from_registration(
            db=db,
            payload=agent_payload,
            last_seen=telemetry_timestamp,
        )

        # Always insert a new telemetry row.
        # Do not merge/deduplicate Low events; the Telemetry page should show every payload.
        telemetry = Telemetry(**telemetry_data)
        db.add(telemetry)
        db.commit()
        db.refresh(telemetry)

        telemetry_was_merged = False

        add_timeline_event(
            db=db,
            telemetry_id=telemetry.id,
            event_type="created",
            message=(
                f"Incident created: {telemetry.alert_type or 'Telemetry event'} "
                f"with {telemetry.severity or 'Low'} severity"
            ),
        )

        if int(telemetry.risk_score or 0) >= 30:
            add_timeline_event(
                db=db,
                telemetry_id=telemetry.id,
                event_type="detection",
                message=(
                    f"Detection triggered: {telemetry.top_reason or telemetry.alert_type or 'Suspicious activity'} "
                    f"| score={int(telemetry.risk_score or 0)}/100"
                ),
            )

        db.commit()

    except Exception as e:
        db.rollback()
        backend_logger.exception("telemetry DB insert failed")
        raise HTTPException(status_code=500, detail=f"Telemetry DB insert failed: {e}")

    serialized = serialize_telemetry(telemetry, db)
    stats_data = build_stats(db)

    event_type = "telemetry_updated" if telemetry_was_merged else "telemetry_created"
    await manager.broadcast_json({"type": event_type, "data": serialized})
    await manager.broadcast_json({"type": "stats_updated", "data": stats_data})

    return {
        "message": "Telemetry merged" if telemetry_was_merged else "Telemetry stored",
        "id": telemetry.id,
        "risk_score": telemetry.risk_score,
        "rule_score": telemetry.rule_score,
        "ai_score": telemetry.ai_score,
        "risk_level": risk_level_from_score(telemetry.risk_score),
        "risk_reasons": risk_reasons,
        "top_reason": telemetry.top_reason,
        "alert_type": telemetry.alert_type,
        "mitre_technique": telemetry.mitre_technique,
        "mitre_tactic": telemetry.mitre_tactic,
        "detection_source": telemetry.detection_source,
        "event_category": telemetry.event_category,
        "severity": telemetry.severity,
        "decoded_command": getattr(telemetry, "decoded_command", None),
        "decode_method": getattr(telemetry, "decode_method", None),
        "decode_layers": safe_json_load(getattr(telemetry, "decode_layers", None)),
        "decoded_suspicious_keywords": safe_json_load(getattr(telemetry, "decoded_suspicious_keywords", None)),
        "decoded_mitre_technique": getattr(telemetry, "decoded_mitre_technique", None),
        "decoded_mitre_tactic": getattr(telemetry, "decoded_mitre_tactic", None),
        "attack_intent": safe_json_load(getattr(telemetry, "attack_intent", None)),
        "attack_summary": getattr(telemetry, "attack_summary", None),
        "ai_attack_explanation": getattr(telemetry, "ai_attack_explanation", None),
        "ai_attack_category": getattr(telemetry, "ai_attack_category", None),
        "ai_confidence_level": getattr(telemetry, "ai_confidence_level", None),
        "recommended_action": getattr(telemetry, "recommended_action", None),
        "incident_status": telemetry.incident_status,
        "timestamp": format_local_timestamp(telemetry.timestamp),
    }

@app.get("/telemetry/{telemetry_id}/timeline")
def get_incident_timeline(
    telemetry_id: int,
    db: Session = Depends(get_db),
    _username: str = Depends(require_dashboard_auth),
):
    telemetry = db.query(Telemetry).filter(Telemetry.id == telemetry_id).first()
    telemetry_timestamp = telemetry.timestamp if telemetry else None

    rows = (
        db.query(IncidentTimeline)
        .filter(IncidentTimeline.telemetry_id == telemetry_id)
        .order_by(IncidentTimeline.created_at.asc())
        .all()
    )

    return [
        {
            "id": row.id,
            "telemetry_id": row.telemetry_id,
            "event_type": row.event_type,
            "message": row.message,
            "created_at": format_local_timestamp(
                correct_legacy_timeline_timestamp(row.created_at, telemetry_timestamp)
            ),
        }
        for row in rows
    ]

@app.get("/telemetry")
def get_telemetry(
    limit: int = 300,
    db: Session = Depends(get_db),
    _username: str = Depends(require_dashboard_auth),
):

    # حماية من القيم الكبيرة
    limit = max(1, min(limit, 500))

    rows = db.query(Telemetry).order_by(Telemetry.timestamp.desc()).limit(limit).all()

    return [serialize_telemetry(item, db) for item in rows]


@app.get("/stats")
def get_stats(
    db: Session = Depends(get_db),
    _username: str = Depends(require_dashboard_auth),
):
    return build_stats(db)


# ============================================================
# INCIDENT STATUS
# ============================================================

@app.patch("/telemetry/{telemetry_id}/status")
async def update_incident_status(
    telemetry_id: int,
    payload: IncidentStatusUpdate,
    db: Session = Depends(get_db),
    _username: str = Depends(require_dashboard_auth),
):
    new_status = (payload.incident_status or "").strip()

    if new_status not in ALLOWED_INCIDENT_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid incident status. Allowed values: {sorted(ALLOWED_INCIDENT_STATUSES)}",
        )

    item = db.query(Telemetry).filter(Telemetry.id == telemetry_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Telemetry event not found")

    old_status = item.incident_status or "New"

    if old_status == new_status:
        serialized = serialize_telemetry(item, db)
        return {
            "message": "No status change",
            "id": item.id,
            "incident_status": item.incident_status,
        }

    item.incident_status = new_status

    add_timeline_event(
        db=db,
        telemetry_id=item.id,
        event_type="status_changed",
        message=f"Status changed from {old_status} to {new_status}",
    )

    db.commit()
    db.refresh(item)

    serialized = serialize_telemetry(item, db)
    stats_data = build_stats(db)

    await manager.broadcast_json({"type": "telemetry_updated", "data": serialized})
    await manager.broadcast_json({"type": "stats_updated", "data": stats_data})

    return {
        "message": "Incident status updated successfully",
        "id": item.id,
        "incident_status": item.incident_status,
    }



# ============================================================
# RESPONSE ACTIONS
# ============================================================


@app.post("/response-actions")
async def create_response_action(
    payload: ResponseActionCreate,
    db: Session = Depends(get_db),
    _username: str = Depends(require_dashboard_auth),
):
    action_type = (payload.action_type or "").strip()

    if action_type not in ALLOWED_RESPONSE_ACTIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action_type. Allowed values: {sorted(ALLOWED_RESPONSE_ACTIONS)}",
        )

    telemetry = db.query(Telemetry).filter(Telemetry.id == payload.telemetry_id).first()
    if not telemetry:
        raise HTTPException(status_code=404, detail="Telemetry event not found")

    # Safety: never let the UI create an action for a different endpoint than the event owner.
    if payload.agent_id != telemetry.agent_id:
        raise HTTPException(
            status_code=400,
            detail="Agent mismatch: response action must target the same agent that generated the telemetry event.",
        )

    target_value = resolve_response_target(action_type, telemetry, payload.target_value)
    validate_response_target(action_type, target_value)

    existing = (
        db.query(ResponseAction)
        .filter(
            ResponseAction.telemetry_id == telemetry.id,
            ResponseAction.action_type == action_type,
            ResponseAction.status.in_(["pending", "in_progress"]),
        )
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=409,
            detail=f"A {action_type} action is already {existing.status} for this incident.",
        )

    action = ResponseAction(
        telemetry_id=telemetry.id,
        agent_id=telemetry.agent_id,
        hostname=telemetry.hostname,
        action_type=action_type,
        target_value=target_value,
        note=payload.note,
        status="pending",
        requested_at=now_local_naive(),
    )

    db.add(action)

    old_status = telemetry.incident_status or "New"
    if old_status == "New":
        telemetry.incident_status = "Investigating"
        add_timeline_event(
            db=db,
            telemetry_id=telemetry.id,
            event_type="status_changed",
            message="Status automatically changed from New to Investigating after response action creation",
        )

    target_note = f" | target={target_value}" if target_value else ""
    add_timeline_event(
        db=db,
        telemetry_id=telemetry.id,
        event_type="response_action_created",
        message=f"Response action queued: {action_type}{target_note}",
    )

    db.commit()
    db.refresh(action)
    db.refresh(telemetry)

    serialized = serialize_response_action(action)
    stats_data = build_stats(db)

    await manager.broadcast_json({"type": "response_action_created", "data": serialized})
    await manager.broadcast_json({"type": "telemetry_updated", "data": serialize_telemetry(telemetry, db)})
    await manager.broadcast_json({"type": "stats_updated", "data": stats_data})

    return {
        "message": "Response action queued successfully",
        **serialized,
    }


@app.get("/response-actions")
def get_response_actions(
    db: Session = Depends(get_db),
    _username: str = Depends(require_dashboard_auth),
):
    rows = (
        db.query(ResponseAction)
        .order_by(ResponseAction.requested_at.desc())
        .limit(200)
        .all()
    )
    return [serialize_response_action(item) for item in rows]


@app.get("/agents/{agent_id}/response-actions/pending")
def get_pending_actions_for_agent(agent_id: str, db: Session = Depends(get_db)):
    rows = (
        db.query(ResponseAction)
        .filter(ResponseAction.agent_id == agent_id, ResponseAction.status == "pending")
        .order_by(ResponseAction.requested_at.asc())
        .all()
    )
    return [serialize_response_action(item) for item in rows]


@app.patch("/response-actions/{action_id}/result")
async def update_response_action_result(
    action_id: int,
    payload: ResponseActionResultUpdate,
    db: Session = Depends(get_db),
):
    new_status = (payload.status or "").strip()

    if new_status not in ALLOWED_RESPONSE_RESULTS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid status. Allowed values: {sorted(ALLOWED_RESPONSE_RESULTS)}",
        )

    item = db.query(ResponseAction).filter(ResponseAction.id == action_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Response action not found")

    old_status = item.status
    item.status = new_status
    item.result_message = payload.result_message
    item.executed_at = (
        now_local_naive() if new_status in {"executed", "failed"} else item.executed_at
    )

    add_timeline_event(
        db=db,
        telemetry_id=item.telemetry_id,
        event_type="response_action_updated",
        message=(
            f"Response action {item.action_type} changed from {old_status} to {new_status}"
            + (f" | result={payload.result_message}" if payload.result_message else "")
        ),
    )

    db.commit()
    db.refresh(item)

    serialized = serialize_response_action(item)
    stats_data = build_stats(db)

    related_telemetry = db.query(Telemetry).filter(Telemetry.id == item.telemetry_id).first()

    await manager.broadcast_json(
        {"type": "response_action_updated", "data": serialized}
    )
    if related_telemetry:
        await manager.broadcast_json(
            {"type": "telemetry_updated", "data": serialize_telemetry(related_telemetry, db)}
        )
    await manager.broadcast_json({"type": "stats_updated", "data": stats_data})

    return {
        "message": "Response action result updated",
        "id": item.id,
        "status": item.status,
        "executed_at": format_local_timestamp(item.executed_at),
        "result_message": item.result_message,
    }


# ============================================================
# AGENTS
# ============================================================


@app.get("/agents")
def get_agents(
    db: Session = Depends(get_db),
    _username: str = Depends(require_dashboard_auth),
):
    agents = (
        db.query(Agent).order_by(Agent.last_seen.desc(), Agent.created_at.desc()).all()
    )
    response = []

    for agent in agents:
        host_events = (
            db.query(Telemetry)
            .filter(Telemetry.hostname == agent.hostname)
            .order_by(Telemetry.timestamp.desc())
            .limit(10)
            .all()
        )

        host_summary = calculate_host_risk_summary(host_events)

        response.append(
            {
                "id": agent.id,
                "agent_id": agent.agent_id,
                "hostname": agent.hostname,
                "ip_address": agent.ip_address,
                "public_ip": agent.public_ip,
                "os": agent.os,
                "country": agent.country,
                "city": agent.city,
                "isp": agent.isp,
                "created_at": format_local_timestamp(agent.created_at),
                "last_seen": format_local_timestamp(agent.last_seen),
                "online_status": get_agent_online_status(agent.last_seen),
                "latest_risk": host_summary["latest_risk"],
                "average_risk": host_summary["average_risk"],
                "high_events_count": host_summary["high_events_count"],
                "host_status": host_summary["host_status"],
            }
        )

    return response


# ============================================================
# EXPORT CSV
# ============================================================


@app.get("/export/telemetry.csv")
def export_telemetry_csv(
    db: Session = Depends(get_db),
    _username: str = Depends(require_dashboard_auth),
):
    rows = db.query(Telemetry).order_by(Telemetry.timestamp.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(
        [
            "id",
            "agent_id",
            "hostname",
            "local_ip",
            "public_ip",
            "os",
            "country",
            "city",
            "isp",
            "timestamp",
            "risk_score",
            "rule_score",
            "ai_score",
            "risk_level",
            "severity",
            "detection_source",
            "event_category",
            "incident_status",
            "alert_type",
            "mitre_technique",
            "mitre_tactic",
            "top_reason",
            "process_name",
            "parent_process",
            "destination_ip",
            "destination_port",
            "risk_reasons",
            "decoded_command",
            "decode_method",
            "decode_layers",
            "decoded_suspicious_keywords",
            "decoded_mitre_technique",
            "decoded_mitre_tactic",
            "attack_intent",
            "attack_summary",
            "ai_attack_explanation",
            "ai_attack_category",
            "ai_confidence_level",
            "recommended_action",
        ]
    )

    for item in rows:
        parsed_reasons = parse_risk_reasons(item.risk_reasons)
        writer.writerow(
            [
                item.id,
                item.agent_id,
                item.hostname,
                item.ip_address,
                item.public_ip,
                item.os,
                item.country,
                item.city,
                item.isp,
                format_local_timestamp(item.timestamp) or "",
                int(item.risk_score or 0),
                int(item.rule_score or 0),
                int(item.ai_score or 0),
                risk_level_from_score(int(item.risk_score or 0)),
                item.severity or "",
                item.detection_source or "",
                item.event_category or "",
                item.incident_status or "New",
                item.alert_type or "",
                item.mitre_technique or "",
                item.mitre_tactic or "",
                item.top_reason or "",
                item.process_name or "",
                item.parent_process or "",
                item.destination_ip or "",
                item.destination_port or "",
                " | ".join(map(str, parsed_reasons)),
                getattr(item, "decoded_command", None) or "",
                getattr(item, "decode_method", None) or "",
                " | ".join(map(str, safe_json_load(getattr(item, "decode_layers", None)))),
                " | ".join(map(str, safe_json_load(getattr(item, "decoded_suspicious_keywords", None)))),
                getattr(item, "decoded_mitre_technique", None) or "",
                getattr(item, "decoded_mitre_tactic", None) or "",
                " | ".join(map(str, safe_json_load(getattr(item, "attack_intent", None)))),
                getattr(item, "attack_summary", None) or "",
                getattr(item, "ai_attack_explanation", None) or "",
                getattr(item, "ai_attack_category", None) or "",
                getattr(item, "ai_confidence_level", None) or "",
                getattr(item, "recommended_action", None) or "",
            ]
        )

    output.seek(0)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=mini_edr_telemetry_report.csv"
        },
    )


# ============================================================
# EXPORT PDF
# ============================================================


@app.get("/export/report.pdf")
def export_pdf_report(
    db: Session = Depends(get_db),
    _username: str = Depends(require_dashboard_auth),
):
    if not PDF_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail=f"PDF export is unavailable because reportlab is not installed correctly. Error: {PDF_IMPORT_ERROR}",
        )

    stats = build_stats(db)

    recent_alerts = (
        db.query(Telemetry).order_by(Telemetry.timestamp.desc()).limit(10).all()
    )
    high_alerts = (
        db.query(Telemetry)
        .filter(Telemetry.risk_score >= 70)
        .order_by(Telemetry.risk_score.desc(), Telemetry.timestamp.desc())
        .limit(10)
        .all()
    )

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "TitleStyle",
        parent=styles["Title"],
        fontSize=22,
        leading=26,
        textColor=colors.HexColor("#0F172A"),
        spaceAfter=10,
    )
    subtitle_style = ParagraphStyle(
        "SubtitleStyle",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#475569"),
        spaceAfter=10,
    )
    section_style = ParagraphStyle(
        "SectionStyle",
        parent=styles["Heading2"],
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#1D4ED8"),
        spaceAfter=8,
        spaceBefore=10,
    )
    body_style = ParagraphStyle(
        "BodyStyle",
        parent=styles["BodyText"],
        fontSize=9,
        leading=12,
        textColor=colors.black,
    )

    elements = []

    elements.append(Paragraph("Mini EDR Security Report", title_style))
    elements.append(
        Paragraph(
            f"Generated on: {now_local().strftime('%Y-%m-%d %H:%M:%S')}",
            subtitle_style,
        )
    )
    elements.append(
        Paragraph(
            "This report summarizes the current security visibility of the Mini EDR platform, "
            "including host status, incident workflow, detections, and geo-enriched endpoint context.",
            body_style,
        )
    )
    elements.append(Spacer(1, 8))

    elements.append(Paragraph("1. Executive Summary", section_style))
    summary_table_data = [
        ["Metric", "Value"],
        ["Connected Hosts", str(stats["connected_hosts"])],
        ["Total Events", str(stats["total_events"])],
        ["Critical Alerts", str(stats["critical_alerts"])],
        ["Highest Risk", str(stats["max_risk"])],
        ["Critical Hosts", str(stats["critical_hosts"])],
        ["Warning Hosts", str(stats["warning_hosts"])],
        ["Healthy Hosts", str(stats["healthy_hosts"])],
        ["Pending Actions", str(stats["pending_actions"])],
        ["Executed Actions", str(stats["executed_actions"])],
        ["Failed Actions", str(stats["failed_actions"])],
        ["Live Events In Memory", str(stats["live_events_count"])],
    ]

    summary_table = Table(summary_table_data, colWidths=[90 * mm, 70 * mm])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1D4ED8")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#94A3B8")),
                ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F8FAFC")),
            ]
        )
    )
    elements.append(summary_table)

    elements.append(Paragraph("2. Top High-Risk Alerts", section_style))
    if high_alerts:
        high_alerts_data = [
            [
                "Host",
                "Severity",
                "Final",
                "Source",
                "Alert Type",
                "MITRE",
            ]
        ]

        for item in high_alerts:
            mitre_display = (
                f"{item.mitre_technique or '-'} / {item.mitre_tactic or '-'}"
            )
            high_alerts_data.append(
                [
                    item.hostname or "-",
                    item.severity or infer_severity_from_score(item.risk_score or 0),
                    str(item.risk_score or 0),
                    item.detection_source
                    or infer_detection_source(item.rule_score, item.ai_score),
                    item.alert_type or "-",
                    mitre_display,
                ]
            )

        high_alerts_table = Table(
            high_alerts_data,
            colWidths=[30 * mm, 22 * mm, 14 * mm, 24 * mm, 55 * mm, 35 * mm],
            repeatRows=1,
        )
        high_alerts_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#B91C1C")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#94A3B8")),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.white),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                ]
            )
        )
        elements.append(high_alerts_table)
    else:
        elements.append(Paragraph("No high-risk alerts found.", body_style))

    elements.append(Paragraph("3. Recent Events Snapshot", section_style))
    if recent_alerts:
        recent_events_data = [
            [
                "Timestamp",
                "Host",
                "Severity",
                "Alert",
                "Top Reason",
            ]
        ]

        for item in recent_alerts:
            recent_events_data.append(
                [
                    format_local_timestamp(item.timestamp) or "-",
                    item.hostname or "-",
                    item.severity or infer_severity_from_score(item.risk_score or 0),
                    item.alert_type or "-",
                    item.top_reason or "-",
                ]
            )

        recent_events_table = Table(
            recent_events_data,
            colWidths=[45 * mm, 28 * mm, 20 * mm, 40 * mm, 36 * mm],
            repeatRows=1,
        )
        recent_events_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#334155")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#94A3B8")),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F8FAFC")),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                ]
            )
        )
        elements.append(recent_events_table)
    else:
        elements.append(Paragraph("No recent events available.", body_style))

    doc.build(elements)
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": "attachment; filename=mini_edr_security_report.pdf"
        },
    )
