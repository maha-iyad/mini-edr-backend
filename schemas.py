from typing import List, Optional

from pydantic import BaseModel, Field, field_validator


# ============================================================
# COMMON HELPERS
# ============================================================

def clean_string(value: str) -> str:
    return value.strip()


# ============================================================
# AGENT
# ============================================================

class AgentRegister(BaseModel):
    agent_id: str = Field(..., min_length=1)
    hostname: str = Field(..., min_length=1)

    ip_address: Optional[str] = None
    public_ip: Optional[str] = None
    os: Optional[str] = None

    country: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None

    @field_validator("agent_id", "hostname")
    @classmethod
    def validate_required_fields(cls, value):
        return clean_string(value)


# ============================================================
# TELEMETRY
# ============================================================

class TelemetryCreate(BaseModel):
    agent_id: str = Field(..., min_length=1)
    hostname: str = Field(..., min_length=1)

    ip_address: Optional[str] = None
    public_ip: Optional[str] = None
    os: Optional[str] = None

    country: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None

    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    process_count: int = 0
    connections_count: int = 0

    suspicious_port: int = 0
    powershell_flag: int = 0
    temp_execution: int = 0

    top_cpu_processes: Optional[str] = None
    network_connections: Optional[str] = None

    process_name: Optional[str] = None
    command_line: Optional[str] = None
    file_path: Optional[str] = None
    parent_process: Optional[str] = None

    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None

    timestamp: Optional[str] = None

    detection_source: Optional[str] = None
    event_category: Optional[str] = None
    severity: Optional[str] = None
    ai_attack_category: Optional[str] = None
    ai_confidence_level: Optional[str] = None
    risk_score: Optional[int] = 0
    ai_score: Optional[int] = 0

    @field_validator("agent_id", "hostname")
    @classmethod
    def validate_required_fields(cls, value):
        return clean_string(value)

    @field_validator("cpu_percent", "memory_percent")
    @classmethod
    def validate_percentages(cls, value):
        return max(0.0, min(float(value), 100.0))

    @field_validator("process_count", "connections_count")
    @classmethod
    def validate_positive_numbers(cls, value):
        return max(0, int(value))


# ============================================================
# LIVE EVENTS
# ============================================================

class LiveEventCreate(BaseModel):
    agent_id: str = Field(..., min_length=1)
    hostname: str = Field(..., min_length=1)

    ip_address: Optional[str] = None
    public_ip: Optional[str] = None
    os: Optional[str] = None

    country: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None

    timestamp: Optional[str] = None

    event_type: Optional[str] = None
    event_title: Optional[str] = None
    event_category: Optional[str] = None
    severity: Optional[str] = None
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    process_count: int = 0

    process_name: Optional[str] = None
    pid: Optional[int] = None

    command_line: Optional[str] = None
    file_path: Optional[str] = None
    parent_process: Optional[str] = None

    destination_ip: Optional[str] = None
    destination_port: Optional[int] = None
    connection_status: Optional[str] = None

    reason: Optional[str] = None
    reason_details: Optional[List[str]] = None

    @field_validator("agent_id", "hostname")
    @classmethod
    def validate_required_fields(cls, value):
        return clean_string(value)

    @field_validator("cpu_percent", "memory_percent")
    @classmethod
    def validate_live_percentages(cls, value):
        return max(0.0, min(float(value), 100.0))

    @field_validator("process_count")
    @classmethod
    def validate_live_process_count(cls, value):
        return max(0, int(value))


# ============================================================
# DASHBOARD AUTH
# ============================================================

class DashboardLoginRequest(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)

    @field_validator("username", "password")
    @classmethod
    def validate_credentials(cls, value):
        return clean_string(value)


class DashboardAuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str
    expires_in: int


# ============================================================
# INCIDENT STATUS
# ============================================================

class IncidentStatusUpdate(BaseModel):
    incident_status: str = Field(..., min_length=1)

    @field_validator("incident_status")
    @classmethod
    def validate_status(cls, value):
        return clean_string(value)


# ============================================================
# RESPONSE ACTIONS
# ============================================================

class ResponseActionCreate(BaseModel):
    telemetry_id: int

    agent_id: str = Field(..., min_length=1)
    hostname: str = Field(..., min_length=1)

    action_type: str = Field(..., min_length=1)

    target_value: Optional[str] = None
    note: Optional[str] = None

    @field_validator("agent_id", "hostname", "action_type")
    @classmethod
    def validate_strings(cls, value):
        return clean_string(value)


class ResponseActionResultUpdate(BaseModel):
    status: str = Field(..., min_length=1)
    result_message: Optional[str] = None

    @field_validator("status")
    @classmethod
    def validate_status(cls, value):
        return clean_string(value)


# ============================================================
# COMMAND DECODING
# ============================================================

class DecodeCommandRequest(BaseModel):
    command: str = Field(..., min_length=1)

    @field_validator("command")
    @classmethod
    def validate_command(cls, value):
        return clean_string(value)


class DecodeCommandResponse(BaseModel):
    success: bool

    extracted_base64: Optional[str] = None
    decoded_text: Optional[str] = None

    message: Optional[str] = None


# ============================================================
# PDF HEALTH
# ============================================================

class PdfHealthResponse(BaseModel):
    status: str
    pdf_available: bool
    pdf_import_error: Optional[str] = None
