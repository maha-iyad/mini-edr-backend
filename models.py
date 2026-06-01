from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from database import Base


try:
    LOCAL_TIMEZONE = ZoneInfo("Asia/Amman")
except Exception:
    LOCAL_TIMEZONE = timezone(timedelta(hours=3))


def local_now_naive():
    return datetime.now(LOCAL_TIMEZONE).replace(tzinfo=None)


class Agent(Base):
    __tablename__ = "agents"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(100), unique=True, index=True, nullable=False)
    hostname = Column(String(255), index=True, nullable=False)

    ip_address = Column(String(100), nullable=True)
    public_ip = Column(String(100), nullable=True)
    os = Column(String(255), nullable=True)

    country = Column(String(100), nullable=True, index=True)
    city = Column(String(100), nullable=True)
    isp = Column(String(255), nullable=True)

    created_at = Column(DateTime, default=local_now_naive, nullable=False, index=True)
    last_seen = Column(DateTime, default=local_now_naive, nullable=False, index=True)

    telemetry_events = relationship("Telemetry", back_populates="agent", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Agent(agent_id='{self.agent_id}', hostname='{self.hostname}')>"


class Telemetry(Base):
    __tablename__ = "telemetry"

    id = Column(Integer, primary_key=True, index=True)

    agent_id = Column(String(100), ForeignKey("agents.agent_id"), index=True, nullable=False)
    hostname = Column(String(255), index=True, nullable=False)

    ip_address = Column(String(100), nullable=True)
    public_ip = Column(String(100), nullable=True)
    os = Column(String(255), nullable=True)

    country = Column(String(100), nullable=True, index=True)
    city = Column(String(100), nullable=True)
    isp = Column(String(255), nullable=True)

    cpu_percent = Column(Float, default=0.0, nullable=False)
    memory_percent = Column(Float, default=0.0, nullable=False)
    process_count = Column(Integer, default=0, nullable=False)
    connections_count = Column(Integer, default=0)

    suspicious_port = Column(Integer, default=0)
    powershell_flag = Column(Integer, default=0)
    temp_execution = Column(Integer, default=0)

    top_cpu_processes = Column(Text, nullable=True)
    network_connections = Column(Text, nullable=True)

    process_name = Column(String(255), nullable=True, index=True)
    command_line = Column(Text, nullable=True)
    file_path = Column(Text, nullable=True)
    parent_process = Column(String(255), nullable=True, index=True)

    destination_ip = Column(String(100), nullable=True)
    destination_port = Column(Integer, nullable=True, index=True)

    risk_score = Column(Integer, default=0, nullable=False, index=True)
    rule_score = Column(Integer, default=0, nullable=False)
    ai_score = Column(Integer, default=0, nullable=False)

    risk_reasons = Column(Text, nullable=True)
    top_reason = Column(String(255), nullable=True)

    alert_type = Column(String(255), nullable=True, index=True)
    mitre_technique = Column(String(100), nullable=True, index=True)
    mitre_tactic = Column(String(100), nullable=True, index=True)

    detection_source = Column(String(50), nullable=True, index=True)
    event_category = Column(String(100), nullable=True, index=True)
    severity = Column(String(50), nullable=True, index=True)

    decoded_command = Column(Text, nullable=True)
    decode_method = Column(String(100), nullable=True)
    decode_layers = Column(Text, nullable=True)
    decoded_suspicious_keywords = Column(Text, nullable=True)

    decoded_mitre_technique = Column(String(100), nullable=True)
    decoded_mitre_tactic = Column(String(100), nullable=True)
    attack_intent = Column(Text, nullable=True)
    attack_summary = Column(Text, nullable=True)
    ai_attack_explanation = Column(Text, nullable=True)
    ai_attack_category = Column(String(100), nullable=True, index=True)
    ai_confidence_level = Column(String(50), nullable=True)
    recommended_action = Column(Text, nullable=True)

    incident_status = Column(String(50), default="New", nullable=False, index=True)
    timestamp = Column(DateTime, default=local_now_naive, nullable=False, index=True)

    agent = relationship("Agent", back_populates="telemetry_events")
    timeline_events = relationship("IncidentTimeline", back_populates="telemetry", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Telemetry(id={self.id}, hostname='{self.hostname}', risk_score={self.risk_score})>"


class ResponseAction(Base):
    __tablename__ = "response_actions"

    id = Column(Integer, primary_key=True, index=True)
    telemetry_id = Column(Integer, ForeignKey("telemetry.id"), index=True, nullable=False)

    agent_id = Column(String(100), index=True, nullable=False)
    hostname = Column(String(255), index=True, nullable=False)

    action_type = Column(String(100), nullable=False, index=True)
    target_value = Column(String(255), nullable=True)
    note = Column(Text, nullable=True)

    status = Column(String(50), default="pending", nullable=False, index=True)
    requested_at = Column(DateTime, default=local_now_naive, nullable=False, index=True)
    executed_at = Column(DateTime, nullable=True, index=True)

    result_message = Column(Text, nullable=True)

    def __repr__(self):
        return f"<ResponseAction(id={self.id}, action_type='{self.action_type}', status='{self.status}')>"


class IncidentTimeline(Base):
    __tablename__ = "incident_timeline"

    id = Column(Integer, primary_key=True, index=True)
    telemetry_id = Column(Integer, ForeignKey("telemetry.id"), nullable=False, index=True)

    event_type = Column(String(100), nullable=False)
    message = Column(Text, nullable=False)

    created_at = Column(DateTime, default=local_now_naive, nullable=False, index=True)

    telemetry = relationship("Telemetry", back_populates="timeline_events")

    def __repr__(self):
        return f"<IncidentTimeline(id={self.id}, telemetry_id={self.telemetry_id}, event_type='{self.event_type}')>"