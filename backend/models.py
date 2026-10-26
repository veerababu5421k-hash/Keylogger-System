"""
Database Schema & Data Models for SecureShield Backend.
Supports Users, Devices, Agents, Events, Incidents, Threat Scores, AI Analyses, Mitigation Actions, and Audit Logs.
"""

import time
import json
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker

Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)
    role = Column(String(20), default="admin")
    created_at = Column(String(30), default=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

class Device(Base):
    __tablename__ = "devices"
    id = Column(String(100), primary_key=True)
    node_name = Column(String(100), nullable=False)
    ip_address = Column(String(50), default="127.0.0.1")
    status = Column(String(20), default="ONLINE")
    last_seen = Column(String(30), default=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

class AgentStatusRecord(Base):
    __tablename__ = "agent_status"
    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String(100), nullable=False)
    agent_name = Column(String(50), nullable=False)
    status = Column(String(20), default="RUNNING")
    is_alive = Column(Boolean, default=True)
    updated_at = Column(String(30), default=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

class SecurityEventRecord(Base):
    __tablename__ = "security_events"
    id = Column(Integer, primary_key=True, autoincrement=True)
    event_id = Column(String(100), unique=True, nullable=False)
    device_id = Column(String(100), nullable=False)
    agent_type = Column(String(50), nullable=False)
    event_type = Column(String(100), nullable=False)
    severity = Column(String(20), default="INFO")
    process_id = Column(Integer, nullable=True)
    process_name = Column(String(200), nullable=True)
    payload_json = Column(Text, default="{}")
    timestamp = Column(String(30), nullable=False)

class IncidentRecord(Base):
    __tablename__ = "incidents"
    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String(100), unique=True, nullable=False)
    device_id = Column(String(100), nullable=False)
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String(20), default="LOW")
    confidence = Column(Float, default=1.0)
    reasons_json = Column(Text, default="[]")
    ai_explanation = Column(Text, nullable=True)
    recommended_mitigation = Column(Text, nullable=True)
    prevention_status = Column(String(50), default="PENDING")
    timestamp = Column(String(30), nullable=False)

class MitigationActionRecord(Base):
    __tablename__ = "mitigation_actions"
    id = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(String(100), nullable=False)
    command = Column(String(500), nullable=False)
    explanation = Column(Text, nullable=False)
    target_pid = Column(Integer, nullable=True)
    target_path = Column(String(300), nullable=True)
    user_confirmed = Column(Boolean, default=False)
    status = Column(String(20), default="PROPOSED")
    output = Column(Text, nullable=True)
    timestamp = Column(String(30), default=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

class AuditLogRecord(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    action = Column(String(100), nullable=False)
    performed_by = Column(String(50), default="system")
    details_json = Column(Text, default="{}")
    timestamp = Column(String(30), default=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

# Database initialization helper
def init_db(db_uri: str = "sqlite:///logs/secureshield.db"):
    engine = create_engine(db_uri, echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return engine, Session
