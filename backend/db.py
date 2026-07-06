from sqlalchemy import create_engine, Column, String, Integer, DateTime, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

DATABASE_URL = "sqlite:///./shadowops.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    source = Column(String, default="unknown")
    rule_name = Column(String, default="")
    raw_alert = Column(Text)
    ai_summary = Column(Text)
    severity = Column(String, default="unknown")
    attack_category = Column(String, default="")
    status = Column(String, default="new")
    created_at = Column(DateTime, default=datetime.utcnow)


class Action(Base):
    __tablename__ = "actions"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, index=True)
    description = Column(String)
    risk_tier = Column(String, default="high")
    reversible = Column(Boolean, default=False)
    status = Column(String, default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)
    executed_at = Column(DateTime, nullable=True)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, index=True)
    action_id = Column(Integer, nullable=True)
    event = Column(String)
    detail = Column(Text)
    actor = Column(String, default="system")
    timestamp = Column(DateTime, default=datetime.utcnow)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()