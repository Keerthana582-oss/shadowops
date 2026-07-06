import json
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session

from db import init_db, get_db, Incident, Action, AuditLog
import llm_engine

app = FastAPI(title="ShadowOps API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

AUTO_EXECUTE_WHITELIST = {
    "add ip to watchlist",
    "tag host for monitoring",
    "notify slack channel",
    "notify on-call channel",
}


@app.on_event("startup")
def on_startup():
    init_db()


class AlertIn(BaseModel):
    source: Optional[str] = "unknown"
    rule_name: Optional[str] = ""
    payload: dict


class ActionDecision(BaseModel):
    approve: bool


@app.post("/ingest")
def ingest_alert(alert: AlertIn, db: Session = Depends(get_db)):
    triage_result = llm_engine.triage(alert.payload)

    incident = Incident(
        source=alert.source,
        rule_name=alert.rule_name,
        raw_alert=json.dumps(alert.payload),
        ai_summary=triage_result.get("summary", ""),
        severity=triage_result.get("severity", "unknown"),
        attack_category=triage_result.get("attack_category", "unknown"),
        status="triaged",
    )
    db.add(incident)
    db.commit()
    db.refresh(incident)

    db.add(AuditLog(
        incident_id=incident.id,
        event="incident_triaged",
        detail=json.dumps(triage_result),
        actor="system",
    ))
    db.commit()

    return {"incident_id": incident.id, "triage": triage_result}


@app.post("/incidents/{incident_id}/generate-playbook")
def generate_playbook(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    playbook = llm_engine.recommend_playbook(
        incident.ai_summary, incident.severity, incident.attack_category
    )

    created_actions = []
    for step in playbook:
        action = Action(
            incident_id=incident.id,
            description=step.get("description", ""),
            risk_tier=step.get("risk_tier", "high"),
            reversible=bool(step.get("reversible", False)),
            status="pending",
        )
        db.add(action)
        db.commit()
        db.refresh(action)
        created_actions.append(action)

        if action.risk_tier == "low" and action.description.lower() in AUTO_EXECUTE_WHITELIST:
            _execute_action(db, action, actor="system")

    incident.status = "actions_pending"
    db.commit()

    return {"incident_id": incident.id, "actions": [a.id for a in created_actions]}


@app.post("/actions/{action_id}/decision")
def decide_action(action_id: int, decision: ActionDecision, db: Session = Depends(get_db)):
    action = db.query(Action).filter(Action.id == action_id).first()
    if not action:
        raise HTTPException(status_code=404, detail="Action not found")

    if decision.approve:
        _execute_action(db, action, actor="user")
    else:
        action.status = "rejected"
        db.commit()
        db.add(AuditLog(
            incident_id=action.incident_id,
            action_id=action.id,
            event="action_rejected",
            detail=action.description,
            actor="user",
        ))
        db.commit()

    return {"action_id": action.id, "status": action.status}


def _execute_action(db: Session, action: Action, actor: str):
    action.status = "executed"
    action.executed_at = datetime.utcnow()
    db.commit()

    db.add(AuditLog(
        incident_id=action.incident_id,
        action_id=action.id,
        event="action_executed",
        detail=f"(simulated) {action.description}",
        actor=actor,
    ))
    db.commit()


@app.get("/incidents")
def list_incidents(db: Session = Depends(get_db)):
    incidents = db.query(Incident).order_by(Incident.created_at.desc()).all()
    return incidents


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    actions = db.query(Action).filter(Action.incident_id == incident_id).all()
    return {"incident": incident, "actions": actions}


@app.get("/actions")
def list_all_actions(db: Session = Depends(get_db)):
    return db.query(Action).all()


@app.get("/incidents/{incident_id}/audit-log")
def get_audit_log(incident_id: int, db: Session = Depends(get_db)):
    logs = db.query(AuditLog).filter(AuditLog.incident_id == incident_id).order_by(AuditLog.timestamp).all()
    return logs


@app.get("/")
def root():
    return {"status": "ShadowOps API is running"}
if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)