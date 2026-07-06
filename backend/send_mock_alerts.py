"""
Posts every alert in mock_data/sample_alerts.json to the running ShadowOps API,
then triggers playbook generation for each resulting incident.

Usage (with the API already running via uvicorn):
    python send_mock_alerts.py
"""
import json
import time
import requests

API_BASE = "http://localhost:8000"

with open("../mock_data/sample_alerts.json") as f:
    alerts = json.load(f)

for i, alert in enumerate(alerts, start=1):
    print(f"\n--- Sending alert {i}/{len(alerts)}: {alert.get('rule_name')} ---")

    resp = requests.post(f"{API_BASE}/ingest", json={
        "source": alert.get("source", "unknown"),
        "rule_name": alert.get("rule_name", ""),
        "payload": alert,
    })
    resp.raise_for_status()
    result = resp.json()
    incident_id = result["incident_id"]
    print(f"Incident #{incident_id} created. Severity: {result['triage'].get('severity')}")
    print(f"Summary: {result['triage'].get('summary')}")

    playbook_resp = requests.post(f"{API_BASE}/incidents/{incident_id}/generate-playbook")
    playbook_resp.raise_for_status()
    print(f"Playbook actions created: {playbook_resp.json().get('actions')}")

    time.sleep(0.5)

print("\nDone. Open http://localhost:8000/docs to inspect results, or GET /incidents.")