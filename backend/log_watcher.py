"""
Watches the Windows Security Event Log for real failed-login events
(Event ID 4625) and forwards them to the ShadowOps /ingest endpoint
as real SIEM-style alerts.

Run this alongside your uvicorn server. Requires Administrator privileges
to read the Security log.

Usage:
    python log_watcher.py
"""
import time
import requests
import win32evtlog
import win32evtlogutil
import win32con

API_BASE = "http://localhost:8000"
SERVER = "localhost"
LOGTYPE = "Security"
FAILED_LOGIN_EVENT_ID = 4625

seen_record_numbers = set()


def check_for_failed_logins():
    hand = win32evtlog.OpenEventLog(SERVER, LOGTYPE)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    events = win32evtlog.ReadEventLog(hand, flags, 0)

    new_alerts = []
    for event in events:
        record_num = event.RecordNumber
        if record_num in seen_record_numbers:
            continue

        event_id = event.EventID & 0xFFFF  # mask off the top bits Windows sometimes sets
        if event_id == FAILED_LOGIN_EVENT_ID:
            seen_record_numbers.add(record_num)
            strings = event.StringInserts or []
            new_alerts.append({
                "source": "WindowsEventLog",
                "rule_name": "Failed Login Attempt",
                "host": SERVER,
                "record_number": record_num,
                "time_generated": str(event.TimeGenerated),
                "raw_message": f"Windows Security Event 4625 (failed logon) recorded at {event.TimeGenerated}. Details: {strings[:5]}",
            })

    win32evtlog.CloseEventLog(hand)
    return new_alerts


def send_alert(alert):
    try:
        resp = requests.post(f"{API_BASE}/ingest", json={
            "source": alert["source"],
            "rule_name": alert["rule_name"],
            "payload": alert,
        })
        resp.raise_for_status()
        result = resp.json()
        print(f"Sent alert -> Incident #{result['incident_id']} (severity: {result['triage'].get('severity')})")
    except Exception as e:
        print(f"Failed to send alert: {e}")


def main():
    print("ShadowOps log watcher started. Watching Windows Security log for failed logins (Event ID 4625).")
    print("Press Ctrl+C to stop.\n")

    # On first run, mark existing events as already seen so we only alert on NEW ones
    initial = check_for_failed_logins()
    print(f"Baseline: {len(initial)} existing failed-login events found (not alerting on history).")

    while True:
        time.sleep(10)
        new_alerts = check_for_failed_logins()
        for alert in new_alerts:
            print(f"\nNew failed login detected: {alert['raw_message']}")
            send_alert(alert)


if __name__ == "__main__":
    main()