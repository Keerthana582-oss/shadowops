\# ShadowOps — Automated AI Incident Responder



ShadowOps is a security incident response tool that uses an LLM to triage

SIEM-style alerts, recommend response actions, and safely automate the

low-risk ones — while keeping a human in the loop for anything destructive.



\## How it works



1\. A SIEM-style alert comes in (currently mock ELK-style alerts, real

&#x20;  webhook integration planned)

2\. Claude triages it — summarizes what happened, assesses severity,

&#x20;  and classifies the attack category

3\. Claude recommends a response playbook — a list of actions, each

&#x20;  tagged by risk tier (low / medium / high)

4\. \*\*Low-risk, reversible actions auto-execute.\*\* Everything else

&#x20;  waits for human approval via the dashboard.

5\. Every triage, recommendation, approval, and execution is logged

&#x20;  to an audit trail.



\## Why this design



The interesting problem here isn't "can an LLM read a log line" —

it's \*\*how much autonomy should an AI have over incident response,

and how do you draw that line safely.\*\* ShadowOps answers that with

a risk-tiering system: the AI can act freely within a narrow,

reversible whitelist, but anything with real blast radius (isolating

a host, disabling an account) always requires a human click.



\## Stack



\- \*\*Backend:\*\* FastAPI + SQLAlchemy (SQLite for dev)

\- \*\*AI:\*\* Claude API (Anthropic)

\- \*\*Frontend:\*\* Single-file HTML/CSS/JS dashboard (no build step)

\- \*\*Audit logging:\*\* every action's actor (system vs human) and

&#x20; timestamp is recorded



\## Running it locally



\\`\\`\\`bash

cd backend

pip install -r requirements.txt

uvicorn main:app --reload

\\`\\`\\`



Then open \\`dashboard.html\\` directly in your browser.



To send mock alerts through the pipeline:

\\`\\`\\`bash

python send\_mock\_alerts.py

\\`\\`\\`



\## What's not built yet



\- Real SIEM webhook integration (currently uses mock alert data)

\- Real action execution (currently simulated — logs what it would do)

\- Deployment

