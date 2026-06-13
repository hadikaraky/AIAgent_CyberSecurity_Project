Hadi KARAKI : 6679
Ali Akar : 6575
# CyberTriage Agent

An AI-powered cybersecurity triage agent that runs in Docker. You describe a security
incident, it classifies the threat using MITRE ATT&CK and known CVEs, scores the
severity, creates an incident record, and generates a HackTheBox-style PDF report.
Built for a university course project at Lebanese University, Faculty of Engineering.

## Running it

```bash
cp .env.example .env
# add your Google Gemini API key to .env

docker compose up --build
```

Then open http://localhost:7860.

## How it works

The agent follows a fixed pipeline: it figures out what you want, collects the
incident details, looks up the threat in the local knowledge base, scores the
severity, asks for your confirmation, writes the incident to the database, and
generates the report. It won't do anything to the database without you confirming
first.

The workflow looks like this:
router → intake → analyze → confirm → action → report

If you ask it something outside its scope it tells you that directly instead of
making something up.

## The four tools

**lookup_threat** — searches the local MITRE ATT&CK tactics and CVE knowledge base
for anything matching the incident description. Returns the technique, tactic,
indicators, and containment steps.

**analyze_severity** — deterministic scoring from 0 to 100 based on the lookup
result, the affected asset, and the source IP. No LLM involved here, just rules.

**create_incident** — writes the confirmed incident to SQLite. Requires explicit
confirmation before it does anything. Logs every call to logs/actions.log.

**generate_report** — produces a HackTheBox-style PDF with cover page, threat
intel table, containment checklist, and disclaimer. Saved to logs/reports/.

## Stack

Python, Gradio, LangGraph, SQLite, ReportLab, Google Gemini (free tier),
Docker. Domain knowledge is stored in JSON and YAML — no vector database,
no embeddings, no RAG pipeline.

## Environment variables 
GOOGLE_API_KEY=your_key_here

GRADIO_SERVER_NAME=0.0.0.0

GRADIO_SERVER_PORT=7860 

Get a free Gemini API key at aistudio.google.com.

## Running without Docker

```bash
pip install -r requirements.txt
export PYTHONPATH=.
python app/data/db_init.py
python app/main.py
```

Tests:

```bash
pytest tests/ -v
```

## AI tools used

Google Gemini is the LLM reasoning core. Cursor was used for code generation
during development.

