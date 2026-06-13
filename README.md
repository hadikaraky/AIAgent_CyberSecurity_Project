# CyberTriage Agent

A Dockerized AI-powered Cybersecurity Triage Agent that helps security analysts classify, document, and respond to security incidents using MITRE ATT&CK, CVE knowledge bases, and structured incident reporting.

## Quick Start

```bash
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY

docker compose up --build
```

Open **http://localhost:7860** in your browser.

## Architecture Overview

The system is organized into 7 layers:

1. **Presentation Layer** — Gradio web UI (`app/main.py`) with chat interface, incident list, and workflow state indicator
2. **Agent Layer** — LangGraph workflow (`app/agent.py`) with intent routing and multi-step triage pipeline
3. **Memory Layer** — Short-term conversation history and working memory state (`app/memory.py`)
4. **Tools Layer** — Four typed tools: lookup, analyze, create incident, generate report (`app/tools/`)
5. **Knowledge Layer** — MITRE ATT&CK tactics, CVE database, and response playbooks (`app/data/`)
6. **Persistence Layer** — SQLite incidents database with Docker volume persistence (`app/data/incidents.db`)
7. **Infrastructure Layer** — Docker containerization with health checks and logging (`Dockerfile`, `docker-compose.yml`)

## Workflow

```
router → [intake | unsupported]
intake → analyze → confirm → action → report → done
```

The agent collects incident details, looks up threat intelligence, scores severity deterministically, requires explicit user confirmation before database writes, and generates Bruno Nakamura-style incident reports.

## Tools

| Tool | Purpose | Data Source |
|------|---------|-------------|
| `lookup_threat` | Match incidents to MITRE techniques and CVEs | `mitre_tactics.json`, `cve_knowledge.json` |
| `analyze_severity` | Deterministic risk scoring (0–100) | Lookup result + asset/IP context |
| `create_incident` | Write confirmed incidents to SQLite | `incidents.db` |
| `generate_report` | Bruno-style structured incident report | All collected incident data |

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ANTHROPIC_API_KEY` | Claude API key for LLM reasoning | *(required)* |
| `GRADIO_SERVER_NAME` | Gradio bind address | `0.0.0.0` |
| `GRADIO_SERVER_PORT` | Gradio port | `7860` |

## Local Development

```bash
pip install -r requirements.txt
export PYTHONPATH=.
python app/data/db_init.py
python app/main.py
```

Run tests:

```bash
pip install pytest
pytest tests/ -v
```

## Team Contributions

| Student | Area | Responsibilities |
|---------|------|------------------|
| Student 1 | Tools | `lookup.py`, `analyze.py`, `action.py`, `report.py`, data files |
| Student 2 | Agent | `agent.py`, `memory.py`, LangGraph workflow, routing logic |
| Student 3 | Platform | `main.py`, Docker setup, `docker-compose.yml`, tests, README |

## AI Tool Declaration

Claude API is used as the LLM reasoning core. Cursor was used for code generation assistance during development.

## Disclaimer

This agent is a **decision-support tool only**. All threat assessments, severity classifications, and containment recommendations must be verified by a qualified security engineer before execution.
