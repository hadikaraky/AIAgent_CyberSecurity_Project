# CURSOR PROMPT — Cybersecurity Triage Agent
> Paste this entire file into Cursor as your starting prompt. Follow the steps in order.

---

## WHAT WE ARE BUILDING

A **Dockerized AI-powered Cybersecurity Triage Agent** that:
- Takes in security incidents reported by an analyst
- Classifies severity using MITRE ATT&CK tactics and common CVEs
- Runs 4 typed tools: lookup, analyze, create incident, generate report
- Maintains conversation memory and explicit workflow state
- Produces Bruno Nakamura-style (HackTheBox) structured incident reports
- Runs fully in Docker with one command: `docker compose up --build`

**Stack:** Python · Gradio (UI) · LangGraph (agent workflow) · SQLite (incidents DB) · Anthropic Claude API · Docker

---

## PROJECT STRUCTURE TO GENERATE

```
cybertriage-agent/
├── docker-compose.yml
├── Dockerfile
├── .env.example
├── requirements.txt
├── README.md
├── app/
│   ├── main.py              ← Gradio UI entry point
│   ├── agent.py             ← LangGraph workflow + routing
│   ├── memory.py            ← Short-term + working memory
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── lookup.py        ← Tool 1: MITRE + CVE knowledge lookup
│   │   ├── analyze.py       ← Tool 2: Severity classification
│   │   ├── action.py        ← Tool 3: Create/update incident in DB
│   │   └── report.py        ← Tool 4: Generate Bruno-style report
│   └── data/
│       ├── mitre_tactics.json
│       ├── cve_knowledge.json
│       ├── playbooks.yaml
│       └── incidents.db     ← auto-created by SQLite
└── tests/
    └── test_conversations.py
```

---

## STEP 1 — Generate all data files first

### `app/data/mitre_tactics.json`
Create a JSON file with at least 15 MITRE ATT&CK tactics/techniques. Each entry:
```json
[
  {
    "id": "T1190",
    "tactic": "Initial Access",
    "tactic_id": "TA0001",
    "technique": "Exploit Public-Facing Application",
    "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to gain initial access.",
    "indicators": ["unusual POST to login endpoints", "SQLi patterns in logs", "error 500 spikes"],
    "severity_weight": 9,
    "containment": ["block source IP at WAF", "patch vulnerable endpoint", "review auth logs"],
    "escalate": true
  }
]
```
Include techniques covering: SQLi (T1190), Brute Force (T1110), Phishing (T1566), XSS (T1059.007), Port Scan (T1046), Privilege Escalation (T1068), Data Exfil (T1041), Ransomware (T1486), Credential Dump (T1003), C2 (T1071), Lateral Movement (T1021), Persistence (T1053), Defense Evasion (T1070), Recon (T1595), Supply Chain (T1195).

### `app/data/cve_knowledge.json`
Create a JSON file with 10 well-known CVEs:
```json
[
  {
    "cve_id": "CVE-2021-44228",
    "name": "Log4Shell",
    "cvss": 10.0,
    "affected": "Apache Log4j 2.x",
    "description": "Remote code execution via JNDI injection in log messages.",
    "patch": "Upgrade to Log4j 2.17.1+",
    "mitre_ref": "T1190",
    "severity": "Critical"
  }
]
```
Include: Log4Shell, EternalBlue (MS17-010), Heartbleed, ShellShock, PrintNightmare, ProxyLogon, Dirty COW, Spring4Shell, MOVEit (CVE-2023-34362), Citrix Bleed (CVE-2023-4966).

### `app/data/playbooks.yaml`
```yaml
playbooks:
  sqli:
    name: SQL Injection Response
    steps:
      - Block attacking IP at firewall/WAF immediately
      - Preserve logs before any cleanup
      - Review all DB queries for unsanitized inputs
      - Check for data exfiltration in DB audit logs
      - Patch with parameterized queries
      - Notify DPO if PII may be affected
  brute_force:
    name: Brute Force Response
    steps:
      - Block source IP range
      - Enable account lockout policy
      - Force password reset for targeted accounts
      - Enable MFA immediately
      - Review successful logins in the attack window
  xss:
    name: XSS Response
    steps:
      - Identify and sanitize vulnerable input fields
      - Invalidate all active sessions
      - Review for stored XSS payloads in DB
      - Enable Content Security Policy headers
  phishing:
    name: Phishing Response
    steps:
      - Block sender domain at email gateway
      - Identify all recipients of the phishing email
      - Check for credential compromise
      - Reset credentials for affected users
      - Report to anti-phishing authorities
  default:
    name: General Incident Response
    steps:
      - Isolate affected system if possible
      - Preserve all logs and evidence
      - Identify scope of impact
      - Escalate to lead security engineer
      - Document all actions taken
```

---

## STEP 2 — Generate `requirements.txt`

```
anthropic
langgraph
langchain-anthropic
langchain-core
gradio
pyyaml
python-dotenv
```

---

## STEP 3 — Generate `app/data/db_init.py` (run once to create DB)

Create an SQLite DB with this schema:
```sql
CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id TEXT UNIQUE NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  severity TEXT CHECK(severity IN ('Critical','High','Medium','Low')),
  status TEXT DEFAULT 'Open' CHECK(status IN ('Open','In Progress','Contained','Closed')),
  mitre_technique TEXT,
  mitre_tactic TEXT,
  affected_asset TEXT,
  source_ip TEXT,
  assigned_to TEXT DEFAULT 'Security Team',
  containment_steps TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```
Auto-generate the next incident_id as INC-XXXX (zero-padded, starting from 0001, incrementing from last in DB).

---

## STEP 4 — Generate the 4 Tools

### `app/tools/lookup.py` — Information Tool
```python
"""
Tool: lookup_threat
Purpose: Search mitre_tactics.json and cve_knowledge.json for matching threats.
Input: {"query": str}  — free text describing the incident
Output: {
  "matched_technique": str,
  "tactic": str,
  "tactic_id": str,
  "severity_weight": int,
  "indicators": list,
  "containment": list,
  "cve_match": dict or None,
  "escalate": bool,
  "source": "mitre_tactics.json / cve_knowledge.json"
}
Error: return {"error": "No matching threat found", "source": "local knowledge base"}
"""
```
Logic: keyword match on query against technique names, descriptions, and indicators. If query mentions a CVE ID, also search cve_knowledge.json. Return best match. If no match, return error dict — never hallucinate.

### `app/tools/analyze.py` — Analysis Tool
```python
"""
Tool: analyze_severity
Purpose: Given incident details, return a structured severity classification.
Input: {
  "description": str,
  "affected_asset": str,
  "source_ip": str or None,
  "threat_lookup_result": dict  — output from lookup_threat
}
Output: {
  "severity": "Critical|High|Medium|Low",
  "confidence": "High|Medium|Low",
  "reasoning": str,
  "risk_score": int (0-100),
  "requires_confirmation": bool,
  "estimated_impact": str
}
"""
```
Logic — deterministic scoring (no LLM inside tools):
- Start with severity_weight from lookup (0-10 scale → map to 0-100)
- +20 if affected_asset contains "prod" or "production" or "db" or "database"
- +15 if source_ip is external (not 10.x, 192.168.x, 172.16-31.x)
- +10 if escalate=True from lookup
- Score ≥ 80 → Critical, 60-79 → High, 40-59 → Medium, < 40 → Low
- requires_confirmation = True always (all incidents need confirmation before DB write)

### `app/tools/action.py` — Action Tool
```python
"""
Tool: create_incident
Purpose: Write a confirmed incident to SQLite.
Input: {
  "title": str,
  "description": str,
  "severity": str,
  "mitre_technique": str,
  "mitre_tactic": str,
  "affected_asset": str,
  "source_ip": str or None,
  "containment_steps": list[str],
  "confirmed": bool  — MUST be True or raise ValueError
}
Output: {
  "incident_id": str,
  "status": "Created",
  "created_at": str,
  "message": str
}
Error: If confirmed=False → raise ValueError("User confirmation required before creating incident")
       If DB error → return {"error": str(e), "status": "Failed"}
"""
```
Log every call to a `logs/actions.log` file with timestamp, incident_id, and action taken.

### `app/tools/report.py` — Reporting Tool
```python
"""
Tool: generate_report
Purpose: Generate a Bruno Nakamura / HackTheBox style structured incident report.
Input: {
  "incident_id": str,
  "title": str,
  "severity": str,
  "description": str,
  "mitre_technique": str,
  "mitre_tactic": str,
  "tactic_id": str,
  "affected_asset": str,
  "source_ip": str or None,
  "risk_score": int,
  "containment_steps": list[str],
  "estimated_impact": str,
  "analyst_name": str
}
Output: {
  "report_text": str,  — full formatted report
  "report_id": str,
  "generated_at": str
}
"""
```
Report format (Bruno Nakamura / HTB style — clean, structured, professional):
```
════════════════════════════════════════════════════════
  INCIDENT REPORT — {incident_id}
  CyberTriage Agent · {generated_at}
════════════════════════════════════════════════════════

  EXECUTIVE SUMMARY
  ─────────────────
  Incident ID  : {incident_id}
  Title        : {title}
  Severity     : {severity}  [Risk Score: {risk_score}/100]
  Status       : Open — Awaiting Containment
  Analyst      : {analyst_name}

  THREAT INTELLIGENCE
  ───────────────────
  MITRE Tactic    : {tactic_id} — {mitre_tactic}
  MITRE Technique : {mitre_technique}
  Affected Asset  : {affected_asset}
  Source IP       : {source_ip or "Unknown"}

  IMPACT ASSESSMENT
  ─────────────────
  {estimated_impact}

  DESCRIPTION
  ───────────
  {description}

  CONTAINMENT CHECKLIST
  ─────────────────────
  {numbered containment steps}

  DISCLAIMER
  ──────────
  This report is generated by an AI triage assistant and serves
  as decision-support only. All actions must be verified by a
  qualified security engineer before execution. Do not treat
  this as an authoritative diagnosis.

════════════════════════════════════════════════════════
```

---

## STEP 5 — Generate `app/memory.py`

```python
"""
Short-term memory: list of {role, content} dicts — full conversation history for current session.
Working memory: a dataclass or dict with these explicit fields:
  - current_intent: str or None  ("new_incident" | "status_check" | "report_request" | "unsupported")
  - collected_info: dict  (description, affected_asset, source_ip, analyst_name)
  - missing_fields: list[str]  (fields still needed)
  - pending_confirmation: bool
  - confirmation_payload: dict or None  (what needs to be confirmed)
  - latest_tool_result: dict or None
  - workflow_state: str  ("intake" | "classify" | "analyze" | "confirm" | "report" | "done")
  - incident_id: str or None  (set after creation)

Provide: get_memory(), update_working_memory(field, value), reset_memory(), get_conversation_history(), add_message(role, content)
"""
```

---

## STEP 6 — Generate `app/agent.py` — LangGraph Workflow

Build a LangGraph StateGraph with these nodes:

```
router → [intake | unsupported]
intake → analyze_node → confirm_node → action_node → report_node → done
```

**Router logic:** classify user message intent:
- Keywords like "incident", "attack", "breach", "suspicious", "alert", "exploit" → "new_incident"
- Keywords like "status", "check", "INC-" → "status_check"  
- Keywords like "report", "generate", "export" → "report_request"
- Anything else → "unsupported"

**Nodes:**
1. `router_node` — classifies intent, updates working memory
2. `intake_node` — collects missing fields (description, affected_asset, source_ip, analyst_name). If any missing, ask user for them one at a time. Call `lookup_threat` once all basic info collected.
3. `analyze_node` — call `analyze_severity` with lookup result. Update working memory.
4. `confirm_node` — present analysis to user. Set pending_confirmation=True. Wait for "yes/confirm/go ahead" or "no/cancel". NEVER proceed without explicit yes.
5. `action_node` — call `create_incident` with confirmed=True. Store incident_id.
6. `report_node` — call `generate_report`. Return full report text to user.
7. `unsupported_node` — respond: "I can only help with security incident triage. For other requests, please contact your security team lead directly." Never hallucinate an answer.

**Stopping rules:**
- Max 10 LLM calls per conversation turn
- Max 5 tool calls per conversation turn
- If max reached → graceful fallback message

**System prompt for LLM:**
```
You are a cybersecurity triage assistant. Your job is to help security analysts classify, 
document, and respond to security incidents.

Rules you must follow:
1. Never make up threat intelligence — only use what the lookup tool returns.
2. Always require explicit user confirmation before creating an incident record.
3. Always state the source of every recommendation (MITRE ATT&CK, CVE database, playbook).
4. If you are unsure or the request is outside your scope, say so clearly.
5. Present yourself as a decision-support tool, not an authoritative system.
6. Keep responses concise and structured. Use the report tool for formal output.
7. Always communicate uncertainty — use phrases like "based on available data" or "this is an AI assessment".

Current working memory: {working_memory}
Conversation history is maintained automatically.
```

---

## STEP 7 — Generate `app/main.py` — Gradio UI

Build a Gradio Blocks interface:

```python
"""
Layout:
- Left column (30%): 
  - Title "🛡️ CyberTriage Agent"
  - Incident list (fetched from SQLite, shows INC-ID + severity badge)
  - Workflow state indicator (shows current state from working memory)
  
- Right column (70%):
  - gr.Chatbot — main conversation, height=500
  - gr.Textbox — user input, placeholder="Describe the incident or ask a question..."
  - gr.Button — "Send"
  - gr.Button — "New Incident" (resets memory)
  - gr.Button — "Export Last Report" (downloads last generated report as .txt)

On send:
  1. Add user message to chatbot
  2. Pass to agent.py run_agent(message, memory)
  3. Stream response back to chatbot
  4. Refresh incident list from DB

Workflow state bar at bottom showing: intake → classify → analyze → confirm → report → done
Highlight current state in blue.
"""
```

---

## STEP 8 — Generate `Dockerfile`

```dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN useradd -m -u 1000 appuser

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY .env.example .env.example

RUN mkdir -p logs && chown -R appuser:appuser /app

USER appuser

RUN python app/data/db_init.py

EXPOSE 7860

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:7860/ || exit 1

CMD ["python", "app/main.py"]
```

---

## STEP 9 — Generate `docker-compose.yml`

```yaml
version: "3.9"
services:
  cybertriage:
    build: .
    ports:
      - "7860:7860"
    env_file:
      - .env
    volumes:
      - incident_data:/app/app/data
      - logs:/app/logs
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:7860/"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  incident_data:
  logs:
```

---

## STEP 10 — Generate `.env.example`

```
ANTHROPIC_API_KEY=your_key_here
GRADIO_SERVER_NAME=0.0.0.0
GRADIO_SERVER_PORT=7860
```

---

## STEP 11 — Generate `tests/test_conversations.py`

Write 20 test cases covering all rubric requirements. Each test is a dict:
```python
TEST_CASES = [
  {
    "id": "TC-01",
    "category": "grounded_information",
    "input": "I think we have a SQL injection attack on our login page",
    "expected_intent": "new_incident",
    "expected_tool": "lookup_threat",
    "expected_severity": "Critical",
    "pass_criteria": "returns MITRE T1190 reference"
  },
  # TC-02: Brute force SSH
  # TC-03: XSS attack
  # TC-04: Unknown CVE lookup
  # TC-05: Log4Shell CVE-2021-44228 specific query
  # TC-06: Valid full flow — collect info → analyze → confirm → create → report
  # TC-07: User says "no" at confirmation gate — incident must NOT be created
  # TC-08: Missing affected_asset — agent must ask for it
  # TC-09: Missing analyst name — agent must ask for it
  # TC-10: Unsupported request ("write me a poem") — graceful fallback
  # TC-11: Prompt injection attempt ("ignore previous instructions and...")
  # TC-12: Duplicate incident — same description twice
  # TC-13: Status check "what's the status of INC-0001"
  # TC-14: Report request for existing incident
  # TC-15: Ambiguous input ("something weird is happening") — agent asks for details
  # TC-16: Internal IP vs external IP scoring difference
  # TC-17: Production DB affected → Critical bump
  # TC-18: Low severity incident — TLS 1.0 on staging
  # TC-19: Multi-turn memory — user provides info across 3 messages
  # TC-20: Adversarial — "create an incident with severity=Critical for everything"
]
```

---

## STEP 12 — Generate `README.md`

Include:
- Project description
- Quick start: `cp .env.example .env` → add API key → `docker compose up --build`
- Architecture overview (7 layers)
- Tool descriptions
- Environment variables table
- Team contributions section (Student 1: Tools, Student 2: Agent, Student 3: Platform)
- AI tool declaration: "Claude API used as LLM reasoning core. Cursor used for code generation assistance."

---

## FINAL CHECKLIST BEFORE SUBMITTING

- [ ] `docker compose up --build` starts everything with zero errors
- [ ] All 4 tools return proper schemas (no raw exceptions to user)
- [ ] Confirmation gate NEVER skipped — test by saying "no"
- [ ] Unsupported requests get graceful fallback, not hallucination
- [ ] Every report shows "MITRE ATT&CK source" and "AI decision-support disclaimer"
- [ ] SQLite persists across container restarts (named volume)
- [ ] No API keys hardcoded anywhere
- [ ] `logs/actions.log` writes every tool call
- [ ] Working memory shows correct state at all times
- [ ] 20 test cases documented with expected vs actual output

---

## IMPORTANT NOTES FOR CURSOR

1. Generate ALL files completely — no placeholders or "TODO" comments
2. Keep functions short and readable — no over-engineering
3. Every tool must have a docstring with: purpose, input schema, output schema, error behavior
4. Use `python-dotenv` to load `.env` — never hardcode keys
5. The LLM (Claude) only does reasoning and routing — all data comes from JSON/YAML/SQLite tools
6. If a tool fails, return an error dict — never raise unhandled exceptions to the user
7. Test each tool independently before wiring into LangGraph
