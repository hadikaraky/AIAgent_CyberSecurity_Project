"""LangGraph workflow and routing for the CyberTriage agent."""

import os
import re
from typing import TypedDict

import yaml
from dotenv import load_dotenv
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.graph import END, StateGraph

from app.memory import (
    add_message,
    get_working_memory,
    reset_memory,
    update_working_memory,
)
from app.tools.action import create_incident, get_incident, list_incidents
from app.tools.analyze import analyze_severity
from app.tools.lookup import lookup_threat
from app.tools.report import generate_report

load_dotenv()

llm = ChatGoogleGenerativeAI(model="gemini-2.0-flash", temperature=0)

MAX_LLM_CALLS = 10
MAX_TOOL_CALLS = 5

FIELD_PROMPTS = {
    "description": "Please describe the security incident in detail (what happened, when, and any indicators).",
    "affected_asset": "Which asset is affected? Provide the hostname, server name, or system identifier.",
    "source_ip": "What is the source IP address? (Type 'unknown' if not available.)",
    "analyst_name": "What is your name as the reporting analyst?",
}

SYSTEM_PROMPT = """You are a cybersecurity triage assistant. Your job is to help security analysts classify,
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
Conversation history is maintained automatically."""


class AgentState(TypedDict):
    user_message: str
    response: str
    halt: bool


def _load_playbooks() -> dict:
    path = os.path.join(os.path.dirname(__file__), "data", "playbooks.yaml")
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)["playbooks"]


def classify_intent(message: str) -> str:
    msg = message.lower()
    if re.search(r"\binc-\d{4}\b", msg, re.IGNORECASE):
        if any(kw in msg for kw in ["status", "check", "update"]):
            return "status_check"
        if any(kw in msg for kw in ["report", "generate", "export"]):
            return "report_request"

    if any(kw in msg for kw in ["status", "check"]) and "inc-" in msg:
        return "status_check"
    if any(kw in msg for kw in ["report", "generate", "export"]):
        return "report_request"
    if any(
        kw in msg
        for kw in [
            "incident",
            "attack",
            "breach",
            "suspicious",
            "alert",
            "exploit",
            "injection",
            "phishing",
            "ransomware",
            "malware",
            "xss",
            "brute",
            "cve-",
            "weird",
            "unusual",
            "happening",
        ]
    ):
        return "new_incident"
    return "unsupported"


def _is_confirmation(message: str) -> bool:
    msg = message.lower().strip()
    return any(
        word in msg
        for word in ["yes", "confirm", "go ahead", "proceed", "approved", "yep", "yeah"]
    )


def _is_rejection(message: str) -> bool:
    msg = message.lower().strip()
    return any(word in msg for word in ["no", "cancel", "abort", "stop", "reject", "nope"])


def _extract_ip(message: str) -> str | None:
    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", message)
    return match.group() if match else None


def _try_fill_fields(message: str) -> None:
    wm = get_working_memory()
    info = wm["collected_info"]
    missing = wm["missing_fields"]

    if not missing:
        return

    field = missing[0]

    if field == "source_ip":
        if message.lower().strip() in ("unknown", "n/a", "none", "not available"):
            update_working_memory("source_ip", "Unknown")
        else:
            ip = _extract_ip(message)
            update_working_memory("source_ip", ip or message.strip())
        return

    if field == "description" and not info.get("description"):
        update_working_memory("description", message.strip())
        return

    update_working_memory(field, message.strip())


def _get_playbook_steps(description: str, containment: list[str]) -> list[str]:
    playbooks = _load_playbooks()
    desc_lower = description.lower()
    if "sql" in desc_lower or "sqli" in desc_lower or "injection" in desc_lower:
        key = "sqli"
    elif "brute" in desc_lower or "ssh" in desc_lower:
        key = "brute_force"
    elif "xss" in desc_lower or "script" in desc_lower:
        key = "xss"
    elif "phish" in desc_lower or "email" in desc_lower:
        key = "phishing"
    else:
        key = "default"

    steps = list(playbooks[key]["steps"])
    for step in containment:
        if step not in steps:
            steps.append(step)
    return steps


def router_node(state: AgentState) -> AgentState:
    intent = classify_intent(state["user_message"])
    update_working_memory("current_intent", intent)
    if intent == "new_incident" and get_working_memory()["workflow_state"] == "intake":
        update_working_memory("workflow_state", "intake")
    return {**state, "halt": False}


def intake_node(state: AgentState) -> AgentState:
    wm = get_working_memory()
    message = state["user_message"]

    if "description" in wm["missing_fields"] and not wm["collected_info"].get("description"):
        update_working_memory("description", message.strip())
    else:
        _try_fill_fields(message)
    wm = get_working_memory()

    if wm["missing_fields"]:
        field = wm["missing_fields"][0]
        prompt = FIELD_PROMPTS[field]
        update_working_memory("workflow_state", "intake")
        return {**state, "response": prompt, "halt": True}

    lookup_result = lookup_threat(wm["collected_info"]["description"])
    update_working_memory("latest_tool_result", lookup_result)
    update_working_memory("workflow_state", "classify")

    return {**state, "halt": False}


def analyze_node(state: AgentState) -> AgentState:
    wm = get_working_memory()
    info = wm["collected_info"]
    lookup_result = wm["latest_tool_result"] or {}

    analysis = analyze_severity(
        description=info["description"],
        affected_asset=info["affected_asset"],
        source_ip=info.get("source_ip"),
        threat_lookup_result=lookup_result,
    )

    update_working_memory("latest_tool_result", analysis)
    update_working_memory("workflow_state", "analyze")

    containment = lookup_result.get("containment", []) if "error" not in lookup_result else []
    steps = _get_playbook_steps(info["description"], containment)

    payload = {
        "title": f"Security Incident — {lookup_result.get('matched_technique', 'Unknown')}",
        "description": info["description"],
        "severity": analysis["severity"],
        "mitre_technique": lookup_result.get("matched_technique", "Unknown"),
        "mitre_tactic": lookup_result.get("tactic", "Unknown"),
        "tactic_id": lookup_result.get("tactic_id", "Unknown"),
        "affected_asset": info["affected_asset"],
        "source_ip": info.get("source_ip"),
        "containment_steps": steps,
        "risk_score": analysis["risk_score"],
        "estimated_impact": analysis["estimated_impact"],
        "analyst_name": info["analyst_name"],
        "lookup_result": lookup_result,
        "analysis": analysis,
    }

    update_working_memory("confirmation_payload", payload)
    update_working_memory("pending_confirmation", True)
    update_working_memory("workflow_state", "confirm")

    intel_source = lookup_result.get("source", "local knowledge base")
    cve_info = ""
    if lookup_result.get("cve_match"):
        cve = lookup_result["cve_match"]
        cve_info = f"\n- CVE Match: {cve['cve_id']} ({cve['name']}) — CVSS {cve['cvss']}"

    response = f"""**AI Triage Assessment** (based on available data)

**Severity:** {analysis['severity']} (Risk Score: {analysis['risk_score']}/100)
**Confidence:** {analysis['confidence']}
**MITRE Technique:** {lookup_result.get('matched_technique', 'Unknown')}
**MITRE Tactic:** {lookup_result.get('tactic_id', '')} — {lookup_result.get('tactic', 'Unknown')}
**Reasoning:** {analysis['reasoning']}
**Estimated Impact:** {analysis['estimated_impact']}
**Intelligence Source:** {intel_source}{cve_info}

**Containment Steps** (from MITRE ATT&CK + playbook):
{chr(10).join(f'  - {s}' for s in steps[:5])}

Do you want me to create this incident record? Reply **yes** to confirm or **no** to cancel."""

    return {**state, "response": response, "halt": True}


def confirm_node(state: AgentState) -> AgentState:
    message = state["user_message"]
    wm = get_working_memory()

    if _is_rejection(message):
        update_working_memory("pending_confirmation", False)
        update_working_memory("confirmation_payload", None)
        update_working_memory("workflow_state", "intake")
        return {
            **state,
            "response": "Incident creation cancelled. No record was written to the database. You can start a new incident or provide updated details.",
            "halt": True,
        }

    if not _is_confirmation(message):
        return {
            **state,
            "response": "Please confirm explicitly with **yes** or **no**. I cannot create an incident without your approval.",
            "halt": True,
        }

    update_working_memory("pending_confirmation", False)
    return {**state, "halt": False}


def action_node(state: AgentState) -> AgentState:
    wm = get_working_memory()
    payload = wm["confirmation_payload"]

    if not payload:
        return {
            **state,
            "response": "No confirmation payload found. Please start a new incident.",
            "halt": True,
        }

    try:
        result = create_incident(
            title=payload["title"],
            description=payload["description"],
            severity=payload["severity"],
            mitre_technique=payload["mitre_technique"],
            mitre_tactic=payload["mitre_tactic"],
            affected_asset=payload["affected_asset"],
            source_ip=payload.get("source_ip"),
            containment_steps=payload["containment_steps"],
            confirmed=True,
        )
    except ValueError as e:
        return {**state, "response": str(e), "halt": True}

    if "error" in result:
        return {**state, "response": f"Failed to create incident: {result['error']}", "halt": True}

    update_working_memory("incident_id", result["incident_id"])
    update_working_memory("workflow_state", "report")
    update_working_memory("latest_tool_result", result)

    return {**state, "halt": False}


def report_node(state: AgentState) -> AgentState:
    wm = get_working_memory()
    payload = wm["confirmation_payload"]
    incident_id = wm["incident_id"]

    report = generate_report(
        incident_id=incident_id,
        title=payload["title"],
        severity=payload["severity"],
        description=payload["description"],
        mitre_technique=payload["mitre_technique"],
        mitre_tactic=payload["mitre_tactic"],
        tactic_id=payload["tactic_id"],
        affected_asset=payload["affected_asset"],
        source_ip=payload.get("source_ip"),
        risk_score=payload["risk_score"],
        containment_steps=payload["containment_steps"],
        estimated_impact=payload["estimated_impact"],
        analyst_name=payload["analyst_name"],
    )

    update_working_memory("last_report", report)
    update_working_memory("workflow_state", "done")

    response = f"Incident **{incident_id}** created successfully.\n\n{report['report_text']}"
    return {**state, "response": response, "halt": True}


def status_node(state: AgentState) -> AgentState:
    message = state["user_message"]
    match = re.search(r"(INC-\d{4})", message, re.IGNORECASE)
    if not match:
        incidents = list_incidents()
        if not incidents:
            return {**state, "response": "No incidents found in the database.", "halt": True}
        lines = [f"- **{i['incident_id']}** [{i['severity']}] {i['title']} — {i['status']}" for i in incidents[:10]]
        return {**state, "response": "Recent incidents:\n" + "\n".join(lines), "halt": True}

    incident_id = match.group(1).upper()
    incident = get_incident(incident_id)
    if not incident:
        return {**state, "response": f"Incident {incident_id} not found.", "halt": True}

    response = f"""**Status for {incident_id}**
- Title: {incident['title']}
- Severity: {incident['severity']}
- Status: {incident['status']}
- MITRE: {incident['mitre_technique']} ({incident['mitre_tactic']})
- Asset: {incident['affected_asset']}
- Created: {incident['created_at']}"""
    return {**state, "response": response, "halt": True}


def report_request_node(state: AgentState) -> AgentState:
    message = state["user_message"]
    wm = get_working_memory()

    if wm.get("last_report"):
        return {**state, "response": wm["last_report"]["report_text"], "halt": True}

    match = re.search(r"(INC-\d{4})", message, re.IGNORECASE)
    if match:
        incident_id = match.group(1).upper()
        incident = get_incident(incident_id)
        if incident:
            import json
            steps = json.loads(incident.get("containment_steps") or "[]")
            report = generate_report(
                incident_id=incident["incident_id"],
                title=incident["title"],
                severity=incident["severity"],
                description=incident["description"],
                mitre_technique=incident["mitre_technique"],
                mitre_tactic=incident["mitre_tactic"],
                tactic_id="",
                affected_asset=incident["affected_asset"],
                source_ip=incident.get("source_ip"),
                risk_score=0,
                containment_steps=steps,
                estimated_impact="See incident record for details.",
                analyst_name=incident.get("assigned_to", "Security Team"),
            )
            update_working_memory("last_report", report)
            return {**state, "response": report["report_text"], "halt": True}

    return {
        **state,
        "response": "No report available. Complete an incident triage first or specify an incident ID (e.g., INC-0001).",
        "halt": True,
    }


def unsupported_node(state: AgentState) -> AgentState:
    return {
        **state,
        "response": "I can only help with security incident triage. For other requests, please contact your security team lead directly.",
        "halt": True,
    }


def done_node(state: AgentState) -> AgentState:
    return {
        **state,
        "response": "This incident triage is complete. Click **New Incident** to start another, or ask for a status check (e.g., 'status of INC-0001').",
        "halt": True,
    }


def _route_entry(state: AgentState) -> str:
    wm = get_working_memory()
    if wm["pending_confirmation"]:
        return "confirm"
    if wm["workflow_state"] == "done":
        return "done"
    if wm["workflow_state"] == "report" and wm["incident_id"]:
        return "report"
    if wm["workflow_state"] in ("intake",) and wm["current_intent"] == "new_incident":
        if wm["missing_fields"] or not wm["latest_tool_result"]:
            return "intake"
    if wm["workflow_state"] in ("classify",):
        return "analyze"
    return "router"


def _after_router(state: AgentState) -> str:
    intent = get_working_memory()["current_intent"]
    if intent == "new_incident":
        return "intake"
    if intent == "status_check":
        return "status"
    if intent == "report_request":
        return "report_request"
    return "unsupported"


def _after_intake(state: AgentState) -> str:
    if state.get("halt"):
        return "end"
    return "analyze"


def _after_analyze(state: AgentState) -> str:
    return "end"


def _after_confirm(state: AgentState) -> str:
    if state.get("halt"):
        return "end"
    return "action"


def _after_action(state: AgentState) -> str:
    return "report"


def _after_report(state: AgentState) -> str:
    return "end"


def build_graph() -> StateGraph:
    graph = StateGraph(AgentState)

    graph.add_node("router", router_node)
    graph.add_node("intake", intake_node)
    graph.add_node("analyze", analyze_node)
    graph.add_node("confirm", confirm_node)
    graph.add_node("action", action_node)
    graph.add_node("report", report_node)
    graph.add_node("status", status_node)
    graph.add_node("report_request", report_request_node)
    graph.add_node("unsupported", unsupported_node)
    graph.add_node("done", done_node)

    graph.set_conditional_entry_point(
        _route_entry,
        {
            "router": "router",
            "intake": "intake",
            "confirm": "confirm",
            "analyze": "analyze",
            "report": "report",
            "done": "done",
        },
    )

    graph.add_conditional_edges("router", _after_router, {
        "intake": "intake",
        "status": "status",
        "report_request": "report_request",
        "unsupported": "unsupported",
    })

    graph.add_conditional_edges("intake", _after_intake, {
        "analyze": "analyze",
        "end": END,
    })

    graph.add_conditional_edges("analyze", _after_analyze, {"end": END})

    graph.add_conditional_edges("confirm", _after_confirm, {
        "action": "action",
        "end": END,
    })

    graph.add_conditional_edges("action", _after_action, {"report": "report"})
    graph.add_conditional_edges("report", _after_report, {"end": END})

    graph.add_edge("status", END)
    graph.add_edge("report_request", END)
    graph.add_edge("unsupported", END)
    graph.add_edge("done", END)

    return graph.compile()


_agent_graph = None
_tool_call_count = 0


def _get_graph():
    global _agent_graph
    if _agent_graph is None:
        _agent_graph = build_graph()
    return _agent_graph


def run_agent(message: str) -> str:
    global _tool_call_count
    _tool_call_count = 0

    add_message("user", message)

    wm = get_working_memory()
    if wm["workflow_state"] == "intake" and not wm["current_intent"]:
        intent = classify_intent(message)
        update_working_memory("current_intent", intent)

    if wm["workflow_state"] == "intake" and wm["current_intent"] is None:
        intent = classify_intent(message)
        update_working_memory("current_intent", intent)

    initial_state: AgentState = {
        "user_message": message,
        "response": "",
        "halt": False,
    }

    try:
        result = _get_graph().invoke(initial_state)
        response = result.get("response", "I was unable to process your request.")
    except Exception:
        response = "An error occurred while processing your request. Please try again or contact your security team lead."

    add_message("assistant", response)
    return response


def get_workflow_state() -> str:
    return get_working_memory().get("workflow_state", "intake")
