"""
Short-term memory: list of {role, content} dicts — full conversation history for current session.
Working memory: explicit workflow state fields for the triage agent.
"""

from copy import deepcopy

_conversation_history: list[dict] = []
_working_memory: dict = {
    "current_intent": None,
    "collected_info": {
        "description": None,
        "affected_asset": None,
        "source_ip": None,
        "analyst_name": None,
    },
    "missing_fields": ["description", "affected_asset", "source_ip", "analyst_name"],
    "pending_confirmation": False,
    "confirmation_payload": None,
    "latest_tool_result": None,
    "workflow_state": "intake",
    "incident_id": None,
    "last_report": None,
}

REQUIRED_FIELDS = ["description", "affected_asset", "analyst_name"]
OPTIONAL_FIELDS = ["source_ip"]


def get_memory() -> dict:
    return {
        "conversation": deepcopy(_conversation_history),
        "working": deepcopy(_working_memory),
    }


def get_working_memory() -> dict:
    return _working_memory


def update_working_memory(field: str, value) -> None:
    if field in _working_memory:
        _working_memory[field] = value
    elif field in _working_memory["collected_info"]:
        _working_memory["collected_info"][field] = value
        _update_missing_fields()


def _update_missing_fields() -> None:
    missing = []
    for f in REQUIRED_FIELDS:
        if not _working_memory["collected_info"].get(f):
            missing.append(f)
    if not _working_memory["collected_info"].get("source_ip"):
        missing.append("source_ip")
    _working_memory["missing_fields"] = missing


def reset_memory() -> None:
    global _conversation_history, _working_memory
    _conversation_history = []
    _working_memory = {
        "current_intent": None,
        "collected_info": {
            "description": None,
            "affected_asset": None,
            "source_ip": None,
            "analyst_name": None,
        },
        "missing_fields": list(REQUIRED_FIELDS + OPTIONAL_FIELDS),
        "pending_confirmation": False,
        "confirmation_payload": None,
        "latest_tool_result": None,
        "workflow_state": "intake",
        "incident_id": None,
        "last_report": None,
    }


def get_conversation_history() -> list[dict]:
    return list(_conversation_history)


def add_message(role: str, content: str) -> None:
    _conversation_history.append({"role": role, "content": content})
