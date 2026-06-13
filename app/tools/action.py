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

import json
import os
import sqlite3
from datetime import datetime, timezone

from app.data.db_init import generate_incident_id, get_connection

LOGS_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "logs")
ACTIONS_LOG = os.path.join(LOGS_DIR, "actions.log")


def _log_action(incident_id: str, action: str):
    os.makedirs(LOGS_DIR, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    with open(ACTIONS_LOG, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] incident_id={incident_id} action={action}\n")


def create_incident(
    title: str,
    description: str,
    severity: str,
    mitre_technique: str,
    mitre_tactic: str,
    affected_asset: str,
    source_ip: str | None,
    containment_steps: list[str],
    confirmed: bool,
) -> dict:
    if not confirmed:
        raise ValueError("User confirmation required before creating incident")

    incident_id = generate_incident_id()
    created_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    containment_json = json.dumps(containment_steps)

    try:
        conn = get_connection()
        conn.execute(
            """
            INSERT INTO incidents (
                incident_id, title, description, severity, mitre_technique,
                mitre_tactic, affected_asset, source_ip, containment_steps, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                incident_id,
                title,
                description,
                severity,
                mitre_technique,
                mitre_tactic,
                affected_asset,
                source_ip,
                containment_json,
                created_at,
                created_at,
            ),
        )
        conn.commit()
        conn.close()

        _log_action(incident_id, f"create_incident severity={severity} technique={mitre_technique}")

        return {
            "incident_id": incident_id,
            "status": "Created",
            "created_at": created_at,
            "message": f"Incident {incident_id} created successfully.",
        }
    except Exception as e:
        _log_action("FAILED", f"create_incident error={str(e)}")
        return {"error": str(e), "status": "Failed"}


def get_incident(incident_id: str) -> dict | None:
    try:
        conn = get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            "SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)
        )
        row = cursor.fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception:
        return None


def list_incidents() -> list[dict]:
    try:
        conn = get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            "SELECT incident_id, title, severity, status, created_at FROM incidents ORDER BY id DESC"
        )
        rows = [dict(r) for r in cursor.fetchall()]
        conn.close()
        return rows
    except Exception:
        return []
