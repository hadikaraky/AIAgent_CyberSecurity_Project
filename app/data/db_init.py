"""Initialize SQLite incidents database."""

import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), "incidents.db")

SCHEMA = """
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
"""


def get_connection():
    return sqlite3.connect(DB_PATH)


def init_db():
    conn = get_connection()
    try:
        conn.execute(SCHEMA)
        conn.commit()
    finally:
        conn.close()


def generate_incident_id() -> str:
    """Generate next INC-XXXX ID from the last record in the database."""
    conn = get_connection()
    try:
        cursor = conn.execute(
            "SELECT incident_id FROM incidents ORDER BY id DESC LIMIT 1"
        )
        row = cursor.fetchone()
        if row:
            last_num = int(row[0].replace("INC-", ""))
            next_num = last_num + 1
        else:
            next_num = 1
        return f"INC-{next_num:04d}"
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
    print(f"Database initialized at {DB_PATH}")
