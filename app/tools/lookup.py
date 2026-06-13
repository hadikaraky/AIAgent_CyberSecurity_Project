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

import json
import os
import re

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")


def _load_json(filename: str) -> list:
    path = os.path.join(DATA_DIR, filename)
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _score_match(query: str, text: str) -> int:
    query_lower = query.lower()
    text_lower = text.lower()
    if text_lower in query_lower:
        return 10
    words = text_lower.split()
    return sum(2 for word in words if len(word) > 3 and word in query_lower)


def lookup_threat(query: str) -> dict:
    if not query or not query.strip():
        return {"error": "No matching threat found", "source": "local knowledge base"}

    query_lower = query.lower()
    tactics = _load_json("mitre_tactics.json")
    cves = _load_json("cve_knowledge.json")

    cve_match = None
    cve_pattern = re.search(r"CVE-\d{4}-\d+", query, re.IGNORECASE)
    if cve_pattern:
        cve_id = cve_pattern.group().upper()
        for cve in cves:
            if cve["cve_id"].upper() == cve_id:
                cve_match = cve
                break

    best_match = None
    best_score = 0

    for tactic in tactics:
        score = 0
        score += _score_match(query_lower, tactic["technique"])
        score += _score_match(query_lower, tactic["description"])
        score += _score_match(query_lower, tactic["id"])
        score += _score_match(query_lower, tactic["tactic"])

        for indicator in tactic.get("indicators", []):
            score += _score_match(query_lower, indicator)

        if score > best_score:
            best_score = score
            best_match = tactic

    if cve_match:
        mitre_ref = cve_match.get("mitre_ref", "")
        for tactic in tactics:
            if tactic["id"] == mitre_ref:
                best_match = tactic
                best_score = max(best_score, 15)
                break

    if best_score == 0 and not cve_match:
        return {"error": "No matching threat found", "source": "local knowledge base"}

    if best_match is None and cve_match:
        return {
            "matched_technique": cve_match.get("mitre_ref", "Unknown"),
            "tactic": "Initial Access",
            "tactic_id": "TA0001",
            "severity_weight": 9,
            "indicators": cve_match.get("keywords", []),
            "containment": [f"Apply patch: {cve_match.get('patch', 'See vendor advisory')}"],
            "cve_match": cve_match,
            "escalate": True,
            "source": "mitre_tactics.json / cve_knowledge.json",
        }

    return {
        "matched_technique": best_match["id"],
        "tactic": best_match["tactic"],
        "tactic_id": best_match["tactic_id"],
        "severity_weight": best_match["severity_weight"],
        "indicators": best_match.get("indicators", []),
        "containment": best_match.get("containment", []),
        "cve_match": cve_match,
        "escalate": best_match.get("escalate", False),
        "source": "mitre_tactics.json / cve_knowledge.json",
    }
