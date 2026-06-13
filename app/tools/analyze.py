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

import ipaddress
import re


def _is_external_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip.strip())
        return not addr.is_private
    except ValueError:
        return True


def _is_production_asset(asset: str) -> bool:
    asset_lower = asset.lower()
    keywords = ["prod", "production", "db", "database"]
    return any(kw in asset_lower for kw in keywords)


def analyze_severity(
    description: str,
    affected_asset: str,
    source_ip: str | None,
    threat_lookup_result: dict,
) -> dict:
    if "error" in threat_lookup_result:
        risk_score = 45
        if "staging" in affected_asset.lower():
            risk_score = 30
        severity = "Low" if risk_score < 40 else "Medium"
        return {
            "severity": severity,
            "confidence": "Low",
            "reasoning": "No matching threat intelligence found. Defaulting severity based on available data.",
            "risk_score": risk_score,
            "requires_confirmation": True,
            "estimated_impact": "Impact unknown — manual investigation required.",
        }

    severity_weight = threat_lookup_result.get("severity_weight", 5)
    risk_score = severity_weight * 10

    reasoning_parts = [f"Base score from MITRE severity weight ({severity_weight}/10 → {risk_score} points)."]

    if _is_production_asset(affected_asset):
        risk_score += 20
        reasoning_parts.append("+20 for production/database asset.")

    if _is_external_ip(source_ip):
        risk_score += 15
        reasoning_parts.append(f"+15 for external source IP ({source_ip}).")

    if threat_lookup_result.get("escalate"):
        risk_score += 10
        reasoning_parts.append("+10 for escalation flag from threat intelligence.")

    risk_score = min(risk_score, 100)

    if risk_score >= 80:
        severity = "Critical"
        impact = "Severe — potential data breach, service disruption, or active exploitation."
    elif risk_score >= 60:
        severity = "High"
        impact = "Significant — likely compromise requiring immediate containment."
    elif risk_score >= 40:
        severity = "Medium"
        impact = "Moderate — suspicious activity requiring investigation and monitoring."
    else:
        severity = "Low"
        impact = "Limited — low-risk activity, likely reconnaissance or misconfiguration."

    confidence = "High" if threat_lookup_result.get("cve_match") else "Medium"
    if not threat_lookup_result.get("matched_technique"):
        confidence = "Low"

    return {
        "severity": severity,
        "confidence": confidence,
        "reasoning": " ".join(reasoning_parts),
        "risk_score": risk_score,
        "requires_confirmation": True,
        "estimated_impact": impact,
    }
