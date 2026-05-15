"""
RegentClaw — Governed Execution policy engine
Evaluates whether a shell/browser/credential/production request is allowed,
needs approval, or should be blocked outright.
"""
from __future__ import annotations

import re
from typing import Any

# ─── risk patterns ────────────────────────────────────────────────────────────

# Shell commands that require approval regardless of environment
_APPROVAL_CMDS = re.compile(
    r"\b(rm\s+-rf|chmod\s+777|chown|dd\s+if=|mkfs|fdisk|shutdown|reboot|"
    r"iptables|ufw|systemctl\s+(stop|disable|mask)|"
    r"kubectl\s+(delete|scale|rollout)\s+(deployment|statefulset|all)"
    r"|helm\s+uninstall|terraform\s+(destroy|apply|import)"
    r"|aws\s+(ec2|iam|s3|rds|lambda)\s+(delete|create|put|update))\b",
    re.I,
)

# Shell commands that are always blocked
_BLOCKED_CMDS = re.compile(
    r"\b(curl\s+.*\|\s*sh|wget\s+.*\|\s*sh|bash\s+-c.*curl|"
    r"python.*exec\(.*os\.|eval\s*\(|"
    r"cat\s+/etc/shadow|cat\s+/etc/passwd.*grep\s+root|"
    r"nc\s+-[el]|ncat|socat.*exec|"
    r"base64\s+-d.*\|\s*(sh|bash)|"
    r"export\s+AWS_SECRET|printenv.*SECRET|env.*TOKEN)\b",
    re.I,
)

# Production keywords
_PROD_PATTERNS = re.compile(r"\b(prod|production|live|prd)\b", re.I)


def _risk_score(channel: str, command: str, environment: str, requested_by: str) -> dict:
    """
    Compute risk score (0-100) and risk_level for a request.
    """
    score  = 20  # baseline
    flags  = []

    if _BLOCKED_CMDS.search(command):
        return {"score": 100, "level": "critical", "flags": ["blocked_command_pattern"], "blocked": True}

    if environment in ("prod", "production", "live", "prd") or _PROD_PATTERNS.search(command):
        score += 40
        flags.append("production_environment")

    if _APPROVAL_CMDS.search(command):
        score += 30
        flags.append("destructive_or_privileged_command")

    if channel == "shell":
        score += 10
    if channel == "credential":
        score += 15
        flags.append("credential_access")
    if channel == "production":
        score += 25
        flags.append("production_gate")

    if "root" in requested_by.lower() or "admin" in requested_by.lower():
        score += 5

    score   = min(score, 99)
    level   = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 40 else "low"
    return {"score": score, "level": level, "flags": flags, "blocked": False}


def evaluate_exec_request(
    channel:       str,
    command:       str,
    environment:   str,
    requested_by:  str,
    justification: str,
    agent_id:      str = "",
) -> dict[str, Any]:
    """
    Full policy evaluation for a governed execution request.
    Returns: { decision, risk_level, trust_score, policy_flags, requires_approval, reason }
    """
    risk = _risk_score(channel, command, environment, requested_by)

    if risk["blocked"]:
        return {
            "decision":          "blocked",
            "risk_level":        "critical",
            "trust_score":       0.0,
            "policy_flags":      risk["flags"],
            "requires_approval": False,
            "reason":            "Command matches blocked pattern — refused by security policy",
        }

    flags             = list(risk["flags"])
    requires_approval = False
    decision          = "allowed"

    # Production always requires dual approval
    if channel == "production" or "production_environment" in flags:
        requires_approval = True
        decision          = "requires_approval"
        flags.append("production_dual_approval_required")

    # High-risk operations require approval
    elif risk["level"] in ("critical", "high"):
        requires_approval = True
        decision          = "requires_approval"

    # Missing justification for privileged ops
    if "destructive_or_privileged_command" in flags and not justification.strip():
        flags.append("justification_required")
        if decision == "allowed":
            decision          = "requires_approval"
            requires_approval = True

    trust_score = max(0.0, 100.0 - risk["score"])

    return {
        "decision":          decision,
        "risk_level":        risk["level"],
        "trust_score":       round(trust_score, 1),
        "policy_flags":      flags,
        "requires_approval": requires_approval,
        "reason":            (
            "Blocked by security policy" if decision == "blocked" else
            "Requires approval — high-risk or production operation" if requires_approval else
            "Allowed"
        ),
    }
