"""
Seed example Event Triggers for RegentClaw.

These demonstrate the three main trigger patterns:
  1. finding_created  — fire workflow when critical/high findings land
  2. finding_escalated — fire workflow when severity jumps to critical
  3. event_created    — fire on specific platform events
  4. webhook_inbound  — receive external system webhooks

Run: docker compose exec backend python seed_triggers.py
"""
import asyncio
import json
from app.core.database import AsyncSessionLocal
from app.models.trigger import EventTrigger
from sqlalchemy import select

TRIGGERS = [
    # ── Finding: Critical endpoint detection → containment workflow ────────
    {
        "name":             "Critical Endpoint Detection → Containment",
        "description":      "Automatically launch the endpoint containment workflow when CrowdStrike/Defender reports a critical finding",
        "trigger_type":     "finding_created",
        "source_filter":    "endpointclaw",
        "severity_min":     "critical",
        "conditions_json":  json.dumps([
            {"field": "severity", "op": "gte",  "value": "critical"},
            {"field": "claw",     "op": "eq",   "value": "endpointclaw"},
        ]),
        "action_type":    "fire_workflow",
        "cooldown_seconds": 300,
        "category":       "detection",
    },
    # ── Finding: KEV hit → threat intel workflow ───────────────────────────
    {
        "name":             "CISA KEV Match → Threat Intel Enrichment",
        "description":      "When a vulnerability is confirmed in the CISA KEV (actively exploited), fire the threat intel enrichment workflow",
        "trigger_type":     "finding_created",
        "source_filter":    "exposureclaw",
        "conditions_json":  json.dumps([
            {"field": "actively_exploited", "op": "eq",  "value": "True"},
            {"field": "severity",           "op": "gte", "value": "high"},
        ]),
        "action_type":    "fire_workflow",
        "cooldown_seconds": 600,
        "category":       "detection",
    },
    # ── Finding: High-risk identity finding → access review ───────────────
    {
        "name":             "High-Risk Identity Finding → Access Review Workflow",
        "description":      "Fires when AccessClaw or IdentityClaw detects a high/critical identity risk",
        "trigger_type":     "finding_created",
        "severity_min":     "high",
        "conditions_json":  json.dumps([
            {"field": "claw",     "op": "in",  "value": "accessclaw,identityclaw"},
            {"field": "severity", "op": "gte", "value": "high"},
        ]),
        "action_type":    "fire_workflow",
        "cooldown_seconds": 900,
        "category":       "identity",
    },
    # ── Finding: Cloud public exposure → cloud scan ────────────────────────
    {
        "name":             "Cloud Public Exposure → Re-scan CloudClaw",
        "description":      "Re-scan CloudClaw when a new public exposure finding is created, to capture the full blast radius",
        "trigger_type":     "finding_created",
        "source_filter":    "cloudclaw",
        "conditions_json":  json.dumps([
            {"field": "category",   "op": "contains", "value": "exposure"},
            {"field": "risk_score", "op": "gte",      "value": "70"},
        ]),
        "action_type":  "fire_scan",
        "target_claw":  "cloudclaw",
        "cooldown_seconds": 1800,
        "category":       "cloud",
    },
    # ── Finding escalation → alert ─────────────────────────────────────────
    {
        "name":             "Finding Escalated to Critical → Alert All Channels",
        "description":      "When any existing finding is escalated to CRITICAL severity, immediately alert all configured channels",
        "trigger_type":     "finding_escalated",
        "severity_min":     "critical",
        "conditions_json":  json.dumps([
            {"field": "severity", "op": "eq", "value": "critical"},
        ]),
        "action_type":  "fire_alert",
        "alert_config_json": json.dumps({
            "title":       "RegentClaw: Finding Escalated to Critical",
            "description": "A security finding was escalated to CRITICAL severity. Immediate review required.",
            "severity":    "critical",
        }),
        "cooldown_seconds": 120,
        "category":       "escalation",
    },
    # ── Event: Policy violation blocked → notify ──────────────────────────
    {
        "name":             "Policy Violation Blocked → Security Alert",
        "description":      "Send an alert when the Trust Fabric policy engine blocks an action",
        "trigger_type":     "event_created",
        "conditions_json":  json.dumps([
            {"field": "outcome", "op": "eq",  "value": "blocked"},
            {"field": "severity", "op": "gte", "value": "high"},
        ]),
        "action_type":  "fire_alert",
        "cooldown_seconds": 60,
        "category":       "compliance",
    },
    # ── Event: AI anomaly detected ─────────────────────────────────────────
    {
        "name":             "ArcClaw AI Anomaly Detected → Workflow",
        "description":      "When ArcClaw flags an AI prompt anomaly, launch the AI security review workflow",
        "trigger_type":     "event_created",
        "source_filter":    "arcclaw",
        "conditions_json":  json.dumps([
            {"field": "is_anomaly",  "op": "eq",  "value": "True"},
            {"field": "outcome",     "op": "neq", "value": "allowed"},
        ]),
        "action_type":    "fire_workflow",
        "cooldown_seconds": 300,
        "category":       "ai_security",
    },
    # ── Webhook: Sentinel incident inbound ────────────────────────────────
    {
        "name":             "Sentinel Incident Webhook → ThreatClaw Enrichment",
        "description":      "POST from Microsoft Sentinel to this webhook to trigger ThreatClaw enrichment and threat intel correlation",
        "trigger_type":     "webhook_inbound",
        "conditions_json":  json.dumps([]),  # fires on any POST to this URL
        "action_type":  "fire_scan",
        "target_claw":  "threatclaw",
        "cooldown_seconds": 120,
        "category":       "integration",
    },
    # ── Webhook: GitHub secret alert ──────────────────────────────────────
    {
        "name":             "GitHub Secret Alert Webhook → DevClaw Scan",
        "description":      "GitHub calls this webhook when a secret is detected. Fires DevClaw scan immediately.",
        "trigger_type":     "webhook_inbound",
        "conditions_json":  json.dumps([
            {"field": "action", "op": "contains", "value": "secret"},
        ]),
        "action_type":  "fire_scan",
        "target_claw":  "devclaw",
        "cooldown_seconds": 300,
        "category":       "devsecops",
    },
]


async def seed():
    async with AsyncSessionLocal() as db:
        # Check how many already exist
        result = await db.execute(select(EventTrigger))
        existing = result.scalars().all()
        existing_names = {t.name for t in existing}

        created = 0
        for t in TRIGGERS:
            if t["name"] in existing_names:
                print(f"  skip (exists): {t['name']}")
                continue
            obj = EventTrigger(**{k: v for k, v in t.items()})
            db.add(obj)
            created += 1
            print(f"  created: {t['name']}")

        await db.commit()
        print(f"\n✅ Seeded {created} triggers ({len(existing)} already existed)")


if __name__ == "__main__":
    asyncio.run(seed())
