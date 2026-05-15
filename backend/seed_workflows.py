"""
RegentClaw — Workflow Seeder
Loads 5 example orchestration workflows.

Usage:
  docker compose exec backend python seed_workflows.py          # additive
  docker compose exec backend python seed_workflows.py --reset  # wipe + reseed
"""
import asyncio
import json
import sys
from sqlalchemy import select, delete
from app.core.database import AsyncSessionLocal
from app.models.workflow import Workflow


def _s(id, name, type_, config=None, on_failure="stop"):
    return {
        "id": id,
        "name": name,
        "type": type_,
        "config": config or {},
        "on_failure": on_failure,
    }


WORKFLOWS = [
    {
        "name": "Daily Identity Audit",
        "description": (
            "Runs the IdentityClaw audit agent every morning to surface orphaned accounts, "
            "stale permissions, and privilege drift. Emits a notification on completion."
        ),
        "trigger_type": "schedule",
        "category": "Identity",
        "tags": "identity,audit,daily",
        "owner_name": "Security Team",
        "steps": [
            _s("s1", "Policy Gate — Identity Scope",
               "policy_check",
               {"field": "module", "op": "eq", "value": "identityclaw", "label": "Identity module active"},
               on_failure="stop"),
            _s("s2", "Run IdentityClaw Audit Agent",
               "agent_run",
               {"label": "IdentityClaw Auditor"},
               on_failure="stop"),
            _s("s3", "Notify — Identity Audit Complete",
               "notify",
               {"message": "Daily identity audit completed. Review findings in IdentityClaw.", "severity": "info"},
               on_failure="continue"),
        ],
    },
    {
        "name": "Zero Trust Access Review",
        "description": (
            "Multi-step access review: verify policy compliance, trigger the AccessClaw privilege "
            "review agent, check for anomalies in UserClaw, and send a summary notification."
        ),
        "trigger_type": "manual",
        "category": "Access Control",
        "tags": "zero-trust,access,review",
        "owner_name": "IAM Team",
        "steps": [
            _s("s1", "Policy Check — MFA Compliance",
               "policy_check",
               {"field": "mfa_enabled", "op": "eq", "value": True, "label": "MFA compliance gate"},
               on_failure="stop"),
            _s("s2", "Run AccessClaw Privilege Review",
               "agent_run",
               {"label": "AccessClaw Reviewer"},
               on_failure="continue"),
            _s("s3", "Run UserClaw Behaviour Analysis",
               "agent_run",
               {"label": "UserClaw Analyst"},
               on_failure="continue"),
            _s("s4", "Condition — Any High-Risk Users Found?",
               "condition",
               {"expression": "user_risk_score > 70"},
               on_failure="continue"),
            _s("s5", "Notify — Access Review Complete",
               "notify",
               {"message": "Zero Trust access review complete. Check AccessClaw and UserClaw for flagged identities.", "severity": "medium"},
               on_failure="continue"),
        ],
    },
    {
        "name": "Incident Response Playbook",
        "description": (
            "Automated first-response playbook triggered on a high-severity ThreatClaw event. "
            "Runs threat triage, triggers network isolation check, logs to audit, and escalates."
        ),
        "trigger_type": "event",
        "category": "Incident Response",
        "tags": "incident,threat,response,soar",
        "owner_name": "SOC Team",
        "steps": [
            _s("s1", "Policy Gate — Threat Severity Check",
               "policy_check",
               {"field": "severity", "op": "gte", "value": "high", "label": "High severity gate"},
               on_failure="stop"),
            _s("s2", "Run ThreatClaw Triage Agent",
               "agent_run",
               {"label": "ThreatClaw Triage"},
               on_failure="continue"),
            _s("s3", "Run NetClaw Isolation Assessment",
               "agent_run",
               {"label": "NetClaw Isolator"},
               on_failure="continue"),
            _s("s4", "Wait — Isolation Confirmation (2s)",
               "wait",
               {"seconds": 2},
               on_failure="continue"),
            _s("s5", "Notify — Incident Escalation",
               "notify",
               {"message": "⚠ Incident response triggered. ThreatClaw and NetClaw actions logged. Escalating to SOC lead.", "severity": "critical"},
               on_failure="continue"),
            _s("s6", "Run InsiderClaw Correlation Check",
               "agent_run",
               {"label": "InsiderClaw Correlator"},
               on_failure="continue"),
        ],
    },
    {
        "name": "Compliance Check Pipeline",
        "description": (
            "Full compliance sweep across multiple modules. Checks policy adherence, runs "
            "ComplianceClaw and PrivacyClaw agents, evaluates vendor risk, and generates a report."
        ),
        "trigger_type": "schedule",
        "category": "Compliance",
        "tags": "compliance,soc2,iso27001,hipaa,audit",
        "owner_name": "Compliance Team",
        "steps": [
            _s("s1", "Policy Check — Audit Logging Active",
               "policy_check",
               {"field": "audit_logging", "op": "eq", "value": "enabled", "label": "Audit logging gate"},
               on_failure="stop"),
            _s("s2", "Run ComplianceClaw Assessment",
               "agent_run",
               {"label": "ComplianceClaw Assessor"},
               on_failure="continue"),
            _s("s3", "Run PrivacyClaw Data Inventory",
               "agent_run",
               {"label": "PrivacyClaw Auditor"},
               on_failure="continue"),
            _s("s4", "Run VendorClaw Risk Review",
               "agent_run",
               {"label": "VendorClaw Risk Reviewer"},
               on_failure="continue"),
            _s("s5", "Condition — Any Critical Findings?",
               "condition",
               {"expression": "critical_findings > 0"},
               on_failure="continue"),
            _s("s6", "Notify — Compliance Report Ready",
               "notify",
               {"message": "Compliance pipeline complete. Report available in ComplianceClaw, PrivacyClaw, and VendorClaw.", "severity": "low"},
               on_failure="continue"),
        ],
    },
    {
        "name": "New Employee Onboarding",
        "description": (
            "Provisions identity, assigns baseline access, audits the new account against Zero Trust "
            "policies, and notifies the IT team. Runs when a new hire record is created."
        ),
        "trigger_type": "event",
        "category": "Identity",
        "tags": "onboarding,identity,access,automation",
        "owner_name": "IT Operations",
        "steps": [
            _s("s1", "Policy Check — Onboarding Authorization",
               "policy_check",
               {"field": "event_type", "op": "eq", "value": "new_hire", "label": "New hire event gate"},
               on_failure="stop"),
            _s("s2", "Run IdentityClaw Provisioning Agent",
               "agent_run",
               {"label": "IdentityClaw Provisioner"},
               on_failure="stop"),
            _s("s3", "Run AccessClaw Baseline Assignment",
               "agent_run",
               {"label": "AccessClaw Baseline"},
               on_failure="continue"),
            _s("s4", "Wait — Propagation Delay (1s)",
               "wait",
               {"seconds": 1},
               on_failure="continue"),
            _s("s5", "Run ArcClaw Account Baseline Scan",
               "agent_run",
               {"label": "ArcClaw Security Baseline"},
               on_failure="continue"),
            _s("s6", "Notify — Onboarding Complete",
               "notify",
               {"message": "New employee onboarding workflow complete. Identity provisioned and baseline access assigned.", "severity": "info"},
               on_failure="continue"),
        ],
    },
]


async def seed(reset: bool = False):
    async with AsyncSessionLocal() as db:
        if reset:
            await db.execute(delete(Workflow.__table__))
            await db.commit()
            print("🗑  Cleared workflows table")

        created = 0
        for wf_def in WORKFLOWS:
            steps = wf_def.pop("steps")
            steps_json = json.dumps(steps)
            step_count = len(steps)

            result = await db.execute(
                select(Workflow).where(Workflow.name == wf_def["name"])
            )
            existing = result.scalar_one_or_none()

            if existing:
                existing.description = wf_def["description"]
                existing.trigger_type = wf_def["trigger_type"]
                existing.category = wf_def["category"]
                existing.tags = wf_def["tags"]
                existing.owner_name = wf_def["owner_name"]
                existing.steps_json = steps_json
                existing.step_count = step_count
                print(f"  ↻  Updated: {wf_def['name']} ({step_count} steps)")
            else:
                db.add(Workflow(
                    **wf_def,
                    steps_json=steps_json,
                    step_count=step_count,
                ))
                created += 1
                print(f"  ✅ Created: {wf_def['name']} ({step_count} steps)")

        await db.commit()
        print(f"\n✅ Done — {created} workflows created, {len(WORKFLOWS) - created} updated")
        print("\nTrigger a workflow from the UI or via API:")
        print("  POST /api/v1/orchestrations/<id>/run")


if __name__ == "__main__":
    reset = "--reset" in sys.argv
    asyncio.run(seed(reset))
