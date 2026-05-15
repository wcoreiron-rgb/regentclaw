"""
RegentClaw — Policy Pack Seeder
Loads 5 compliance framework packs: Zero Trust Baseline, SOC2, ISO27001, HIPAA, PCI-DSS.

Usage:
  docker compose exec backend python seed_policy_packs.py          # additive
  docker compose exec backend python seed_policy_packs.py --reset  # wipe + reseed
"""
import asyncio
import json
import sys
from sqlalchemy import select, delete
from app.core.database import AsyncSessionLocal
from app.models.policy_pack import PolicyPack


# ─────────────────────────────────────────────────────────────────────────────
#  Pack definitions
# ─────────────────────────────────────────────────────────────────────────────

PACKS = [
    {
        "name": "Zero Trust Baseline",
        "framework": "zero-trust",
        "version": "1.0",
        "description": (
            "Foundational Zero Trust policies enforcing least-privilege, continuous "
            "verification, and microsegmentation across all RegentClaw modules."
        ),
        "policies": [
            {
                "name": "ZT — Block Unauthenticated API Access",
                "description": "TRUST FABRIC | Block any API request arriving without a valid identity token",
                "priority": 5,
                "scope": "global",
                "condition_json": json.dumps({"field": "auth_token", "op": "eq", "value": "none"}),
                "action": "deny",
                "is_active": True,
            },
            {
                "name": "ZT — Require MFA for Privileged Actions",
                "description": "ACCESSCLAW | Pause privileged access requests until MFA is verified",
                "priority": 10,
                "scope": "module",
                "scope_target": "accessclaw",
                "condition_json": json.dumps({"field": "privilege_level", "op": "eq", "value": "elevated"}),
                "action": "require_approval",
                "is_active": True,
            },
            {
                "name": "ZT — Block Lateral Movement",
                "description": "NETCLAW | Block east-west traffic not matching an approved microsegment policy",
                "priority": 15,
                "scope": "module",
                "scope_target": "netclaw",
                "condition_json": json.dumps({"field": "traffic_direction", "op": "eq", "value": "lateral"}),
                "action": "deny",
                "is_active": True,
            },
            {
                "name": "ZT — Monitor All AI Invocations",
                "description": "ARCCLAW | Log and score every LLM prompt for anomaly detection",
                "priority": 20,
                "scope": "module",
                "scope_target": "arcclaw",
                "condition_json": json.dumps({"field": "action_type", "op": "eq", "value": "llm_prompt"}),
                "action": "monitor",
                "is_active": True,
            },
            {
                "name": "ZT — Block Connector Install Without Approval",
                "description": "COREOS | Require administrator approval before activating new connectors",
                "priority": 25,
                "scope": "connector",
                "condition_json": json.dumps({"field": "connector_status", "op": "eq", "value": "pending"}),
                "action": "require_approval",
                "is_active": True,
            },
            {
                "name": "ZT — Block Shell Access from Agents",
                "description": "ARCCLAW | Deny any agent action that requests shell execution privileges",
                "priority": 30,
                "scope": "module",
                "scope_target": "arcclaw",
                "condition_json": json.dumps({"field": "shell_access", "op": "eq", "value": True}),
                "action": "deny",
                "is_active": True,
            },
            {
                "name": "ZT — Block Unapproved Data Egress",
                "description": "DATACLAW | Block data transfers to destinations not on the allowlist",
                "priority": 35,
                "scope": "module",
                "scope_target": "dataclaw",
                "condition_json": json.dumps({"field": "destination", "op": "eq", "value": "unapproved"}),
                "action": "deny",
                "is_active": True,
            },
            {
                "name": "ZT — Monitor Identity Anomalies",
                "description": "IDENTITYCLAW | Flag accounts showing anomalous access patterns for review",
                "priority": 40,
                "scope": "module",
                "scope_target": "identityclaw",
                "condition_json": json.dumps({"field": "risk_score", "op": "gte", "value": 70}),
                "action": "monitor",
                "is_active": True,
            },
        ],
    },
    {
        "name": "SOC 2 Type II",
        "framework": "soc2",
        "version": "1.0",
        "description": (
            "Policies aligned to AICPA SOC 2 Trust Services Criteria: Security, "
            "Availability, Confidentiality, Processing Integrity, and Privacy."
        ),
        "policies": [
            {
                "name": "SOC2 — Require Audit Logging for All Access",
                "description": "LOGCLAW | Block any resource access that cannot produce an audit log entry",
                "priority": 10,
                "scope": "global",
                "condition_json": json.dumps({"field": "audit_logging", "op": "eq", "value": "disabled"}),
                "action": "deny",
                "is_active": True,
            },
            {
                "name": "SOC2 — Monitor Change Management Events",
                "description": "CONFIGCLAW | Log all infrastructure and configuration changes for SOC2 evidence",
                "priority": 20,
                "scope": "module",
                "scope_target": "configclaw",
                "condition_json": json.dumps({"field": "event_type", "op": "eq", "value": "config_change"}),
                "action": "monitor",
                "is_active": True,
            },
            {
                "name": "SOC2 — Require Approval for Infrastructure Changes",
                "description": "CLOUDCLAW | Pause production infrastructure modifications pending change advisory board review",
                "priority": 25,
                "scope": "module",
                "scope_target": "cloudclaw",
                "condition_json": json.dumps({"field": "environment", "op": "eq", "value": "production"}),
                "action": "require_approval",
                "is_active": True,
            },
            {
                "name": "SOC2 — Block Sensitive Data in Logs",
                "description": "LOGCLAW | Deny log writes containing PII, credentials, or financial data",
                "priority": 30,
                "scope": "module",
                "scope_target": "logclaw",
                "condition_json": json.dumps({"field": "data_classification", "op": "in", "value": ["pii", "credentials", "financial"]}),
                "action": "deny",
                "is_active": True,
            },
            {
                "name": "SOC2 — Monitor Third-Party Access",
                "description": "VENDORCLAW | Track all vendor and third-party connections for availability and confidentiality reviews",
                "priority": 35,
                "scope": "module",
                "scope_target": "vendorclaw",
                "condition_json": json.dumps({"field": "access_type", "op": "eq", "value": "third_party"}),
                "action": "monitor",
                "is_active": True,
            },
            {
                "name": "SOC2 — Flag After-Hours Access",
                "description": "USERCLAW | Monitor resource access occurring outside defined business hours",
                "priority": 40,
                "scope": "module",
                "scope_target": "userclaw",
                "condition_json": json.dumps({"field": "access_hour", "op": "outside", "value": "08:00-18:00"}),
                "action": "monitor",
                "is_active": True,
            },
            {
                "name": "SOC2 — Block Direct Agent DB Writes",
                "description": "DATACLAW | Deny agents direct write access to databases; require API intermediary",
                "priority": 45,
                "scope": "module",
                "scope_target": "dataclaw",
                "condition_json": json.dumps({"field": "action_type", "op": "eq", "value": "direct_db_write"}),
                "action": "deny",
                "is_active": True,
            },
        ],
    },
    {
        "name": "ISO 27001:2022",
        "framework": "iso27001",
        "version": "2022",
        "description": (
            "Controls mapped to ISO/IEC 27001:2022 Annex A — covering organizational, "
            "people, physical, and technological security controls."
        ),
        "policies": [
            {
                "name": "ISO27001 — Block Unencrypted Data Transfers",
                "description": "DATACLAW | Deny any data transfer not using an approved encryption protocol",
                "priority": 10,
                "scope": "module",
                "scope_target": "dataclaw",
                "condition_json": json.dumps({"field": "encryption", "op": "eq", "value": "none"}),
                "action": "deny",
                "is_active": True,
            },
            {
                "name": "ISO27001 — Require Approval for External Data Sharing",
                "description": "PRIVACYCLAW | Pause data transfers to external organizations pending data owner sign-off",
                "priority": 15,
                "scope": "module",
                "scope_target": "privacyclaw",
                "condition_json": json.dumps({"field": "recipient_type", "op": "eq", "value": "external"}),
                "action": "require_approval",
                "is_active": True,
            },
            {
                "name": "ISO27001 — Monitor Asset Changes",
                "description": "CONFIGCLAW | Track all changes to the asset register and configuration baseline",
                "priority": 20,
                "scope": "module",
                "scope_target": "configclaw",
                "condition_json": json.dumps({"field": "event_type", "op": "eq", "value": "asset_change"}),
                "action": "monitor",
                "is_active": True,
            },
            {
                "name": "ISO27001 — Block Access to PII Without Justification",
                "description": "PRIVACYCLAW | Deny PII access requests that lack a recorded business justification",
                "priority": 25,
                "scope": "module",
                "scope_target": "privacyclaw",
                "condition_json": json.dumps({"field": "business_justification", "op": "eq", "value": "none"}),
                "action": "deny",
                "is_active": True,
            },
            {
                "name": "ISO27001 — Monitor Privileged Identity Changes",
                "description": "IDENTITYCLAW | Log all additions, removals, and modifications of privileged accounts",
                "priority": 30,
                "scope": "module",
                "scope_target": "identityclaw",
                "condition_json": json.dumps({"field": "account_type", "op": "eq", "value": "privileged"}),
                "action": "monitor",
                "is_active": True,
            },
            {
                "name": "ISO27001 — Require Approval for New External Connections",
                "description": "NETCLAW | Pause any new outbound connection to an external IP or domain",
                "priority": 35,
                "scope": "module",
                "scope_target": "netclaw",
                "condition_json": json.dumps({"field": "connection_type", "op": "eq", "value": "new_external"}),
                "action": "require_approval",
                "is_active": True,
            },
            {
                "name": "ISO27001 — Block Unauthenticated API Calls",
                "description": "APPCLAW | Deny API requests that do not present a valid bearer token",
                "priority": 40,
                "scope": "module",
                "scope_target": "appclaw",
                "condition_json": json.dumps({"field": "auth_method", "op": "eq", "value": "none"}),
                "action": "deny",
                "is_active": True,
            },
            {
                "name": "ISO27001 — Monitor Vulnerability Findings",
                "description": "EXPOSURECLAW | Track all CVE findings and exposure scores for risk register updates",
                "priority": 45,
                "scope": "module",
                "scope_target": "exposureclaw",
                "condition_json": json.dumps({"field": "cvss_score", "op": "gte", "value": 7.0}),
                "action": "monitor",
                "is_active": True,
            },
        ],
    },
    {
        "name": "HIPAA Security Rule",
        "framework": "hipaa",
        "version": "1.0",
        "description": (
            "Safeguards for Protected Health Information (PHI) under the HIPAA Security Rule — "
            "Administrative, Physical, and Technical safeguards (45 CFR Part 164)."
        ),
        "policies": [
            {
                "name": "HIPAA — Block Unauthorized PHI Access",
                "description": "PRIVACYCLAW | Deny access to Protected Health Information without explicit authorization",
                "priority": 5,
                "scope": "module",
                "scope_target": "privacyclaw",
                "condition_json": json.dumps({"field": "data_classification", "op": "eq", "value": "phi"}),
                "action": "deny",
                "is_active": True,
            },
            {
                "name": "HIPAA — Monitor All PHI Access",
                "description": "LOGCLAW | Audit log every read, write, and export of Protected Health Information",
                "priority": 10,
                "scope": "module",
                "scope_target": "logclaw",
                "condition_json": json.dumps({"field": "data_type", "op": "eq", "value": "phi"}),
                "action": "monitor",
                "is_active": True,
            },
            {
                "name": "HIPAA — Require Approval for PHI Export",
                "description": "DATACLAW | Pause bulk PHI exports pending privacy officer review",
                "priority": 15,
                "scope": "module",
                "scope_target": "dataclaw",
                "condition_json": json.dumps({"field": "operation", "op": "eq", "value": "bulk_export_phi"}),
                "action": "require_approval",
                "is_active": True,
            },
            {
                "name": "HIPAA — Block PHI in AI Prompts",
                "description": "ARCCLAW | Deny LLM prompts that contain identifiable Protected Health Information",
                "priority": 20,
                "scope": "module",
                "scope_target": "arcclaw",
                "condition_json": json.dumps({"field": "pii_detected", "op": "eq", "value": "phi"}),
                "action": "deny",
                "is_active": True,
            },
            {
                "name": "HIPAA — Monitor After-Hours PHI Access",
                "description": "USERCLAW | Flag PHI access occurring outside covered entity's defined hours of operation",
                "priority": 25,
                "scope": "module",
                "scope_target": "userclaw",
                "condition_json": json.dumps({"field": "phi_access_after_hours", "op": "eq", "value": True}),
                "action": "monitor",
                "is_active": True,
            },
            {
                "name": "HIPAA — Block Unencrypted PHI Transmission",
                "description": "NETCLAW | Deny any PHI transmission that lacks end-to-end encryption",
                "priority": 30,
                "scope": "module",
                "scope_target": "netclaw",
                "condition_json": json.dumps({"field": "phi_encrypted", "op": "eq", "value": False}),
                "action": "deny",
                "is_active": True,
            },
            {
                "name": "HIPAA — Require BAA Before Vendor PHI Access",
                "description": "VENDORCLAW | Block vendor connections to PHI systems without a signed Business Associate Agreement",
                "priority": 35,
                "scope": "module",
                "scope_target": "vendorclaw",
                "condition_json": json.dumps({"field": "baa_signed", "op": "eq", "value": False}),
                "action": "deny",
                "is_active": True,
            },
            {
                "name": "HIPAA — Monitor PHI Deletion Events",
                "description": "DATACLAW | Audit log all PHI deletion and de-identification operations",
                "priority": 40,
                "scope": "module",
                "scope_target": "dataclaw",
                "condition_json": json.dumps({"field": "operation", "op": "eq", "value": "delete_phi"}),
                "action": "monitor",
                "is_active": True,
            },
        ],
    },
    {
        "name": "PCI-DSS v4.0",
        "framework": "pci-dss",
        "version": "4.0",
        "description": (
            "Payment Card Industry Data Security Standard controls protecting cardholder data "
            "environments (CDE) — Requirements 1-12 mapped to RegentClaw enforcement."
        ),
        "policies": [
            {
                "name": "PCI — Block CDE Access Without MFA",
                "description": "ACCESSCLAW | Deny access to the cardholder data environment without multi-factor authentication",
                "priority": 5,
                "scope": "module",
                "scope_target": "accessclaw",
                "condition_json": json.dumps({"field": "target_zone", "op": "eq", "value": "cde"}),
                "action": "deny",
                "is_active": True,
            },
            {
                "name": "PCI — Monitor All Payment System Access",
                "description": "LOGCLAW | Continuously audit all connections to payment processing systems",
                "priority": 10,
                "scope": "module",
                "scope_target": "logclaw",
                "condition_json": json.dumps({"field": "system_type", "op": "eq", "value": "payment"}),
                "action": "monitor",
                "is_active": True,
            },
            {
                "name": "PCI — Block Unencrypted Cardholder Data Transmission",
                "description": "NETCLAW | Deny any network transmission of PANs or CVVs without strong cryptography",
                "priority": 15,
                "scope": "module",
                "scope_target": "netclaw",
                "condition_json": json.dumps({"field": "card_data_encrypted", "op": "eq", "value": False}),
                "action": "deny",
                "is_active": True,
            },
            {
                "name": "PCI — Require Approval for Payment System Changes",
                "description": "CONFIGCLAW | Pause changes to CDE systems pending change advisory board approval",
                "priority": 20,
                "scope": "module",
                "scope_target": "configclaw",
                "condition_json": json.dumps({"field": "target_system", "op": "eq", "value": "cde"}),
                "action": "require_approval",
                "is_active": True,
            },
            {
                "name": "PCI — Block CVV/PAN in AI Prompts",
                "description": "ARCCLAW | Deny LLM prompts containing card verification values or primary account numbers",
                "priority": 25,
                "scope": "module",
                "scope_target": "arcclaw",
                "condition_json": json.dumps({"field": "card_data_in_prompt", "op": "eq", "value": True}),
                "action": "deny",
                "is_active": True,
            },
            {
                "name": "PCI — Monitor Failed Payment Auth Events",
                "description": "THREATCLAW | Track repeated failed authentication attempts to payment systems for fraud detection",
                "priority": 30,
                "scope": "module",
                "scope_target": "threatclaw",
                "condition_json": json.dumps({"field": "failed_payment_auth", "op": "gte", "value": 3}),
                "action": "monitor",
                "is_active": True,
            },
            {
                "name": "PCI — Require Approval for Firewall Changes",
                "description": "NETCLAW | Pause modifications to CDE firewall rules until security team approves",
                "priority": 35,
                "scope": "module",
                "scope_target": "netclaw",
                "condition_json": json.dumps({"field": "change_type", "op": "eq", "value": "firewall_rule"}),
                "action": "require_approval",
                "is_active": True,
            },
            {
                "name": "PCI — Block Direct CDE Database Access",
                "description": "DATACLAW | Deny direct database queries to CDE tables without intermediary application layer",
                "priority": 40,
                "scope": "module",
                "scope_target": "dataclaw",
                "condition_json": json.dumps({"field": "target_db", "op": "eq", "value": "cde_database"}),
                "action": "deny",
                "is_active": True,
            },
        ],
    },
]


# ─────────────────────────────────────────────────────────────────────────────
#  Seed logic
# ─────────────────────────────────────────────────────────────────────────────

async def seed(reset: bool = False):
    async with AsyncSessionLocal() as db:
        if reset:
            await db.execute(delete(PolicyPack.__table__))
            await db.commit()
            print("🗑  Cleared policy_packs table")

        created = 0
        for pack_def in PACKS:
            policies = pack_def.pop("policies")
            policies_json = json.dumps(policies)
            policy_count = len(policies)

            result = await db.execute(
                select(PolicyPack).where(PolicyPack.name == pack_def["name"])
            )
            existing = result.scalar_one_or_none()
            if existing:
                existing.description = pack_def["description"]
                existing.framework = pack_def["framework"]
                existing.version = pack_def["version"]
                existing.policies_json = policies_json
                existing.policy_count = policy_count
                print(f"  ↻  Updated: {pack_def['name']} ({policy_count} policies)")
            else:
                db.add(PolicyPack(
                    **pack_def,
                    policies_json=policies_json,
                    policy_count=policy_count,
                ))
                created += 1
                print(f"  ✅ Created: {pack_def['name']} ({policy_count} policies)")

        await db.commit()
        print(f"\n✅ Done — {created} packs created, {len(PACKS) - created} updated")
        print("\nApply a pack from the UI or via API:")
        print("  POST /api/v1/policy-packs/<id>/apply")


if __name__ == "__main__":
    reset = "--reset" in sys.argv
    asyncio.run(seed(reset))
