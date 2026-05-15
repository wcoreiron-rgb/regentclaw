"""
Seed IncidentMemory, AssetMemory, and TenantMemory with realistic demo data.
Records are upserted (skipped if already present) so the script is idempotent.

Run: python seed_memory.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

import json
import uuid
from datetime import datetime, timedelta

from app.database import SessionLocal, engine, Base
from app.models.memory import IncidentMemory, AssetMemory, TenantMemory

Base.metadata.create_all(bind=engine)

NOW = datetime.utcnow()

# ──────────────────────────────────────────────────────────────────────────────
# IncidentMemory records
# ──────────────────────────────────────────────────────────────────────────────
INCIDENTS = [
    {
        "id": uuid.UUID("11111111-1111-1111-1111-111111111001"),
        "title": "Credential Stuffing Attack — Azure AD",
        "description": (
            "Sustained credential stuffing attack targeting Azure AD login endpoint. "
            "Multiple accounts exceeded failed-login thresholds; one service account "
            "briefly compromised before session was revoked."
        ),
        "severity": "high",
        "status": "contained",
        "source_claw": "identityclaw",
        "source_finding_id": "find-azure-001",
        "affected_assets": json.dumps(["azure-ad-tenant", "svc-crowdstrike-sync"]),
        "affected_users": json.dumps(["alice@company.com", "bob@company.com"]),
        "scope_tags": "identity,credential,azure",
        "mitre_tactics": "Initial Access,Credential Access",
        "mitre_techniques": "T1110.004,T1078",
        "timeline_json": json.dumps([
            {"timestamp": (NOW - timedelta(hours=10)).isoformat(), "actor": "identityclaw", "action": "detected", "detail": "Anomalous login volume from 203.0.113.99", "type": "detection"},
            {"timestamp": (NOW - timedelta(hours=9)).isoformat(), "actor": "alice@company.com", "action": "alerted", "detail": "Alert sent to on-call analyst", "type": "notification"},
            {"timestamp": (NOW - timedelta(hours=7)).isoformat(), "actor": "agent-threat-hunter-001", "action": "investigated", "detail": "Confirmed stuffing pattern via IP correlation", "type": "investigation"},
            {"timestamp": (NOW - timedelta(hours=5)).isoformat(), "actor": "alice@company.com", "action": "contained", "detail": "Blocked source IPs; revoked compromised session tokens", "type": "containment"},
        ]),
        "timeline_count": 4,
        "linked_runs": json.dumps(["run-threat-hunt-001", "run-identity-block-002"]),
        "root_cause": "Leaked credential list from third-party breach circulated on dark web forums.",
        "remediation_notes": "Enforced MFA for all service accounts; added velocity-based lockout policy.",
        "false_positive": False,
        "mttr_minutes": 300.0,
        "risk_score_at_open": 78.5,
        "assigned_to": "alice@company.com",
        "created_by": "identityclaw",
        "opened_at": NOW - timedelta(hours=10),
        "contained_at": NOW - timedelta(hours=5),
        "closed_at": None,
        "updated_at": NOW - timedelta(hours=1),
    },
    {
        "id": uuid.UUID("11111111-1111-1111-1111-111111111002"),
        "title": "Ransomware Precursor — Lateral Movement Detected",
        "description": (
            "ThreatHunter agent detected lateral movement consistent with pre-ransomware "
            "staging: credential dumping on workstation 192.168.1.45 followed by SMB "
            "enumeration across the /24 subnet."
        ),
        "severity": "critical",
        "status": "investigating",
        "source_claw": "endpointclaw",
        "source_finding_id": "find-endpoint-007",
        "affected_assets": json.dumps(["192.168.1.45", "192.168.1.0/24"]),
        "affected_users": json.dumps(["dave@company.com"]),
        "scope_tags": "endpoint,lateral-movement,ransomware",
        "mitre_tactics": "Credential Access,Lateral Movement,Discovery",
        "mitre_techniques": "T1003.001,T1021.002,T1135",
        "timeline_json": json.dumps([
            {"timestamp": (NOW - timedelta(hours=3)).isoformat(), "actor": "endpointclaw", "action": "detected", "detail": "LSASS dump on 192.168.1.45 via Mimikatz signature", "type": "detection"},
            {"timestamp": (NOW - timedelta(hours=2, minutes=45)).isoformat(), "actor": "agent-threat-hunter-001", "action": "correlated", "detail": "SMB scan originating from same host", "type": "investigation"},
            {"timestamp": (NOW - timedelta(hours=2)).isoformat(), "actor": "dave@company.com", "action": "isolated", "detail": "Host 192.168.1.45 network-isolated pending forensics", "type": "containment"},
        ]),
        "timeline_count": 3,
        "linked_runs": json.dumps(["run-endpoint-isolate-005"]),
        "root_cause": None,
        "remediation_notes": None,
        "false_positive": False,
        "mttr_minutes": None,
        "risk_score_at_open": 95.0,
        "assigned_to": "dave@company.com",
        "created_by": "endpointclaw",
        "opened_at": NOW - timedelta(hours=3),
        "contained_at": None,
        "closed_at": None,
        "updated_at": NOW - timedelta(minutes=30),
    },
    {
        "id": uuid.UUID("11111111-1111-1111-1111-111111111003"),
        "title": "S3 Bucket Misconfiguration — Public Read Exposure",
        "description": (
            "CloudClaw identified an S3 bucket with public read ACL containing audit "
            "logs from the compliance pipeline. No evidence of external access, but "
            "bucket was exposed for approximately 4 hours."
        ),
        "severity": "medium",
        "status": "remediated",
        "source_claw": "cloudclaw",
        "source_finding_id": "find-cloud-014",
        "affected_assets": json.dumps(["s3://rc-compliance-audit-logs"]),
        "affected_users": json.dumps([]),
        "scope_tags": "cloud,s3,misconfiguration,data-exposure",
        "mitre_tactics": "Collection,Exfiltration",
        "mitre_techniques": "T1530",
        "timeline_json": json.dumps([
            {"timestamp": (NOW - timedelta(days=2, hours=6)).isoformat(), "actor": "cloudclaw", "action": "detected", "detail": "Bucket ACL changed to public-read by CI/CD pipeline deploy role", "type": "detection"},
            {"timestamp": (NOW - timedelta(days=2, hours=5)).isoformat(), "actor": "agent-compliance-sweep", "action": "assessed", "detail": "No CloudTrail GetObject events from external principals in exposure window", "type": "investigation"},
            {"timestamp": (NOW - timedelta(days=2, hours=4)).isoformat(), "actor": "carol@company.com", "action": "remediated", "detail": "ACL reverted to private; deploy role permissions scoped down", "type": "remediation"},
        ]),
        "timeline_count": 3,
        "linked_runs": json.dumps(["run-cloud-remediate-003"]),
        "root_cause": "Over-permissioned CI/CD deploy role applied default ACL instead of bucket policy.",
        "remediation_notes": "Scoped deploy role to s3:PutObject only; added SCPs to block public ACLs org-wide.",
        "false_positive": False,
        "mttr_minutes": 120.0,
        "risk_score_at_open": 55.0,
        "assigned_to": "carol@company.com",
        "created_by": "cloudclaw",
        "opened_at": NOW - timedelta(days=2, hours=6),
        "contained_at": NOW - timedelta(days=2, hours=4),
        "closed_at": NOW - timedelta(days=2),
        "updated_at": NOW - timedelta(days=2),
    },
    {
        "id": uuid.UUID("11111111-1111-1111-1111-111111111004"),
        "title": "Suspicious OAuth App Consent — Broad Mail Access",
        "description": (
            "An unknown OAuth application requested and received mail.read + files.read "
            "permissions from a contractor account. App was not in the approved OAuth "
            "allowlist and has not been seen before in the tenant."
        ),
        "severity": "high",
        "status": "open",
        "source_claw": "identityclaw",
        "source_finding_id": "find-oauth-022",
        "affected_assets": json.dumps(["azure-ad-tenant"]),
        "affected_users": json.dumps(["eve.contractor@external.io"]),
        "scope_tags": "identity,oauth,consent-phishing",
        "mitre_tactics": "Persistence,Collection",
        "mitre_techniques": "T1098.003,T1114.002",
        "timeline_json": json.dumps([
            {"timestamp": (NOW - timedelta(hours=1)).isoformat(), "actor": "identityclaw", "action": "detected", "detail": "OAuth consent event for app ID a1b2c3d4 with mail.read scope", "type": "detection"},
        ]),
        "timeline_count": 1,
        "linked_runs": json.dumps([]),
        "root_cause": None,
        "remediation_notes": None,
        "false_positive": False,
        "mttr_minutes": None,
        "risk_score_at_open": 72.0,
        "assigned_to": None,
        "created_by": "identityclaw",
        "opened_at": NOW - timedelta(hours=1),
        "contained_at": None,
        "closed_at": None,
        "updated_at": NOW - timedelta(hours=1),
    },
    {
        "id": uuid.UUID("11111111-1111-1111-1111-111111111005"),
        "title": "Off-Hours Admin Login — Backup Service Account",
        "description": (
            "Backup service account svc-backup-agent authenticated interactively at "
            "02:17 UTC — well outside its normal 22:00–23:30 automated window. "
            "Session was interactive (not the scheduled job) and accessed prod/admin paths."
        ),
        "severity": "medium",
        "status": "false_positive",
        "source_claw": "identityclaw",
        "source_finding_id": "find-identity-031",
        "affected_assets": json.dumps(["prod-backup-server"]),
        "affected_users": json.dumps(["svc-backup-agent"]),
        "scope_tags": "identity,off-hours,service-account",
        "mitre_tactics": "Initial Access",
        "mitre_techniques": "T1078.004",
        "timeline_json": json.dumps([
            {"timestamp": (NOW - timedelta(days=3, hours=22)).isoformat(), "actor": "identityclaw", "action": "detected", "detail": "Interactive login at 02:17 UTC outside maintenance window", "type": "detection"},
            {"timestamp": (NOW - timedelta(days=3, hours=21)).isoformat(), "actor": "bob@company.com", "action": "investigated", "detail": "Confirmed as on-call engineer using service account for emergency patch", "type": "investigation"},
            {"timestamp": (NOW - timedelta(days=3, hours=20)).isoformat(), "actor": "bob@company.com", "action": "closed", "detail": "Marked false positive; engineer to use personal account for emergency access going forward", "type": "closure"},
        ]),
        "timeline_count": 3,
        "linked_runs": json.dumps([]),
        "root_cause": "On-call engineer used service account credentials stored in password manager instead of break-glass personal account.",
        "remediation_notes": "Revoked shared service account password; updated runbook to specify break-glass procedure.",
        "false_positive": True,
        "mttr_minutes": 60.0,
        "risk_score_at_open": 48.0,
        "assigned_to": "bob@company.com",
        "created_by": "identityclaw",
        "opened_at": NOW - timedelta(days=3, hours=22),
        "contained_at": None,
        "closed_at": NOW - timedelta(days=3, hours=20),
        "updated_at": NOW - timedelta(days=3, hours=20),
    },
]

# ──────────────────────────────────────────────────────────────────────────────
# AssetMemory records
# ──────────────────────────────────────────────────────────────────────────────
ASSETS = [
    {
        "asset_id": "192.168.1.45",
        "asset_type": "endpoint",
        "display_name": "Internal Workstation — Dave Okonkwo",
        "claw": "endpointclaw",
        "risk_score": 91.0,
        "risk_level": "critical",
        "total_findings": 7,
        "open_findings": 3,
        "critical_findings": 2,
        "incidents_involved": 1,
        "risk_history_json": json.dumps([
            {"timestamp": (NOW - timedelta(days=7)).isoformat(), "score": 12.0, "level": "low", "event": "baseline"},
            {"timestamp": (NOW - timedelta(days=3)).isoformat(), "score": 35.0, "level": "medium", "event": "policy_violation"},
            {"timestamp": (NOW - timedelta(hours=3)).isoformat(), "score": 91.0, "level": "critical", "event": "lateral_movement_detected"},
        ]),
        "context_notes": (
            "Network-isolated 2026-05-03 after credential dumping and SMB scan activity. "
            "Forensics collection in progress. Do not reconnect without SOC sign-off."
        ),
        "tags": "isolated,forensics,endpoint,high-priority",
        "first_seen_at": NOW - timedelta(days=90),
        "last_seen_at": NOW - timedelta(hours=3),
    },
    {
        "asset_id": "azure-ad-tenant",
        "asset_type": "identity",
        "display_name": "Corporate Azure AD Tenant",
        "claw": "identityclaw",
        "risk_score": 68.0,
        "risk_level": "high",
        "total_findings": 14,
        "open_findings": 5,
        "critical_findings": 1,
        "incidents_involved": 3,
        "risk_history_json": json.dumps([
            {"timestamp": (NOW - timedelta(days=30)).isoformat(), "score": 20.0, "level": "low", "event": "baseline"},
            {"timestamp": (NOW - timedelta(days=10)).isoformat(), "score": 45.0, "level": "medium", "event": "mfa_gap_detected"},
            {"timestamp": (NOW - timedelta(hours=10)).isoformat(), "score": 68.0, "level": "high", "event": "credential_stuffing_incident"},
        ]),
        "context_notes": (
            "Three active incidents linked to this tenant in the past 72 hours. "
            "MFA enforced for all users post-incident-001. Conditional access policies updated."
        ),
        "tags": "identity,azure,mfa,active-incidents",
        "first_seen_at": NOW - timedelta(days=180),
        "last_seen_at": NOW - timedelta(hours=1),
    },
    {
        "asset_id": "s3://rc-compliance-audit-logs",
        "asset_type": "data_store",
        "display_name": "Compliance Audit Log Bucket",
        "claw": "cloudclaw",
        "risk_score": 18.0,
        "risk_level": "low",
        "total_findings": 2,
        "open_findings": 0,
        "critical_findings": 0,
        "incidents_involved": 1,
        "risk_history_json": json.dumps([
            {"timestamp": (NOW - timedelta(days=14)).isoformat(), "score": 5.0, "level": "low", "event": "baseline"},
            {"timestamp": (NOW - timedelta(days=2, hours=6)).isoformat(), "score": 55.0, "level": "medium", "event": "public_acl_exposure"},
            {"timestamp": (NOW - timedelta(days=2)).isoformat(), "score": 18.0, "level": "low", "event": "remediated"},
        ]),
        "context_notes": (
            "Previously exposed for ~4 hours via misconfigured ACL (incident-003). "
            "Remediated. SCP added to prevent recurrence. Reviewed by compliance team."
        ),
        "tags": "s3,cloud,data,remediated",
        "first_seen_at": NOW - timedelta(days=60),
        "last_seen_at": NOW - timedelta(days=2),
    },
    {
        "asset_id": "203.0.113.99",
        "asset_type": "network",
        "display_name": "Suspicious External IP",
        "claw": "netclaw",
        "risk_score": 88.0,
        "risk_level": "critical",
        "total_findings": 5,
        "open_findings": 5,
        "critical_findings": 3,
        "incidents_involved": 2,
        "risk_history_json": json.dumps([
            {"timestamp": (NOW - timedelta(hours=12)).isoformat(), "score": 50.0, "level": "medium", "event": "first_seen_scanning"},
            {"timestamp": (NOW - timedelta(hours=10)).isoformat(), "score": 88.0, "level": "critical", "event": "linked_to_credential_stuffing"},
        ]),
        "context_notes": (
            "Source IP for credential stuffing attack (incident-001). "
            "Listed in AlienVault OTX and Shodan as known malicious scanner. "
            "Blocked at perimeter firewall."
        ),
        "tags": "external-ip,blocked,threat-intel,credential-stuffing",
        "first_seen_at": NOW - timedelta(hours=12),
        "last_seen_at": NOW - timedelta(hours=10),
    },
]

# ──────────────────────────────────────────────────────────────────────────────
# TenantMemory record (single row, id=1)
# ──────────────────────────────────────────────────────────────────────────────
TENANT = {
    "id": 1,
    "overall_risk_level": "high",
    "overall_risk_score": 74.5,
    "active_incident_count": 3,
    "open_finding_count": 21,
    "critical_finding_count": 5,
    "active_threats_json": json.dumps([
        {"name": "Credential Stuffing Campaign", "severity": "high", "ioc_type": "ip", "first_seen": (NOW - timedelta(hours=10)).isoformat()},
        {"name": "Ransomware Precursor Activity", "severity": "critical", "ioc_type": "behavior", "first_seen": (NOW - timedelta(hours=3)).isoformat()},
        {"name": "OAuth Consent Phishing", "severity": "high", "ioc_type": "app_id", "first_seen": (NOW - timedelta(hours=1)).isoformat()},
    ]),
    "high_risk_assets_json": json.dumps([
        {"asset_id": "192.168.1.45", "risk_score": 91.0, "reason": "Lateral movement — network isolated"},
        {"asset_id": "azure-ad-tenant", "risk_score": 68.0, "reason": "3 active incidents; credential stuffing ongoing"},
        {"asset_id": "203.0.113.99", "risk_score": 88.0, "reason": "Confirmed malicious external IP — blocked"},
    ]),
    "threat_context_json": json.dumps([
        {"ioc": "203.0.113.99", "ioc_type": "ip", "confidence": "high", "source": "AlienVault OTX", "seen_at": (NOW - timedelta(hours=10)).isoformat()},
        {"ioc": "T1110.004", "ioc_type": "technique", "confidence": "confirmed", "source": "endpointclaw", "seen_at": (NOW - timedelta(hours=3)).isoformat()},
        {"ioc": "T1003.001", "ioc_type": "technique", "confidence": "confirmed", "source": "endpointclaw", "seen_at": (NOW - timedelta(hours=3)).isoformat()},
        {"ioc": "a1b2c3d4", "ioc_type": "oauth_app_id", "confidence": "medium", "source": "identityclaw", "seen_at": (NOW - timedelta(hours=1)).isoformat()},
    ]),
    "analyst_notes": (
        "2026-05-03: Three concurrent incidents active. Priority 1 — ransomware precursor on 192.168.1.45 "
        "(host isolated, forensics in progress). Priority 2 — OAuth consent phishing on contractor account "
        "(application revocation pending). Credential stuffing campaign appears contained after MFA enforcement. "
        "Risk level elevated from medium to high at 03:00 UTC."
    ),
    "risk_delta_7d": 28.5,
    "risk_delta_30d": 15.0,
    "updated_at": NOW,
    "last_ingested_at": NOW - timedelta(minutes=15),
}


# ──────────────────────────────────────────────────────────────────────────────
# Main seeder
# ──────────────────────────────────────────────────────────────────────────────
def seed():
    db = SessionLocal()
    seeded_incidents = 0
    seeded_assets = 0
    seeded_tenant = 0

    try:
        # ── IncidentMemory ─────────────────────────────────────────────────────
        for inc in INCIDENTS:
            existing = db.query(IncidentMemory).filter(
                IncidentMemory.id == inc["id"]
            ).first()
            if not existing:
                record = IncidentMemory(**inc)
                db.add(record)
                print(f"  + IncidentMemory: {inc['title']}")
                seeded_incidents += 1
            else:
                print(f"  – IncidentMemory (exists): {inc['title']}")

        # ── AssetMemory ────────────────────────────────────────────────────────
        for asset in ASSETS:
            existing = db.query(AssetMemory).filter(
                AssetMemory.asset_id == asset["asset_id"]
            ).first()
            if not existing:
                record = AssetMemory(**asset)
                db.add(record)
                print(f"  + AssetMemory: {asset['display_name']}")
                seeded_assets += 1
            else:
                print(f"  – AssetMemory (exists): {asset['display_name']}")

        # ── TenantMemory ───────────────────────────────────────────────────────
        existing = db.query(TenantMemory).filter(
            TenantMemory.id == TENANT["id"]
        ).first()
        if not existing:
            record = TenantMemory(**TENANT)
            db.add(record)
            print(f"  + TenantMemory: id={TENANT['id']} (risk={TENANT['overall_risk_level']})")
            seeded_tenant = 1
        else:
            print(f"  – TenantMemory (exists): id={TENANT['id']}")

        db.commit()
        print(
            f"\n✓ Seeded {seeded_incidents} incident(s), "
            f"{seeded_assets} asset(s), "
            f"{seeded_tenant} tenant memory record(s)."
        )

    finally:
        db.close()


if __name__ == "__main__":
    seed()
