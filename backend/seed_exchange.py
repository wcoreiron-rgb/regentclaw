"""
Seed the Security Exchange with publishers and packages.
Run: python seed_exchange.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

import uuid
from datetime import datetime, timedelta
from app.database import SessionLocal, engine, Base
from app.models.exchange import ExchangePublisher, ExchangePackage, ExchangeInstallRecord

Base.metadata.create_all(bind=engine)


PUBLISHERS = [
    {
        "id": "pub-ascend", "name": "Ascend Technologies", "slug": "ascend",
        "description": "Official RegentClaw security modules and reference implementations.",
        "website": "https://ascend.tech", "tier": "official", "is_verified": True,
        "pgp_fingerprint": "CAFE DEAD BEEF 0001 ABCD EF12 3456 7890 AABB CCDD",
        "total_packages": 8, "avg_trust_score": 98.0,
    },
    {
        "id": "pub-crowdstrike", "name": "CrowdStrike", "slug": "crowdstrike",
        "description": "Falcon platform integrations and threat intelligence packs.",
        "website": "https://crowdstrike.com", "tier": "verified", "is_verified": True,
        "pgp_fingerprint": "F4LC 0N00 DEAD BEEF 1234 5678 9ABC DEF0 1122 3344",
        "total_packages": 5, "avg_trust_score": 96.5,
    },
    {
        "id": "pub-sentinel", "name": "Microsoft Sentinel", "slug": "microsoft-sentinel",
        "description": "Official Microsoft Sentinel SIEM integration skill packs.",
        "website": "https://microsoft.com/sentinel", "tier": "verified", "is_verified": True,
        "pgp_fingerprint": "MSFT SENT INEL 0002 5555 AAAA BBBB CCCC DDDD EEEE",
        "total_packages": 4, "avg_trust_score": 95.0,
    },
    {
        "id": "pub-paloalto", "name": "Palo Alto Networks", "slug": "paloalto",
        "description": "XSOAR playbooks and Cortex integrations for RegentClaw.",
        "website": "https://paloaltonetworks.com", "tier": "verified", "is_verified": True,
        "pgp_fingerprint": "PA0A LT0N 0003 FACE FEED 8765 4321 ABCD EF01 2345",
        "total_packages": 3, "avg_trust_score": 94.0,
    },
    {
        "id": "pub-community", "name": "RegentClaw Community", "slug": "community",
        "description": "Community-contributed security skills and policies.",
        "website": "https://github.com/regentclaw/community", "tier": "community",
        "is_verified": False, "pgp_fingerprint": "",
        "total_packages": 6, "avg_trust_score": 78.0,
    },
]


PACKAGES = [
    # ── Official Ascend packs ──────────────────────────────────────────────
    {
        "id": "pkg-001", "publisher_id": "pub-ascend", "publisher_name": "Ascend Technologies",
        "name": "Zero Trust Core Policies", "slug": "zt-core-policies",
        "package_type": "policy_pack", "category": "Zero Trust", "is_official": True,
        "tags": ["zero-trust", "policies", "core", "compliance"],
        "description": "Foundational Zero Trust policy set covering identity, device, and network.",
        "long_description": "Complete set of 47 policies implementing NIST SP 800-207 Zero Trust Architecture across all RegentClaw modules. Covers identity verification, device health, network segmentation, data classification, and least-privilege access. Includes NIST mapping metadata for compliance evidence.",
        "version": "2.1.0", "license_type": "Proprietary",
        "trust_score": 99.0, "download_count": 4821, "rating": 4.9, "rating_count": 312,
        "is_featured": True, "is_signed": True, "signature_verified": True,
        "sha256_checksum": "a3f8d2b1c9e4f7a0d5b8c2e1f4a7d0b3c6e9f2a5d8b1c4e7f0a3d6b9c2e5f8a1",
        "manifest_json": {
            "skills": [
                {"name": "Enforce MFA on All Admin Access", "claw": "IdentityClaw", "action": "enforce_mfa"},
                {"name": "Block Unmanaged Devices", "claw": "EndpointClaw", "action": "block_device"},
                {"name": "Encrypt Data at Rest", "claw": "DataClaw", "action": "enforce_encryption"},
                {"name": "Micro-segment East-West Traffic", "claw": "NetClaw", "action": "segment_traffic"},
                {"name": "Revoke Orphaned Credentials", "claw": "AccessClaw", "action": "revoke_credentials"},
            ]
        },
    },
    {
        "id": "pkg-002", "publisher_id": "pub-ascend", "publisher_name": "Ascend Technologies",
        "name": "SOC2 Type II Evidence Pack", "slug": "soc2-evidence-pack",
        "package_type": "policy_pack", "category": "Compliance", "is_official": True,
        "tags": ["soc2", "compliance", "evidence", "audit"],
        "description": "Automated SOC2 Type II evidence collection across all trust service criteria.",
        "long_description": "Automates evidence gathering for all five SOC2 Trust Service Criteria: Security, Availability, Processing Integrity, Confidentiality, and Privacy. Generates audit-ready reports with timestamps and signed attestations.",
        "version": "1.4.0", "license_type": "Proprietary",
        "trust_score": 98.5, "download_count": 3201, "rating": 4.8, "rating_count": 198,
        "is_featured": True, "is_signed": True, "signature_verified": True,
        "sha256_checksum": "b4g9e3c2d0f8b7a1e6c5d4b3a2f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1",
        "manifest_json": {
            "skills": [
                {"name": "Collect Access Control Evidence", "claw": "IdentityClaw", "action": "collect_evidence"},
                {"name": "Collect Availability Metrics", "claw": "CoreOS", "action": "collect_metrics"},
                {"name": "Collect Encryption Evidence", "claw": "DataClaw", "action": "collect_evidence"},
                {"name": "Generate SOC2 Audit Report", "claw": "ComplianceClaw", "action": "generate_report"},
            ]
        },
    },
    {
        "id": "pkg-003", "publisher_id": "pub-ascend", "publisher_name": "Ascend Technologies",
        "name": "AI Security Hardening Pack", "slug": "ai-security-hardening",
        "package_type": "skill_pack", "category": "AI Security", "is_official": True,
        "tags": ["ai", "llm", "arcclaw", "hardening", "model-security"],
        "description": "Harden AI/LLM deployments with prompt injection detection, output filtering, and model firewall policies.",
        "long_description": "Protects AI systems from adversarial attacks including prompt injection, jailbreaking, data exfiltration via LLMs, and model poisoning. Integrates with ArcClaw and Model Router for real-time classification and blocking.",
        "version": "1.0.0", "license_type": "Proprietary",
        "trust_score": 97.0, "download_count": 2150, "rating": 4.7, "rating_count": 145,
        "is_featured": True, "is_signed": True, "signature_verified": True,
        "sha256_checksum": "c5h0f4d3e1g9c8b2f7d6e5c4b3a2g1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4",
        "manifest_json": {
            "skills": [
                {"name": "Detect Prompt Injection", "claw": "ArcClaw", "action": "detect_injection"},
                {"name": "Filter LLM Output", "claw": "ArcClaw", "action": "filter_output"},
                {"name": "Classify Data Sensitivity", "claw": "ModelRouter", "action": "classify"},
                {"name": "Block High-Risk LLM Calls", "claw": "ArcClaw", "action": "block_call"},
                {"name": "Audit AI Access Logs", "claw": "ArcClaw", "action": "audit_logs"},
            ]
        },
    },
    # ── CrowdStrike packs ─────────────────────────────────────────────────
    {
        "id": "pkg-004", "publisher_id": "pub-crowdstrike", "publisher_name": "CrowdStrike",
        "name": "Falcon XDR Response Pack", "slug": "falcon-xdr-response",
        "package_type": "skill_pack", "category": "Threat Detection", "is_official": False,
        "tags": ["crowdstrike", "falcon", "xdr", "edr", "response"],
        "description": "Automated threat response playbooks powered by CrowdStrike Falcon XDR telemetry.",
        "long_description": "Orchestrates real-time endpoint isolation, process kill, and network quarantine using Falcon sensor commands. Chains ThreatClaw and EndpointClaw for coordinated cross-domain response in under 60 seconds.",
        "version": "3.2.1", "license_type": "CrowdStrike EULA",
        "trust_score": 96.0, "download_count": 5830, "rating": 4.9, "rating_count": 421,
        "is_featured": True, "is_signed": True, "signature_verified": True,
        "sha256_checksum": "d6i1g5e4f2h0d9c3g8f7e6d5c4b3h2g1f0e9d8c7b6a5g4f3e2d1c0b9a8g7f6e5",
        "manifest_json": {
            "skills": [
                {"name": "Isolate Compromised Host", "claw": "EndpointClaw", "action": "isolate_host"},
                {"name": "Kill Malicious Process", "claw": "EndpointClaw", "action": "kill_process"},
                {"name": "Quarantine Suspicious File", "claw": "EndpointClaw", "action": "quarantine_file"},
                {"name": "Enrich with Falcon Intel", "claw": "ThreatClaw", "action": "enrich_ioc"},
                {"name": "Open Incident Record", "claw": "Memory", "action": "create_incident"},
            ]
        },
    },
    {
        "id": "pkg-005", "publisher_id": "pub-crowdstrike", "publisher_name": "CrowdStrike",
        "name": "Threat Intel Enrichment", "slug": "cs-threat-intel",
        "package_type": "skill_pack", "category": "Threat Intelligence", "is_official": False,
        "tags": ["threat-intel", "ioc", "crowdstrike", "enrichment"],
        "description": "Enrich any IOC with CrowdStrike Falcon Intelligence in real time.",
        "long_description": "Fetches file hashes, domains, IPs, and CVEs from Falcon Intelligence API. Scores and tags threats, and automatically escalates critical indicators to ThreatClaw hunting workflows.",
        "version": "2.0.0", "license_type": "CrowdStrike EULA",
        "trust_score": 95.5, "download_count": 4120, "rating": 4.8, "rating_count": 289,
        "is_featured": False, "is_signed": True, "signature_verified": True,
        "sha256_checksum": "e7j2h6f5g3i1e0d4h9g8f7e6d5c4i3h2g1f0e9d8c7b6a5h4g3f2e1d0c9b8a7g6",
        "manifest_json": {
            "skills": [
                {"name": "Lookup File Hash", "claw": "ThreatClaw", "action": "lookup_hash"},
                {"name": "Lookup Domain", "claw": "ThreatClaw", "action": "lookup_domain"},
                {"name": "Score IP Reputation", "claw": "NetClaw", "action": "score_ip"},
                {"name": "Tag High-Risk IOCs", "claw": "ThreatClaw", "action": "tag_ioc"},
            ]
        },
    },
    # ── Microsoft Sentinel ────────────────────────────────────────────────
    {
        "id": "pkg-006", "publisher_id": "pub-sentinel", "publisher_name": "Microsoft Sentinel",
        "name": "Sentinel SIEM Connector Pack", "slug": "sentinel-siem-pack",
        "package_type": "connector", "category": "SIEM", "is_official": False,
        "tags": ["sentinel", "siem", "microsoft", "log-analytics"],
        "description": "Bidirectional Microsoft Sentinel integration — ingest alerts, push findings, close incidents.",
        "long_description": "Deep integration with Microsoft Sentinel including alert ingestion via Logic Apps, finding push-back via Security Graph API, and automated incident synchronisation. Includes pre-built KQL alert rules mapped to RegentClaw policies.",
        "version": "1.5.0", "license_type": "MIT",
        "trust_score": 94.5, "download_count": 3890, "rating": 4.7, "rating_count": 231,
        "is_featured": True, "is_signed": True, "signature_verified": True,
        "sha256_checksum": "f8k3i7g6h4j2f1e5i0h9g8f7e6d5j4i3h2g1f0e9d8c7b6a5i4h3g2f1e0d9c8b7",
        "manifest_json": {
            "connector_type": "log_siem",
            "capabilities": ["ingest_alerts", "push_findings", "sync_incidents", "run_kql"],
        },
    },
    {
        "id": "pkg-007", "publisher_id": "pub-sentinel", "publisher_name": "Microsoft Sentinel",
        "name": "Azure AD Identity Hunting Pack", "slug": "azure-ad-identity-hunting",
        "package_type": "playbook", "category": "Identity Security", "is_official": False,
        "tags": ["azure-ad", "identity", "hunting", "entra"],
        "description": "Proactive identity threat hunting playbooks using Azure AD sign-in and audit logs.",
        "long_description": "Seven automated hunting playbooks covering impossible travel, legacy auth abuse, MFA bypass attempts, service principal abuse, and privileged role escalation. Each playbook generates a scored finding with MITRE ATT&CK context.",
        "version": "1.2.0", "license_type": "MIT",
        "trust_score": 93.0, "download_count": 2950, "rating": 4.6, "rating_count": 178,
        "is_featured": False, "is_signed": True, "signature_verified": True,
        "sha256_checksum": "g9l4j8h7i5k3g2f6j1i0h9g8f7e6k5j4i3h2g1f0e9d8c7b6a5j4i3h2g1f0e9d8",
        "manifest_json": {
            "playbooks": [
                {"name": "Impossible Travel Hunting", "claw": "IdentityClaw"},
                {"name": "Legacy Auth Abuse Hunting", "claw": "AccessClaw"},
                {"name": "MFA Bypass Hunting", "claw": "IdentityClaw"},
                {"name": "Service Principal Abuse", "claw": "IdentityClaw"},
                {"name": "Privileged Role Escalation Hunting", "claw": "AccessClaw"},
            ]
        },
    },
    # ── Palo Alto ─────────────────────────────────────────────────────────
    {
        "id": "pkg-008", "publisher_id": "pub-paloalto", "publisher_name": "Palo Alto Networks",
        "name": "Cortex XSOAR Playbooks", "slug": "cortex-xsoar-playbooks",
        "package_type": "playbook", "category": "SOAR", "is_official": False,
        "tags": ["xsoar", "soar", "paloalto", "playbooks", "automation"],
        "description": "Port of 12 top XSOAR playbooks into RegentClaw orchestration format.",
        "long_description": "Includes Phishing Investigation, Ransomware Containment, Cloud Misconfiguration Remediation, Insider Threat Investigation, and 8 more industry-proven playbooks adapted to the RegentClaw claw architecture with full policy gating.",
        "version": "2.3.0", "license_type": "Palo Alto EULA",
        "trust_score": 93.5, "download_count": 4450, "rating": 4.7, "rating_count": 302,
        "is_featured": True, "is_signed": True, "signature_verified": True,
        "sha256_checksum": "h0m5k9i8j6l4h3g7k2j1i0h9g8f7l6k5j4i3h2g1f0e9d8c7b6a5k4j3i2h1g0f9",
        "manifest_json": {
            "playbooks": [
                {"name": "Phishing Investigation", "claws": ["IdentityClaw", "LogClaw", "ThreatClaw"]},
                {"name": "Ransomware Containment", "claws": ["EndpointClaw", "NetClaw", "DataClaw"]},
                {"name": "Cloud Misconfiguration Remediation", "claws": ["CloudClaw", "ConfigClaw"]},
                {"name": "Insider Threat Investigation", "claws": ["InsiderClaw", "UserClaw", "AuditClaw"]},
            ]
        },
    },
    # ── Community packs ────────────────────────────────────────────────────
    {
        "id": "pkg-009", "publisher_id": "pub-community", "publisher_name": "RegentClaw Community",
        "name": "AWS Security Baseline", "slug": "aws-security-baseline",
        "package_type": "policy_pack", "category": "Cloud Security", "is_official": False,
        "tags": ["aws", "cloud", "cis", "baseline", "community"],
        "description": "CIS AWS Foundations Benchmark v2.0 mapped to RegentClaw CloudClaw policies.",
        "long_description": "220 CIS AWS Foundations Benchmark controls mapped to automated CloudClaw checks. Covers IAM, S3 bucket policies, VPC flow logs, CloudTrail, GuardDuty configuration, and security group hygiene.",
        "version": "2.0.1", "license_type": "MIT",
        "trust_score": 84.0, "download_count": 8920, "rating": 4.6, "rating_count": 534,
        "is_featured": True, "is_signed": False, "signature_verified": False,
        "sha256_checksum": "i1n6l0j9k7m5i4h8l3k2j1i0h9g8m7l6k5j4i3h2g1f0e9d8c7b6a5l4k3j2i1h0",
        "manifest_json": {
            "skills": [
                {"name": "Check IAM Password Policy", "claw": "CloudClaw", "action": "check_iam"},
                {"name": "Detect Public S3 Buckets", "claw": "CloudClaw", "action": "scan_s3"},
                {"name": "Verify CloudTrail Enabled", "claw": "LogClaw", "action": "verify_cloudtrail"},
                {"name": "Audit Security Groups", "claw": "NetClaw", "action": "audit_sg"},
            ]
        },
    },
    {
        "id": "pkg-010", "publisher_id": "pub-community", "publisher_name": "RegentClaw Community",
        "name": "Kubernetes Hardening Pack", "slug": "k8s-hardening",
        "package_type": "skill_pack", "category": "Infrastructure", "is_official": False,
        "tags": ["kubernetes", "k8s", "hardening", "devsecops", "community"],
        "description": "NSA/CISA Kubernetes Hardening Guide controls mapped to RegentClaw DevClaw and ConfigClaw.",
        "long_description": "Implements NSA/CISA Kubernetes hardening guidance including pod security standards, RBAC least privilege, network policies, secrets management, and admission control checks. Generates CIS Kubernetes Benchmark findings.",
        "version": "1.1.0", "license_type": "Apache 2.0",
        "trust_score": 81.0, "download_count": 5670, "rating": 4.4, "rating_count": 387,
        "is_featured": False, "is_signed": False, "signature_verified": False,
        "sha256_checksum": "j2o7m1k0l8n6j5i9m4l3k2j1i0h9n8m7l6k5j4i3h2g1f0e9d8c7b6a5m4l3k2j1",
        "manifest_json": {
            "skills": [
                {"name": "Enforce Pod Security Standards", "claw": "DevClaw", "action": "enforce_pss"},
                {"name": "Audit RBAC Permissions", "claw": "AccessClaw", "action": "audit_rbac"},
                {"name": "Scan for Privileged Containers", "claw": "ConfigClaw", "action": "scan_privileged"},
                {"name": "Check Network Policies", "claw": "NetClaw", "action": "check_netpol"},
            ]
        },
    },
    {
        "id": "pkg-011", "publisher_id": "pub-community", "publisher_name": "RegentClaw Community",
        "name": "GDPR Privacy Controls", "slug": "gdpr-privacy-controls",
        "package_type": "policy_pack", "category": "Privacy", "is_official": False,
        "tags": ["gdpr", "privacy", "compliance", "eu", "community"],
        "description": "GDPR Article controls mapped to PrivacyClaw and DataClaw policies.",
        "long_description": "Maps GDPR Articles 5–49 to automated PrivacyClaw and DataClaw controls. Includes consent management checks, data subject access request automation, breach notification workflows, and data residency verification.",
        "version": "1.3.0", "license_type": "Creative Commons BY 4.0",
        "trust_score": 79.0, "download_count": 3210, "rating": 4.3, "rating_count": 241,
        "is_featured": False, "is_signed": False, "signature_verified": False,
        "sha256_checksum": "k3p8n2l1m9o7k6j0n5m4l3k2j1i0o9n8m7l6k5j4i3h2g1f0e9d8c7b6a5n4m3l2",
        "manifest_json": {
            "skills": [
                {"name": "Verify Data Residency", "claw": "DataClaw", "action": "verify_residency"},
                {"name": "Automate DSAR Response", "claw": "PrivacyClaw", "action": "handle_dsar"},
                {"name": "Detect PII Exposure", "claw": "DataClaw", "action": "detect_pii"},
                {"name": "Trigger Breach Notification", "claw": "PrivacyClaw", "action": "breach_notify"},
            ]
        },
    },
    {
        "id": "pkg-012", "publisher_id": "pub-community", "publisher_name": "RegentClaw Community",
        "name": "GitHub Advanced Security Bridge", "slug": "github-advanced-security",
        "package_type": "connector", "category": "DevSecOps", "is_official": False,
        "tags": ["github", "ghas", "sast", "secrets", "devsecops", "community"],
        "description": "Ingest GitHub Advanced Security code scanning, secret scanning, and Dependabot alerts.",
        "long_description": "Pulls GHAS findings into AppClaw and DevClaw. Maps code scanning alerts to OWASP Top 10, escalates secret scanning detections to AccessClaw for immediate rotation, and converts Dependabot advisories to ExposureClaw findings.",
        "version": "1.0.2", "license_type": "MIT",
        "trust_score": 77.0, "download_count": 2870, "rating": 4.2, "rating_count": 189,
        "is_featured": False, "is_signed": False, "signature_verified": False,
        "sha256_checksum": "l4q9o3m2n0p8l7k1o6n5m4l3k2j1p0o9n8m7l6k5j4i3h2g1f0e9d8c7b6a5o4n3",
        "manifest_json": {
            "connector_type": "code_security",
            "capabilities": ["code_scanning", "secret_scanning", "dependabot", "sbom"],
        },
    },
]


def seed():
    db = SessionLocal()
    try:
        # Publishers
        for p in PUBLISHERS:
            existing = db.query(ExchangePublisher).filter(ExchangePublisher.id == p["id"]).first()
            if not existing:
                db.add(ExchangePublisher(**p, created_at=datetime.utcnow()))
                print(f"  + Publisher: {p['name']}")

        # Packages
        for p in PACKAGES:
            existing = db.query(ExchangePackage).filter(ExchangePackage.id == p["id"]).first()
            if not existing:
                db.add(ExchangePackage(
                    **p,
                    created_at=datetime.utcnow() - timedelta(days=len(PACKAGES) - PACKAGES.index(p)),
                    updated_at=datetime.utcnow(),
                ))
                print(f"  + Package: {p['name']}")

        db.commit()
        print(f"\nSeeded {len(PUBLISHERS)} publishers and {len(PACKAGES)} packages.")
    finally:
        db.close()


if __name__ == "__main__":
    seed()
