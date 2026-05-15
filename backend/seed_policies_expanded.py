"""
RegentClaw — Expanded Policy Seed (adds 8-10 per claw)
Expands from 123 → ~230 policies across all 25 claws.

Usage:
  docker compose exec backend python seed_policies_expanded.py
  docker compose exec backend python seed_policies_expanded.py --reset

Priority bands (10-unit expansion of originals):
  ArcClaw       37–39   IdentityClaw  47–49   CloudClaw     54–59
  AccessClaw    64–69   EndpointClaw  74–79   NetClaw       84–89
  DataClaw      94–99   AppClaw      104–109  SaaSClaw     114–119
  ThreatClaw   124–129  LogClaw      134–139  IntelClaw    144–149
  UserClaw     154–159  InsiderClaw  164–169  AutomationClaw 174–179
  AttackPathClaw 184–189 ExposureClaw 194–199 ComplianceClaw 204–209
  PrivacyClaw  214–219  VendorClaw   224–229  DevClaw      234–239
  ConfigClaw   244–249  RecoveryClaw 254–259
"""

import asyncio
import json
import sys
from app.core.database import AsyncSessionLocal
from app.models.policy import Policy, PolicyAction, PolicyScope


EXPANDED_POLICIES = [

    # ══════════════════════════════════════════════════════════════════════════
    # ARCCLAW — AI Security (new: 37–39)
    # ══════════════════════════════════════════════════════════════════════════
    {
        "name": "Block Sensitive Data in AI Prompts",
        "description": "ARCCLAW | Detects and blocks prompts containing API keys, tokens, passwords, private keys, or connection strings before they reach any LLM. Prevents accidental secret exfiltration via AI.",
        "priority": 37, "scope": "module", "scope_target": "arcclaw",
        "condition_json": json.dumps({"field": "prompt_content", "op": "contains", "value": "api_key"}),
        "action": "deny",
    },
    {
        "name": "Block Source Code Upload to AI",
        "description": "ARCCLAW | Prevents source code files (.py, .js, .ts, .go, etc.) from being submitted to AI tools. Source code may contain secrets, proprietary algorithms, or vulnerable patterns.",
        "priority": 38, "scope": "module", "scope_target": "arcclaw",
        "condition_json": json.dumps({"field": "prompt_type", "op": "eq", "value": "source_code"}),
        "action": "deny",
    },
    {
        "name": "Block Unsanctioned AI Tool Access",
        "description": "ARCCLAW | Only AI tools registered in the approved connector list may be accessed. Any request to an unregistered AI endpoint (ChatGPT personal, Claude.ai, etc.) is blocked.",
        "priority": 39, "scope": "module", "scope_target": "arcclaw",
        "condition_json": json.dumps({"field": "target", "op": "eq", "value": "unsanctioned_ai"}),
        "action": "deny",
    },
    {
        "name": "Detect Regulated Data in AI Prompts",
        "description": "ARCCLAW | Flags prompts containing patterns matching PII, PHI, PCI (SSN, credit cards, patient IDs, DOB). Logs and alerts — does not block by default to avoid false positives.",
        "priority": 40, "scope": "module", "scope_target": "arcclaw",
        "condition_json": json.dumps({"field": "prompt_type", "op": "eq", "value": "regulated_data"}),
        "action": "monitor",
    },
    {
        "name": "Flag AI Usage Outside Business Hours",
        "description": "ARCCLAW | AI tool usage between 10pm–6am local time is flagged for review. Off-hours AI usage by service accounts is a common data exfiltration vector.",
        "priority": 41, "scope": "module", "scope_target": "arcclaw",
        "condition_json": json.dumps({"field": "hour_of_day", "op": "outside", "value": "6-22"}),
        "action": "monitor",
    },
    {
        "name": "Monitor Prompt Volume Anomalies",
        "description": "ARCCLAW | Alerts when a single user exceeds 500 AI requests/hour or 3000/day. Volume anomalies may indicate automated data harvesting via AI APIs.",
        "priority": 42, "scope": "module", "scope_target": "arcclaw",
        "condition_json": json.dumps({"field": "prompt_count_hour", "op": "gte", "value": 500}),
        "action": "monitor",
    },
    {
        "name": "Require Approval for File Upload to AI",
        "description": "ARCCLAW | Any file attachment submitted to an AI tool requires manager approval. File uploads can exfiltrate confidential documents, contracts, or financial data.",
        "priority": 43, "scope": "module", "scope_target": "arcclaw",
        "condition_json": json.dumps({"field": "has_file_attachment", "op": "eq", "value": True}),
        "action": "require_approval",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # IDENTITYCLAW — Identity Risk (new: 47–56)
    # ══════════════════════════════════════════════════════════════════════════
    {
        "name": "Detect Users Without MFA",
        "description": "IDENTITYCLAW | Identifies all active user accounts that do not have MFA enrolled. MFA absence is the single highest-impact identity risk. Generates alert per user.",
        "priority": 47, "scope": "module", "scope_target": "identityclaw",
        "condition_json": json.dumps({"field": "mfa_enabled", "op": "eq", "value": False}),
        "action": "monitor",
    },
    {
        "name": "Detect Privileged Accounts Without PIM/JIT",
        "description": "IDENTITYCLAW | Global admins, privileged role members, and service principals with high permissions that are permanently assigned (not JIT/PIM) are flagged for review.",
        "priority": 48, "scope": "module", "scope_target": "identityclaw",
        "condition_json": json.dumps({"field": "privileged_permanent", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect Stale Guest Users",
        "description": "IDENTITYCLAW | Guest accounts inactive for 30+ days that still have access to resources are flagged. External guests should be offboarded when collaboration ends.",
        "priority": 49, "scope": "module", "scope_target": "identityclaw",
        "condition_json": json.dumps({"field": "guest_inactive_days", "op": "gte", "value": 30}),
        "action": "monitor",
    },
    {
        "name": "Detect New Global Admin Assignment",
        "description": "IDENTITYCLAW | Any assignment of the Global Administrator role triggers an immediate high-severity alert and requires approval before the assignment takes effect.",
        "priority": 50, "scope": "module", "scope_target": "identityclaw",
        "condition_json": json.dumps({"field": "role_assigned", "op": "eq", "value": "Global Administrator"}),
        "action": "require_approval",
    },
    {
        "name": "Detect Risky Sign-Ins",
        "description": "IDENTITYCLAW | Sign-ins scored as medium or high risk by the identity provider (Entra ID Risk, Okta ThreatInsight) generate an alert and trigger step-up authentication.",
        "priority": 51, "scope": "module", "scope_target": "identityclaw",
        "condition_json": json.dumps({"field": "signin_risk", "op": "in", "value": ["medium", "high"]}),
        "action": "monitor",
    },
    {
        "name": "Detect Impossible Travel",
        "description": "IDENTITYCLAW | Flags sign-ins from two geographically distinct locations within a timeframe that makes travel physically impossible. Indicates credential sharing or compromise.",
        "priority": 52, "scope": "module", "scope_target": "identityclaw",
        "condition_json": json.dumps({"field": "impossible_travel", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect Service Principals with High Permissions",
        "description": "IDENTITYCLAW | Service principals (app registrations, managed identities) with Owner, Contributor, or User Access Administrator roles are flagged for least-privilege review.",
        "priority": 53, "scope": "module", "scope_target": "identityclaw",
        "condition_json": json.dumps({"field": "sp_high_permission", "op": "eq", "value": True}),
        "action": "monitor",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # CLOUDCLAW — Cloud Security (new: 54–63)
    # ══════════════════════════════════════════════════════════════════════════
    {
        "name": "Detect Open Management Ports",
        "description": "CLOUDCLAW | Flags NSGs/Security Groups with RDP (3389) or SSH (22) open to 0.0.0.0/0. Management ports exposed to the internet are the #1 initial access vector.",
        "priority": 54, "scope": "module", "scope_target": "cloudclaw",
        "condition_json": json.dumps({"field": "port_exposed", "op": "in", "value": [3389, 22]}),
        "action": "monitor",
    },
    {
        "name": "Detect Unencrypted Disks",
        "description": "CLOUDCLAW | Identifies VM disks (OS and data) that do not have encryption-at-rest enabled. Unencrypted disks violate ISO 27001, SOC 2, and most data protection regulations.",
        "priority": 55, "scope": "module", "scope_target": "cloudclaw",
        "condition_json": json.dumps({"field": "disk_encrypted", "op": "eq", "value": False}),
        "action": "monitor",
    },
    {
        "name": "Detect Resources Without Required Tags",
        "description": "CLOUDCLAW | Cloud resources missing mandatory tags (owner, environment, cost-center, data-classification) are flagged. Untagged resources cannot be owned or governed.",
        "priority": 56, "scope": "module", "scope_target": "cloudclaw",
        "condition_json": json.dumps({"field": "missing_required_tags", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect Missing Defender Plans",
        "description": "CLOUDCLAW | Subscriptions or resource groups without Microsoft Defender plans enabled (CSPM, servers, storage, SQL, etc.) are flagged. Defender coverage gaps create blind spots.",
        "priority": 57, "scope": "module", "scope_target": "cloudclaw",
        "condition_json": json.dumps({"field": "defender_plan_missing", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect Key Vault Public Network Access",
        "description": "CLOUDCLAW | Azure Key Vaults accessible from public networks (not restricted to private endpoints or approved IP ranges) are flagged as critical misconfigurations.",
        "priority": 58, "scope": "module", "scope_target": "cloudclaw",
        "condition_json": json.dumps({"field": "keyvault_public_access", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect Unattached Public IPs",
        "description": "CLOUDCLAW | Public IP addresses not attached to any active resource are flagged. Unattached IPs are attack surface that costs money and provides zero value.",
        "priority": 59, "scope": "module", "scope_target": "cloudclaw",
        "condition_json": json.dumps({"field": "public_ip_unattached", "op": "eq", "value": True}),
        "action": "monitor",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # ACCESSCLAW — PAM / Privileged Access (new: 64–69)
    # ══════════════════════════════════════════════════════════════════════════
    {
        "name": "Detect Shared Service Account Credentials",
        "description": "ACCESSCLAW | Service accounts whose credentials are used by more than one system or person are flagged. Shared credentials eliminate individual accountability.",
        "priority": 64, "scope": "module", "scope_target": "accessclaw",
        "condition_json": json.dumps({"field": "credential_shared", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect Credentials Not Rotated Within Policy",
        "description": "ACCESSCLAW | Privileged account passwords and service account secrets not rotated within the organization's rotation policy (default 90 days) are flagged.",
        "priority": 65, "scope": "module", "scope_target": "accessclaw",
        "condition_json": json.dumps({"field": "credential_age_days", "op": "gte", "value": 90}),
        "action": "monitor",
    },
    {
        "name": "Require Approval for Standing Privileged Access",
        "description": "ACCESSCLAW | Any request for standing (permanent, non-JIT) privileged access to production systems requires multi-approver review. JIT access is the default posture.",
        "priority": 66, "scope": "module", "scope_target": "accessclaw",
        "condition_json": json.dumps({"field": "access_type", "op": "eq", "value": "standing_privileged"}),
        "action": "require_approval",
    },
    {
        "name": "Alert on Privileged Session Without Recording",
        "description": "ACCESSCLAW | Privileged sessions (to servers, databases, network devices) that do not have session recording enabled are flagged. Session recordings are required for audit evidence.",
        "priority": 67, "scope": "module", "scope_target": "accessclaw",
        "condition_json": json.dumps({"field": "session_recorded", "op": "eq", "value": False}),
        "action": "monitor",
    },
    {
        "name": "Detect Local Admin Accounts on Endpoints",
        "description": "ACCESSCLAW | Endpoint devices with local administrator accounts enabled (outside LAPS-managed accounts) are flagged. Local admins are the primary lateral movement enabler.",
        "priority": 68, "scope": "module", "scope_target": "accessclaw",
        "condition_json": json.dumps({"field": "local_admin_enabled", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Require Approval for Emergency Break-Glass Access",
        "description": "ACCESSCLAW | Any use of break-glass emergency accounts requires immediate dual approval and triggers a mandatory post-incident review within 24 hours.",
        "priority": 69, "scope": "module", "scope_target": "accessclaw",
        "condition_json": json.dumps({"field": "break_glass_used", "op": "eq", "value": True}),
        "action": "require_approval",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # ENDPOINTCLAW — Endpoint Security (new: 74–79)
    # ══════════════════════════════════════════════════════════════════════════
    {
        "name": "Detect Outdated Operating Systems",
        "description": "ENDPOINTCLAW | Endpoints running EOL or unsupported OS versions (Windows 10 <22H2, macOS <13, Ubuntu <22.04) are flagged as high risk. EOL systems cannot receive security patches.",
        "priority": 74, "scope": "module", "scope_target": "endpointclaw",
        "condition_json": json.dumps({"field": "os_supported", "op": "eq", "value": False}),
        "action": "monitor",
    },
    {
        "name": "Detect Disabled Host Firewall",
        "description": "ENDPOINTCLAW | Endpoints with the host-based firewall disabled (Windows Defender Firewall, macOS pf) are flagged. Host firewall is the last line of defense for lateral movement.",
        "priority": 75, "scope": "module", "scope_target": "endpointclaw",
        "condition_json": json.dumps({"field": "firewall_enabled", "op": "eq", "value": False}),
        "action": "monitor",
    },
    {
        "name": "Detect Risky USB Usage",
        "description": "ENDPOINTCLAW | USB mass storage device connections on endpoints are monitored. Bulk file transfers to USB are flagged as potential data exfiltration events.",
        "priority": 76, "scope": "module", "scope_target": "endpointclaw",
        "condition_json": json.dumps({"field": "usb_mass_storage_connected", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect Suspicious Process Chains",
        "description": "ENDPOINTCLAW | Process chains indicative of living-off-the-land attacks (cmd.exe → powershell → wscript, Office → cmd, etc.) are flagged for immediate investigation.",
        "priority": 77, "scope": "module", "scope_target": "endpointclaw",
        "condition_json": json.dumps({"field": "suspicious_process_chain", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Auto-Isolate Endpoint on Critical Threat",
        "description": "ENDPOINTCLAW | Endpoints with a critical-severity active threat (ransomware, rootkit, active C2 callback) are automatically isolated from the network pending investigation.",
        "priority": 78, "scope": "module", "scope_target": "endpointclaw",
        "condition_json": json.dumps({"field": "threat_severity", "op": "eq", "value": "critical"}),
        "action": "isolate",
    },
    {
        "name": "Detect EDR Agent Tampering",
        "description": "ENDPOINTCLAW | Endpoints where the EDR agent has been stopped, uninstalled, or tampered with generate a critical alert. Agent tampering is a pre-ransomware indicator.",
        "priority": 79, "scope": "module", "scope_target": "endpointclaw",
        "condition_json": json.dumps({"field": "edr_tampered", "op": "eq", "value": True}),
        "action": "monitor",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # NETCLAW — Network Security (new: 84–89)
    # ══════════════════════════════════════════════════════════════════════════
    {
        "name": "Detect Exposed RDP to Internet",
        "description": "NETCLAW | Firewall rules or NSGs allowing RDP (TCP 3389) inbound from any source (0.0.0.0/0) are flagged as critical. RDP exposure is the #1 ransomware initial access vector.",
        "priority": 84, "scope": "module", "scope_target": "netclaw",
        "condition_json": json.dumps({"field": "rdp_internet_exposed", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect ANY/ANY Firewall Rules",
        "description": "NETCLAW | Network ACL or firewall rules with source=ANY, destination=ANY, port=ANY are flagged as critical misconfigurations. These rules effectively disable the firewall.",
        "priority": 85, "scope": "module", "scope_target": "netclaw",
        "condition_json": json.dumps({"field": "rule_any_any", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect Missing Web Application Firewall",
        "description": "NETCLAW | Internet-facing web applications without a WAF in front of them are flagged. WAF is required for OWASP Top 10 protection on all customer-facing endpoints.",
        "priority": 86, "scope": "module", "scope_target": "netclaw",
        "condition_json": json.dumps({"field": "waf_present", "op": "eq", "value": False}),
        "action": "monitor",
    },
    {
        "name": "Detect Lateral Movement Network Paths",
        "description": "NETCLAW | East-west traffic flows between network segments that should be isolated (e.g., workstation→server direct, user segment→database) are flagged as potential lateral movement.",
        "priority": 87, "scope": "module", "scope_target": "netclaw",
        "condition_json": json.dumps({"field": "lateral_movement_detected", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect DNS Exfiltration Patterns",
        "description": "NETCLAW | High-volume DNS queries to external resolvers, unusually long DNS names, or DNS TXT record abuse patterns are flagged as potential data exfiltration via DNS tunneling.",
        "priority": 88, "scope": "module", "scope_target": "netclaw",
        "condition_json": json.dumps({"field": "dns_exfil_pattern", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Alert on Unmanaged Internet-Facing Assets",
        "description": "NETCLAW | IP addresses or hostnames resolving to the organization's ASN that are not registered in the asset inventory are flagged as shadow IT attack surface.",
        "priority": 89, "scope": "module", "scope_target": "netclaw",
        "condition_json": json.dumps({"field": "asset_unmanaged", "op": "eq", "value": True}),
        "action": "monitor",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # DATACLAW — Data Security / DLP (new: 94–99)
    # ══════════════════════════════════════════════════════════════════════════
    {
        "name": "Detect Public File Sharing",
        "description": "DATACLAW | Files or folders shared with 'Anyone with the link' or set to public access in SharePoint, OneDrive, Google Drive, or Box are flagged for immediate review.",
        "priority": 94, "scope": "module", "scope_target": "dataclaw",
        "condition_json": json.dumps({"field": "file_public_share", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect Sensitive Files in Open Locations",
        "description": "DATACLAW | Files classified as confidential or restricted stored in locations accessible beyond the intended audience (public sites, broad groups) are flagged.",
        "priority": 95, "scope": "module", "scope_target": "dataclaw",
        "condition_json": json.dumps({"field": "sensitive_file_exposed", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Alert on Large Data Downloads",
        "description": "DATACLAW | Single-session downloads exceeding 500MB from corporate systems are flagged as potential data exfiltration. Threshold adjustable per data classification level.",
        "priority": 96, "scope": "module", "scope_target": "dataclaw",
        "condition_json": json.dumps({"field": "download_size_mb", "op": "gte", "value": 500}),
        "action": "monitor",
    },
    {
        "name": "Detect External Sharing of Confidential Files",
        "description": "DATACLAW | Files with a 'Confidential' or 'Restricted' sensitivity label shared with external (non-domain) email addresses are flagged and the share is blocked pending review.",
        "priority": 97, "scope": "module", "scope_target": "dataclaw",
        "condition_json": json.dumps({"field": "confidential_external_share", "op": "eq", "value": True}),
        "action": "deny",
    },
    {
        "name": "Require Approval for Bulk Data Export",
        "description": "DATACLAW | Export operations generating more than 10,000 records from any system require manager and data owner approval. Bulk exports are the most common data theft pattern.",
        "priority": 98, "scope": "module", "scope_target": "dataclaw",
        "condition_json": json.dumps({"field": "export_record_count", "op": "gte", "value": 10000}),
        "action": "require_approval",
    },
    {
        "name": "Detect Unclassified Sensitive Data",
        "description": "DATACLAW | Data stores (SharePoint, OneDrive, S3, Blob) containing content that matches PII, PHI, or PCI patterns but has no sensitivity label applied are flagged for classification.",
        "priority": 99, "scope": "module", "scope_target": "dataclaw",
        "condition_json": json.dumps({"field": "unclassified_sensitive_content", "op": "eq", "value": True}),
        "action": "monitor",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # APPCLAW — Application / API Security (new: 104–109)
    # ══════════════════════════════════════════════════════════════════════════
    {
        "name": "Detect APIs Without Authentication",
        "description": "APPCLAW | API endpoints responding without requiring an authentication token (Bearer, API key, mTLS) are flagged as critical. Unauthenticated APIs are OWASP API Top 10 #1.",
        "priority": 104, "scope": "module", "scope_target": "appclaw",
        "condition_json": json.dumps({"field": "api_auth_required", "op": "eq", "value": False}),
        "action": "monitor",
    },
    {
        "name": "Detect Excessive API Rate Limit Breaches",
        "description": "APPCLAW | APIs being called at rates exceeding their defined rate limits from a single source IP are flagged. Rate limit abuse can indicate credential stuffing or data harvesting.",
        "priority": 105, "scope": "module", "scope_target": "appclaw",
        "condition_json": json.dumps({"field": "rate_limit_breached", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect API Keys in Application Logs",
        "description": "APPCLAW | Application logs containing API key patterns, Bearer tokens, or connection strings are flagged. Secrets in logs are a top secret-exposure vector.",
        "priority": 106, "scope": "module", "scope_target": "appclaw",
        "condition_json": json.dumps({"field": "secret_in_logs", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Block API Access from Sanctioned Countries",
        "description": "APPCLAW | API requests originating from countries on the organization's restricted list are blocked. Geo-fencing is a baseline control for regulatory compliance.",
        "priority": 107, "scope": "module", "scope_target": "appclaw",
        "condition_json": json.dumps({"field": "source_country_blocked", "op": "eq", "value": True}),
        "action": "deny",
    },
    {
        "name": "Detect Vulnerable Dependency in Production",
        "description": "APPCLAW | Applications with dependencies containing CVSS 9.0+ vulnerabilities deployed to production are flagged. Critical CVEs in production libraries require immediate patching.",
        "priority": 108, "scope": "module", "scope_target": "appclaw",
        "condition_json": json.dumps({"field": "critical_cve_in_dep", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Require Approval for New Production API Scope",
        "description": "APPCLAW | Adding new OAuth2 scopes or API permissions to a production application requires security review and approval before the change is applied.",
        "priority": 109, "scope": "module", "scope_target": "appclaw",
        "condition_json": json.dumps({"field": "new_api_scope_added", "op": "eq", "value": True}),
        "action": "require_approval",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # SAASCLAW — SaaS Security (new: 114–119)
    # ══════════════════════════════════════════════════════════════════════════
    {
        "name": "Detect Risky OAuth App Consents",
        "description": "SAASCLAW | Third-party OAuth applications that have been granted Mail.Read, Files.ReadWrite.All, or similar broad permissions by users are flagged for admin review.",
        "priority": 114, "scope": "module", "scope_target": "saasclaw",
        "condition_json": json.dumps({"field": "oauth_high_risk_scope", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect External Mailbox Forwarding",
        "description": "SAASCLAW | Email accounts with forwarding rules sending messages to external (non-company) addresses are flagged. Mailbox forwarding is a common BEC persistence technique.",
        "priority": 115, "scope": "module", "scope_target": "saasclaw",
        "condition_json": json.dumps({"field": "external_forward_enabled", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect Anonymous SharePoint Links",
        "description": "SAASCLAW | SharePoint/OneDrive links that allow access to anyone without authentication are flagged. Anonymous links bypass all identity and access controls.",
        "priority": 116, "scope": "module", "scope_target": "saasclaw",
        "condition_json": json.dumps({"field": "anonymous_link_active", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect SaaS Admin Role Changes",
        "description": "SAASCLAW | Changes to admin roles in M365, Google Workspace, Salesforce, or other SaaS platforms generate an alert and require justification within 24 hours.",
        "priority": 117, "scope": "module", "scope_target": "saasclaw",
        "condition_json": json.dumps({"field": "saas_admin_role_changed", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect Suspicious App Consent Grants",
        "description": "SAASCLAW | Consent grants to apps requesting access to all users' data (tenant-wide consent) are flagged. Tenant-wide consent is an admin action that should never be user-initiated.",
        "priority": 118, "scope": "module", "scope_target": "saasclaw",
        "condition_json": json.dumps({"field": "tenant_wide_consent", "op": "eq", "value": True}),
        "action": "require_approval",
    },
    {
        "name": "Detect Unused SaaS Admin Accounts",
        "description": "SAASCLAW | SaaS platform administrator accounts with no login activity in 60+ days are flagged for deprovisioning. Stale admin accounts are a silent attack surface.",
        "priority": 119, "scope": "module", "scope_target": "saasclaw",
        "condition_json": json.dumps({"field": "saas_admin_inactive_days", "op": "gte", "value": 60}),
        "action": "monitor",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # THREATCLAW — Detection & Response (new: 124–129)
    # ══════════════════════════════════════════════════════════════════════════
    {
        "name": "Correlate Identity + Endpoint + Cloud Events",
        "description": "THREATCLAW | When the same user/identity appears in risky events across identity, endpoint, AND cloud within 1 hour, the combined signal is correlated into a high-severity incident.",
        "priority": 124, "scope": "module", "scope_target": "threatclaw",
        "condition_json": json.dumps({"field": "cross_pillar_correlation", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect Repeated Failed Logins",
        "description": "THREATCLAW | More than 10 failed login attempts within 5 minutes from the same source IP or targeting the same account triggers a brute force alert.",
        "priority": 125, "scope": "module", "scope_target": "threatclaw",
        "condition_json": json.dumps({"field": "failed_logins_5min", "op": "gte", "value": 10}),
        "action": "monitor",
    },
    {
        "name": "Detect Malware Alert on Privileged Identity",
        "description": "THREATCLAW | When a malware or ransomware alert is triggered on an endpoint belonging to a privileged user (admin, executive), the severity is automatically escalated to critical.",
        "priority": 126, "scope": "module", "scope_target": "threatclaw",
        "condition_json": json.dumps({"field": "malware_on_privileged_host", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Auto-Create Incident Timeline",
        "description": "THREATCLAW | For high and critical alerts, ThreatClaw automatically assembles a timeline of related events (logins, file access, network, process) to accelerate investigation.",
        "priority": 127, "scope": "module", "scope_target": "threatclaw",
        "condition_json": json.dumps({"field": "alert_severity", "op": "in", "value": ["high", "critical"]}),
        "action": "monitor",
    },
    {
        "name": "Detect Suspicious IP Reputation",
        "description": "THREATCLAW | Connections to or from IPs flagged by threat intel feeds (VirusTotal, AbuseIPDB, GreyNoise) as malicious, C2, or tor exit nodes generate an immediate alert.",
        "priority": 128, "scope": "module", "scope_target": "threatclaw",
        "condition_json": json.dumps({"field": "ip_reputation_malicious", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Require Approval for Automated Containment",
        "description": "THREATCLAW | Before ThreatClaw auto-isolates a host or disables an account, the action requires SOC analyst approval — unless the threat confidence score exceeds 95.",
        "priority": 129, "scope": "module", "scope_target": "threatclaw",
        "condition_json": json.dumps({"field": "containment_confidence", "op": "lt", "value": 95}),
        "action": "require_approval",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # LOGCLAW — SIEM / Observability (new: 134–139)
    # ══════════════════════════════════════════════════════════════════════════
    {
        "name": "Detect Missing Diagnostic Logging",
        "description": "LOGCLAW | Azure resources, AWS services, or GCP services with diagnostic logging disabled are flagged. Missing logs create compliance gaps and blind spots for threat detection.",
        "priority": 134, "scope": "module", "scope_target": "logclaw",
        "condition_json": json.dumps({"field": "diagnostic_logging_disabled", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect Log Retention Below Policy Minimum",
        "description": "LOGCLAW | Log retention periods below the organization minimum (default 90 days, or regulatory minimum) are flagged. Short retention prevents forensic investigation.",
        "priority": 135, "scope": "module", "scope_target": "logclaw",
        "condition_json": json.dumps({"field": "log_retention_days", "op": "lt", "value": 90}),
        "action": "monitor",
    },
    {
        "name": "Alert on Log Volume Anomaly",
        "description": "LOGCLAW | A sudden >50% drop or >200% increase in log volume from any source is flagged. Volume anomalies may indicate log deletion, service outage, or flood attack.",
        "priority": 136, "scope": "module", "scope_target": "logclaw",
        "condition_json": json.dumps({"field": "log_volume_anomaly", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Alert on Unmonitored Critical System",
        "description": "LOGCLAW | Critical systems (domain controllers, PAM vaults, firewalls, identity providers) that have not sent logs to the SIEM in 15+ minutes are flagged as a coverage gap.",
        "priority": 137, "scope": "module", "scope_target": "logclaw",
        "condition_json": json.dumps({"field": "critical_system_silent_min", "op": "gte", "value": 15}),
        "action": "monitor",
    },
    {
        "name": "Detect SIEM Rule Modifications",
        "description": "LOGCLAW | Changes to detection rules, alert thresholds, or SIEM configurations generate an alert. Rule tampering can silence detections silently.",
        "priority": 138, "scope": "module", "scope_target": "logclaw",
        "condition_json": json.dumps({"field": "siem_rule_modified", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Require Approval for Log Forwarding Rule Changes",
        "description": "LOGCLAW | Adding or modifying log forwarding destinations (new Syslog targets, export to external storage) requires admin approval. Unauthorized forwarding = data exfiltration.",
        "priority": 139, "scope": "module", "scope_target": "logclaw",
        "condition_json": json.dumps({"field": "log_forward_rule_changed", "op": "eq", "value": True}),
        "action": "require_approval",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # INTELCLAW — Threat Intelligence (new: 144–149)
    # ══════════════════════════════════════════════════════════════════════════
    {
        "name": "Enrich Alerts With Threat Intelligence",
        "description": "INTELCLAW | All high/critical alerts are automatically enriched with threat intel context (VirusTotal, AbuseIPDB, MITRE ATT&CK mapping) before reaching the SOC queue.",
        "priority": 144, "scope": "module", "scope_target": "intelclaw",
        "condition_json": json.dumps({"field": "alert_severity", "op": "in", "value": ["high", "critical"]}),
        "action": "monitor",
    },
    {
        "name": "Detect IOC Match in Traffic",
        "description": "INTELCLAW | Network connections, DNS lookups, or file hashes matching current threat intel IOC feeds (domains, IPs, hashes) generate an immediate alert.",
        "priority": 145, "scope": "module", "scope_target": "intelclaw",
        "condition_json": json.dumps({"field": "ioc_match", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect Newly Registered Domain Access",
        "description": "INTELCLAW | Connections to domains registered within the last 30 days are flagged. Freshly registered domains are frequently used for phishing and C2 infrastructure.",
        "priority": 146, "scope": "module", "scope_target": "intelclaw",
        "condition_json": json.dumps({"field": "domain_age_days", "op": "lt", "value": 30}),
        "action": "monitor",
    },
    {
        "name": "Alert on Dark Web Credential Exposure",
        "description": "INTELCLAW | Corporate email addresses or credentials found in dark web breach databases trigger an immediate alert and password reset requirement.",
        "priority": 147, "scope": "module", "scope_target": "intelclaw",
        "condition_json": json.dumps({"field": "darkweb_credential_found", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect MITRE ATT&CK Tactic Chains",
        "description": "INTELCLAW | When events map to 3+ MITRE ATT&CK techniques in a single kill-chain (Recon→Initial Access→Execution) within 24 hours, a critical incident is created.",
        "priority": 148, "scope": "module", "scope_target": "intelclaw",
        "condition_json": json.dumps({"field": "mitre_chain_depth", "op": "gte", "value": 3}),
        "action": "monitor",
    },
    {
        "name": "Require Approval for Threat Intel Feed Changes",
        "description": "INTELCLAW | Adding, removing, or modifying threat intel feed sources requires security team approval. Removing feeds creates blind spots; adding untrusted feeds can cause alert fatigue.",
        "priority": 149, "scope": "module", "scope_target": "intelclaw",
        "condition_json": json.dumps({"field": "intel_feed_modified", "op": "eq", "value": True}),
        "action": "require_approval",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # USERCLAW — User Behavior Analytics (new: 154–159)
    # ══════════════════════════════════════════════════════════════════════════
    {
        "name": "Detect Anomalous File Access Volume",
        "description": "USERCLAW | Users accessing significantly more files than their 30-day baseline (>3 standard deviations) are flagged for insider threat review.",
        "priority": 154, "scope": "module", "scope_target": "userclaw",
        "condition_json": json.dumps({"field": "file_access_anomaly_sigma", "op": "gte", "value": 3}),
        "action": "monitor",
    },
    {
        "name": "Detect Login From New Country",
        "description": "USERCLAW | First-time login from a country not in a user's historical location profile generates an alert and requires MFA step-up.",
        "priority": 155, "scope": "module", "scope_target": "userclaw",
        "condition_json": json.dumps({"field": "login_country_new", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect After-Hours Privileged Access",
        "description": "USERCLAW | Privileged account activity (admin portals, PAM checkouts, root logins) outside of the user's normal working hours is flagged for review.",
        "priority": 156, "scope": "module", "scope_target": "userclaw",
        "condition_json": json.dumps({"field": "privileged_access_after_hours", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect Peer Group Behavior Deviation",
        "description": "USERCLAW | Users whose behavior significantly deviates from their peer group (same department, role, location) in terms of data access or application usage are flagged.",
        "priority": 157, "scope": "module", "scope_target": "userclaw",
        "condition_json": json.dumps({"field": "peer_group_deviation", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Alert on Rapid Permission Changes",
        "description": "USERCLAW | Users whose permissions change more than 3 times in 24 hours are flagged. Rapid permission churn may indicate privilege escalation or account compromise.",
        "priority": 158, "scope": "module", "scope_target": "userclaw",
        "condition_json": json.dumps({"field": "permission_changes_24h", "op": "gte", "value": 3}),
        "action": "monitor",
    },
    {
        "name": "Detect Mass Email Sending",
        "description": "USERCLAW | Users sending more than 200 emails in one hour (outside of approved bulk-mail systems) are flagged for potential phishing campaign, BEC, or account compromise.",
        "priority": 159, "scope": "module", "scope_target": "userclaw",
        "condition_json": json.dumps({"field": "emails_sent_per_hour", "op": "gte", "value": 200}),
        "action": "monitor",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # INSIDERCLAW — Insider Risk (new: 164–169)
    # ══════════════════════════════════════════════════════════════════════════
    {
        "name": "Detect Pre-Departure Data Hoarding",
        "description": "INSIDERCLAW | Employees with a known departure date (resignation/termination) who increase data downloads or copying activity are flagged as high insider risk.",
        "priority": 164, "scope": "module", "scope_target": "insiderclaw",
        "condition_json": json.dumps({"field": "departure_date_set_data_spike", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect Personal Cloud Storage Uploads",
        "description": "INSIDERCLAW | File uploads to personal cloud storage (Dropbox personal, Google Drive personal, iCloud) from corporate devices are flagged as policy violations.",
        "priority": 165, "scope": "module", "scope_target": "insiderclaw",
        "condition_json": json.dumps({"field": "personal_cloud_upload", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect Sensitive Data Printed",
        "description": "INSIDERCLAW | Documents classified as confidential or restricted that are sent to physical printers are flagged. Printed documents bypass all digital DLP controls.",
        "priority": 166, "scope": "module", "scope_target": "insiderclaw",
        "condition_json": json.dumps({"field": "confidential_doc_printed", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect Access to Competitor or Job Search Sites",
        "description": "INSIDERCLAW | Browsing to job search sites or competitor platforms combined with simultaneous data download activity generates a combined insider risk score elevation.",
        "priority": 167, "scope": "module", "scope_target": "insiderclaw",
        "condition_json": json.dumps({"field": "job_search_plus_data_activity", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Require Approval for High-Risk Employee Data Access",
        "description": "INSIDERCLAW | Employees with an elevated insider risk score (75+) attempting to access sensitive data repositories require manager approval before access is granted.",
        "priority": 168, "scope": "module", "scope_target": "insiderclaw",
        "condition_json": json.dumps({"field": "insider_risk_score", "op": "gte", "value": 75}),
        "action": "require_approval",
    },
    {
        "name": "Detect Anomalous Badge + Digital Access Correlation",
        "description": "INSIDERCLAW | Users whose digital access logs show activity in a building/office where their badge access shows they are not present are flagged for credential sharing investigation.",
        "priority": 169, "scope": "module", "scope_target": "insiderclaw",
        "condition_json": json.dumps({"field": "badge_digital_mismatch", "op": "eq", "value": True}),
        "action": "monitor",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # AUTOMATIONCLAW — SOAR (new: 174–179)
    # ══════════════════════════════════════════════════════════════════════════
    {
        "name": "Require Approval for Automated Account Disable",
        "description": "AUTOMATIONCLAW | Automated playbooks that disable user accounts must have at least one human approval step unless the threat confidence score exceeds 98.",
        "priority": 174, "scope": "module", "scope_target": "automationclaw",
        "condition_json": json.dumps({"field": "playbook_action", "op": "eq", "value": "disable_account"}),
        "action": "require_approval",
    },
    {
        "name": "Block Runaway Automation Loops",
        "description": "AUTOMATIONCLAW | Automated playbooks that trigger more than 50 actions in 5 minutes are paused and flagged. Runaway automation can cause more damage than the original incident.",
        "priority": 175, "scope": "module", "scope_target": "automationclaw",
        "condition_json": json.dumps({"field": "playbook_actions_5min", "op": "gte", "value": 50}),
        "action": "deny",
    },
    {
        "name": "Monitor All SOAR Playbook Executions",
        "description": "AUTOMATIONCLAW | Every playbook execution is logged with actor, trigger event, actions taken, and outcome. SOAR actions are high-impact and require full auditability.",
        "priority": 176, "scope": "module", "scope_target": "automationclaw",
        "condition_json": json.dumps({"field": "playbook_executed", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Require Approval for Network Block Automation",
        "description": "AUTOMATIONCLAW | Automated playbooks that add firewall block rules or disable network access require SOC lead approval. Blocking production traffic has business impact.",
        "priority": 177, "scope": "module", "scope_target": "automationclaw",
        "condition_json": json.dumps({"field": "playbook_action", "op": "eq", "value": "block_network"}),
        "action": "require_approval",
    },
    {
        "name": "Alert on Playbook Failure",
        "description": "AUTOMATIONCLAW | When a security playbook fails to complete (timeout, API error, permission denied), a high-severity alert is raised so the action can be completed manually.",
        "priority": 178, "scope": "module", "scope_target": "automationclaw",
        "condition_json": json.dumps({"field": "playbook_failed", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Require Dual Approval for Critical Playbooks",
        "description": "AUTOMATIONCLAW | Playbooks classified as critical impact (mass user disable, domain controller actions, firewall policy changes) require approval from two distinct senior analysts.",
        "priority": 179, "scope": "module", "scope_target": "automationclaw",
        "condition_json": json.dumps({"field": "playbook_impact", "op": "eq", "value": "critical"}),
        "action": "require_approval",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # ATTACKPATHCLAW — Attack Path Analysis (new: 184–189)
    # ══════════════════════════════════════════════════════════════════════════
    {
        "name": "Alert on Critical Asset Reachability",
        "description": "ATTACKPATHCLAW | When attack path analysis identifies a feasible path from an internet-exposed asset to a Tier-0 asset (domain controller, PAM vault, identity provider), a critical alert is raised.",
        "priority": 184, "scope": "module", "scope_target": "attackpathclaw",
        "condition_json": json.dumps({"field": "tier0_reachable", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect Excessive Kerberoastable Accounts",
        "description": "ATTACKPATHCLAW | Service accounts with SPNs set that are Kerberoastable (especially those with admin privileges) are flagged. Kerberoasting is a primary AD attack technique.",
        "priority": 185, "scope": "module", "scope_target": "attackpathclaw",
        "condition_json": json.dumps({"field": "kerberoastable_privileged", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect Overly Permissive Trust Relationships",
        "description": "ATTACKPATHCLAW | AD domain trusts or Azure tenant-to-tenant trust configurations that allow transitive access to privileged resources are flagged for architecture review.",
        "priority": 186, "scope": "module", "scope_target": "attackpathclaw",
        "condition_json": json.dumps({"field": "trust_overly_permissive", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect ACL Abuse Paths",
        "description": "ATTACKPATHCLAW | Active Directory ACL configurations that allow a non-privileged account to reset passwords, modify group memberships, or own privileged objects are flagged.",
        "priority": 187, "scope": "module", "scope_target": "attackpathclaw",
        "condition_json": json.dumps({"field": "acl_abuse_path_exists", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Monitor Attack Path Changes After Remediation",
        "description": "ATTACKPATHCLAW | After a critical attack path is remediated, the path is re-evaluated daily for 30 days to verify the fix is durable and hasn't been re-introduced.",
        "priority": 188, "scope": "module", "scope_target": "attackpathclaw",
        "condition_json": json.dumps({"field": "remediated_path_recheck", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Require Approval for Attack Simulation Execution",
        "description": "ATTACKPATHCLAW | Running attack path simulations (BloodHound queries, assumed breach exercises) in production environments requires CISO approval.",
        "priority": 189, "scope": "module", "scope_target": "attackpathclaw",
        "condition_json": json.dumps({"field": "attack_simulation_requested", "op": "eq", "value": True}),
        "action": "require_approval",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # EXPOSURECLAW — External Attack Surface (new: 194–199)
    # ══════════════════════════════════════════════════════════════════════════
    {
        "name": "Detect New Internet-Facing Assets",
        "description": "EXPOSURECLAW | Any new IP, hostname, or subdomain appearing on the organization's internet-facing attack surface that is not in the approved asset inventory is flagged immediately.",
        "priority": 194, "scope": "module", "scope_target": "exposureclaw",
        "condition_json": json.dumps({"field": "new_internet_asset_discovered", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect Expired TLS Certificates",
        "description": "EXPOSURECLAW | TLS/SSL certificates expiring within 14 days or already expired on internet-facing services are flagged. Certificate expiry causes outages and enables MITM.",
        "priority": 195, "scope": "module", "scope_target": "exposureclaw",
        "condition_json": json.dumps({"field": "cert_expiry_days", "op": "lte", "value": 14}),
        "action": "monitor",
    },
    {
        "name": "Detect Open Admin Panels on Internet",
        "description": "EXPOSURECLAW | Admin panels (Kubernetes dashboard, Grafana, phpMyAdmin, admin.*, etc.) exposed to the internet without IP restriction are flagged as critical.",
        "priority": 196, "scope": "module", "scope_target": "exposureclaw",
        "condition_json": json.dumps({"field": "admin_panel_internet_exposed", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect Subdomain Takeover Risk",
        "description": "EXPOSURECLAW | DNS CNAME records pointing to decommissioned cloud services (Azure, AWS, GitHub Pages) that could be claimed by an attacker are flagged as subdomain takeover risks.",
        "priority": 197, "scope": "module", "scope_target": "exposureclaw",
        "condition_json": json.dumps({"field": "subdomain_takeover_risk", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect High-Severity CVEs on Internet Services",
        "description": "EXPOSURECLAW | Internet-facing services running software with CVSS 9.0+ vulnerabilities that have public exploits available are flagged as critical remediation priority.",
        "priority": 198, "scope": "module", "scope_target": "exposureclaw",
        "condition_json": json.dumps({"field": "internet_service_critical_cve", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Require Approval for New Internet Exposure",
        "description": "EXPOSURECLAW | Opening a new port or service to the internet (security group, firewall rule, load balancer listener) requires security team approval and asset registration.",
        "priority": 199, "scope": "module", "scope_target": "exposureclaw",
        "condition_json": json.dumps({"field": "new_internet_exposure_requested", "op": "eq", "value": True}),
        "action": "require_approval",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # COMPLIANCECLAW — GRC / Compliance (new: 204–209)
    # ══════════════════════════════════════════════════════════════════════════
    {
        "name": "Map Findings to Compliance Frameworks",
        "description": "COMPLIANCECLAW | All security findings are automatically mapped to applicable control frameworks (ISO 27001, SOC 2, NIST CSF, HIPAA, PCI DSS) for compliance reporting.",
        "priority": 204, "scope": "module", "scope_target": "complianceclaw",
        "condition_json": json.dumps({"field": "finding_unmapped", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect Missing Access Reviews",
        "description": "COMPLIANCECLAW | Privileged access reviews that are overdue (past their scheduled review date by 7+ days) are flagged. Access reviews are required by SOC 2 CC6.3 and ISO A.9.2.",
        "priority": 205, "scope": "module", "scope_target": "complianceclaw",
        "condition_json": json.dumps({"field": "access_review_overdue_days", "op": "gte", "value": 7}),
        "action": "monitor",
    },
    {
        "name": "Detect Policy Exception Without Expiry",
        "description": "COMPLIANCECLAW | Policy exceptions granted without an expiration date are flagged. All exceptions must have a defined review and expiry date to prevent permanent control bypasses.",
        "priority": 206, "scope": "module", "scope_target": "complianceclaw",
        "condition_json": json.dumps({"field": "exception_no_expiry", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Alert on Compliance Score Drop",
        "description": "COMPLIANCECLAW | A drop of 5+ points in the organization's compliance score for any framework within a single week triggers an alert and review cycle.",
        "priority": 207, "scope": "module", "scope_target": "complianceclaw",
        "condition_json": json.dumps({"field": "compliance_score_drop", "op": "gte", "value": 5}),
        "action": "monitor",
    },
    {
        "name": "Detect Missing Audit Log Coverage",
        "description": "COMPLIANCECLAW | Systems in scope for SOC 2 or ISO 27001 audits that do not have audit logging enabled are flagged as critical compliance gaps.",
        "priority": 208, "scope": "module", "scope_target": "complianceclaw",
        "condition_json": json.dumps({"field": "audit_log_missing_inscope", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Track Remediation Status for Open Findings",
        "description": "COMPLIANCECLAW | Open compliance findings not remediated within their SLA (critical: 7d, high: 30d, medium: 90d) are escalated and reported to the compliance dashboard.",
        "priority": 209, "scope": "module", "scope_target": "complianceclaw",
        "condition_json": json.dumps({"field": "remediation_sla_breached", "op": "eq", "value": True}),
        "action": "monitor",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # PRIVACYCLAW — Privacy / Data Protection (new: 214–219)
    # ══════════════════════════════════════════════════════════════════════════
    {
        "name": "Detect PII in Unencrypted Storage",
        "description": "PRIVACYCLAW | Data stores containing PII (names, emails, SSNs, addresses) that are not encrypted at rest are flagged as GDPR/CCPA violations.",
        "priority": 214, "scope": "module", "scope_target": "privacyclaw",
        "condition_json": json.dumps({"field": "pii_unencrypted", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect Cross-Border Data Transfer Without Safeguards",
        "description": "PRIVACYCLAW | Data transfers to countries without EU adequacy decisions or appropriate safeguards (SCCs, BCRs) are flagged as GDPR Chapter V violations.",
        "priority": 215, "scope": "module", "scope_target": "privacyclaw",
        "condition_json": json.dumps({"field": "cross_border_transfer_unsafe", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Alert on Data Subject Request Overdue",
        "description": "PRIVACYCLAW | GDPR data subject access requests (DSAR) not fulfilled within 25 days (5 days before legal deadline) generate an escalation alert.",
        "priority": 216, "scope": "module", "scope_target": "privacyclaw",
        "condition_json": json.dumps({"field": "dsar_overdue_days", "op": "gte", "value": 25}),
        "action": "monitor",
    },
    {
        "name": "Detect Consent Records Without Audit Trail",
        "description": "PRIVACYCLAW | Marketing or data processing activities where consent was collected but no audit trail (timestamp, version, method) exists are flagged as compliance gaps.",
        "priority": 217, "scope": "module", "scope_target": "privacyclaw",
        "condition_json": json.dumps({"field": "consent_no_audit_trail", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Require Approval for New PII Processing Activity",
        "description": "PRIVACYCLAW | Any new processing activity involving PII must be reviewed by the DPO and added to the Record of Processing Activities (ROPA) before it begins.",
        "priority": 218, "scope": "module", "scope_target": "privacyclaw",
        "condition_json": json.dumps({"field": "new_pii_processing", "op": "eq", "value": True}),
        "action": "require_approval",
    },
    {
        "name": "Alert on Data Breach Indicators",
        "description": "PRIVACYCLAW | Events matching data breach patterns (mass export + external destination + off-hours + new location) trigger a 72-hour GDPR notification timer alert.",
        "priority": 219, "scope": "module", "scope_target": "privacyclaw",
        "condition_json": json.dumps({"field": "breach_indicator_score", "op": "gte", "value": 80}),
        "action": "monitor",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # VENDORCLAW — Third-Party Risk (new: 224–229)
    # ══════════════════════════════════════════════════════════════════════════
    {
        "name": "Alert on Vendor Security Score Drop",
        "description": "VENDORCLAW | Vendors whose BitSight or SecurityScorecard rating drops by 10+ points in a week are flagged. Rating drops often precede or follow security incidents.",
        "priority": 224, "scope": "module", "scope_target": "vendorclaw",
        "condition_json": json.dumps({"field": "vendor_score_drop", "op": "gte", "value": 10}),
        "action": "monitor",
    },
    {
        "name": "Detect Vendor with Access Beyond Contract Scope",
        "description": "VENDORCLAW | Third-party vendors or contractors accessing systems, data, or environments not covered in their contract scope are flagged for immediate access review.",
        "priority": 225, "scope": "module", "scope_target": "vendorclaw",
        "condition_json": json.dumps({"field": "vendor_access_out_of_scope", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect Vendor Breach Disclosure",
        "description": "VENDORCLAW | When a vendor discloses a breach or is named in public breach databases, all active vendor connections and data flows are flagged for immediate impact assessment.",
        "priority": 226, "scope": "module", "scope_target": "vendorclaw",
        "condition_json": json.dumps({"field": "vendor_breach_disclosed", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect Overdue Vendor Security Assessments",
        "description": "VENDORCLAW | Critical vendors whose annual security assessment is overdue by 30+ days are flagged. Unassessed vendors should have their access reviewed pending re-assessment.",
        "priority": 227, "scope": "module", "scope_target": "vendorclaw",
        "condition_json": json.dumps({"field": "vendor_assessment_overdue_days", "op": "gte", "value": 30}),
        "action": "monitor",
    },
    {
        "name": "Require Approval for New Critical Vendor Onboarding",
        "description": "VENDORCLAW | Onboarding a new vendor classified as critical (access to PII, financial data, or production systems) requires CISO approval and security questionnaire completion.",
        "priority": 228, "scope": "module", "scope_target": "vendorclaw",
        "condition_json": json.dumps({"field": "critical_vendor_onboarding", "op": "eq", "value": True}),
        "action": "require_approval",
    },
    {
        "name": "Alert on Vendor MFA Not Enforced",
        "description": "VENDORCLAW | Third-party vendor accounts accessing corporate systems that do not have MFA enforced are flagged. Vendor accounts without MFA are a top supply chain attack vector.",
        "priority": 229, "scope": "module", "scope_target": "vendorclaw",
        "condition_json": json.dumps({"field": "vendor_mfa_missing", "op": "eq", "value": True}),
        "action": "monitor",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # DEVCLAW — DevSecOps (new: 234–239)
    # ══════════════════════════════════════════════════════════════════════════
    {
        "name": "Detect Secrets in Code Repositories",
        "description": "DEVCLAW | API keys, passwords, private keys, and connection strings committed to source code repositories (GitHub, GitLab, Azure DevOps) are flagged and the commit is blocked.",
        "priority": 234, "scope": "module", "scope_target": "devclaw",
        "condition_json": json.dumps({"field": "secret_in_repo_commit", "op": "eq", "value": True}),
        "action": "deny",
    },
    {
        "name": "Detect Public Repositories With Sensitive Code",
        "description": "DEVCLAW | Private repositories that have been made public, or repositories containing internal API endpoints, internal IP references, or customer data patterns are flagged.",
        "priority": 235, "scope": "module", "scope_target": "devclaw",
        "condition_json": json.dumps({"field": "public_repo_sensitive_content", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect Unprotected Default Branches",
        "description": "DEVCLAW | Repositories where the main/master branch has no branch protection rules (no required reviews, no status checks) are flagged. Unprotected branches allow direct pushes.",
        "priority": 236, "scope": "module", "scope_target": "devclaw",
        "condition_json": json.dumps({"field": "branch_protection_missing", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Block Deployment if Critical Security Gate Fails",
        "description": "DEVCLAW | CI/CD pipelines where the security scan (SAST, SCA, container scan) has failed with critical findings are blocked from deploying to production.",
        "priority": 237, "scope": "module", "scope_target": "devclaw",
        "condition_json": json.dumps({"field": "security_gate_critical_fail", "op": "eq", "value": True}),
        "action": "deny",
    },
    {
        "name": "Detect Overly Permissive CI/CD Pipeline Permissions",
        "description": "DEVCLAW | GitHub Actions workflows or Azure Pipelines with write permissions to all repos, or self-hosted runners with broad network access, are flagged for scope reduction.",
        "priority": 238, "scope": "module", "scope_target": "devclaw",
        "condition_json": json.dumps({"field": "pipeline_permissions_excessive", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect Vulnerable Container Base Images",
        "description": "DEVCLAW | Container images built on base images with CVSS 9.0+ vulnerabilities that are deployed to production registries are flagged for immediate rebuild.",
        "priority": 239, "scope": "module", "scope_target": "devclaw",
        "condition_json": json.dumps({"field": "container_base_critical_cve", "op": "eq", "value": True}),
        "action": "monitor",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # CONFIGCLAW — Hardening / Configuration (new: 244–249)
    # ══════════════════════════════════════════════════════════════════════════
    {
        "name": "Detect Baseline Configuration Drift",
        "description": "CONFIGCLAW | Servers, endpoints, or cloud resources whose configuration has drifted from the approved CIS benchmark or organizational hardening baseline are flagged.",
        "priority": 244, "scope": "module", "scope_target": "configclaw",
        "condition_json": json.dumps({"field": "config_drift_detected", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect Missing Security Patches",
        "description": "CONFIGCLAW | Systems missing critical or high-severity security patches (CVSS ≥7.0) that have been available for 30+ days are flagged. Patch SLA breaches are compliance violations.",
        "priority": 245, "scope": "module", "scope_target": "configclaw",
        "condition_json": json.dumps({"field": "critical_patch_overdue_days", "op": "gte", "value": 30}),
        "action": "monitor",
    },
    {
        "name": "Detect Default Credentials in Use",
        "description": "CONFIGCLAW | Network devices, servers, or applications responding to default vendor credentials (admin/admin, admin/password) are flagged as critical misconfigurations.",
        "priority": 246, "scope": "module", "scope_target": "configclaw",
        "condition_json": json.dumps({"field": "default_credentials_active", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Detect Insecure TLS Versions",
        "description": "CONFIGCLAW | Services accepting TLS 1.0 or TLS 1.1 connections are flagged. TLS 1.0/1.1 are deprecated and vulnerable to POODLE, BEAST, and CRIME attacks.",
        "priority": 247, "scope": "module", "scope_target": "configclaw",
        "condition_json": json.dumps({"field": "tls_version_insecure", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Require Approval for Hardening Exception",
        "description": "CONFIGCLAW | Requests to exempt a system from a hardening requirement (CIS benchmark control, organizational policy) require CISO approval and a documented compensating control.",
        "priority": 248, "scope": "module", "scope_target": "configclaw",
        "condition_json": json.dumps({"field": "hardening_exception_requested", "op": "eq", "value": True}),
        "action": "require_approval",
    },
    {
        "name": "Alert on Unauthorized Configuration Change",
        "description": "CONFIGCLAW | Configuration changes to production systems that were not submitted through the change management process (no approved change ticket) are flagged as unauthorized.",
        "priority": 249, "scope": "module", "scope_target": "configclaw",
        "condition_json": json.dumps({"field": "config_change_no_ticket", "op": "eq", "value": True}),
        "action": "monitor",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # RECOVERYCLAW — Resilience / Recovery (new: 254–259)
    # ══════════════════════════════════════════════════════════════════════════
    {
        "name": "Detect Missing Backup Coverage",
        "description": "RECOVERYCLAW | Systems classified as critical or high business impact that have not had a successful backup in 24+ hours are flagged. Backup failure + ransomware = unrecoverable.",
        "priority": 254, "scope": "module", "scope_target": "recoveryclaw",
        "condition_json": json.dumps({"field": "backup_missing_hours", "op": "gte", "value": 24}),
        "action": "monitor",
    },
    {
        "name": "Detect Backup Stored in Same Region as Primary",
        "description": "RECOVERYCLAW | Backups stored in the same geographic region as the primary system do not meet DR requirements. A regional outage or disaster would destroy both copies.",
        "priority": 255, "scope": "module", "scope_target": "recoveryclaw",
        "condition_json": json.dumps({"field": "backup_same_region", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Alert on Recovery Test Overdue",
        "description": "RECOVERYCLAW | Disaster recovery tests for critical systems overdue by 30+ days are flagged. Untested recovery procedures fail when they are needed most.",
        "priority": 256, "scope": "module", "scope_target": "recoveryclaw",
        "condition_json": json.dumps({"field": "dr_test_overdue_days", "op": "gte", "value": 30}),
        "action": "monitor",
    },
    {
        "name": "Detect Backup Integrity Failure",
        "description": "RECOVERYCLAW | Backups that fail their integrity check (checksum mismatch, restore test failure, corruption detected) are flagged and the backup system is alerted for immediate re-run.",
        "priority": 257, "scope": "module", "scope_target": "recoveryclaw",
        "condition_json": json.dumps({"field": "backup_integrity_failed", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Require Approval for Recovery Environment Access",
        "description": "RECOVERYCLAW | Access to recovery environments (DR sites, backup systems, recovery vaults) requires dual approval. Recovery environments contain sensitive full-system backups.",
        "priority": 258, "scope": "module", "scope_target": "recoveryclaw",
        "condition_json": json.dumps({"field": "recovery_env_access_requested", "op": "eq", "value": True}),
        "action": "require_approval",
    },
    {
        "name": "Detect RTO/RPO Violation Risk",
        "description": "RECOVERYCLAW | When current backup age + estimated restore time exceeds the system's defined RTO/RPO targets, a pre-emptive alert is raised before an actual disaster occurs.",
        "priority": 259, "scope": "module", "scope_target": "recoveryclaw",
        "condition_json": json.dumps({"field": "rto_rpo_at_risk", "op": "eq", "value": True}),
        "action": "monitor",
    },
]


async def seed(reset: bool = False) -> None:
    async with AsyncSessionLocal() as db:
        if reset:
            print("🗑  Deleting ALL policies and re-seeding from scratch…")
            from sqlalchemy import delete
            await db.execute(delete(Policy))
            await db.commit()
            print("   Done.\n")
            # After reset, also run the original seed
            import subprocess, sys
            print("▶  Running original seed_policies.py --reset first…")
            subprocess.run([sys.executable, "seed_policies.py", "--reset"])
            print()

        # Get existing names to skip duplicates
        from sqlalchemy import select
        result = await db.execute(select(Policy.name))
        existing = {row[0] for row in result.fetchall()}

        by_layer: dict = {}
        added = 0

        for spec in EXPANDED_POLICIES:
            if spec["name"] in existing:
                print(f"  ↩  Skip (exists): {spec['name']}")
                continue

            layer = spec["description"].split("|")[0].strip()
            policy = Policy(
                name=spec["name"],
                description=spec["description"],
                priority=spec["priority"],
                scope=PolicyScope(spec.get("scope", "global")),
                scope_target=spec.get("scope_target"),
                condition_json=spec.get("condition_json", "{}"),
                action=PolicyAction(spec["action"]),
                is_active=True,
            )
            db.add(policy)
            by_layer.setdefault(layer, 0)
            by_layer[layer] += 1
            added += 1

        await db.commit()

        print("\n📋  Expanded policy summary:")
        for layer, count in sorted(by_layer.items()):
            print(f"   {layer:<20} +{count}")
        print(f"\n✅  Added {added} new policies.")


if __name__ == "__main__":
    reset = "--reset" in sys.argv
    asyncio.run(seed(reset=reset))
