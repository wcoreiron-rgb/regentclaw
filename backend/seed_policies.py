"""
RegentClaw — Policy Seed Script
=================================
Run this once after docker compose up to load all default policies.

Usage:
  docker compose exec backend python seed_policies.py
  docker compose exec backend python seed_policies.py --reset

Policy priority scheme:
  Trust Fabric   1–18   → Platform-wide enforcement (highest)
  CoreOS        20–26   → Platform governance
  ArcClaw       30–36   → AI Security
  IdentityClaw  40–46   → Identity Risk
  CloudClaw     50–53   → Cloud Security
  AccessClaw    60–63   → Access / PAM
  EndpointClaw  70–73   → Endpoint Security
  NetClaw       80–83   → Network Security
  DataClaw      90–93   → Data Security
  AppClaw      100–103  → Application / API Security
  SaaSClaw     110–113  → SaaS Security
  ThreatClaw   120–123  → Detection & Response
  LogClaw      130–133  → SIEM / Observability
  IntelClaw    140–143  → Threat Intelligence
  UserClaw     150–153  → User Behavior Analytics
  InsiderClaw  160–163  → Insider Risk
  AutomationClaw 170–173 → SOAR
  AttackPathClaw 180–183 → Attack Path Analysis
  ExposureClaw 190–193  → External Attack Surface
  ComplianceClaw 200–203 → Compliance
  PrivacyClaw  210–213  → Privacy
  VendorClaw   220–223  → Third-Party Risk
  DevClaw      230–233  → DevSecOps
  ConfigClaw   240–243  → Hardening / Configuration
  RecoveryClaw 250–253  → Resilience / Recovery
"""

import asyncio
import json
import sys
from app.core.database import AsyncSessionLocal
from app.models.policy import Policy, PolicyAction, PolicyScope


POLICIES = [

    # ══════════════════════════════════════════════════════════════════════════
    # TRUST FABRIC — Platform-wide enforcement (priority 1–18)
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name": "Block Shell Execution",
        "description": (
            "TRUST FABRIC | Denies any action that attempts shell/terminal execution. "
            "No module or agent may run bash, sh, powershell, or exec commands. "
            "This is the #1 attack vector in agentic systems (per 1Password research)."
        ),
        "priority": 1, "scope": "global",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "shell"}),
        "action": "deny",
    },
    {
        "name": "Block Credential Access",
        "description": (
            "TRUST FABRIC | Denies any action targeting credential stores, secrets, "
            "API keys, passwords, or tokens. Applies to all modules. "
            "Agents must use the secrets broker — never direct access."
        ),
        "priority": 2, "scope": "global",
        "condition_json": json.dumps({"field": "target", "op": "contains", "value": "credential"}),
        "action": "deny",
    },
    {
        "name": "Block Secret Access",
        "description": (
            "TRUST FABRIC | Companion to credential block — also catches 'secret' "
            "as a target keyword. Covers env vars, vaults, and secret stores."
        ),
        "priority": 3, "scope": "global",
        "condition_json": json.dumps({"field": "target", "op": "contains", "value": "secret"}),
        "action": "deny",
    },
    {
        "name": "Block Code Execution",
        "description": (
            "TRUST FABRIC | Denies execute_code actions from any actor. "
            "Prevents remote code execution (RCE) — OWASP Agentic Top 10 (ASI-04). "
            "No module may execute arbitrary code without explicit sandboxed approval."
        ),
        "priority": 4, "scope": "global",
        "condition_json": json.dumps({"field": "action", "op": "eq", "value": "execute_code"}),
        "action": "deny",
    },
    {
        "name": "Require Approval for Delete Actions",
        "description": (
            "TRUST FABRIC | Any delete/drop/wipe/purge action requires admin approval "
            "before execution. Prevents accidental or malicious data destruction. "
            "Affects all modules — databases, files, user records, config."
        ),
        "priority": 5, "scope": "global",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "delete"}),
        "action": "require_approval",
    },
    {
        "name": "Require Approval for Bulk Export",
        "description": (
            "TRUST FABRIC | Bulk data export or mass download requires admin approval. "
            "This is the most common exfiltration pattern — large data moves should "
            "never be automatic. Applies across all modules."
        ),
        "priority": 6, "scope": "global",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "export_bulk"}),
        "action": "require_approval",
    },
    {
        "name": "Block Data Exfiltration to External Destinations",
        "description": (
            "TRUST FABRIC | Blocks any action that moves data to an external email address, "
            "FTP server, or unauthorized external endpoint. Exfiltration is OWASP Agentic "
            "Top 10 (ASI-06: Unintended Data Exposure). No agent may send data outside the "
            "trust boundary without explicit approval."
        ),
        "priority": 7, "scope": "global",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "email_external"}),
        "action": "deny",
    },
    {
        "name": "Block FTP and Unauthorized Uploads",
        "description": (
            "TRUST FABRIC | Blocks FTP uploads and any action classified as an unauthorized "
            "file transfer to an external host. Companion to the email exfiltration block — "
            "covers the full spectrum of data-out attack vectors."
        ),
        "priority": 8, "scope": "global",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "ftp_upload"}),
        "action": "deny",
    },
    {
        "name": "Block Lateral Movement — Network Scanning",
        "description": (
            "TRUST FABRIC | Denies network scanning, port probing, and host enumeration actions. "
            "Lateral movement via network discovery is OWASP Agentic Top 10 (ASI-07: Lateral "
            "Movement). No agent or module may enumerate internal network topology."
        ),
        "priority": 9, "scope": "global",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "network_scan"}),
        "action": "deny",
    },
    {
        "name": "Block Port Probing",
        "description": (
            "TRUST FABRIC | Companion to network scan block — catches port probe and host "
            "discovery actions specifically. Prevents agents from mapping internal services "
            "as a precursor to lateral movement or privilege escalation."
        ),
        "priority": 10, "scope": "global",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "port_probe"}),
        "action": "deny",
    },
    {
        "name": "Require Approval for Privilege Escalation",
        "description": (
            "TRUST FABRIC | Any action containing 'escalate' requires admin approval before "
            "execution. Privilege escalation is OWASP Agentic Top 10 (ASI-03). Applies "
            "platform-wide — no module may self-escalate or escalate another identity silently."
        ),
        "priority": 11, "scope": "global",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "escalate"}),
        "action": "require_approval",
    },
    {
        "name": "Block Unauthorized External API Calls",
        "description": (
            "TRUST FABRIC | Blocks any action targeting an external_endpoint that has not been "
            "registered and approved in the CoreOS Connector Registry. Prevents agents from "
            "calling arbitrary external services — a key supply chain attack vector (ASI-09)."
        ),
        "priority": 12, "scope": "global",
        "condition_json": json.dumps({"field": "target", "op": "contains", "value": "external_endpoint"}),
        "action": "deny",
    },
    {
        "name": "Monitor All Agent Write Operations",
        "description": (
            "TRUST FABRIC | Every write action from an agent-type actor is logged and risk-scored. "
            "Agents should operate read-mostly; writes indicate state changes that need full "
            "audit coverage. Feeds the anomaly detector for volume and timing analysis."
        ),
        "priority": 13, "scope": "global",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "write"}),
        "action": "monitor",
    },
    {
        "name": "Block Configuration Tampering",
        "description": (
            "TRUST FABRIC | Blocks write actions targeting configuration resources. Config "
            "tampering can silently disable security controls, redirect traffic, or escalate "
            "permissions. No agent or module may modify system configuration without approval."
        ),
        "priority": 14, "scope": "global",
        "condition_json": json.dumps({"field": "target", "op": "contains", "value": "config"}),
        "action": "deny",
    },
    {
        "name": "Block Database Drop and Truncate",
        "description": (
            "TRUST FABRIC | Catches drop_table, truncate, and wipe actions that are not covered "
            "by the generic delete block. Destructive database operations are irreversible — "
            "this is a hard block, not an approval gate."
        ),
        "priority": 15, "scope": "global",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "drop_table"}),
        "action": "deny",
    },
    {
        "name": "Isolate Actors Exceeding Risk Threshold",
        "description": (
            "TRUST FABRIC | Any actor whose risk score reaches or exceeds 90 is automatically "
            "isolated — all further actions are denied until a human reviews and releases them. "
            "This is the automated containment / blast radius control mechanism."
        ),
        "priority": 16, "scope": "global",
        "condition_json": json.dumps({"field": "risk_score", "op": "gte", "value": 90}),
        "action": "isolate",
    },
    {
        "name": "Require Approval for Token and Key Rotation",
        "description": (
            "TRUST FABRIC | Rotating API keys, signing tokens, or auth secrets requires admin "
            "approval. Unauthorized rotation can lock out legitimate users or silently hand "
            "control to a compromised agent. Applies to all modules."
        ),
        "priority": 17, "scope": "global",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "rotate_key"}),
        "action": "require_approval",
    },
    {
        "name": "Block Audit Log Tampering",
        "description": (
            "TRUST FABRIC | No actor may write to, delete from, or truncate the audit log. "
            "Audit integrity is the foundation of accountability — if an agent can erase its "
            "own trail, all other controls are weakened. This policy cannot be overridden."
        ),
        "priority": 18, "scope": "global",
        "condition_json": json.dumps({"field": "target", "op": "contains", "value": "audit_log"}),
        "action": "deny",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # COREOS — Platform Governance (priority 20–26)
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name": "Block Unowned Agent Actions",
        "description": (
            "COREOS | Agents with no assigned owner (orphaned) are blocked from taking actions. "
            "Every agent must have a human owner in the Identity Registry. "
            "This enforces the Zero Trust principle: every identity has an owner."
        ),
        "priority": 20, "scope": "global",
        "condition_json": json.dumps({"field": "actor_type", "op": "eq", "value": "agent"}),
        "action": "monitor",
    },
    {
        "name": "Flag New Connector Usage",
        "description": (
            "COREOS | Monitor all actions from connector-type actors. "
            "Connectors must be registered, approved, and scoped before use. "
            "Any connector action is logged and scored for anomalies."
        ),
        "priority": 21, "scope": "global",
        "condition_json": json.dumps({"field": "actor_type", "op": "eq", "value": "connector"}),
        "action": "monitor",
    },
    {
        "name": "Require Approval for Privileged Identity Changes",
        "description": (
            "COREOS | Changing roles, permissions, or privilege levels on any identity "
            "requires admin approval. Prevents privilege escalation — "
            "OWASP Agentic Top 10 (ASI-03: Identity & Privilege Abuse)."
        ),
        "priority": 22, "scope": "module", "scope_target": "coreos",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "privilege"}),
        "action": "require_approval",
    },
    {
        "name": "Block Unregistered Module Activation",
        "description": (
            "COREOS | Any module or Claw that has not been registered in CoreOS's module "
            "inventory is blocked from executing actions. Every component must declare its "
            "identity, owner, and scope before it can participate in the platform."
        ),
        "priority": 23, "scope": "module", "scope_target": "coreos",
        "condition_json": json.dumps({"field": "actor_type", "op": "eq", "value": "unregistered"}),
        "action": "deny",
    },
    {
        "name": "Require Approval for Connector Scope Expansion",
        "description": (
            "COREOS | When a connector attempts to act on a target outside its declared scope, "
            "the action is paused for admin approval. Connectors must operate within their "
            "approved boundaries — scope creep is a silent privilege escalation."
        ),
        "priority": 24, "scope": "module", "scope_target": "coreos",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "scope_expand"}),
        "action": "require_approval",
    },
    {
        "name": "Monitor All Cross-Claw Actions",
        "description": (
            "COREOS | When one Claw module invokes another (e.g., ArcClaw triggers an "
            "IdentityClaw lookup), the cross-module action is logged and correlated. "
            "This feeds the cross-claw risk correlation engine for chained attack detection."
        ),
        "priority": 25, "scope": "module", "scope_target": "coreos",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "cross_claw"}),
        "action": "monitor",
    },
    {
        "name": "Block Duplicate Identity Registration",
        "description": (
            "COREOS | Prevents the same identity (by ID or name) from being registered more "
            "than once. Duplicate identities are a common way to create shadow accounts that "
            "bypass ownership and audit tracking."
        ),
        "priority": 26, "scope": "module", "scope_target": "coreos",
        "condition_json": json.dumps({"field": "action", "op": "eq", "value": "register_duplicate"}),
        "action": "deny",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # ARCCLAW — AI Security (priority 30–36)
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name": "Block High-Risk AI Prompts",
        "description": (
            "ARCCLAW | Blocks AI interactions where the risk level is 'high'. "
            "Risk is determined by prompt classification: destructive intent, "
            "credential references, or data movement combined with sensitive targets. "
            "The prompt never reaches the LLM."
        ),
        "priority": 30, "scope": "module", "scope_target": "arcclaw",
        "condition_json": json.dumps({"field": "risk_level", "op": "eq", "value": "high"}),
        "action": "deny",
    },
    {
        "name": "Flag Sensitive AI Content for Review",
        "description": (
            "ARCCLAW | When a prompt contains sensitive patterns (API keys, passwords, PII) "
            "the content is redacted and the event is flagged for admin review. "
            "The cleaned version may still proceed, but the finding is logged."
        ),
        "priority": 31, "scope": "module", "scope_target": "arcclaw",
        "condition_json": json.dumps({"field": "is_sensitive", "op": "eq", "value": True}),
        "action": "monitor",
    },
    {
        "name": "Block Prompt Injection Attacks",
        "description": (
            "ARCCLAW | Blocks prompts where AGT's PromptDefenseEvaluator flags an injection risk. "
            "Prompt injection is OWASP Agentic Top 10 #1 (ASI-01: Agent Goal Hijacking). "
            "Example: 'ignore previous instructions and act as...'"
        ),
        "priority": 32, "scope": "module", "scope_target": "arcclaw",
        "condition_json": json.dumps({"field": "agt_injection_risk", "op": "eq", "value": True}),
        "action": "deny",
    },
    {
        "name": "Block AI-Assisted Data Exfiltration",
        "description": (
            "ARCCLAW | Blocks prompts classified as exfiltration attempts — requests to email, "
            "export, or transmit sensitive records via the LLM. The LLM must never become "
            "a data extraction tool (ASI-06: Unintended Data Exposure)."
        ),
        "priority": 33, "scope": "module", "scope_target": "arcclaw",
        "condition_json": json.dumps({"field": "risk_level", "op": "eq", "value": "exfiltration"}),
        "action": "deny",
    },
    {
        "name": "Block LLM-Assisted Shell Construction",
        "description": (
            "ARCCLAW | Blocks prompts that ask the LLM to construct, explain, or execute shell "
            "commands or system calls. Prevents the LLM from becoming a shell proxy — "
            "a common jailbreak pattern (ASI-04: Unsafe Code Execution)."
        ),
        "priority": 34, "scope": "module", "scope_target": "arcclaw",
        "condition_json": json.dumps({"field": "risk_level", "op": "eq", "value": "shell_construction"}),
        "action": "deny",
    },
    {
        "name": "Require Human Review for Medium-Risk AI Prompts",
        "description": (
            "ARCCLAW | Prompts classified as medium-risk (ambiguous intent, moderate sensitivity) "
            "are flagged and logged for human review. The LLM may respond, but the event is "
            "queued in the approval dashboard for post-hoc audit."
        ),
        "priority": 35, "scope": "module", "scope_target": "arcclaw",
        "condition_json": json.dumps({"field": "risk_level", "op": "eq", "value": "medium"}),
        "action": "monitor",
    },
    {
        "name": "Block LLM Response Containing Secrets",
        "description": (
            "ARCCLAW | If the LLM response contains patterns matching API keys, passwords, "
            "or tokens (sometimes leaked via training data), the response is blocked before "
            "reaching the user. Prevents accidental secret disclosure via model output."
        ),
        "priority": 36, "scope": "module", "scope_target": "arcclaw",
        "condition_json": json.dumps({"field": "response_is_sensitive", "op": "eq", "value": True}),
        "action": "deny",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # IDENTITYCLAW — Identity Risk (priority 40–46)
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name": "Alert on High Identity Risk Score",
        "description": (
            "IDENTITYCLAW | Monitors all actions from identities with a risk score ≥ 50. "
            "High-risk identities include: orphaned agents, accounts with recent anomalies, "
            "or accounts that have triggered multiple blocked actions."
        ),
        "priority": 40, "scope": "module", "scope_target": "identityclaw",
        "condition_json": json.dumps({"field": "risk_score", "op": "gte", "value": 50}),
        "action": "monitor",
    },
    {
        "name": "Require Approval for Service Account Actions",
        "description": (
            "IDENTITYCLAW | Service accounts and automated service identities must "
            "have their actions approved for sensitive operations. Service identities "
            "are non-human — they should operate within narrow, predefined boundaries."
        ),
        "priority": 41, "scope": "module", "scope_target": "identityclaw",
        "condition_json": json.dumps({"field": "actor_type", "op": "eq", "value": "service"}),
        "action": "monitor",
    },
    {
        "name": "Block Orphaned Identity Actions",
        "description": (
            "IDENTITYCLAW | An identity with no active owner is blocked from all actions "
            "until ownership is re-assigned. Orphaned accounts are the #1 source of ghost "
            "access in enterprise environments."
        ),
        "priority": 42, "scope": "module", "scope_target": "identityclaw",
        "condition_json": json.dumps({"field": "action", "op": "eq", "value": "orphaned_actor"}),
        "action": "deny",
    },
    {
        "name": "Isolate Identity on Critical Risk Score",
        "description": (
            "IDENTITYCLAW | An identity whose risk score reaches 80 or above is automatically "
            "isolated — further actions are blocked and the identity is quarantined pending "
            "human review. This is the blast radius limiter for compromised identities."
        ),
        "priority": 43, "scope": "module", "scope_target": "identityclaw",
        "condition_json": json.dumps({"field": "risk_score", "op": "gte", "value": 80}),
        "action": "isolate",
    },
    {
        "name": "Monitor Non-Human Identity Logins",
        "description": (
            "IDENTITYCLAW | Any login or authentication event from a non-human identity "
            "(agent, service, connector) is logged with full context. Non-human auth events "
            "that occur outside business hours are escalated automatically for review."
        ),
        "priority": 44, "scope": "module", "scope_target": "identityclaw",
        "condition_json": json.dumps({"field": "action", "op": "eq", "value": "authenticate"}),
        "action": "monitor",
    },
    {
        "name": "Require Approval for Identity Deactivation",
        "description": (
            "IDENTITYCLAW | Deactivating or offboarding any identity requires admin approval. "
            "Silently deactivating an identity — especially an agent with active workflows — "
            "can break running processes or be used to cover tracks after an incident."
        ),
        "priority": 45, "scope": "module", "scope_target": "identityclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "deactivate"}),
        "action": "require_approval",
    },
    {
        "name": "Flag Repeated Authentication Failures",
        "description": (
            "IDENTITYCLAW | Three or more authentication failures from the same identity within "
            "a rolling 15-minute window triggers a monitor event and risk score increase. "
            "Brute force and credential stuffing are caught here before escalation."
        ),
        "priority": 46, "scope": "module", "scope_target": "identityclaw",
        "condition_json": json.dumps({"field": "action", "op": "eq", "value": "auth_failure_repeated"}),
        "action": "monitor",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # CLOUDCLAW — Cloud Security (priority 50–53)
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name": "Block Access to Untagged Cloud Resources",
        "description": (
            "CLOUDCLAW | Blocks access to cloud resources (VMs, buckets, databases) that lack "
            "required governance tags (owner, environment, data-classification). Untagged resources "
            "bypass cost tracking, compliance scoping, and access controls — they must be tagged "
            "before any agent or service can interact with them."
        ),
        "priority": 50, "scope": "module", "scope_target": "cloudclaw",
        "condition_json": json.dumps({"field": "target", "op": "contains", "value": "untagged_resource"}),
        "action": "deny",
    },
    {
        "name": "Alert on Public Cloud Storage Bucket",
        "description": (
            "CLOUDCLAW | Detects when a storage bucket (S3, Azure Blob, GCS) is configured for "
            "public access. Public buckets are one of the most common causes of enterprise data "
            "breaches. CloudClaw flags these immediately for remediation review."
        ),
        "priority": 51, "scope": "module", "scope_target": "cloudclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "public_bucket"}),
        "action": "monitor",
    },
    {
        "name": "Require Approval for Cross-Region Data Transfer",
        "description": (
            "CLOUDCLAW | Moving data across cloud regions — especially from production to "
            "non-production regions — requires admin approval. Cross-region transfers can "
            "violate data sovereignty laws (GDPR, CCPA) and bypass regional security controls."
        ),
        "priority": 52, "scope": "module", "scope_target": "cloudclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "cross_region_transfer"}),
        "action": "require_approval",
    },
    {
        "name": "Block Root / Owner Account Direct Usage",
        "description": (
            "CLOUDCLAW | Blocks direct usage of cloud root or owner-level accounts for "
            "operational tasks. Root accounts must be reserved for emergency break-glass "
            "scenarios only. All usage is logged and triggers an immediate security alert."
        ),
        "priority": 53, "scope": "module", "scope_target": "cloudclaw",
        "condition_json": json.dumps({"field": "actor_id", "op": "contains", "value": "root"}),
        "action": "deny",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # ACCESSCLAW — Privileged Access Management (priority 60–63)
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name": "Require Session Recording for Privileged Access",
        "description": (
            "ACCESSCLAW | Any privileged session (admin, root, break-glass) must have session "
            "recording enabled before it can proceed. Session recordings are stored in the "
            "immutable audit log and linked to the initiating identity's risk profile."
        ),
        "priority": 60, "scope": "module", "scope_target": "accessclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "privileged_session"}),
        "action": "require_approval",
    },
    {
        "name": "Block Persistent Privileged Access — Enforce JIT",
        "description": (
            "ACCESSCLAW | Standing privileged access (always-on admin roles) is blocked. "
            "Privileged access must be Just-In-Time (JIT) — time-boxed, approved, and "
            "auto-expired. Persistent elevated access is the #1 lateral movement enabler."
        ),
        "priority": 61, "scope": "module", "scope_target": "accessclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "standing_privilege"}),
        "action": "deny",
    },
    {
        "name": "Flag Shared Account Usage",
        "description": (
            "ACCESSCLAW | Detects and flags usage of shared or generic accounts (admin, sa, "
            "svc_shared). Shared accounts destroy accountability — every action must be "
            "traceable to a named individual or registered service identity."
        ),
        "priority": 62, "scope": "module", "scope_target": "accessclaw",
        "condition_json": json.dumps({"field": "actor_id", "op": "contains", "value": "shared"}),
        "action": "monitor",
    },
    {
        "name": "Block Credential Sharing Between Identities",
        "description": (
            "ACCESSCLAW | Detects patterns where a single credential is used by multiple "
            "distinct source IPs or user agents simultaneously. Credential sharing is a "
            "policy violation and a strong indicator of account compromise."
        ),
        "priority": 63, "scope": "module", "scope_target": "accessclaw",
        "condition_json": json.dumps({"field": "action", "op": "eq", "value": "credential_sharing"}),
        "action": "deny",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # ENDPOINTCLAW — Endpoint Security (priority 70–73)
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name": "Block Access from Unmanaged Devices",
        "description": (
            "ENDPOINTCLAW | Blocks resource access from devices that are not registered in "
            "the endpoint management platform (Intune, Jamf, CrowdStrike). Unmanaged devices "
            "cannot be verified for patch level, encryption, or EDR coverage."
        ),
        "priority": 70, "scope": "module", "scope_target": "endpointclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "unmanaged_device"}),
        "action": "deny",
    },
    {
        "name": "Isolate End-of-Life Operating System Endpoints",
        "description": (
            "ENDPOINTCLAW | Endpoints running EOL operating systems (Windows 7, Server 2008, "
            "macOS 12 and below) are automatically isolated from sensitive network segments. "
            "EOL systems cannot receive security patches — they are a persistent risk."
        ),
        "priority": 71, "scope": "module", "scope_target": "endpointclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "eol_os"}),
        "action": "isolate",
    },
    {
        "name": "Flag Endpoints Missing EDR Agent",
        "description": (
            "ENDPOINTCLAW | Endpoints that are active on the network but have no EDR agent "
            "reporting (CrowdStrike Falcon, Defender for Endpoint) are flagged for immediate "
            "remediation. No-EDR endpoints are invisible to detection controls."
        ),
        "priority": 72, "scope": "module", "scope_target": "endpointclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "no_edr_agent"}),
        "action": "monitor",
    },
    {
        "name": "Block Removable Media Data Transfer",
        "description": (
            "ENDPOINTCLAW | Blocks write operations to removable media (USB drives, external "
            "HDDs, SD cards). Removable media is the most common physical exfiltration vector, "
            "especially for insider threat scenarios. Read access may be permitted per policy."
        ),
        "priority": 73, "scope": "module", "scope_target": "endpointclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "removable_media_write"}),
        "action": "deny",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # NETCLAW — Network Security (priority 80–83)
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name": "Block East-West Lateral Scanning",
        "description": (
            "NETCLAW | Blocks internal east-west network scanning and host enumeration. "
            "Lateral scanning is the first stage of an internal attacker mapping your network "
            "after initial compromise. Detected scanning triggers immediate isolation review."
        ),
        "priority": 80, "scope": "module", "scope_target": "netclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "east_west_scan"}),
        "action": "deny",
    },
    {
        "name": "Alert on DNS Tunneling Patterns",
        "description": (
            "NETCLAW | Detects anomalous DNS query patterns that indicate DNS tunneling — "
            "a technique used to exfiltrate data or establish C2 channels through DNS. "
            "High-frequency queries to random subdomains or oversized TXT records are flagged."
        ),
        "priority": 81, "scope": "module", "scope_target": "netclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "dns_tunnel"}),
        "action": "monitor",
    },
    {
        "name": "Flag Unauthorized VPN Split Tunneling",
        "description": (
            "NETCLAW | Detects and flags VPN configurations that allow split tunneling without "
            "explicit approval. Split tunneling routes some traffic outside the monitored VPN "
            "path — creating a blind spot for network security controls."
        ),
        "priority": 82, "scope": "module", "scope_target": "netclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "split_tunnel"}),
        "action": "monitor",
    },
    {
        "name": "Block Connections to Tor and Anonymizer Networks",
        "description": (
            "NETCLAW | Blocks outbound connections to known Tor exit nodes, anonymizer proxies, "
            "and VPN-over-VPN services. These channels are used to obscure exfiltration paths "
            "and C2 communication. No legitimate business traffic requires Tor."
        ),
        "priority": 83, "scope": "module", "scope_target": "netclaw",
        "condition_json": json.dumps({"field": "target", "op": "contains", "value": "tor_exit_node"}),
        "action": "deny",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # DATACLAW — Data Security (priority 90–93)
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name": "Block Transfer of Unclassified Sensitive Data",
        "description": (
            "DATACLAW | Blocks data transfers where the source data has not been classified "
            "or is classified as sensitive/confidential but lacks an approved transfer policy. "
            "Data must be classified before it can move — unclassified data is treated as "
            "potentially sensitive by default."
        ),
        "priority": 90, "scope": "module", "scope_target": "dataclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "unclassified_transfer"}),
        "action": "deny",
    },
    {
        "name": "Alert on Bulk Data Download",
        "description": (
            "DATACLAW | Triggers when a single identity downloads more than the volume threshold "
            "in a rolling 24-hour window (default: 500MB or 10,000 records). Bulk downloads "
            "are the most common pre-exfiltration signal in insider threat scenarios."
        ),
        "priority": 91, "scope": "module", "scope_target": "dataclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "bulk_download"}),
        "action": "monitor",
    },
    {
        "name": "Require Encryption for Sensitive Data at Rest",
        "description": (
            "DATACLAW | Any storage of data classified as sensitive or confidential must use "
            "approved encryption (AES-256 minimum). Unencrypted sensitive data at rest is a "
            "compliance violation and triggers an immediate remediation requirement."
        ),
        "priority": 92, "scope": "module", "scope_target": "dataclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "unencrypted_storage"}),
        "action": "require_approval",
    },
    {
        "name": "Flag Data Retained Beyond Policy Limits",
        "description": (
            "DATACLAW | Detects data that has exceeded its defined retention period without "
            "being archived or deleted. Over-retained data increases breach exposure and creates "
            "compliance liability under GDPR, CCPA, and HIPAA frameworks."
        ),
        "priority": 93, "scope": "module", "scope_target": "dataclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "retention_exceeded"}),
        "action": "monitor",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # APPCLAW — Application / API Security (priority 100–103)
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name": "Block Unauthenticated API Access",
        "description": (
            "APPCLAW | Blocks requests to internal APIs that arrive without a valid "
            "authentication token (JWT, OAuth, API key). Every API endpoint — internal "
            "or external — must enforce authentication. No anonymous API access permitted."
        ),
        "priority": 100, "scope": "module", "scope_target": "appclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "unauthenticated_api"}),
        "action": "deny",
    },
    {
        "name": "Block Deprecated API Version Usage",
        "description": (
            "APPCLAW | Blocks calls to deprecated or end-of-life API versions that no longer "
            "receive security patches. Deprecated APIs often contain unpatched vulnerabilities "
            "and should be migrated to current versions before they can be called."
        ),
        "priority": 101, "scope": "module", "scope_target": "appclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "deprecated_api"}),
        "action": "deny",
    },
    {
        "name": "Block Server-Side Request Forgery Attempts",
        "description": (
            "APPCLAW | Detects and blocks SSRF attempts — requests where user-supplied URLs "
            "cause the server to make requests to internal services or cloud metadata endpoints. "
            "SSRF is OWASP Top 10 A10 and a common cloud environment attack vector."
        ),
        "priority": 102, "scope": "module", "scope_target": "appclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "ssrf_attempt"}),
        "action": "deny",
    },
    {
        "name": "Alert on API Rate Limit Breach",
        "description": (
            "APPCLAW | Monitors and logs API calls that breach defined rate limits. "
            "Sudden rate spikes can indicate automated scraping, brute force credential testing, "
            "or DDoS preparation. Repeated breaches escalate to block automatically."
        ),
        "priority": 103, "scope": "module", "scope_target": "appclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "rate_limit_breach"}),
        "action": "monitor",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # SAASCLAW — SaaS Security (priority 110–113)
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name": "Alert on Shadow IT SaaS Detection",
        "description": (
            "SAASCLAW | Flags the use of unapproved SaaS applications discovered via DNS logs, "
            "browser agent data, or OAuth consent grants. Shadow IT creates unmonitored data "
            "flows — sensitive data may be stored in tools the security team cannot see."
        ),
        "priority": 110, "scope": "module", "scope_target": "saasclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "shadow_saas"}),
        "action": "monitor",
    },
    {
        "name": "Flag Excessive OAuth Permission Grants",
        "description": (
            "SAASCLAW | Detects OAuth grants where a SaaS application requests permissions "
            "beyond what is needed for its declared function (e.g., a note-taking app requesting "
            "mail.read). Excessive OAuth grants are a persistent privilege expansion risk."
        ),
        "priority": 111, "scope": "module", "scope_target": "saasclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "oauth_over_permission"}),
        "action": "monitor",
    },
    {
        "name": "Require MFA for All SaaS Admin Accounts",
        "description": (
            "SAASCLAW | Blocks admin-level operations in SaaS platforms where the admin "
            "account does not have MFA enrolled. SaaS admin accounts are high-value targets — "
            "MFA is the single most effective control against credential-based compromise."
        ),
        "priority": 112, "scope": "module", "scope_target": "saasclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "saas_admin_no_mfa"}),
        "action": "require_approval",
    },
    {
        "name": "Flag Inactive SaaS Licenses",
        "description": (
            "SAASCLAW | Identifies SaaS licenses that have had no login activity for 90+ days. "
            "Inactive accounts still hold permissions and often retain OAuth tokens — they "
            "should be deprovisioned to reduce attack surface and licensing costs."
        ),
        "priority": 113, "scope": "module", "scope_target": "saasclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "inactive_saas_license"}),
        "action": "monitor",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # THREATCLAW — Detection & Response (priority 120–123)
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name": "Alert on IOC Match",
        "description": (
            "THREATCLAW | Triggers when an observed IP, domain, file hash, or URL matches "
            "an active Indicator of Compromise (IOC) from the threat intelligence feed. "
            "IOC matches are high-confidence threat signals requiring immediate investigation."
        ),
        "priority": 120, "scope": "module", "scope_target": "threatclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "ioc_match"}),
        "action": "monitor",
    },
    {
        "name": "Alert on MITRE ATT&CK TTP Detection",
        "description": (
            "THREATCLAW | Flags behavioral patterns that match known MITRE ATT&CK techniques "
            "(e.g., T1059 Command Execution, T1003 Credential Dumping, T1071 C2 via App Layer). "
            "TTP-based detection catches novel malware that evades signature-based controls."
        ),
        "priority": 121, "scope": "module", "scope_target": "threatclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "mitre_ttp"}),
        "action": "monitor",
    },
    {
        "name": "Auto-Escalate Critical Severity Alerts",
        "description": (
            "THREATCLAW | Any alert scored at critical severity is automatically escalated "
            "for immediate human review and triggers a PagerDuty/Slack notification to the "
            "on-call security engineer. Critical alerts cannot wait for batch review."
        ),
        "priority": 122, "scope": "module", "scope_target": "threatclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "critical_alert"}),
        "action": "require_approval",
    },
    {
        "name": "Block Connections from Threat Actor Infrastructure",
        "description": (
            "THREATCLAW | Blocks inbound and outbound connections to/from IP ranges and domains "
            "attributed to known threat actor infrastructure (APT groups, ransomware operators, "
            "commodity malware C2 servers). Updated daily via IntelClaw threat feed sync."
        ),
        "priority": 123, "scope": "module", "scope_target": "threatclaw",
        "condition_json": json.dumps({"field": "target", "op": "contains", "value": "threat_actor_infra"}),
        "action": "deny",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # LOGCLAW — SIEM / Observability (priority 130–133)
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name": "Block Log Tampering",
        "description": (
            "LOGCLAW | Blocks any action that modifies, truncates, or deletes log data. "
            "Log tampering is a universal post-compromise behavior — attackers erase their "
            "trail before pivoting. LogClaw's logs are write-once by design."
        ),
        "priority": 130, "scope": "module", "scope_target": "logclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "log_tamper"}),
        "action": "deny",
    },
    {
        "name": "Alert on Log Forwarding Failure",
        "description": (
            "LOGCLAW | Triggers when a configured log source stops forwarding data for more "
            "than 15 minutes. Log forwarding failures can indicate network issues — or "
            "deliberate silencing of a log source during an attack."
        ),
        "priority": 131, "scope": "module", "scope_target": "logclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "log_forward_fail"}),
        "action": "monitor",
    },
    {
        "name": "Alert on Audit Log Gap",
        "description": (
            "LOGCLAW | Detects unexpected gaps in the audit log timeline. Continuous log "
            "streams should have no gaps — a gap may indicate log deletion, a pipeline "
            "failure, or deliberate evasion. All gaps require documented explanation."
        ),
        "priority": 132, "scope": "module", "scope_target": "logclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "audit_gap"}),
        "action": "monitor",
    },
    {
        "name": "Flag Abnormal Log Volume Suppression",
        "description": (
            "LOGCLAW | Flags a sudden drop of 50%+ in log volume from any source without a "
            "corresponding maintenance window. Volume suppression is a known technique "
            "attackers use to prevent detection while operating inside the environment."
        ),
        "priority": 133, "scope": "module", "scope_target": "logclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "log_volume_drop"}),
        "action": "monitor",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # INTELCLAW — Threat Intelligence (priority 140–143)
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name": "Auto-Alert on Critical CVE Affecting Inventory",
        "description": (
            "INTELCLAW | When a new CVE is published with CVSS score ≥ 9.0, IntelClaw "
            "cross-references the affected software against the asset inventory and alerts "
            "on matches within 4 hours of publication. Zero-days cannot wait for weekly scans."
        ),
        "priority": 140, "scope": "module", "scope_target": "intelclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "critical_cve"}),
        "action": "monitor",
    },
    {
        "name": "Alert on Dark Web Credential Exposure",
        "description": (
            "INTELCLAW | Monitors dark web feeds and breach databases for org-domain credentials. "
            "When an employee email/password pair appears in a breach dump, IntelClaw triggers "
            "an immediate password reset and risk score elevation for that identity."
        ),
        "priority": 141, "scope": "module", "scope_target": "intelclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "darkweb_exposure"}),
        "action": "monitor",
    },
    {
        "name": "Block Action on Active IOC Match",
        "description": (
            "INTELCLAW | When an actor's IP, device, or account matches an active IOC from "
            "the threat intelligence feed, all non-read actions from that actor are blocked "
            "until the IOC is reviewed and cleared. IOC-matched actors are treated as compromised."
        ),
        "priority": 142, "scope": "module", "scope_target": "intelclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "active_ioc_block"}),
        "action": "deny",
    },
    {
        "name": "Require Approval for External Intelligence Sharing",
        "description": (
            "INTELCLAW | Sharing threat intelligence data externally (ISAC submissions, vendor "
            "sharing, MISP federation) requires explicit admin approval. Intel sharing may "
            "inadvertently disclose internal infrastructure details or active response actions."
        ),
        "priority": 143, "scope": "module", "scope_target": "intelclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "intel_share_external"}),
        "action": "require_approval",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # USERCLAW — User Behavior Analytics (priority 150–153)
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name": "Alert on Impossible Travel Login",
        "description": (
            "USERCLAW | Flags authentication events from geographically impossible locations — "
            "two logins from different countries within a timeframe shorter than physical travel "
            "time. This is a strong indicator of credential compromise or VPN misuse."
        ),
        "priority": 150, "scope": "module", "scope_target": "userclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "impossible_travel"}),
        "action": "monitor",
    },
    {
        "name": "Alert on Significant Off-Hours Access",
        "description": (
            "USERCLAW | Monitors access events that fall significantly outside an identity's "
            "established working hours baseline. A user who never logs in before 9am suddenly "
            "accessing systems at 3am is a high-priority behavioral anomaly."
        ),
        "priority": 151, "scope": "module", "scope_target": "userclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "off_hours_access"}),
        "action": "monitor",
    },
    {
        "name": "Flag Peer Group Behavior Deviation",
        "description": (
            "USERCLAW | Alerts when a user's behavior deviates significantly from their peer "
            "group baseline (same team, role, department). A developer suddenly accessing "
            "finance systems or an analyst downloading 10x their usual data volume is flagged."
        ),
        "priority": 152, "scope": "module", "scope_target": "userclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "peer_deviation"}),
        "action": "monitor",
    },
    {
        "name": "Alert on Excessive Download Velocity",
        "description": (
            "USERCLAW | Triggers when a user's data download rate exceeds their 30-day "
            "baseline by 5x or more within a single session. Rapid, high-volume downloads "
            "are the most consistent pre-departure exfiltration signal."
        ),
        "priority": 153, "scope": "module", "scope_target": "userclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "download_velocity"}),
        "action": "monitor",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # INSIDERCLAW — Insider Risk (priority 160–163)
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name": "Elevate Monitoring for Departing Employees",
        "description": (
            "INSIDERCLAW | When an employee submits a resignation or is added to the offboarding "
            "list, their identity is flagged for elevated monitoring. All file access, downloads, "
            "and external sharing during the notice period are logged at high fidelity."
        ),
        "priority": 160, "scope": "module", "scope_target": "insiderclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "departing_employee"}),
        "action": "monitor",
    },
    {
        "name": "Block Mass File Access by Flagged Departing Users",
        "description": (
            "INSIDERCLAW | A departing employee who accesses more than their rolling baseline "
            "of files in the notice period has their mass-access actions blocked. Individual "
            "file access continues normally — only bulk collection triggers this control."
        ),
        "priority": 161, "scope": "module", "scope_target": "insiderclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "departing_bulk_access"}),
        "action": "deny",
    },
    {
        "name": "Alert on Sensitive Data Staging",
        "description": (
            "INSIDERCLAW | Detects when an identity copies large volumes of sensitive data "
            "to a staging location (personal folder, temp directory, removable media mount) "
            "consistent with pre-exfiltration preparation. Staging is the step before the move."
        ),
        "priority": 162, "scope": "module", "scope_target": "insiderclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "data_staging"}),
        "action": "monitor",
    },
    {
        "name": "Enforce Contractor Access Scope Restrictions",
        "description": (
            "INSIDERCLAW | Contractor and vendor identities are limited to their approved "
            "access scope — any access outside their declared work scope requires approval. "
            "Contractors must not traverse organizational boundaries without explicit grant."
        ),
        "priority": 163, "scope": "module", "scope_target": "insiderclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "contractor_scope_breach"}),
        "action": "require_approval",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # AUTOMATIONCLAW — SOAR (priority 170–173)
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name": "Require Approval for Destructive Playbook Actions",
        "description": (
            "AUTOMATIONCLAW | Automated playbooks that include destructive actions (kill process, "
            "isolate host, delete account, block IP) require human approval before execution. "
            "SOAR automation must never be fully autonomous for high-impact actions."
        ),
        "priority": 170, "scope": "module", "scope_target": "automationclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "destructive_playbook"}),
        "action": "require_approval",
    },
    {
        "name": "Alert on Runaway Automation Loop",
        "description": (
            "AUTOMATIONCLAW | Detects when a SOAR playbook or automation script triggers "
            "itself more than 3 times within 60 seconds. Automation loops can exhaust API "
            "rate limits, spam alerts, and create system instability."
        ),
        "priority": 171, "scope": "module", "scope_target": "automationclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "automation_loop"}),
        "action": "monitor",
    },
    {
        "name": "Audit All Cross-System Automated Actions",
        "description": (
            "AUTOMATIONCLAW | Every automated action that touches more than one system "
            "(e.g., close Sentinel alert + isolate CrowdStrike host + create Jira ticket) "
            "is logged as a single correlated automation event for full audit traceability."
        ),
        "priority": 172, "scope": "module", "scope_target": "automationclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "cross_system_auto"}),
        "action": "monitor",
    },
    {
        "name": "Block Unapproved Playbook Deployment",
        "description": (
            "AUTOMATIONCLAW | New SOAR playbooks or modifications to existing playbooks must "
            "be approved before they can run in production. Unapproved automation is a "
            "governance gap — it can silently change incident response behavior."
        ),
        "priority": 173, "scope": "module", "scope_target": "automationclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "unapproved_playbook"}),
        "action": "deny",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # ATTACKPATHCLAW — Attack Path Analysis (priority 180–183)
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name": "Alert When Attack Path Reaches Crown Jewel Asset",
        "description": (
            "ATTACKPATHCLAW | Triggers when graph analysis identifies a viable attack path "
            "from an internet-exposed or compromised asset to a crown jewel (domain controller, "
            "production database, backup server, HSM). Crown jewel proximity is the highest "
            "priority finding in any attack surface analysis."
        ),
        "priority": 180, "scope": "module", "scope_target": "attackpathclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "crown_jewel_path"}),
        "action": "monitor",
    },
    {
        "name": "Isolate Asset on Confirmed Attack Path",
        "description": (
            "ATTACKPATHCLAW | When an asset is confirmed as a node in an active attack path "
            "(not just modeled — actively being traversed), it is automatically isolated "
            "from sensitive segments until the path is broken and the asset is remediated."
        ),
        "priority": 181, "scope": "module", "scope_target": "attackpathclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "active_attack_path"}),
        "action": "isolate",
    },
    {
        "name": "Block Identified Credential Relay Attack Paths",
        "description": (
            "ATTACKPATHCLAW | Blocks the specific network paths used in identified credential "
            "relay attacks (Pass-the-Hash, Pass-the-Ticket, NTLM relay). These paths are "
            "blocked at the network layer until the underlying misconfiguration is fixed."
        ),
        "priority": 182, "scope": "module", "scope_target": "attackpathclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "credential_relay_path"}),
        "action": "deny",
    },
    {
        "name": "Require Approval for Crown Jewel Asset Access",
        "description": (
            "ATTACKPATHCLAW | Any access to assets designated as crown jewels requires "
            "explicit Just-In-Time approval — even from privileged accounts. Crown jewel "
            "access is the highest-stakes operation in any enterprise environment."
        ),
        "priority": 183, "scope": "module", "scope_target": "attackpathclaw",
        "condition_json": json.dumps({"field": "target", "op": "contains", "value": "crown_jewel"}),
        "action": "require_approval",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # EXPOSURECLAW — External Attack Surface Management (priority 190–193)
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name": "Alert on Newly Discovered External Service",
        "description": (
            "EXPOSURECLAW | Flags when a new internet-facing service, port, or subdomain "
            "is discovered that was not in the previously approved external inventory. "
            "New external services may be shadow IT, misconfigured deployments, or "
            "attacker-created infrastructure using org-owned IPs."
        ),
        "priority": 190, "scope": "module", "scope_target": "exposureclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "new_external_service"}),
        "action": "monitor",
    },
    {
        "name": "Block Expired SSL Certificate Endpoints",
        "description": (
            "EXPOSURECLAW | Blocks traffic to or from external endpoints with expired SSL "
            "certificates. Expired certificates indicate abandoned infrastructure and "
            "create vulnerability to MITM attacks. Services must renew before they can be used."
        ),
        "priority": 191, "scope": "module", "scope_target": "exposureclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "expired_ssl"}),
        "action": "deny",
    },
    {
        "name": "Alert on Admin Interface Exposed to Internet",
        "description": (
            "EXPOSURECLAW | Detects admin panels, management consoles, SSH, RDP, and database "
            "ports directly exposed to the internet. Admin interfaces must be behind VPN "
            "or Zero Trust access controls — never directly internet-accessible."
        ),
        "priority": 192, "scope": "module", "scope_target": "exposureclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "exposed_admin_interface"}),
        "action": "monitor",
    },
    {
        "name": "Block Unapproved Open Ports on External Perimeter",
        "description": (
            "EXPOSURECLAW | Blocks access through ports that are not on the approved external "
            "perimeter policy (typically 80/443 only for web, plus approved VPN ports). "
            "Every open port on the external surface is an attack vector."
        ),
        "priority": 193, "scope": "module", "scope_target": "exposureclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "unapproved_open_port"}),
        "action": "deny",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # COMPLIANCECLAW — Compliance (priority 200–203)
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name": "Auto-Create Ticket on Policy Violation",
        "description": (
            "COMPLIANCECLAW | Every Trust Fabric deny or require_approval event automatically "
            "creates a compliance ticket (Jira/ServiceNow) linked to the specific control "
            "framework (SOC 2, ISO 27001, NIST CSF, CIS) that the event maps to."
        ),
        "priority": 200, "scope": "module", "scope_target": "complianceclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "policy_violation"}),
        "action": "monitor",
    },
    {
        "name": "Require Evidence Collection for Auditable Events",
        "description": (
            "COMPLIANCECLAW | For events flagged as auditable (SOC 2 evidence, ISO 27001 "
            "control tests), ComplianceClaw requires that supporting evidence is collected "
            "and linked before the event can be closed. No evidence = open finding."
        ),
        "priority": 201, "scope": "module", "scope_target": "complianceclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "auditable_event"}),
        "action": "require_approval",
    },
    {
        "name": "Block Compliance Exception Without Formal Approval",
        "description": (
            "COMPLIANCECLAW | Any exception to a compliance control — where a required control "
            "is not implemented as specified — requires a formal risk acceptance document "
            "signed by an authorized approver. Undocumented exceptions are policy violations."
        ),
        "priority": 202, "scope": "module", "scope_target": "complianceclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "compliance_exception"}),
        "action": "require_approval",
    },
    {
        "name": "Monitor Framework Control Mapping Gaps",
        "description": (
            "COMPLIANCECLAW | Detects when a new Claw module or connector is added to the "
            "platform without a corresponding control mapping in the active compliance frameworks "
            "(SOC 2, ISO 27001, NIST CSF). Every component must be in-scope for compliance."
        ),
        "priority": 203, "scope": "module", "scope_target": "complianceclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "unmapped_control"}),
        "action": "monitor",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # PRIVACYCLAW — Privacy (priority 210–213)
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name": "Block Unnecessary PII Collection",
        "description": (
            "PRIVACYCLAW | Blocks collection of PII fields that are not required for the "
            "declared processing purpose. Data minimization is a core GDPR Article 5 principle "
            "and CCPA requirement — collect only what is necessary."
        ),
        "priority": 210, "scope": "module", "scope_target": "privacyclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "unnecessary_pii"}),
        "action": "deny",
    },
    {
        "name": "Require Approval for Cross-Border PII Transfer",
        "description": (
            "PRIVACYCLAW | Transferring PII across national borders (especially EU to non-adequate "
            "countries) requires explicit approval and must include a valid transfer mechanism "
            "(SCCs, BCRs, or adequacy decision). GDPR Chapter V violations carry severe penalties."
        ),
        "priority": 211, "scope": "module", "scope_target": "privacyclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "cross_border_pii"}),
        "action": "require_approval",
    },
    {
        "name": "Alert on Data Subject Access Request",
        "description": (
            "PRIVACYCLAW | Detects and routes incoming Data Subject Access Requests (DSARs) "
            "from GDPR/CCPA data subjects. DSARs must be acknowledged within 72 hours and "
            "fulfilled within 30 days — PrivacyClaw ensures the timer starts immediately."
        ),
        "priority": 212, "scope": "module", "scope_target": "privacyclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "dsar_received"}),
        "action": "monitor",
    },
    {
        "name": "Require Privacy Impact Assessment for New Processing",
        "description": (
            "PRIVACYCLAW | Any new data processing activity involving personal data requires "
            "a Privacy Impact Assessment (PIA/DPIA) before it can go live. GDPR Article 35 "
            "mandates DPIAs for high-risk processing — PrivacyClaw enforces this gate."
        ),
        "priority": 213, "scope": "module", "scope_target": "privacyclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "new_data_processing"}),
        "action": "require_approval",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # VENDORCLAW — Third-Party Risk (priority 220–223)
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name": "Block Connections to Unapproved Vendors",
        "description": (
            "VENDORCLAW | Blocks outbound connections and data sharing to vendors that have "
            "not completed the third-party security assessment and been approved by the "
            "security and procurement team. Every vendor is a potential supply chain risk."
        ),
        "priority": 220, "scope": "module", "scope_target": "vendorclaw",
        "condition_json": json.dumps({"field": "target", "op": "contains", "value": "unapproved_vendor"}),
        "action": "deny",
    },
    {
        "name": "Enforce Time-Limited Vendor Access Windows",
        "description": (
            "VENDORCLAW | Vendor access to internal systems must be time-boxed with explicit "
            "start and end times. Access windows are granted via JIT approval and "
            "automatically revoked at the end of the approved window. No standing vendor access."
        ),
        "priority": 221, "scope": "module", "scope_target": "vendorclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "vendor_access_expired"}),
        "action": "deny",
    },
    {
        "name": "Alert on Known Vendor Security Incident",
        "description": (
            "VENDORCLAW | When a vendor in the approved vendor list experiences a publicly "
            "disclosed security incident (breach, ransomware, data leak), VendorClaw "
            "automatically alerts the security team and triggers a vendor risk re-assessment."
        ),
        "priority": 222, "scope": "module", "scope_target": "vendorclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "vendor_breach"}),
        "action": "monitor",
    },
    {
        "name": "Flag Fourth-Party Exposure Risk",
        "description": (
            "VENDORCLAW | Monitors and flags when an approved vendor uses a sub-processor "
            "(fourth party) that has not been disclosed or assessed. Fourth-party risk "
            "is where most supply chain attacks originate — SolarWinds was a fourth-party attack."
        ),
        "priority": 223, "scope": "module", "scope_target": "vendorclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "fourth_party_risk"}),
        "action": "monitor",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # DEVCLAW — DevSecOps (priority 230–233)
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name": "Block Code Commits Containing Secrets",
        "description": (
            "DEVCLAW | Scans every code commit for hardcoded secrets (API keys, passwords, "
            "connection strings, private keys). Commits containing detected secrets are "
            "blocked from merging until the secret is removed and rotated. Pre-commit "
            "hooks + CI pipeline gate provide defense-in-depth."
        ),
        "priority": 230, "scope": "module", "scope_target": "devclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "commit_with_secret"}),
        "action": "deny",
    },
    {
        "name": "Block Deployment of Known Vulnerable Dependencies",
        "description": (
            "DEVCLAW | Blocks deployment of application packages or container images that "
            "contain dependencies with known critical CVEs (CVSS ≥ 9.0). Supply chain "
            "attacks via compromised dependencies (log4shell, xz-utils) are caught here."
        ),
        "priority": 231, "scope": "module", "scope_target": "devclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "vulnerable_dependency"}),
        "action": "deny",
    },
    {
        "name": "Require Remediation of Critical SAST Findings",
        "description": (
            "DEVCLAW | Code with unresolved critical SAST findings (SQL injection, path "
            "traversal, XSS, deserialization vulnerabilities) cannot be deployed to production "
            "without an approved exception. Security must be fixed before shipping — not after."
        ),
        "priority": 232, "scope": "module", "scope_target": "devclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "critical_sast_finding"}),
        "action": "require_approval",
    },
    {
        "name": "Require Signed Container Images in Production",
        "description": (
            "DEVCLAW | Only container images with a valid cryptographic signature from an "
            "approved signing authority may be deployed to production. Unsigned images could "
            "be tampered with in the registry — image signing closes the supply chain gap."
        ),
        "priority": 233, "scope": "module", "scope_target": "devclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "unsigned_container"}),
        "action": "deny",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # CONFIGCLAW — Hardening / Configuration (priority 240–243)
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name": "Alert on CIS Benchmark Deviation",
        "description": (
            "CONFIGCLAW | Detects configuration drift from CIS Benchmark hardening standards "
            "(CIS AWS Foundations, CIS Windows Server, CIS Kubernetes). Any deviation from "
            "the approved baseline triggers an alert and remediation ticket."
        ),
        "priority": 240, "scope": "module", "scope_target": "configclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "cis_deviation"}),
        "action": "monitor",
    },
    {
        "name": "Block Default Credential Usage",
        "description": (
            "CONFIGCLAW | Blocks authentication using known default credentials "
            "(admin/admin, root/root, changeme, vendor defaults). Default credentials "
            "are tested by every automated attacker and IoT botnet within minutes of exposure."
        ),
        "priority": 241, "scope": "module", "scope_target": "configclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "default_credential"}),
        "action": "deny",
    },
    {
        "name": "Flag Unnecessary Services Running on Endpoints",
        "description": (
            "CONFIGCLAW | Detects and flags unnecessary services or daemons running on "
            "endpoints that are not in the approved service baseline (e.g., Telnet, FTP, "
            "SMBv1, Print Spooler on non-print servers). Every unnecessary service "
            "is an unnecessary attack surface."
        ),
        "priority": 242, "scope": "module", "scope_target": "configclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "unnecessary_service"}),
        "action": "monitor",
    },
    {
        "name": "Alert on Unauthorized Configuration Drift",
        "description": (
            "CONFIGCLAW | Detects changes to system configuration that were not made via "
            "the approved change management process. Unauthorized config changes are either "
            "security incidents or governance failures — both require investigation."
        ),
        "priority": 243, "scope": "module", "scope_target": "configclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "config_drift"}),
        "action": "monitor",
    },

    # ══════════════════════════════════════════════════════════════════════════
    # RECOVERYCLAW — Resilience / Recovery (priority 250–253)
    # ══════════════════════════════════════════════════════════════════════════

    {
        "name": "Require Backup Verification Before Critical System Changes",
        "description": (
            "RECOVERYCLAW | Before any change to a critical system (OS upgrade, schema "
            "migration, infrastructure replacement), RecoveryClaw requires confirmation "
            "that a verified, restorable backup exists. No backup = no change approval."
        ),
        "priority": 250, "scope": "module", "scope_target": "recoveryclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "unverified_backup_change"}),
        "action": "require_approval",
    },
    {
        "name": "Alert on Recovery Time Objective Risk",
        "description": (
            "RECOVERYCLAW | Triggers when backup age, replication lag, or system state "
            "indicates that the current RTO/RPO would be breached in a recovery scenario. "
            "RTO risk alerts give teams time to remediate before an incident forces recovery."
        ),
        "priority": 251, "scope": "module", "scope_target": "recoveryclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "rto_breach_risk"}),
        "action": "monitor",
    },
    {
        "name": "Enforce Immutable Backup for Critical Data",
        "description": (
            "RECOVERYCLAW | Backups of critical data (databases, secrets, config) must be "
            "stored in immutable storage (WORM — Write Once Read Many). Ransomware routinely "
            "encrypts or deletes mutable backups before detonating — immutability is the "
            "only reliable defense."
        ),
        "priority": 252, "scope": "module", "scope_target": "recoveryclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "mutable_critical_backup"}),
        "action": "require_approval",
    },
    {
        "name": "Require Periodic Disaster Recovery Test Completion",
        "description": (
            "RECOVERYCLAW | Flags systems that have not had a successful DR test within the "
            "defined test interval (default: 90 days). An untested DR plan is not a DR plan — "
            "RecoveryClaw ensures tests happen before an incident forces the issue."
        ),
        "priority": 253, "scope": "module", "scope_target": "recoveryclaw",
        "condition_json": json.dumps({"field": "action", "op": "contains", "value": "dr_test_overdue"}),
        "action": "monitor",
    },
]


# ── Seed function ──────────────────────────────────────────────────────────────

async def seed(reset: bool = False):
    from sqlalchemy import select, delete
    async with AsyncSessionLocal() as db:

        if reset:
            await db.execute(delete(Policy))
            await db.commit()
            print("  RESET  All existing policies cleared.\n")

        added = 0
        updated = 0
        for p in POLICIES:
            existing = await db.execute(select(Policy).where(Policy.name == p["name"]))
            row = existing.scalar_one_or_none()

            if row:
                row.description    = p["description"]
                row.priority       = p["priority"]
                row.scope          = PolicyScope(p["scope"])
                row.scope_target   = p.get("scope_target")
                row.condition_json = p["condition_json"]
                row.action         = PolicyAction(p["action"])
                row.is_active      = True
                print(f"  UPDATE {p['name']}")
                updated += 1
            else:
                policy = Policy(
                    name=p["name"],
                    description=p["description"],
                    priority=p["priority"],
                    scope=PolicyScope(p["scope"]),
                    scope_target=p.get("scope_target"),
                    condition_json=p["condition_json"],
                    action=PolicyAction(p["action"]),
                    is_active=True,
                    version="1.0",
                    created_by="RegentClaw Seed",
                )
                db.add(policy)
                print(f"  ADD    {p['name']}")
                added += 1

        await db.commit()

        # Summary by layer
        layers = {}
        for p in POLICIES:
            desc = p["description"]
            layer = desc.split("|")[0].strip() if "|" in desc else "OTHER"
            layers[layer] = layers.get(layer, 0) + 1

        print(f"\nDone — {added} added, {updated} updated.")
        print(f"Total policies: {len(POLICIES)}\n")
        print("Policies by layer:")
        for layer, count in sorted(layers.items()):
            print(f"  {layer:<20} {count} policies")


if __name__ == "__main__":
    reset_flag = "--reset" in sys.argv
    asyncio.run(seed(reset=reset_flag))
