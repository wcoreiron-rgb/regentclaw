# RegentClaw Production Deployment Guide

**Status:** baseline hardening guide, not a hosted-service certification.

Use this guide when moving RegentClaw from local Docker development into a production-like environment.

## Required Controls

| Area | Requirement |
|---|---|
| TLS | Terminate HTTPS at a trusted reverse proxy or ingress. Do not expose backend HTTP directly to the internet. |
| Secrets | Set production secrets through your secret manager. Do not commit `.env`, Fernet keys, remote-agent enrollment secrets, API keys, or connector credentials. |
| Database | Use managed PostgreSQL or a backed-up PostgreSQL service. Enable automated backups and test restore before production use. |
| Redis | Require network isolation and authentication where supported. Treat Redis as sensitive runtime state. |
| Authentication | Require real JWT/OIDC identity in front of operator routes. Do not rely on local development defaults. |
| Trust Fabric | Keep policy evaluation fail-closed for execution, remediation, model calls, connector calls, and evidence exports. |
| CI security | Keep SBOM and dependency audit jobs enabled. Use `security/supply_chain_baseline.json` only for time-boxed accepted legacy findings. |
| Terraform/IaC gates | Run TerraClaw build/review/plan analysis before Terraform applies. Treat BLOCK decisions as release blockers unless explicitly overridden through governed approval. |

## Minimum Environment Checklist

- `DATABASE_URL` points to production PostgreSQL.
- `REDIS_URL` points to a private Redis endpoint.
- `FERNET_KEY` or equivalent secrets encryption key is generated and stored outside git.
- `REMOTE_AGENT_ENROLLMENT_SECRET` is set to a high-entropy value.
- Model provider keys are tenant-scoped where possible.
- Connector credentials are configured through the connector UI/API and encrypted at rest.
- CORS allows only approved frontend origins.
- Reverse proxy enforces TLS, request size limits, and sane timeouts.
- Backend logs redact request bodies and secrets.
- Terraform modules generated or reviewed by TerraClaw are checked before apply.

## TerraClaw Terraform/IaC Gates

For Terraform-backed releases, run TerraClaw first:

```http
POST /api/v1/terraclaw/build
POST /api/v1/terraclaw/review
POST /api/v1/terraclaw/plan
```

Use `build` when an operator wants a secure Terraform module from plain
English. Use `review` for existing `.tf` content. Use `plan` before apply to
detect risky creates, deletes, replacements, public network exposure, weak data
protection, hardcoded secrets, excessive IAM, missing diagnostics, and other
high-risk IaC changes.

## Backup And Restore

1. Take a PostgreSQL backup before every migration.
2. Restore the backup into a staging environment before production rollout.
3. Run backend tests and a smoke test against staging.
4. Apply migrations during a maintenance window when table sizes are large.

## Compliance Evidence Export

ComplianceClaw provides an audit-ready JSON export:

```http
POST /api/v1/complianceclaw/evidence/export
```

Request:

```json
{
  "requested_by": "compliance-admin",
  "frameworks": ["SOC 2", "ISO 27001"],
  "include_findings": true,
  "include_audit_logs": true,
  "max_audit_logs": 100,
  "classification": "confidential"
}
```

The export is Trust Fabric-governed and includes:

- policy decision metadata
- linked findings
- compliance-relevant audit logs
- per-framework evidence counts
- SHA-256 chain-of-custody hash

Exports are vendor-generated evidence bundles. Independent audit review is still required before compliance reliance.
