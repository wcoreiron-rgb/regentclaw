# RegentClaw — Tenant Isolation Model

## Current Isolation Model

RegentClaw does not have an explicit `tenant_id` column. Ownership is expressed
inconsistently across models:

| Model | Ownership field | Type | Enforced in API? |
|-------|----------------|------|-----------------|
| `Connector` | `owner_id` | UUID (nullable) | **No** |
| `Finding` | *(none)* | — | **No** |
| `IncidentMemory` | `created_by` | free-text string | **No** |
| `AssetMemory` | *(none)* | — | **No** |
| `SwarmJob` | `requested_by` | free-text string | **No** |
| `AuditLog` | `actor` | free-text string | **No** |

The `secrets_manager` credential store is keyed by `connector_id` string with no
tenant ownership check. A caller who knows a connector UUID can retrieve its
credentials regardless of which tenant created that connector.

## What the Tests Prove

`backend/tests/test_tenant_isolation.py` contains eight tests grouped in
`TestTenantIsolation`. They fall into two categories:

**Passing tests (gaps visible at DB layer but data model holds):**
- `test_connector_db_rows_are_scoped_by_owner_id` — confirms `owner_id` column exists
  and a WHERE clause correctly scopes rows; the gap is that the API never applies this clause.
- `test_swarm_job_db_filter_by_requested_by` — confirms `requested_by` is queryable.
- `test_audit_log_db_filter_by_actor` — confirms `actor` can filter audit logs.
- `test_credential_store_keyed_by_connector_id` — confirms that an unknown connector ID
  returns `None` from `get_credential`.
- `test_finding_api_returns_all_findings_gap_documented` — actively documents that both
  tenants' findings appear in an unfiltered API response.

**`xfail` tests (gaps that must be fixed):**
- `test_connector_api_filters_by_caller_owner` — GET /api/v1/connectors returns all
  connectors; no owner scoping applied.
- `test_finding_not_visible_across_tenants` — `Finding` has no ownership column;
  cross-tenant bleed is structural.
- `test_incident_memory_isolated_by_tenant` — API does not filter `IncidentMemory` by caller.
- `test_asset_memory_isolated_by_tenant` — `AssetMemory` has no ownership column at all.
- `test_swarm_job_api_does_not_leak_across_tenants` — swarm job list is unscoped.
- `test_credential_store_rejects_cross_tenant_access` — `get_credential` has no tenant check.
- `test_audit_log_api_scoped_to_caller` — audit log list is unscoped.
- `test_connector_list_does_not_expose_other_tenant_owner_ids` — `owner_id` values
  from all tenants appear in the list response, enabling UUID enumeration attacks.

Most tenant-gap tests are currently marked `xfail(strict=False)` so CI keeps
signal without blocking feature work; they should be moved to strict/pass as
each enforcement gap is closed and verified.

## Gaps That Remain

1. **No platform-wide tenant_id.** `Finding`, `AssetMemory`, `RiskTrendSnapshot`, and
   `TenantMemory` have no ownership field. Adding data without a tenant anchor makes
   future isolation retrofits expensive.

2. **API endpoints do not read caller identity for scoping.** Even where `owner_id`
   exists (`Connector`), the route performs `select(Connector)` with no WHERE clause.

3. **Secrets manager has no tenant parameter.** `get_credential(connector_id)` trusts
   the caller knows the right UUID; there is no secondary ownership check.

4. **owner_id exposed in list responses.** Tenant UUIDs are returned in the connector
   list payload, enabling UUID enumeration across tenants.

## Recommended Next Steps

**Short term (application layer):**
- Extract the caller's `owner_id` from the JWT claim in `get_current_user`.
- Pass it into every list/get route and add `.where(Model.owner_id == caller_owner_id)`.
- Strip `owner_id` from serialized responses so it is never returned to clients.
- Add a `tenant_id` parameter to `secrets_manager.store_credential` and
  `get_credential`, and verify it matches on retrieval.

**Medium term (schema):**
- Add `owner_id UUID NOT NULL` to `Finding`, `IncidentMemory`, `AssetMemory`,
  and `SwarmJob` via Alembic migration.
- Replace the `requested_by` / `created_by` free-text strings with typed UUIDs
  that reference a users or organizations table.

**Long term (database layer — strongest guarantee):**
- Enable **PostgreSQL Row-Level Security (RLS)** on all tables.
- Create a `SET LOCAL app.current_tenant = :tenant_id` call at the start of each
  request, and define RLS policies such as:
  ```sql
  CREATE POLICY tenant_isolation ON connectors
    USING (owner_id = current_setting('app.current_tenant')::uuid);
  ```
- RLS enforces isolation even if application code is buggy or a query bypasses
  the ORM layer, providing defence-in-depth that cannot be accidentally removed
  by a code change alone.
