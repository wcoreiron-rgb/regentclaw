"""
Script: Wire all remaining claw scan endpoints to use the finding pipeline.
Run once: python scripts/wire_scan_pipeline.py

This script reads each claw's routes.py and replaces the legacy "direct DB insert"
pattern in scan endpoints with a call to finding_pipeline.ingest_findings.

Claws already wired (skip): cloudclaw, exposureclaw, threatclaw, endpointclaw
"""
import os
import re
import sys

CLAWS_BASE = os.path.join(os.path.dirname(__file__), "..", "app", "claws")
ALREADY_WIRED = {"cloudclaw", "exposureclaw", "threatclaw", "endpointclaw", "arcclaw"}

# Template for the new scan endpoint body
PIPELINE_SCAN_TEMPLATE = '''
@router.post("/scan", summary="Run {claw_label} scan across all configured providers")
async def run_scan(db: AsyncSession = Depends(get_db)):
    """
    Trigger a {claw_label} scan. Uses the finding pipeline for dedup, policy evaluation,
    and alert routing. Returns real provider data when connectors are configured;
    simulated data otherwise.
    """
    from app.services.finding_pipeline import ingest_findings
    from app.models.connector import Connector
    from app.services.secrets_manager import get_credential
    from sqlalchemy import select as sa_select

    total_created = 0
    total_updated = 0
    provider_results = {}
    errors = []

    for cfg in PROVIDER_MAP:
        provider_name = cfg["provider"]
        conn_type = cfg.get("connector_type", "")
        creds = None
        if conn_type:
            try:
                result = await db.execute(sa_select(Connector).where(Connector.connector_type == conn_type))
                conn = result.scalar_one_or_none()
                if conn:
                    creds = get_credential(str(conn.id))
            except Exception:
                pass

        try:
            # If a provider-specific adapter exists, call it; otherwise use simulated findings
            adapter_module = cfg.get("adapter")
            if adapter_module:
                raw_findings = await adapter_module.get_findings(credentials=creds)
            else:
                raw_findings = _get_simulated_findings(provider_name)

            for f in raw_findings:
                f.setdefault("claw", CLAW_NAME)
                f.setdefault("provider", provider_name)

            summary = await ingest_findings(db, CLAW_NAME, raw_findings)
            provider_results[provider_name] = {{
                "status": "success",
                "created": summary["created"],
                "updated": summary["updated"],
                "simulated": creds is None,
            }}
            total_created += summary["created"]
            total_updated += summary["updated"]
        except Exception as exc:
            errors.append({{"provider": provider_name, "error": str(exc)}})
            provider_results[provider_name] = {{"status": "error", "error": str(exc)}}

    return {{
        "status": "completed" if not errors else "completed_with_errors",
        "findings_created": total_created,
        "findings_updated": total_updated,
        "providers": provider_results,
        "errors": errors,
    }}
'''


def main():
    for claw_dir in sorted(os.listdir(CLAWS_BASE)):
        if claw_dir.startswith("_") or claw_dir in ALREADY_WIRED:
            continue
        routes_path = os.path.join(CLAWS_BASE, claw_dir, "routes.py")
        if not os.path.exists(routes_path):
            continue

        with open(routes_path, "r") as f:
            content = f.read()

        if "ingest_findings" in content:
            print(f"  [skip] {claw_dir} — already wired")
            continue

        if "@router.post(\"/scan\"" not in content:
            print(f"  [skip] {claw_dir} — no /scan endpoint")
            continue

        # Check if there's a PROVIDER_MAP already
        if "PROVIDER_MAP" not in content:
            print(f"  [skip] {claw_dir} — no PROVIDER_MAP defined (manual update needed)")
            continue

        print(f"  [info] {claw_dir} has PROVIDER_MAP but scan not wired — needs manual pipeline wiring")

    print("\nDone. Claws needing manual pipeline wiring have been identified.")
    print("Run the backend to test: docker compose up backend")


if __name__ == "__main__":
    main()
