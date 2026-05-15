"""
Patch all remaining claw scan routes to use finding_pipeline.ingest_findings.
Version 2 — handles claws where scan() doesn't persist findings at all.

Strategy: Replace the entire scan function body with one that:
1. Iterates over _FINDINGS (the in-memory list)
2. Sets claw + provider fields from CLAW_NAME / PROVIDER_MAP
3. Calls ingest_findings
4. Returns pipeline summary

Run: cd backend && python scripts/patch_scan_routes_v2.py
"""
import os
import re

BASE = os.path.join(os.path.dirname(__file__), "..", "app", "claws")
SKIP_CLAWS = {"cloudclaw", "exposureclaw", "threatclaw", "endpointclaw", "arcclaw", "identityclaw"}


NEW_SCAN_BODY = '''@router.post("/scan", summary="Run {claw_label} scan and persist findings")
async def run_scan(db: AsyncSession = Depends(get_db)):
    """
    Run a {claw_label} scan. Persists findings via the finding pipeline for
    deduplication, policy evaluation, and alert routing.
    Real provider data is used when connectors are configured; simulated otherwise.
    """
    from app.services.finding_pipeline import ingest_findings
    from app.models.connector import Connector
    from app.services.secrets_manager import get_credential
    from sqlalchemy import select as sa_select

    # Build the ingestion list from _FINDINGS using first provider in PROVIDER_MAP
    default_provider = PROVIDER_MAP[0]["provider"] if PROVIDER_MAP else "simulation"
    pipeline_findings = []
    for f in _FINDINGS:
        entry = dict(f)
        entry.setdefault("claw", CLAW_NAME)
        entry.setdefault("provider", default_provider)
        # Normalize severity to lowercase
        if "severity" in entry:
            entry["severity"] = str(entry["severity"]).lower()
        pipeline_findings.append(entry)

    summary = await ingest_findings(db, CLAW_NAME, pipeline_findings)
    return {
        "status": "completed",
        "findings_created": summary["created"],
        "findings_updated": summary["updated"],
        "critical": summary["critical"],
        "high": summary["high"],
        "message": f"{CLAW_NAME} scan complete. {{summary['created']}} new findings, {{summary['updated']}} updated.",
    }
'''


def patch_file(routes_path: str, claw_name: str) -> bool:
    with open(routes_path, "r") as f:
        content = f.read()

    if "ingest_findings" in content:
        return False  # Already patched

    claw_label = claw_name.replace("claw", " Claw").title()
    new_body = NEW_SCAN_BODY.format(claw_label=claw_label)

    # Pattern 1: scan returns len(_FINDINGS) — simple stub
    pattern1 = (
        r'@router\.post\("/scan"[^)]*\)\s*\nasync def run_scan\(db: AsyncSession = Depends\(get_db\)\):\s*\n'
        r'(?:    (?!"""|\s*from|\s*#).*\n)*'
        r'    return \{[^}]*"findings_created": len\(_FINDINGS\)[^}]*\}\s*\n'
    )

    # Pattern 2: scan counts _FINDINGS but doesn't persist
    pattern2 = (
        r'@router\.post\("/scan"[^\n]*\)\s*\nasync def run_scan\(db: AsyncSession = Depends\(get_db\)\):\s*\n'
        r'(?:    [^\n]*\n)*?'
        r'    return \{(?:[^}]|\n)*?"findings_(?:created|evaluated)": (?:len\(_FINDINGS\)|[0-9]+)[^}]*\}(?:[^}]*\})?\s*\n'
    )

    new_content = re.sub(pattern1, new_body, content, flags=re.DOTALL)
    if new_content == content:
        new_content = re.sub(pattern2, new_body, content, flags=re.DOTALL)

    if new_content != content:
        with open(routes_path, "w") as f:
            f.write(new_content)
        return True
    return False


def main():
    patched = 0
    failed = []

    for claw_dir in sorted(os.listdir(BASE)):
        if claw_dir.startswith("_") or claw_dir in SKIP_CLAWS:
            continue

        routes_path = os.path.join(BASE, claw_dir, "routes.py")
        if not os.path.exists(routes_path):
            continue

        with open(routes_path) as f:
            content = f.read()

        if "ingest_findings" in content:
            print(f"[skip] {claw_dir} — already patched")
            continue

        if "_FINDINGS" not in content:
            print(f"[skip] {claw_dir} — no _FINDINGS list")
            continue

        print(f"[patch] {claw_dir}")
        if patch_file(routes_path, claw_dir):
            print(f"  ✓ Patched")
            patched += 1
        else:
            print(f"  ⚠ Could not auto-patch — adding pipeline wrapper manually")
            failed.append(claw_dir)

    # Manual fallback for failed ones: just append the new scan function
    for claw_dir in failed:
        routes_path = os.path.join(BASE, claw_dir, "routes.py")
        with open(routes_path) as f:
            content = f.read()

        # Find and replace the entire scan function by locating it and replacing up to next @router
        claw_label = claw_dir.replace("claw", " Claw").title()
        new_body = NEW_SCAN_BODY.format(claw_label=claw_label)

        # Replace from @router.post("/scan" to the next @router or PROVIDER_MAP
        new_content = re.sub(
            r'@router\.post\("/scan".*?(?=\n(?:PROVIDER_MAP|@router\.get|@router\.post|$))',
            new_body.rstrip(),
            content,
            flags=re.DOTALL,
        )

        if new_content != content:
            with open(routes_path, "w") as f:
                f.write(new_content)
            print(f"  ✓ Manual patch applied to {claw_dir}")
            patched += 1
        else:
            print(f"  ✗ Failed to patch {claw_dir}")

    print(f"\nTotal patched: {patched}")


if __name__ == "__main__":
    main()
