"""
CloudClaw — Cloud Security Posture Management Routes
Supports AWS Security Hub, Azure Defender for Cloud, GCP Security Command Center.
"""
import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.core.database import get_db
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.models.connector import Connector
from app.schemas.finding import FindingRead
from app.services.secrets_manager import get_credential

from app.claws.cloudclaw.providers import aws as aws_adapter
from app.claws.cloudclaw.providers import azure as azure_adapter
from app.claws.cloudclaw.providers import gcp as gcp_adapter

logger = logging.getLogger("cloudclaw")

router = APIRouter(prefix="/cloudclaw", tags=["CloudClaw — Cloud Security"])

CLAW_NAME = "cloudclaw"

# Maps connector_type values to provider labels
PROVIDER_CONFIG = [
    {
        "provider": "aws",
        "connector_type": "aws_security_hub",
        "label": "AWS Security Hub",
        "adapter": aws_adapter,
    },
    {
        "provider": "azure",
        "connector_type": "azure_defender",
        "label": "Azure Defender for Cloud",
        "adapter": azure_adapter,
    },
    {
        "provider": "gcp",
        "connector_type": "gcp_scc",
        "label": "GCP Security Command Center",
        "adapter": gcp_adapter,
    },
]


# ─── Helper: look up connector + credentials ─────────────────────────────────

async def _get_provider_credentials(db: AsyncSession, connector_type: str) -> Optional[dict]:
    """
    Check if a connector of the given type exists and has stored credentials.
    Returns the decrypted credential dict, or None if not configured.
    """
    result = await db.execute(
        select(Connector).where(Connector.connector_type == connector_type)
    )
    connector = result.scalar_one_or_none()
    if not connector:
        return None

    connector_id = str(connector.id)
    creds = get_credential(connector_id)
    return creds  # None if no secret stored


# ─── Routes ──────────────────────────────────────────────────────────────────

@router.get("/stats")
async def get_cloudclaw_stats(db: AsyncSession = Depends(get_db)):
    """
    CloudClaw summary: finding counts by severity and provider, open/critical totals,
    and which cloud providers are connected.
    """
    # Base query: only cloudclaw findings
    base = select(Finding).where(Finding.claw == CLAW_NAME)

    # By severity
    sev_result = await db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.claw == CLAW_NAME)
        .group_by(Finding.severity)
    )
    by_severity = {s.value: 0 for s in FindingSeverity}
    for sev, count in sev_result.all():
        by_severity[sev] = count

    # By provider
    prov_result = await db.execute(
        select(Finding.provider, func.count(Finding.id))
        .where(Finding.claw == CLAW_NAME)
        .group_by(Finding.provider)
    )
    by_provider = {}
    for provider, count in prov_result.all():
        by_provider[provider] = count

    # Total findings
    total_result = await db.execute(
        select(func.count(Finding.id)).where(Finding.claw == CLAW_NAME)
    )
    total_findings = total_result.scalar() or 0

    # Open count
    open_result = await db.execute(
        select(func.count(Finding.id))
        .where(Finding.claw == CLAW_NAME)
        .where(Finding.status == FindingStatus.OPEN)
    )
    open_count = open_result.scalar() or 0

    # Critical count
    critical_result = await db.execute(
        select(func.count(Finding.id))
        .where(Finding.claw == CLAW_NAME)
        .where(Finding.severity == FindingSeverity.CRITICAL)
    )
    critical_count = critical_result.scalar() or 0

    # Which providers appear in the findings
    providers_connected = list(by_provider.keys())

    return {
        "total_findings": total_findings,
        "by_severity": by_severity,
        "by_provider": by_provider,
        "open_count": open_count,
        "critical_count": critical_count,
        "providers_connected": providers_connected,
    }


@router.get("/findings", response_model=list[FindingRead])
async def get_cloudclaw_findings(
    severity: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    db: AsyncSession = Depends(get_db),
):
    """List CloudClaw findings with optional filters."""
    stmt = (
        select(Finding)
        .where(Finding.claw == CLAW_NAME)
        .order_by(desc(Finding.risk_score), desc(Finding.created_at))
    )

    if severity:
        stmt = stmt.where(Finding.severity == FindingSeverity(severity))
    if provider:
        stmt = stmt.where(Finding.provider == provider)
    if status:
        stmt = stmt.where(Finding.status == FindingStatus(status))

    stmt = stmt.limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get("/providers")
async def get_configured_providers(db: AsyncSession = Depends(get_db)):
    """
    Return which cloud providers are configured (have a registered connector + stored credentials).
    """
    output = []
    for cfg in PROVIDER_CONFIG:
        creds = await _get_provider_credentials(db, cfg["connector_type"])
        output.append({
            "provider": cfg["provider"],
            "label": cfg["label"],
            "configured": creds is not None,
        })
    return output


@router.post("/scan")
async def trigger_scan(db: AsyncSession = Depends(get_db)):
    """
    Trigger a cloud security scan across all configured providers.
    Uses the finding pipeline for deduplication, policy evaluation, and alert routing.
    """
    from app.services.finding_pipeline import ingest_findings

    provider_results = {}
    errors = []
    total_created = 0
    total_updated = 0

    for cfg in PROVIDER_CONFIG:
        provider_name = cfg["provider"]
        creds = await _get_provider_credentials(db, cfg["connector_type"])

        try:
            raw_findings = await cfg["adapter"].get_findings(credentials=creds)

            # Ensure each finding has the correct claw/provider fields
            for f in raw_findings:
                f.setdefault("claw", CLAW_NAME)
                f.setdefault("provider", provider_name)

            summary = await ingest_findings(db, CLAW_NAME, raw_findings)

            provider_results[provider_name] = {
                "status": "success",
                "created": summary["created"],
                "updated": summary["updated"],
                "critical": summary["critical"],
                "high": summary["high"],
                "simulated": creds is None,
            }
            total_created += summary["created"]
            total_updated += summary["updated"]

        except Exception as exc:
            logger.error("CloudClaw scan failed for %s: %s", provider_name, exc)
            errors.append({"provider": provider_name, "error": str(exc)})
            provider_results[provider_name] = {"status": "error", "error": str(exc)}

    status_msg = "completed" if not errors else "completed_with_errors"
    return {
        "status": status_msg,
        "findings_created": total_created,
        "findings_updated": total_updated,
        "providers": provider_results,
        "errors": errors,
        "message": (
            f"CloudClaw scan complete. {total_created} new findings, "
            f"{total_updated} updated across {len(PROVIDER_CONFIG)} providers."
        ),
    }
