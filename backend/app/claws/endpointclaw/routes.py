"""EndpointClaw — Endpoint Security API Routes."""
import logging
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.core.database import get_db
from app.models.finding import Finding, FindingSeverity, FindingStatus
from app.models.connector import Connector
from app.services.secrets_manager import get_credential
from app.claws.endpointclaw.providers import crowdstrike as crowdstrike_adapter
from app.claws.endpointclaw.providers import defender as defender_adapter
from app.claws.endpointclaw.providers import sentinelone as sentinelone_adapter

logger = logging.getLogger("endpointclaw")

router = APIRouter(prefix="/endpointclaw", tags=["EndpointClaw — Endpoint Security"])

CLAW_NAME = "endpointclaw"

PROVIDER_CONFIG = [
    {"provider": "crowdstrike",          "connector_type": "crowdstrike",         "adapter": crowdstrike_adapter},
    {"provider": "defender_endpoint",    "connector_type": "defender_endpoint",   "adapter": defender_adapter},
    {"provider": "sentinelone",          "connector_type": "sentinelone",         "adapter": sentinelone_adapter},
]


async def _get_credentials(db: AsyncSession, connector_type: str) -> Optional[dict]:
    result = await db.execute(select(Connector).where(Connector.connector_type == connector_type))
    conn = result.scalar_one_or_none()
    if not conn:
        return None
    return get_credential(str(conn.id))


@router.get("/stats", summary="EndpointClaw summary statistics")
async def get_stats(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Finding).where(Finding.claw == "endpointclaw"))
    findings = result.scalars().all()

    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    by_category = {"malware": 0, "outdated_os": 0, "missing_edr": 0, "unencrypted_disk": 0}
    open_count = 0
    endpoints_at_risk = set()

    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else f.severity
        if sev in by_severity:
            by_severity[sev] += 1
        cat = f.category or ""
        if cat in by_category:
            by_category[cat] += 1
        status = f.status.value if hasattr(f.status, "value") else f.status
        if status == "open":
            open_count += 1
        if f.resource_id:
            endpoints_at_risk.add(f.resource_id)

    return {
        "total_findings": len(findings),
        "by_severity": by_severity,
        "endpoints_at_risk": len(endpoints_at_risk),
        "open_count": open_count,
        "by_category": by_category,
    }


@router.get("/findings", summary="All EndpointClaw findings")
async def get_findings(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Finding).where(Finding.claw == "endpointclaw").order_by(Finding.risk_score.desc())
    )
    findings = result.scalars().all()
    return [
        {
            "id": str(f.id),
            "claw": f.claw,
            "provider": f.provider,
            "title": f.title,
            "description": f.description,
            "category": f.category,
            "severity": f.severity.value if hasattr(f.severity, "value") else f.severity,
            "status": f.status.value if hasattr(f.status, "value") else f.status,
            "resource_id": f.resource_id,
            "resource_type": f.resource_type,
            "resource_name": f.resource_name,
            "region": f.region,
            "cvss_score": f.cvss_score,
            "epss_score": f.epss_score,
            "risk_score": f.risk_score,
            "actively_exploited": f.actively_exploited,
            "remediation": f.remediation,
            "remediation_effort": f.remediation_effort,
            "external_id": f.external_id,
            "first_seen": f.first_seen.isoformat() if f.first_seen else None,
            "last_seen": f.last_seen.isoformat() if f.last_seen else None,
        }
        for f in findings
    ]


@router.post("/scan", summary="Scan all configured endpoint security providers")
async def run_scan(db: AsyncSession = Depends(get_db)):
    """
    Scan all configured endpoint security providers (CrowdStrike, Defender, SentinelOne).
    Uses the finding pipeline for deduplication, policy evaluation, and alert routing.
    """
    from app.services.finding_pipeline import ingest_findings

    provider_results = {}
    errors = []
    total_created = 0
    total_updated = 0

    for cfg in PROVIDER_CONFIG:
        provider_name = cfg["provider"]
        creds = await _get_credentials(db, cfg["connector_type"])

        try:
            raw_findings = await cfg["adapter"].get_findings(credentials=creds)
            for f in raw_findings:
                f.setdefault("claw", CLAW_NAME)
                f.setdefault("provider", provider_name)

            summary = await ingest_findings(db, CLAW_NAME, raw_findings)
            provider_results[provider_name] = {
                "status": "success",
                "created": summary["created"],
                "updated": summary["updated"],
                "simulated": creds is None,
            }
            total_created += summary["created"]
            total_updated += summary["updated"]
        except Exception as exc:
            logger.error("EndpointClaw scan failed for %s: %s", provider_name, exc)
            errors.append({"provider": provider_name, "error": str(exc)})
            provider_results[provider_name] = {"status": "error", "error": str(exc)}

    return {
        "status": "completed" if not errors else "completed_with_errors",
        "findings_created": total_created,
        "findings_updated": total_updated,
        "providers": provider_results,
        "errors": errors,
    }


PROVIDER_MAP = [
    {"provider": "crowdstrike_falcon",             "label": "CrowdStrike Falcon",              "connector_type": "crowdstrike"},
    {"provider": "microsoft_defender_endpoint",    "label": "Microsoft Defender for Endpoint", "connector_type": "defender_endpoint"},
    {"provider": "sentinelone",                    "label": "SentinelOne",                     "connector_type": "sentinelone"},
]


@router.get("/providers", summary="EndpointClaw provider connection status")
async def get_providers(db: AsyncSession = Depends(get_db)):
    from app.services.connector_check import check_providers
    return await check_providers(db, PROVIDER_MAP)
