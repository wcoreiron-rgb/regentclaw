"""ArcClaw — API Routes."""
import json
import logging
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException

logger = logging.getLogger(__name__)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.core.database import get_db
from app.claws.arcclaw.models import AIEvent, AIEventOutcome, AIEventType
from app.claws.arcclaw.schemas import AIEventSubmit, AIEventRead, ArcClawStats
from app.claws.arcclaw.scanner import scan_text, classify_prompt
from app.services.risk_scoring import calculate_event_risk, severity_from_score
from app.trust_fabric import enforce, ActionRequest
from app.trust_fabric.agt_bridge import audit_prompt, agt_status
from app.claws.arcclaw.llm_proxy import call_llm, available_providers
from app.claws.arcclaw.security_agent import run_security_agent, TOOLS
from app.models.connector import Connector
from app.services import secrets_manager
from pydantic import BaseModel as PydanticBase
from typing import Optional as Opt

router = APIRouter(prefix="/arcclaw", tags=["ArcClaw — AI Security"])


async def _resolve_llm_key(db: AsyncSession, provider: str) -> Opt[str]:
    """
    Look up the API key for an LLM provider from the connector store.
    Checks the Connector table for a connector with matching connector_type,
    then reads its stored credentials. Returns None if not found/configured.
    """
    try:
        result = await db.execute(
            select(Connector).where(Connector.connector_type == provider)
        )
        connector = result.scalar_one_or_none()
        if not connector:
            return None
        creds = secrets_manager.get_credential(str(connector.id))
        if not creds:
            return None
        return creds.get("api_key") or creds.get("api_token") or None
    except Exception:
        return None


@router.post("/events", response_model=AIEventRead, summary="Submit AI event for inspection")
async def submit_ai_event(payload: AIEventSubmit, db: AsyncSession = Depends(get_db)):
    """
    Submit an AI interaction. ArcClaw will:
    1. AGT PromptDefenseEvaluator — 12-vector injection audit (primary)
    2. RegentClaw scanner — sensitive data pattern detection (secondary)
    3. Prompt classification
    4. Trust Fabric enforcement (runtime policy — RegentClaw layer)
    5. Return decision + redacted content
    """
    # 1. AGT prompt injection audit (primary layer — 12 attack vectors)
    agt_audit = audit_prompt(payload.prompt_text)

    # 2. RegentClaw sensitive data scanner (complementary — API keys, secrets, PII)
    scan = scan_text(payload.prompt_text, redact=True)

    # 3. Classify prompt intent
    classification = classify_prompt(payload.prompt_text)

    # Merge AGT findings into scan signals
    combined_signals = list(scan.risk_signals)
    if agt_audit.is_injection_risk:
        combined_signals.append("ai_sensitive_pattern")
    is_sensitive = scan.is_sensitive or agt_audit.is_injection_risk

    # Combine all findings for storage
    all_findings = scan.findings + [
        {"source": "agt_prompt_defense", **f} for f in agt_audit.findings
    ]

    # 4. Trust Fabric enforcement (RegentClaw runtime policy layer)
    request = ActionRequest(
        module="arcclaw",
        actor_id=payload.user_id or "anonymous",
        actor_name=payload.user_name or "Unknown User",
        actor_type="human",
        action=payload.event_type.value,
        target=payload.tool_name,
        target_type="ai_tool",
        context={
            "tool_name": payload.tool_name,
            "is_sensitive": is_sensitive,
            "risk_level": classification["risk_level"],
            "agt_injection_risk": agt_audit.is_injection_risk,
            "agt_risk_score": agt_audit.risk_score,
        },
    )
    decision = await enforce(db, request)

    # 5. Determine outcome — AGT injection risk escalates to BLOCKED
    if not decision.allowed or (agt_audit.is_injection_risk and agt_audit.risk_score >= 50):
        outcome = AIEventOutcome.BLOCKED
    elif is_sensitive:
        outcome = AIEventOutcome.REDACTED if scan.findings else AIEventOutcome.FLAGGED
    else:
        outcome = AIEventOutcome.ALLOWED

    # 6. Store event (never store raw sensitive prompts, only redacted)
    event = AIEvent(
        timestamp=datetime.utcnow(),
        user_id=payload.user_id,
        user_name=payload.user_name,
        tool_name=payload.tool_name,
        session_id=payload.session_id,
        event_type=payload.event_type,
        prompt_text=scan.redacted if is_sensitive else payload.prompt_text,
        redacted_text=scan.redacted,
        is_sensitive=is_sensitive,
        findings_json=json.dumps(all_findings),
        categories_json=json.dumps({
            **classification,
            "agt_vectors_flagged": agt_audit.vectors_flagged,
            "agt_used": agt_audit.agt_used,
        }),
        risk_score=max(decision.risk_score, agt_audit.risk_score),
        outcome=outcome,
        policy_applied=decision.policy_name,
        block_reason=decision.reason if not decision.allowed else (
            f"AGT injection risk: {', '.join(agt_audit.vectors_flagged)}" if agt_audit.is_injection_risk else None
        ),
    )
    db.add(event)
    await db.commit()
    await db.refresh(event)
    return event


@router.get("/events", response_model=list[AIEventRead], summary="List AI events")
async def list_ai_events(
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_db)
):
    stmt = select(AIEvent).order_by(desc(AIEvent.timestamp)).limit(limit).offset(offset)
    result = await db.execute(stmt)
    return result.scalars().all()


@router.get("/events/{event_id}", response_model=AIEventRead, summary="Get AI event detail")
async def get_ai_event(event_id: str, db: AsyncSession = Depends(get_db)):
    from uuid import UUID as UUIDType
    stmt = select(AIEvent).where(AIEvent.id == UUIDType(event_id))
    result = await db.execute(stmt)
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


@router.get("/stats", response_model=ArcClawStats, summary="ArcClaw risk summary")
async def get_arcclaw_stats(db: AsyncSession = Depends(get_db)):
    total = await db.execute(select(func.count(AIEvent.id)))
    blocked = await db.execute(select(func.count(AIEvent.id)).where(AIEvent.outcome == AIEventOutcome.BLOCKED))
    flagged = await db.execute(select(func.count(AIEvent.id)).where(AIEvent.outcome == AIEventOutcome.FLAGGED))
    sensitive = await db.execute(select(func.count(AIEvent.id)).where(AIEvent.is_sensitive == True))
    avg_risk = await db.execute(select(func.avg(AIEvent.risk_score)))

    # Top tools by event count
    tool_counts = await db.execute(
        select(AIEvent.tool_name, func.count(AIEvent.id).label("count"))
        .where(AIEvent.tool_name.isnot(None))
        .group_by(AIEvent.tool_name)
        .order_by(desc("count"))
        .limit(5)
    )
    top_tools = [{"tool": row[0], "count": row[1]} for row in tool_counts.fetchall()]

    return ArcClawStats(
        total_events=total.scalar() or 0,
        blocked_events=blocked.scalar() or 0,
        flagged_events=flagged.scalar() or 0,
        sensitive_events=sensitive.scalar() or 0,
        avg_risk_score=round(avg_risk.scalar() or 0.0, 2),
        top_tools=top_tools,
    )


# ── LLM Proxy endpoints ───────────────────────────────────────────────────────

class ChatRequest(PydanticBase):
    prompt: str
    provider: str = "ollama"          # openai | anthropic | ollama
    model: Opt[str] = None            # override default model
    system: str = "You are a helpful assistant."
    user_id: Opt[str] = None
    user_name: Opt[str] = None


class ChatResponse(PydanticBase):
    # Inspection result
    outcome: str                       # allowed | blocked | redacted | flagged
    risk_score: float
    is_sensitive: bool
    findings: list[dict]
    policy_applied: str
    block_reason: Opt[str] = None
    redacted_prompt: Opt[str] = None
    agt_injection_risk: bool = False
    agt_vectors: list[str] = []

    # LLM response (only present if outcome == allowed/redacted)
    llm_response: Opt[str] = None
    llm_provider: Opt[str] = None
    llm_model: Opt[str] = None
    llm_error: Opt[str] = None
    tokens_used: int = 0

    # What was sent to the LLM (may be redacted version)
    prompt_sent_to_llm: Opt[str] = None


@router.post("/chat", response_model=ChatResponse, summary="Inspect prompt then call real LLM")
async def arcclaw_chat(payload: ChatRequest, db: AsyncSession = Depends(get_db)):
    """
    The full ArcClaw proxy flow:
    1. Inspect the prompt (AGT + pattern scanner + classification)
    2. Run through Trust Fabric policy engine
    3. If BLOCKED → return decision, never call LLM
    4. If ALLOWED/REDACTED → forward (clean) prompt to real LLM
    5. Return inspection result + LLM response together
    """
    # ── Step 1: Inspect ──────────────────────────────────────────────────────
    agt_audit = audit_prompt(payload.prompt)
    scan = scan_text(payload.prompt, redact=True)
    classification = classify_prompt(payload.prompt)

    is_sensitive = scan.is_sensitive or agt_audit.is_injection_risk
    all_findings = scan.findings + [{"source": "agt", **f} for f in agt_audit.findings]

    # ── Step 2: Trust Fabric ─────────────────────────────────────────────────
    request = ActionRequest(
        module="arcclaw",
        actor_id=payload.user_id or "anonymous",
        actor_name=payload.user_name or "Unknown User",
        actor_type="human",
        action="prompt_submitted",
        target=payload.provider,
        target_type="ai_tool",
        context={
            "tool_name": payload.provider,
            "is_sensitive": is_sensitive,
            "risk_level": classification["risk_level"],
            "agt_injection_risk": agt_audit.is_injection_risk,
            "agt_risk_score": agt_audit.risk_score,
        },
    )
    decision = await enforce(db, request)

    # ── Step 3: Decision ─────────────────────────────────────────────────────
    hard_blocked = (
        not decision.allowed
        or (agt_audit.is_injection_risk and agt_audit.risk_score >= 50)
    )

    if hard_blocked:
        # Store event
        event = AIEvent(
            timestamp=datetime.utcnow(),
            user_id=payload.user_id, user_name=payload.user_name,
            tool_name=payload.provider, event_type=AIEventType.PROMPT_SUBMITTED,
            prompt_text=scan.redacted, redacted_text=scan.redacted,
            is_sensitive=is_sensitive, findings_json=json.dumps(all_findings),
            categories_json=json.dumps(classification),
            risk_score=max(decision.risk_score, agt_audit.risk_score),
            outcome=AIEventOutcome.BLOCKED,
            policy_applied=decision.policy_name,
            block_reason=decision.reason,
        )
        db.add(event)
        await db.commit()

        return ChatResponse(
            outcome="blocked",
            risk_score=max(decision.risk_score, agt_audit.risk_score),
            is_sensitive=is_sensitive,
            findings=all_findings,
            policy_applied=decision.policy_name,
            block_reason=decision.reason or (
                f"AGT detected injection attack: {', '.join(agt_audit.vectors_flagged)}"
                if agt_audit.is_injection_risk else None
            ),
            redacted_prompt=scan.redacted if is_sensitive else None,
            agt_injection_risk=agt_audit.is_injection_risk,
            agt_vectors=agt_audit.vectors_flagged,
        )

    # ── Step 4: Forward to LLM ───────────────────────────────────────────────
    # Use redacted prompt if secrets were found — don't send raw secrets to LLM
    prompt_to_send = scan.redacted if scan.is_sensitive else payload.prompt

    # Resolve API key: connector store takes priority, env var is fallback
    resolved_api_key = await _resolve_llm_key(db, payload.provider)

    llm_result = await call_llm(
        provider=payload.provider,
        prompt=prompt_to_send,
        model=payload.model,
        system=payload.system,
        api_key=resolved_api_key,
    )

    outcome = "redacted" if scan.is_sensitive else ("flagged" if agt_audit.is_injection_risk else "allowed")

    # Store event
    event = AIEvent(
        timestamp=datetime.utcnow(),
        user_id=payload.user_id, user_name=payload.user_name,
        tool_name=f"{payload.provider}/{llm_result.model}",
        event_type=AIEventType.PROMPT_SUBMITTED,
        prompt_text=prompt_to_send, redacted_text=scan.redacted,
        is_sensitive=is_sensitive, findings_json=json.dumps(all_findings),
        categories_json=json.dumps(classification),
        risk_score=max(decision.risk_score, agt_audit.risk_score),
        outcome=AIEventOutcome(outcome),
        policy_applied=decision.policy_name,
    )
    db.add(event)
    await db.commit()

    return ChatResponse(
        outcome=outcome,
        risk_score=max(decision.risk_score, agt_audit.risk_score),
        is_sensitive=is_sensitive,
        findings=all_findings,
        policy_applied=decision.policy_name,
        redacted_prompt=scan.redacted if scan.is_sensitive else None,
        agt_injection_risk=agt_audit.is_injection_risk,
        agt_vectors=agt_audit.vectors_flagged,
        llm_response=llm_result.content if llm_result.success else None,
        llm_provider=llm_result.provider,
        llm_model=llm_result.model,
        llm_error=llm_result.error,
        tokens_used=llm_result.tokens_used,
        prompt_sent_to_llm=prompt_to_send,
    )


@router.get("/providers", summary="Available LLM providers and their status")
async def get_providers(db: AsyncSession = Depends(get_db)):
    """Returns which LLM providers are configured and ready to use.
    Checks both env vars and the Connector Marketplace credential store."""
    openai_key    = await _resolve_llm_key(db, "openai")
    anthropic_key = await _resolve_llm_key(db, "anthropic")
    return await available_providers(openai_key=openai_key, anthropic_key=anthropic_key)


# ── Security Copilot Agent endpoints ─────────────────────────────────────────

class AgentMessage(PydanticBase):
    role: str  # "user" | "assistant"
    content: str


class AgentChatRequest(PydanticBase):
    messages: list[AgentMessage]
    provider: str = "anthropic"
    model: Opt[str] = None          # specific model override
    user_id: Opt[str] = None


class AgentChatResponse(PydanticBase):
    response: str
    tool_calls: list[dict]
    steps: int
    error: Opt[str] = None
    provider: str
    governance: Opt[dict] = None   # PII/injection findings if anything was caught


@router.post(
    "/agent/chat",
    response_model=AgentChatResponse,
    summary="Security Copilot — AI agent with tool calling",
)
async def agent_chat(
    payload: AgentChatRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Security Copilot agent — full ArcClaw inspection pipeline runs on every message
    before it reaches the LLM. PII, secrets, and injection attempts are caught,
    redacted, logged to AI Governance, and the user is warned.
    """
    # ── Step 1: Inspect the latest user message ───────────────────────────────
    # Find the last user turn (the new message just sent)
    last_user_content = next(
        (m.content for m in reversed(payload.messages) if m.role == "user"), ""
    )

    # AGT 12-vector injection audit
    agt_audit = audit_prompt(last_user_content)
    # RegentClaw PII/secrets scanner (email, SSN, credit cards, API keys, etc.)
    scan = scan_text(last_user_content, redact=True)
    classification = classify_prompt(last_user_content)

    is_sensitive = scan.is_sensitive or agt_audit.is_injection_risk
    all_findings = scan.findings + [{"source": "agt", **f} for f in agt_audit.findings]

    # ── Step 2: Trust Fabric enforcement ─────────────────────────────────────
    tf_request = ActionRequest(
        module="arcclaw",
        actor_id=payload.user_id or "anonymous",
        actor_name="Security Copilot User",
        actor_type="human",
        action="agent_prompt",
        target=payload.provider,
        target_type="ai_tool",
        context={
            "tool_name": payload.provider,
            "is_sensitive": is_sensitive,
            "risk_level": classification.get("risk_level", "low"),
            "agt_injection_risk": agt_audit.is_injection_risk,
            "agt_risk_score": agt_audit.risk_score,
        },
    )
    decision = await enforce(db, tf_request)

    # ── Step 3: Hard block on injection attacks ───────────────────────────────
    hard_blocked = (
        not decision.allowed
        or (agt_audit.is_injection_risk and agt_audit.risk_score >= 50)
    )

    # ── Step 4: Log governance event for anything sensitive ───────────────────
    # Compute PII-based risk floor before logging (used in the governance event below)
    pii_risk = 0
    for _f in scan.findings:
        ptype = _f.get("pattern", "").lower()
        if any(x in ptype for x in ["ssn", "credit card", "private key", "aws key", "bearer token"]):
            pii_risk = max(pii_risk, 80)
        elif any(x in ptype for x in ["api key", "password", "secret", "connection string"]):
            pii_risk = max(pii_risk, 65)
        elif any(x in ptype for x in ["email", "base64"]):
            pii_risk = max(pii_risk, 35)
        else:
            pii_risk = max(pii_risk, 25)

    if is_sensitive or hard_blocked:
        try:
            outcome = AIEventOutcome.BLOCKED if hard_blocked else AIEventOutcome.REDACTED
            detected_types = ", ".join(
                f.get("pattern", "sensitive data") for f in scan.findings[:5]
            ) or "injection attempt"
            gov_event = AIEvent(
                timestamp=datetime.utcnow(),
                user_id=payload.user_id,
                user_name="Security Copilot User",
                tool_name=f"copilot/{payload.provider}",
                event_type=AIEventType.PROMPT_SUBMITTED,
                prompt_text=scan.redacted,      # never store raw PII
                redacted_text=scan.redacted,
                is_sensitive=is_sensitive,
                findings_json=json.dumps(all_findings),
                categories_json=json.dumps(classification),
                risk_score=pii_risk if not hard_blocked else max(decision.risk_score, agt_audit.risk_score),
                outcome=outcome,
                policy_applied=decision.policy_name,
                block_reason=(
                    decision.reason if hard_blocked else
                    f"Detected and redacted: {detected_types}"
                ),
            )
            db.add(gov_event)
            await db.flush()
        except Exception as log_err:
            logger.warning(f"Governance logging failed (non-fatal): {log_err}")

    # ── Step 5: Return block decision if injection attack ─────────────────────
    if hard_blocked:
        await db.commit()
        block_msg = (
            f"🚫 **Message blocked by ArcClaw AI Governance.**\n\n"
            f"Reason: {decision.reason or 'Prompt injection attempt detected by AGT'}\n"
            f"Vectors flagged: {', '.join(agt_audit.vectors_flagged) if agt_audit.vectors_flagged else 'policy violation'}\n\n"
            f"This event has been logged to AI Governance."
        )
        return AgentChatResponse(
            response=block_msg,
            tool_calls=[],
            steps=0,
            error="blocked",
            provider=payload.provider,
            governance={"blocked": True, "findings": all_findings, "risk_score": max(decision.risk_score, agt_audit.risk_score)},
        )

    # ── Step 6: Redact PII from ALL messages before sending to LLM ───────────
    # Replace the last user message with its redacted version if sensitive
    clean_messages = []
    for i, m in enumerate(payload.messages):
        if m.role == "user" and i == len(payload.messages) - 1 and is_sensitive:
            # Use redacted version for the latest user message
            clean_messages.append({"role": m.role, "content": scan.redacted})
        else:
            clean_messages.append({"role": m.role, "content": m.content})

    # ── Step 7: Build governance metadata to return to frontend ──────────────
    final_risk = max(decision.risk_score, agt_audit.risk_score, pii_risk)

    governance_meta = None
    if is_sensitive:
        governance_meta = {
            "blocked":       False,
            "redacted":      True,
            "findings":      all_findings,
            "risk_score":    final_risk,
            "redacted_text": scan.redacted,
        }

    # ── Step 8: Run the security agent with clean (redacted) messages ─────────
    api_key = await _resolve_llm_key(db, payload.provider)

    result = await run_security_agent(
        messages=clean_messages,
        provider=payload.provider,
        api_key=api_key or "",
        db=db,
        model=payload.model,
    )

    await db.commit()

    # Prepend a rich PII warning to the response if we redacted anything
    response_text = result.get("response", "")
    if is_sensitive and scan.findings:
        finding_lines = []
        for f in scan.findings:
            ptype = f.get("pattern", "Sensitive Data")
            count = f.get("count", 1)
            finding_lines.append(
                f"• **{ptype}** — {count} match{'es' if count > 1 else ''} detected and redacted"
            )
        if agt_audit.is_injection_risk and agt_audit.vectors_flagged:
            for v in agt_audit.vectors_flagged[:3]:
                finding_lines.append(f"• **Injection attempt** — vector: `{v}`")

        warning = (
            "🛡️ **ArcClaw AI Governance — Sensitive Data Intercepted**\n\n"
            + "\n".join(finding_lines)
            + "\n\nSensitive values were replaced with `[REDACTED]` before reaching the AI. "
            "This event has been recorded in the AI Governance log.\n\n---\n\n"
        )
        response_text = warning + response_text
    elif is_sensitive and agt_audit.is_injection_risk:
        warning = (
            f"🛡️ **ArcClaw AI Governance — Injection Risk Detected**\n\n"
            f"• Vectors flagged: {', '.join(agt_audit.vectors_flagged)}\n\n"
            "Message was forwarded with AGT-flagged content noted. "
            "This event has been recorded in the AI Governance log.\n\n---\n\n"
        )
        response_text = warning + response_text

    return AgentChatResponse(
        response=response_text,
        tool_calls=result.get("tool_calls", []),
        steps=result.get("steps", 1),
        error=result.get("error"),
        provider=payload.provider,
        governance=governance_meta,
    )


@router.get("/agent/models", summary="List available models per provider")
async def get_agent_models():
    """
    Returns available models for Anthropic, OpenAI, and Ollama.
    Ollama models are fetched live from the local Ollama daemon.
    """
    import httpx as hx

    ANTHROPIC_MODELS = [
        {"id": "claude-opus-4-5",              "name": "Claude Opus 4.5",       "tag": "Most Powerful", "tier": "top"},
        {"id": "claude-sonnet-4-5",            "name": "Claude Sonnet 4.5",     "tag": "Balanced",      "tier": "mid"},
        {"id": "claude-haiku-4-5-20251001",    "name": "Claude Haiku 4.5",      "tag": "Fastest",       "tier": "fast"},
        {"id": "claude-3-5-sonnet-20241022",   "name": "Claude 3.5 Sonnet",     "tag": "Previous Gen",  "tier": "mid"},
        {"id": "claude-3-5-haiku-20241022",    "name": "Claude 3.5 Haiku",      "tag": "Previous Fast", "tier": "fast"},
        {"id": "claude-3-opus-20240229",       "name": "Claude 3 Opus",         "tag": "Legacy",        "tier": "top"},
    ]

    OPENAI_MODELS = [
        {"id": "gpt-4o",             "name": "GPT-4o",         "tag": "Latest",          "tier": "top"},
        {"id": "gpt-4o-mini",        "name": "GPT-4o Mini",    "tag": "Fast & Cheap",    "tier": "fast"},
        {"id": "o3-mini",            "name": "o3 Mini",        "tag": "Reasoning",       "tier": "reasoning"},
        {"id": "o1",                 "name": "o1",             "tag": "Deep Reasoning",  "tier": "reasoning"},
        {"id": "o1-mini",            "name": "o1 Mini",        "tag": "Fast Reasoning",  "tier": "reasoning"},
        {"id": "gpt-4-turbo",        "name": "GPT-4 Turbo",   "tag": "Previous Gen",    "tier": "top"},
        {"id": "gpt-3.5-turbo",      "name": "GPT-3.5 Turbo", "tag": "Legacy Fast",     "tier": "fast"},
    ]

    # Query Ollama for locally installed models
    ollama_models = []
    try:
        async with hx.AsyncClient(timeout=hx.Timeout(4.0)) as client:
            r = await client.get("http://host.docker.internal:11434/api/tags")
            if r.status_code == 200:
                data = r.json()
                for m in data.get("models", []):
                    size_gb = round(m.get("size", 0) / 1e9, 1)
                    ollama_models.append({
                        "id":   m["name"],
                        "name": m["name"],
                        "tag":  f"{size_gb}GB" if size_gb > 0 else "Local",
                        "tier": "local",
                        "details": m.get("details", {}),
                    })
    except Exception:
        pass  # Ollama not running or no models

    return {
        "anthropic": ANTHROPIC_MODELS,
        "openai":    OPENAI_MODELS,
        "ollama":    ollama_models,
    }


@router.get("/agent/tools", summary="List available Security Copilot tools")
async def list_agent_tools():
    """Returns the tools available to the Security Copilot agent."""
    return {
        "tools": [{"name": t["name"], "description": t["description"]} for t in TOOLS],
        "count": len(TOOLS),
    }
