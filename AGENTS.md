# RegentClaw Agent Operating Guide

## Project Purpose
RegentClaw is a Zero Trust security action engine for detection triage, policy-governed orchestration, and remediation workflows across modular Claw services.

## Stack
- Backend: FastAPI, SQLAlchemy async, PostgreSQL, Redis
- Frontend: Next.js 14, TypeScript, Tailwind
- Tooling: pytest, Docker Compose

## Architecture Overview
- `backend/app/trust_fabric/`: policy enforcement, anomaly scoring, containment
- `backend/app/core/swarm/`: parallel swarm orchestration, aggregation, judging
- `backend/app/claws/*/`: Claw modules with routes/providers
- `backend/app/api/routes/`: platform APIs
- `frontend/src/app/`: platform pages and module views

## Commands
- Backend dev: `cd backend && uvicorn main:app --reload`
- Frontend dev: `cd frontend && npm run dev`
- Frontend lint: `cd frontend && npm run lint`
- Frontend build: `cd frontend && npm run build`
- Backend tests: `cd backend && pytest`
- Full stack: `docker-compose up --build`

## Coding Conventions
- Keep diffs surgical and localized.
- Follow existing file/module patterns before adding abstractions.
- Keep UI consistent with existing design system and nav model.
- Avoid introducing new dependencies unless clearly necessary.

## Security Requirements
- Route security-sensitive actions through Trust Fabric checks.
- No bypass of policy evaluation for model, connector, or remediation actions.
- Preserve auditability for decisions and containment outcomes.
- Do not log raw secrets, tokens, or sensitive tenant payloads.

## Data Protection / Tenant Isolation
- Treat cross-tenant data mixing as a critical bug.
- Keep connector credentials scoped and encrypted.
- Redact or avoid sensitive values in errors and telemetry.

## Logging Rules
- Log outcome, reason, and identifiers; avoid sensitive body dumps.
- Prefer structured payloads over free-form debug logs.

## Do-Not-Touch Without Approval
- `backend/alembic/versions/` existing migrations
- secrets/key material under ignored local secret paths
- broad refactors of shared policy/runtime core outside scoped task

## Definition Of Done
- Feature works end-to-end with graceful failure handling.
- Existing tests/lint/build still pass for impacted layers.
- Any new route/page is discoverable and documented.
- Security implications and guardrails are preserved.

## PR / Review Expectations
- Include what changed, why, and verification steps.
- Call out limitations, TODOs, and risk areas explicitly.
- Keep unrelated churn out of the diff.

