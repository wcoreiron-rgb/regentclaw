# RegentClaw Maturity Matrix (2026)

**Date:** 2026-05-29  
**Purpose:** Public, conservative status tracking for platform security/runtime maturity.

Status legend:
- **Shipped**: in mainline runtime with verifiable behavior.
- **In Progress**: partially implemented or feature-flagged; not complete.
- **Planned**: scoped, not yet implemented.

| Capability Area | Status | Current Evidence | Gaps to Close |
|---|---|---|---|
| Cryptographic agent identity mesh | In Progress | Ed25519 inter-agent signing + verify endpoint | Full attestation mesh (SPIFFE-like), key lifecycle/rotation policy |
| Hard execution isolation model | In Progress | Ring policy + Trust Fabric ring decisions | Uniform enforcement across all action paths + hardened OS sandbox guarantees |
| Formal SRE governance layer | In Progress | Error-budget + circuit-breaker primitives, SRE API/status | Published SLO docs, error-budget policy packs, richer telemetry/export |
| OWASP Agentic Top 10 evidence mapping | In Progress | Dedicated ASI mapping markdown + linked controls | Per-category adversarial tests and deeper evidence anchors |
| Inter-agent secure messaging (prod default) | In Progress | Feature-flagged signed secure channel in swarm paths | Default-on rollout + key governance + replay resistance policy |
| Policy test harness strength | In Progress | Ring tests + trust-fabric regressions | Deny/allow pack expansion, replay/chaos regression suites, CI policy gates |
| Multi-tenant hardening proof | Planned | Foundational model separation patterns | Explicit tenant-isolation test suite + boundary documentation |
| Connector trust/provenance verification | In Progress | Gateway scan/policy checks on installs | Signed provenance and checksum verification chain |
| Operator-grade executive reporting | In Progress | Trust Fabric dashboard + probes + status panels | Executive risk rollups linked to evidence/compliance controls |
| Public maturity transparency | In Progress | This matrix + OWASP split docs | Keep matrix synced with code and tests each release |

---

## Reference Documents

- `docs/owasp-agentic-mapping.md` (LLM Top 10 mapping)
- `docs/owasp-asi-mapping.md` (Agentic ASI Top 10 mapping)
- `backend/app/trust_fabric/enforcement.py`
- `backend/app/services/sre_policy.py`
- `backend/app/services/ring_policy.py`

