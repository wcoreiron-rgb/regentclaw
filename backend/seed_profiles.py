"""
Seed MemoryClaw behavioral profiles with realistic demo data.
Generates entity profiles (users, agents, assets, connectors) and
behavior events that demonstrate the anomaly detection engine working.

Run: python seed_profiles.py
"""
import sys, os, random
from datetime import datetime, timedelta
sys.path.insert(0, os.path.dirname(__file__))

from app.database import SessionLocal, engine, Base
from app.services.profile_service import log_behavior_event, recompute_baseline

Base.metadata.create_all(bind=engine)

# ──────────────────────────────────────────────────────────────────────────────
# Entity definitions
# ──────────────────────────────────────────────────────────────────────────────
ENTITIES = [
    # Normal users — plenty of events to build a solid baseline
    {
        "entity_id":   "alice@company.com",
        "entity_type": "user",
        "display_name": "Alice Chen",
        "source_claw": "identityclaw",
        "profile": "normal",           # routine 9-to-5, login + read + api_call
    },
    {
        "entity_id":   "bob@company.com",
        "entity_type": "user",
        "display_name": "Bob Martinez",
        "source_claw": "identityclaw",
        "profile": "normal",
    },
    {
        "entity_id":   "carol@company.com",
        "entity_type": "user",
        "display_name": "Carol Singh",
        "source_claw": "identityclaw",
        "profile": "anomalous_time",   # logs in at 3am (off-hours anomaly)
    },
    {
        "entity_id":   "dave@company.com",
        "entity_type": "user",
        "display_name": "Dave Okonkwo",
        "source_claw": "identityclaw",
        "profile": "velocity_spike",   # sudden burst of 400 events in 1 hour
    },
    {
        "entity_id":   "eve.contractor@external.io",
        "entity_type": "user",
        "display_name": "Eve (Contractor)",
        "source_claw": "accessclaw",
        "profile": "new_claw",         # starts touching claws outside her typical set
    },
    # Service accounts
    {
        "entity_id":   "svc-crowdstrike-sync",
        "entity_type": "service_account",
        "display_name": "CrowdStrike Sync Service",
        "source_claw": "endpointclaw",
        "profile": "normal",
    },
    {
        "entity_id":   "svc-backup-agent",
        "entity_type": "service_account",
        "display_name": "Backup Agent",
        "source_claw": "dataclaw",
        "profile": "anomalous_action",  # starts running 'delete' instead of 'backup'
    },
    # Agents
    {
        "entity_id":   "agent-threat-hunter-001",
        "entity_type": "agent",
        "display_name": "ThreatHunter Agent",
        "source_claw": "threatclaw",
        "profile": "normal",
    },
    {
        "entity_id":   "agent-compliance-sweep",
        "entity_type": "agent",
        "display_name": "Compliance Sweep Agent",
        "source_claw": "complianceclaw",
        "profile": "high_anomaly",      # multiple anomaly signals simultaneously
    },
    # Assets / IPs
    {
        "entity_id":   "192.168.1.45",
        "entity_type": "ip",
        "display_name": "Internal Workstation",
        "source_claw": "netclaw",
        "profile": "normal",
    },
    {
        "entity_id":   "203.0.113.99",
        "entity_type": "ip",
        "display_name": "Suspicious External IP",
        "source_claw": "netclaw",
        "profile": "high_anomaly",
    },
]

# ──────────────────────────────────────────────────────────────────────────────
# Action libraries per profile type
# ──────────────────────────────────────────────────────────────────────────────
NORMAL_ACTIONS    = ["login", "read", "api_call", "logout", "search", "download", "upload"]
ADMIN_ACTIONS     = ["login", "read", "api_call", "scan", "policy_check", "audit", "export"]
THREAT_ACTIONS    = ["scan", "query", "alert", "enrich", "correlate", "triage", "report"]
NETWORK_ACTIONS   = ["connect", "dns_lookup", "http_request", "port_scan", "tls_handshake"]
ANOMALOUS_ACTIONS = ["delete", "bulk_export", "credential_access", "lateral_move", "exec"]

NORMAL_CLAWS = {
    "user":            ["identityclaw", "accessclaw"],
    "service_account": ["endpointclaw", "dataclaw", "logclaw"],
    "agent":           ["threatclaw", "complianceclaw"],
    "ip":              ["netclaw"],
}

# ──────────────────────────────────────────────────────────────────────────────
# Event generation helpers
# ──────────────────────────────────────────────────────────────────────────────
NOW = datetime.utcnow()

def _past(hours: float) -> datetime:
    return NOW - timedelta(hours=hours)

def _business_hour() -> int:
    """Return a random hour in typical business window (8–18)."""
    return random.randint(8, 17)

def _off_hour() -> int:
    """Return a random off-hours hour (0–6 or 22–23)."""
    return random.choice(list(range(0, 6)) + [22, 23])


def build_events(entity: dict) -> list[dict]:
    """Return a list of event kwargs for log_behavior_event()."""
    eid   = entity["entity_id"]
    etype = entity["entity_type"]
    stype = entity.get("source_claw", "identityclaw")
    prof  = entity["profile"]
    events = []

    base_claws = NORMAL_CLAWS.get(etype, ["identityclaw"])

    # ── 1. Normal baseline (30–60 events spread over 7 days) ─────────────────
    baseline_count = random.randint(30, 60)
    base_actions   = ADMIN_ACTIONS if etype in ("agent", "service_account") else NORMAL_ACTIONS

    for i in range(baseline_count):
        hours_ago = random.uniform(24, 168)  # 1–7 days ago
        hour = _business_hour()
        events.append({
            "entity_id":   eid,
            "entity_type": etype,
            "claw":        random.choice(base_claws),
            "action":      random.choice(base_actions),
            "resource":    f"resource/{random.choice(['config','data','report','api'])}/{random.randint(1,20)}",
            "outcome":     "allowed",
            "display_name": entity["display_name"],
            "source_claw": stype,
            "_occurred_at": NOW - timedelta(hours=hours_ago, minutes=random.randint(0, 59)),
            "_hour": hour,
        })

    # ── 2. Profile-specific anomalous events ──────────────────────────────────

    if prof == "anomalous_time":
        # Off-hours logins in the last 6 hours
        for i in range(6):
            hour = _off_hour()
            events.append({
                "entity_id":   eid,
                "entity_type": etype,
                "claw":        base_claws[0],
                "action":      "login",
                "resource":    "auth/session",
                "outcome":     "allowed",
                "display_name": entity["display_name"],
                "source_claw": stype,
                "_occurred_at": NOW - timedelta(hours=random.uniform(0.5, 5)),
                "_hour": hour,
            })

    elif prof == "velocity_spike":
        # 40 events in the last 30 minutes
        for i in range(40):
            events.append({
                "entity_id":   eid,
                "entity_type": etype,
                "claw":        base_claws[0],
                "action":      random.choice(["api_call", "download", "read"]),
                "resource":    f"bulk/export/{random.randint(1, 5)}",
                "outcome":     "allowed",
                "display_name": entity["display_name"],
                "source_claw": stype,
                "_occurred_at": NOW - timedelta(minutes=random.uniform(1, 30)),
                "_hour": NOW.hour,
            })

    elif prof == "new_claw":
        # Actions via claws she's never used before
        new_claws = ["cloudclaw", "threatclaw", "dataclaw", "appclaw"]
        for i in range(8):
            events.append({
                "entity_id":   eid,
                "entity_type": etype,
                "claw":        random.choice(new_claws),
                "action":      random.choice(["scan", "export", "query", "access"]),
                "resource":    f"admin/sensitive/{random.randint(1,10)}",
                "outcome":     "allowed",
                "display_name": entity["display_name"],
                "source_claw": stype,
                "_occurred_at": NOW - timedelta(hours=random.uniform(0.5, 3)),
                "_hour": _business_hour(),
            })

    elif prof == "anomalous_action":
        # Rare/unexpected actions
        for i in range(5):
            events.append({
                "entity_id":   eid,
                "entity_type": etype,
                "claw":        base_claws[0],
                "action":      random.choice(ANOMALOUS_ACTIONS),
                "resource":    "prod/backup/archive",
                "outcome":     random.choice(["allowed", "anomalous"]),
                "display_name": entity["display_name"],
                "source_claw": stype,
                "_occurred_at": NOW - timedelta(hours=random.uniform(1, 12)),
                "_hour": _business_hour(),
            })

    elif prof == "high_anomaly":
        # Combination: off-hours + new claw + anomalous action
        new_claws = ["identityclaw", "accessclaw", "cloudclaw"]
        for i in range(10):
            hour = _off_hour() if i < 4 else _business_hour()
            events.append({
                "entity_id":   eid,
                "entity_type": etype,
                "claw":        random.choice(new_claws),
                "action":      random.choice(ANOMALOUS_ACTIONS),
                "resource":    f"prod/admin/{random.randint(1,5)}",
                "outcome":     "anomalous",
                "display_name": entity["display_name"],
                "source_claw": stype,
                "_occurred_at": NOW - timedelta(hours=random.uniform(0.5, 6)),
                "_hour": hour,
            })

    return events


# ──────────────────────────────────────────────────────────────────────────────
# Main seeder
# ──────────────────────────────────────────────────────────────────────────────
def seed():
    db = SessionLocal()
    total_entities = 0
    total_events   = 0

    try:
        for entity in ENTITIES:
            print(f"\n  → {entity['display_name']} ({entity['entity_id']})  [{entity['profile']}]")
            events = build_events(entity)

            for ev in events:
                # Pop internal scheduling keys
                occurred_at = ev.pop("_occurred_at")
                hour        = ev.pop("_hour")

                result = log_behavior_event(
                    db,
                    entity_id    = ev["entity_id"],
                    entity_type  = ev["entity_type"],
                    claw         = ev["claw"],
                    action       = ev["action"],
                    resource     = ev.get("resource", ""),
                    outcome      = ev.get("outcome", "allowed"),
                    display_name = ev.get("display_name", ""),
                    source_claw  = ev.get("source_claw", ""),
                    workflow_run_id = "",
                    agent_id     = "",
                    finding_id   = "",
                    incident_id  = "",
                    metadata     = {},
                )
                # Back-patch occurred_at and hour to simulate historical events
                from app.models.entity_profile import BehaviorEvent
                ev_row = db.query(BehaviorEvent).filter(BehaviorEvent.id == result["event_id"]).first()
                if ev_row:
                    ev_row.occurred_at = occurred_at
                    ev_row.hour_of_day = hour
                db.commit()

                total_events += 1

            # Force a full baseline recomputation after all events are loaded
            recompute_baseline(db, entity["entity_id"])

            # Read back final profile state for summary
            from app.models.entity_profile import EntityProfile as EP
            p = db.query(EP).filter(EP.entity_id == entity["entity_id"]).first()
            if p:
                print(f"     events={p.event_count}  anomaly_level={p.anomaly_level}  "
                      f"anomaly_score={p.anomaly_score:.1f}  risk={p.risk_score:.1f}  "
                      f"baseline={'✓' if p.baseline_established else '…building'}")

            total_entities += 1

    finally:
        db.close()

    print(f"\n✓ Seeded {total_entities} entity profiles with {total_events} behavior events.")


if __name__ == "__main__":
    random.seed(42)   # deterministic for reproducibility
    seed()
