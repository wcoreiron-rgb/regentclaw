"""
Seed the Governed Execution Channels with credential broker entries.
Run: python seed_exec_channels.py
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

import uuid
from datetime import datetime, timedelta
from app.database import SessionLocal, engine, Base
from app.models.exec_channels import CredentialBrokerEntry

Base.metadata.create_all(bind=engine)

CREDENTIALS = [
    {
        "name": "crowdstrike-api-key",
        "description": "CrowdStrike Falcon API key for EndpointClaw and ThreatClaw",
        "secret_path": "secrets/crowdstrike/api_key",
        "secret_type": "api_key",
        "owner": "EndpointClaw",
        "allowed_claws": ["EndpointClaw", "ThreatClaw"],
        "allowed_envs": ["dev", "staging", "prod"],
        "requires_approval": False,
        "max_uses_per_hour": 100,
    },
    {
        "name": "aws-admin-credentials",
        "description": "AWS admin credentials for CloudClaw production operations",
        "secret_path": "secrets/aws/admin_credentials",
        "secret_type": "password",
        "owner": "CloudClaw",
        "allowed_claws": ["CloudClaw"],
        "allowed_envs": ["prod"],
        "requires_approval": True,
        "max_uses_per_hour": 10,
    },
    {
        "name": "azure-service-principal",
        "description": "Azure Service Principal for IdentityClaw and AccessClaw",
        "secret_path": "secrets/azure/service_principal",
        "secret_type": "certificate",
        "owner": "IdentityClaw",
        "allowed_claws": ["IdentityClaw", "AccessClaw"],
        "allowed_envs": ["dev", "staging", "prod"],
        "requires_approval": False,
        "max_uses_per_hour": 200,
    },
    {
        "name": "splunk-hec-token",
        "description": "Splunk HTTP Event Collector token for LogClaw",
        "secret_path": "secrets/splunk/hec_token",
        "secret_type": "token",
        "owner": "LogClaw",
        "allowed_claws": ["LogClaw"],
        "allowed_envs": ["dev", "staging", "prod"],
        "requires_approval": False,
        "max_uses_per_hour": 1000,
    },
    {
        "name": "github-pat",
        "description": "GitHub Personal Access Token for DevClaw",
        "secret_path": "secrets/github/pat",
        "secret_type": "token",
        "owner": "DevClaw",
        "allowed_claws": ["DevClaw", "AppClaw"],
        "allowed_envs": ["dev", "staging"],
        "requires_approval": False,
        "max_uses_per_hour": 500,
    },
    {
        "name": "production-db-password",
        "description": "Production database password — requires dual approval",
        "secret_path": "secrets/db/production_password",
        "secret_type": "password",
        "owner": "DataClaw",
        "allowed_claws": ["DataClaw"],
        "allowed_envs": ["prod"],
        "requires_approval": True,
        "max_uses_per_hour": 5,
        "rotation_due": datetime.utcnow() + timedelta(days=30),
    },
    {
        "name": "ssh-deploy-key",
        "description": "SSH deploy key for production server access",
        "secret_path": "secrets/ssh/deploy_key",
        "secret_type": "ssh_key",
        "owner": "platform",
        "allowed_claws": [],
        "allowed_envs": ["prod"],
        "requires_approval": True,
        "max_uses_per_hour": 20,
    },
]


def seed():
    db = SessionLocal()
    try:
        for c in CREDENTIALS:
            existing = db.query(CredentialBrokerEntry).filter(
                CredentialBrokerEntry.name == c["name"]
            ).first()
            if not existing:
                entry = CredentialBrokerEntry(
                    id          = str(uuid.uuid4()),
                    created_at  = datetime.utcnow(),
                    is_active   = True,
                    use_count   = 0,
                    **{k: v for k, v in c.items() if k != "rotation_due"},
                )
                if "rotation_due" in c:
                    entry.rotation_due = c["rotation_due"]
                db.add(entry)
                print(f"  + Credential: {c['name']}")
        db.commit()
        print(f"\nSeeded {len(CREDENTIALS)} credential broker entries.")
    finally:
        db.close()


if __name__ == "__main__":
    seed()
