"""TerraClaw — Terraform Security & Governance Claw."""
import re
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from app.core.database import get_db
from app.models.finding import Finding
from app.services.connector_check import is_connector_configured
from app.trust_fabric import ActionRequest, enforce
from app.claws.arcclaw.scanner import scan_text, classify_prompt
from app.trust_fabric.agt_bridge import audit_prompt
from app.claws.terraclaw.terraform_mcp import get_provider_hints, mcp_available

router = APIRouter(prefix="/terraclaw", tags=["TerraClaw"])

CLAW_NAME = "terraclaw"

PROVIDER_MAP = [
    {"provider": "terraform_cloud", "label": "Terraform Cloud",  "connector_type": "terraform_cloud"},
    {"provider": "tfsec",           "label": "tfsec / Trivy",    "connector_type": "tfsec"},
    {"provider": "checkov",         "label": "Checkov",          "connector_type": "checkov"},
    {"provider": "infracost",       "label": "Infracost",        "connector_type": "infracost"},
]

# ─── Security rule engine ─────────────────────────────────────────────────────

_RULES = [
    {
        "id": "TC-NET-001",
        "name": "Security Group / NSG open to internet (SSH port 22)",
        "category": "networking",
        "pattern": r'(from_port\s*=\s*"?22"?|destination_port_range\s*=\s*"?22"?)[\s\S]{0,300}(cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]|source_address_prefix\s*=\s*"\*")',
        "severity": "CRITICAL",
        "risk_delta": 30,
        "secure_score_delta": -20,
        "frameworks": ["CIS AWS 4.1", "CIS Azure 6.2", "NIST AC-17", "SOC2 CC6.6"],
        "remediation": "Restrict SSH access to known IP ranges or route through a VPN/bastion host. Remove 0.0.0.0/0 from ingress rules.",
    },
    {
        "id": "TC-NET-002",
        "name": "Security Group / NSG open to internet (RDP port 3389)",
        "category": "networking",
        "pattern": r'(from_port\s*=\s*"?3389"?|destination_port_range\s*=\s*"?3389"?)[\s\S]{0,300}(cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]|source_address_prefix\s*=\s*"\*")',
        "severity": "CRITICAL",
        "risk_delta": 30,
        "secure_score_delta": -20,
        "frameworks": ["CIS AWS 4.2", "CIS Azure 6.1", "NIST AC-17", "SOC2 CC6.6"],
        "remediation": "Disable RDP access from the internet. Use Azure Bastion, AWS Systems Manager Session Manager, or a VPN.",
    },
    {
        "id": "TC-NET-003",
        "name": "Wildcard ingress from internet (0.0.0.0/0 or *)",
        "category": "networking",
        "pattern": r'(cidr_blocks\s*=\s*\["0\.0\.0\.0/0"\]|source_address_prefix\s*=\s*"\*")',
        "severity": "HIGH",
        "risk_delta": 20,
        "secure_score_delta": -12,
        "frameworks": ["CIS AWS 4.1", "CIS Azure 6.2", "NIST SC-7"],
        "remediation": "Replace wildcard CIDR with specific, least-privilege IP ranges. Review all ingress rules.",
    },
    {
        "id": "TC-NET-004",
        "name": "Database public network access enabled",
        "category": "networking",
        "pattern": r'public_network_access_enabled\s*=\s*true',
        "severity": "CRITICAL",
        "risk_delta": 35,
        "secure_score_delta": -25,
        "frameworks": ["CIS Azure 4.1", "NIST SC-7", "SOC2 CC6.6", "ISO 27001 A.13.1"],
        "remediation": "Set public_network_access_enabled = false and provision a Private Endpoint to route traffic through the VNet.",
    },
    {
        "id": "TC-DATA-001",
        "name": "Storage account allows public blob access",
        "category": "data",
        "pattern": r'(allow_blob_public_access\s*=\s*true|allow_nested_items_to_be_public\s*=\s*true)',
        "severity": "HIGH",
        "risk_delta": 22,
        "secure_score_delta": -10,
        "frameworks": ["CIS Azure 3.7", "CIS Azure 3.8", "NIST SC-28", "SOC2 CC6.1"],
        "remediation": "Set allow_blob_public_access = false on all storage accounts. Use SAS tokens or managed identity for access.",
    },
    {
        "id": "TC-DATA-002",
        "name": "HTTPS-only traffic not enforced on storage account",
        "category": "data",
        "pattern": r'enable_https_traffic_only\s*=\s*false',
        "severity": "HIGH",
        "risk_delta": 20,
        "secure_score_delta": -10,
        "frameworks": ["CIS Azure 3.1", "NIST SC-8", "SOC2 CC6.7"],
        "remediation": "Set enable_https_traffic_only = true to enforce TLS in transit.",
    },
    {
        "id": "TC-DATA-003",
        "name": "RDS / database encryption at rest disabled",
        "category": "data",
        "pattern": r'storage_encrypted\s*=\s*false',
        "severity": "HIGH",
        "risk_delta": 22,
        "secure_score_delta": -15,
        "frameworks": ["CIS AWS 2.3.1", "NIST SC-28", "SOC2 CC6.1", "PCI-DSS 3.4"],
        "remediation": "Set storage_encrypted = true and specify a KMS key via kms_key_id for customer-managed encryption.",
    },
    {
        "id": "TC-DATA-004",
        "name": "Minimum TLS version below 1.2",
        "category": "data",
        "pattern": r'min_tls_version\s*=\s*"(TLS1_0|TLS1_1|TLS10|TLS11)"',
        "severity": "MEDIUM",
        "risk_delta": 15,
        "secure_score_delta": -8,
        "frameworks": ["CIS Azure 3.2", "NIST SC-8", "SOC2 CC6.7"],
        "remediation": "Set min_tls_version = \"TLS1_2\" or higher on all storage accounts and app services.",
    },
    {
        "id": "TC-IAM-001",
        "name": "Wildcard IAM action (*) grants excessive permissions",
        "category": "identity",
        "pattern": r'"actions"\s*:\s*\[\s*"\*"\s*\]|actions\s*=\s*\["?\*"?\]',
        "severity": "HIGH",
        "risk_delta": 25,
        "secure_score_delta": -15,
        "frameworks": ["CIS AWS 1.16", "NIST AC-6", "SOC2 CC6.3", "ISO 27001 A.9.4"],
        "remediation": "Apply least-privilege: enumerate specific IAM actions required. Use permission boundaries where applicable.",
    },
    {
        "id": "TC-IAM-002",
        "name": "Owner or Contributor role assignment to broad principal",
        "category": "identity",
        "pattern": r'role_definition_name\s*=\s*"(Owner|Contributor)"',
        "severity": "HIGH",
        "risk_delta": 20,
        "secure_score_delta": -15,
        "frameworks": ["CIS Azure 1.23", "NIST AC-6", "SOC2 CC6.3"],
        "remediation": "Replace Owner/Contributor roles with scoped custom roles. Prefer Reader + specific action roles. Use PIM for just-in-time access.",
    },
    {
        "id": "TC-SEC-001",
        "name": "Hardcoded password or secret in Terraform resource",
        "category": "secrets",
        "pattern": r'(password|secret|api_key|token)\s*=\s*"[^${\s]{8,}"',
        "severity": "CRITICAL",
        "risk_delta": 40,
        "secure_score_delta": -25,
        "frameworks": ["CIS AWS 1.21", "NIST IA-5", "SOC2 CC6.2", "OWASP LLM06"],
        "remediation": "Remove all plaintext secrets. Use var.* with sensitive = true, or reference Key Vault / Secrets Manager via data sources. Never commit credentials to version control.",
    },
    {
        "id": "TC-MON-001",
        "name": "Missing Azure Monitor diagnostic settings",
        "category": "monitoring",
        "pattern": r'resource\s+"azurerm_(storage_account|mssql_server|key_vault|kubernetes_cluster|app_service)"',
        "severity": "MEDIUM",
        "risk_delta": 10,
        "secure_score_delta": -5,
        "frameworks": ["CIS Azure 5.1", "NIST AU-2", "SOC2 CC7.2"],
        "remediation": "Add an azurerm_monitor_diagnostic_setting resource referencing each sensitive resource. Route logs to a Log Analytics workspace.",
        "requires_absence": "azurerm_monitor_diagnostic_setting",
    },
    {
        "id": "TC-MON-002",
        "name": "AWS CloudTrail not enabled for account",
        "category": "monitoring",
        "pattern": r'resource\s+"aws_(s3_bucket|rds_instance|db_instance|instance)"',
        "severity": "MEDIUM",
        "risk_delta": 10,
        "secure_score_delta": -5,
        "frameworks": ["CIS AWS 3.1", "NIST AU-2", "SOC2 CC7.2"],
        "remediation": "Ensure an aws_cloudtrail resource with is_multi_region_trail = true is included in your Terraform module.",
        "requires_absence": "aws_cloudtrail",
    },
    {
        "id": "TC-NET-005",
        "name": "AKS / EKS cluster API server publicly accessible",
        "category": "networking",
        "pattern": r'(api_server_authorized_ip_ranges\s*=\s*\[\]|enable_private_cluster\s*=\s*false)',
        "severity": "HIGH",
        "risk_delta": 25,
        "secure_score_delta": -15,
        "frameworks": ["CIS Azure 8.2", "CIS AWS EKS 1.1", "NIST SC-7"],
        "remediation": "Set enable_private_cluster = true or populate api_server_authorized_ip_ranges with your corporate IP ranges.",
    },
]

# ─── Seeded findings (shown when no connector configured) ─────────────────────

_FINDINGS = [
    {
        "id": "tc-0001-4000-8000-000000000001",
        "claw": "terraclaw",
        "provider": "checkov",
        "title": "Azure SQL Server: public_network_access_enabled = true detected in prod module",
        "description": "The azurerm_mssql_server resource in modules/prod/sql.tf has public_network_access_enabled = true, exposing the SQL server directly to the internet. This bypasses private endpoint controls and allows unauthenticated connection attempts from any IP.",
        "category": "networking",
        "severity": "CRITICAL",
        "resource_type": "azurerm_mssql_server",
        "resource_name": "prod-sql-server",
        "region": "eastus",
        "status": "OPEN",
        "remediation": "Set public_network_access_enabled = false and add an azurerm_private_endpoint resource with a private DNS zone link.",
        "remediation_effort": "Medium",
        "risk_score": 0.92,
        "actively_exploited": False,
        "frameworks": ["CIS Azure 4.1", "NIST SC-7", "SOC2 CC6.6"],
        "secure_score_delta": -25,
        "first_seen": "2026-05-10T00:00:00Z",
    },
    {
        "id": "tc-0002-4000-8000-000000000002",
        "claw": "terraclaw",
        "provider": "tfsec",
        "title": "AWS Security Group allows unrestricted SSH (0.0.0.0/0) on port 22",
        "description": "The aws_security_group resource 'bastion-sg' in networking/sg.tf permits TCP ingress on port 22 from 0.0.0.0/0. Any internet host can initiate SSH connections to all instances in this security group, vastly expanding the attack surface.",
        "category": "networking",
        "severity": "CRITICAL",
        "resource_type": "aws_security_group",
        "resource_name": "bastion-sg",
        "region": "us-east-1",
        "status": "OPEN",
        "remediation": "Replace cidr_blocks = [\"0.0.0.0/0\"] with your corporate egress IPs. Deploy an AWS Systems Manager Session Manager endpoint as a bastion-free alternative.",
        "remediation_effort": "Low",
        "risk_score": 0.90,
        "actively_exploited": False,
        "frameworks": ["CIS AWS 4.1", "NIST AC-17", "SOC2 CC6.6"],
        "secure_score_delta": -20,
        "first_seen": "2026-05-12T00:00:00Z",
    },
    {
        "id": "tc-0003-4000-8000-000000000003",
        "claw": "terraclaw",
        "provider": "checkov",
        "title": "Hardcoded admin_password in azurerm_mssql_server resource",
        "description": "The Terraform resource azurerm_mssql_server in modules/prod/sql.tf contains administrator_login_password = \"Passw0rd123!\" in plaintext. This credential is committed to source control and visible to anyone with repository access.",
        "category": "secrets",
        "severity": "CRITICAL",
        "resource_type": "azurerm_mssql_server",
        "resource_name": "prod-sql-server",
        "region": "eastus",
        "status": "OPEN",
        "remediation": "Remove the hardcoded password immediately. Rotate the credential. Reference Azure Key Vault via a data source: data.azurerm_key_vault_secret.sql_admin_password.value. Invalidate any exposed credentials from version history.",
        "remediation_effort": "Medium",
        "risk_score": 0.97,
        "actively_exploited": False,
        "frameworks": ["CIS AWS 1.21", "NIST IA-5", "SOC2 CC6.2", "OWASP LLM06"],
        "secure_score_delta": -25,
        "first_seen": "2026-05-14T00:00:00Z",
    },
    {
        "id": "tc-0004-4000-8000-000000000004",
        "claw": "terraclaw",
        "provider": "tfsec",
        "title": "Azure Storage Account allows public blob access (allow_blob_public_access = true)",
        "description": "The storage account 'appdata-store' in storage/main.tf has allow_blob_public_access = true, permitting anonymous unauthenticated reads of any blob container configured as public. Data exfiltration risk if containers are accidentally set to public.",
        "category": "data",
        "severity": "HIGH",
        "resource_type": "azurerm_storage_account",
        "resource_name": "appdata-store",
        "region": "westeurope",
        "status": "OPEN",
        "remediation": "Set allow_blob_public_access = false. Audit all containers for public access level. Use SAS tokens or managed identity for application access.",
        "remediation_effort": "Low",
        "risk_score": 0.78,
        "actively_exploited": False,
        "frameworks": ["CIS Azure 3.7", "NIST SC-28", "SOC2 CC6.1"],
        "secure_score_delta": -10,
        "first_seen": "2026-05-15T00:00:00Z",
    },
    {
        "id": "tc-0005-4000-8000-000000000005",
        "claw": "terraclaw",
        "provider": "checkov",
        "title": "AKS cluster API server not restricted to private network",
        "description": "The azurerm_kubernetes_cluster 'prod-aks' in aks/cluster.tf has api_server_authorized_ip_ranges = [] and enable_private_cluster = false. The Kubernetes API server is reachable from the public internet.",
        "category": "networking",
        "severity": "HIGH",
        "resource_type": "azurerm_kubernetes_cluster",
        "resource_name": "prod-aks",
        "region": "eastus2",
        "status": "OPEN",
        "remediation": "Set enable_private_cluster = true to make the API server accessible only from within the VNet. If a private cluster is not feasible, populate api_server_authorized_ip_ranges with your corporate egress IPs.",
        "remediation_effort": "High",
        "risk_score": 0.82,
        "actively_exploited": False,
        "frameworks": ["CIS Azure 8.2", "NIST SC-7", "SOC2 CC6.6"],
        "secure_score_delta": -15,
        "first_seen": "2026-05-16T00:00:00Z",
    },
    {
        "id": "tc-0006-4000-8000-000000000006",
        "claw": "terraclaw",
        "provider": "tfsec",
        "title": "AWS RDS instance storage not encrypted (storage_encrypted = false)",
        "description": "The aws_db_instance 'app-postgres' in rds/main.tf has storage_encrypted = false. All data written to RDS storage is unencrypted at rest, violating PCI-DSS 3.4 and SOC 2 CC6.1 requirements for data-at-rest protection.",
        "category": "data",
        "severity": "HIGH",
        "resource_type": "aws_db_instance",
        "resource_name": "app-postgres",
        "region": "us-west-2",
        "status": "OPEN",
        "remediation": "Set storage_encrypted = true. Specify kms_key_id for customer-managed keys. Note: encryption can only be enabled at creation time — snapshot and restore to a new encrypted instance if already deployed.",
        "remediation_effort": "High",
        "risk_score": 0.76,
        "actively_exploited": False,
        "frameworks": ["CIS AWS 2.3.1", "NIST SC-28", "SOC2 CC6.1", "PCI-DSS 3.4"],
        "secure_score_delta": -15,
        "first_seen": "2026-05-17T00:00:00Z",
    },
    {
        "id": "tc-0007-4000-8000-000000000007",
        "claw": "terraclaw",
        "provider": "checkov",
        "title": "Azure IAM: Owner role assigned at subscription scope",
        "description": "The azurerm_role_assignment resource in iam/assignments.tf assigns the 'Owner' role to a service principal at subscription scope (/subscriptions/...). This grants unrestricted administrative control over all resources in the subscription.",
        "category": "identity",
        "severity": "HIGH",
        "resource_type": "azurerm_role_assignment",
        "resource_name": "sp-subscription-owner",
        "region": "global",
        "status": "OPEN",
        "remediation": "Replace the Owner role with a scoped custom role containing only required permissions. If ownership is needed temporarily, use Azure PIM for just-in-time access with approval workflow.",
        "remediation_effort": "Medium",
        "risk_score": 0.80,
        "actively_exploited": False,
        "frameworks": ["CIS Azure 1.23", "NIST AC-6", "SOC2 CC6.3"],
        "secure_score_delta": -15,
        "first_seen": "2026-05-18T00:00:00Z",
    },
    {
        "id": "tc-0008-4000-8000-000000000008",
        "claw": "terraclaw",
        "provider": "tfsec",
        "title": "Azure Storage Account: enable_https_traffic_only = false",
        "description": "The storage account 'legacy-backups' in storage/backup.tf has enable_https_traffic_only = false, allowing HTTP connections. Data in transit between clients and the storage account is not guaranteed to be encrypted.",
        "category": "data",
        "severity": "HIGH",
        "resource_type": "azurerm_storage_account",
        "resource_name": "legacy-backups",
        "region": "northeurope",
        "status": "OPEN",
        "remediation": "Set enable_https_traffic_only = true. Also set min_tls_version = \"TLS1_2\" to enforce a minimum cipher suite standard.",
        "remediation_effort": "Low",
        "risk_score": 0.72,
        "actively_exploited": False,
        "frameworks": ["CIS Azure 3.1", "NIST SC-8", "SOC2 CC6.7"],
        "secure_score_delta": -10,
        "first_seen": "2026-05-19T00:00:00Z",
    },
]

# ─── Secure Terraform templates for generation ────────────────────────────────

_TEMPLATES = {
    "azure_sql": '''# Secure Azure SQL Server with Private Endpoint
# Generated by TerraClaw — security-first defaults applied

resource "azurerm_mssql_server" "main" {
  name                         = var.server_name
  resource_group_name          = var.resource_group_name
  location                     = var.location
  version                      = "12.0"
  administrator_login          = var.admin_username
  administrator_login_password = var.admin_password  # Use Key Vault reference in production
  minimum_tls_version          = "1.2"

  # TC-NET-004: Disable public network access — route via Private Endpoint
  public_network_access_enabled = false

  azuread_administrator {
    login_username = var.aad_admin_username
    object_id      = var.aad_admin_object_id
  }

  tags = var.tags
}

resource "azurerm_mssql_database" "main" {
  name           = var.db_name
  server_id      = azurerm_mssql_server.main.id
  sku_name       = "S2"
  zone_redundant = true

  # TC-DATA-003: Encryption at rest — transparent data encryption enabled by default in Azure SQL
}

resource "azurerm_private_endpoint" "sql" {
  name                = "${var.server_name}-pe"
  location            = var.location
  resource_group_name = var.resource_group_name
  subnet_id           = var.private_endpoint_subnet_id

  private_service_connection {
    name                           = "${var.server_name}-psc"
    private_connection_resource_id = azurerm_mssql_server.main.id
    subresource_names              = ["sqlServer"]
    is_manual_connection           = false
  }
}

resource "azurerm_private_dns_zone_group" "sql" {
  name                 = "sql-dns-zone-group"
  private_endpoint_id  = azurerm_private_endpoint.sql.id
  private_dns_zone_ids = [var.sql_private_dns_zone_id]
}

# TC-MON-001: Diagnostic settings for audit and threat detection
resource "azurerm_mssql_server_security_alert_policy" "main" {
  resource_group_name = var.resource_group_name
  server_name         = azurerm_mssql_server.main.name
  state               = "Enabled"
  email_account_admins = true
}

resource "azurerm_mssql_server_vulnerability_assessment" "main" {
  server_security_alert_policy_id = azurerm_mssql_server_security_alert_policy.main.id
  storage_container_path          = "${var.vulnerability_storage_url}/"

  recurring_scans {
    enabled                   = true
    email_subscription_admins = true
    emails                    = var.security_alert_emails
  }
}
''',
    "azure_storage": '''# Secure Azure Storage Account
# Generated by TerraClaw — security-first defaults applied

resource "azurerm_storage_account" "main" {
  name                     = var.storage_name
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "ZRS"

  # TC-DATA-002: Enforce HTTPS only
  enable_https_traffic_only = true

  # TC-DATA-004: Enforce minimum TLS 1.2
  min_tls_version = "TLS1_2"

  # TC-DATA-001: Disable public blob access
  allow_nested_items_to_be_public = false

  # Disable shared key access — use Azure AD / managed identity
  shared_access_key_enabled = false

  blob_properties {
    versioning_enabled  = true
    change_feed_enabled = true

    delete_retention_policy {
      days = 30
    }

    container_delete_retention_policy {
      days = 30
    }
  }

  network_rules {
    default_action             = "Deny"
    ip_rules                   = var.allowed_ip_ranges
    virtual_network_subnet_ids = var.allowed_subnet_ids
    bypass                     = ["AzureServices"]
  }

  identity {
    type = "SystemAssigned"
  }

  tags = var.tags
}

# TC-MON-001: Diagnostic logging
resource "azurerm_monitor_diagnostic_setting" "storage" {
  name               = "${var.storage_name}-diagnostics"
  target_resource_id = "${azurerm_storage_account.main.id}/blobServices/default"
  log_analytics_workspace_id = var.log_analytics_workspace_id

  enabled_log { category = "StorageRead" }
  enabled_log { category = "StorageWrite" }
  enabled_log { category = "StorageDelete" }

  metric {
    category = "Transaction"
    enabled  = true
  }
}
''',
    "aws_rds": '''# Secure AWS RDS PostgreSQL Instance
# Generated by TerraClaw — security-first defaults applied

resource "aws_db_subnet_group" "main" {
  name       = "${var.identifier}-subnet-group"
  subnet_ids = var.private_subnet_ids
  tags       = var.tags
}

resource "aws_security_group" "rds" {
  name        = "${var.identifier}-rds-sg"
  description = "RDS access — internal only"
  vpc_id      = var.vpc_id

  # TC-NET-003: No 0.0.0.0/0 ingress — restrict to application security group only
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [var.app_security_group_id]
    description     = "PostgreSQL from application tier only"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound"
  }

  tags = var.tags
}

resource "aws_db_instance" "main" {
  identifier        = var.identifier
  engine            = "postgres"
  engine_version    = "15.4"
  instance_class    = var.instance_class
  allocated_storage = var.allocated_storage
  db_name           = var.db_name
  username          = var.db_username
  password          = var.db_password  # Use AWS Secrets Manager reference in production

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  # TC-DATA-003: Encryption at rest
  storage_encrypted = true
  kms_key_id        = var.kms_key_arn

  # No public access — private subnets only
  publicly_accessible = false

  # Automated backups
  backup_retention_period = 30
  backup_window           = "03:00-04:00"

  # Multi-AZ for high availability
  multi_az = true

  # Auto minor version updates
  auto_minor_version_upgrade = true

  deletion_protection = true

  # TC-MON-002: Enable enhanced monitoring and performance insights
  monitoring_interval = 60
  monitoring_role_arn = var.rds_monitoring_role_arn

  performance_insights_enabled          = true
  performance_insights_retention_period = 7
  performance_insights_kms_key_id       = var.kms_key_arn

  # CloudWatch log exports
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]

  tags = var.tags
}
''',
    "aws_ec2": '''# Secure AWS EC2 Instance
# Generated by TerraClaw — security-first defaults applied

resource "aws_security_group" "instance" {
  name        = "${var.name}-sg"
  description = "Instance security — no direct internet ingress"
  vpc_id      = var.vpc_id

  # TC-NET-001 / TC-NET-002: No SSH or RDP from internet
  # Use AWS Systems Manager Session Manager instead

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS egress for AWS API calls"
  }

  tags = var.tags
}

resource "aws_iam_role" "instance" {
  name = "${var.name}-instance-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

# SSM access — no SSH keys or open port 22 required
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "instance" {
  name = "${var.name}-instance-profile"
  role = aws_iam_role.instance.name
}

resource "aws_instance" "main" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  subnet_id              = var.private_subnet_id
  vpc_security_group_ids = [aws_security_group.instance.id]
  iam_instance_profile   = aws_iam_instance_profile.instance.name

  # No public IP
  associate_public_ip_address = false

  # TC-DATA-003: EBS root encryption
  root_block_device {
    encrypted   = true
    kms_key_id  = var.kms_key_arn
    volume_size = var.root_volume_size
  }

  metadata_options {
    # IMDSv2 required — prevents SSRF credential theft
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
  }

  tags = var.tags
}
''',
    "aks": '''# Secure Azure Kubernetes Service (AKS) Cluster
# Generated by TerraClaw — security-first defaults applied

resource "azurerm_kubernetes_cluster" "main" {
  name                = var.cluster_name
  location            = var.location
  resource_group_name = var.resource_group_name
  dns_prefix          = var.cluster_name
  kubernetes_version  = var.kubernetes_version

  # TC-NET-005: Private cluster — API server not reachable from internet
  private_cluster_enabled = true

  default_node_pool {
    name                = "system"
    node_count          = var.system_node_count
    vm_size             = var.system_vm_size
    vnet_subnet_id      = var.node_subnet_id
    os_disk_size_gb     = 128
    os_disk_type        = "Ephemeral"

    upgrade_settings {
      max_surge = "33%"
    }
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.aks.id]
  }

  network_profile {
    network_plugin     = "azure"
    network_policy     = "azure"
    service_cidr       = var.service_cidr
    dns_service_ip     = var.dns_service_ip
    load_balancer_sku  = "standard"
    outbound_type      = "userDefinedRouting"
  }

  azure_active_directory_role_based_access_control {
    managed                = true
    azure_rbac_enabled     = true
    admin_group_object_ids = var.aks_admin_group_ids
  }

  # TC-MON-001: Azure Monitor / Defender for Containers
  oms_agent {
    log_analytics_workspace_id = var.log_analytics_workspace_id
  }

  microsoft_defender {
    log_analytics_workspace_id = var.log_analytics_workspace_id
  }

  # Disable local accounts — enforce AAD auth
  local_account_disabled = true

  key_vault_secrets_provider {
    secret_rotation_enabled = true
  }

  maintenance_window_auto_upgrade {
    frequency   = "Weekly"
    interval    = 1
    duration    = 4
    day_of_week = "Sunday"
    start_time  = "00:00"
    utc_offset  = "+00:00"
  }

  tags = var.tags
}
''',
}


def _detect_template_key(description: str) -> str:
    desc_lower = description.lower()
    if any(k in desc_lower for k in ("azure sql", "mssql", "sql server")):
        return "azure_sql"
    if any(k in desc_lower for k in ("azure storage", "storage account", "blob")):
        return "azure_storage"
    if any(k in desc_lower for k in ("aws rds", "rds postgres", "aurora", "rds mysql")):
        return "aws_rds"
    if any(k in desc_lower for k in ("aws ec2", "ec2 instance", "virtual machine", "aws vm")):
        return "aws_ec2"
    if any(k in desc_lower for k in ("aks", "kubernetes", "k8s", "eks", "gke")):
        return "aks"
    # Default to azure_storage as a safe starting template
    return "azure_storage"


def _run_rules(hcl: str) -> tuple[list[dict], int, int]:
    """Run all security rules against HCL. Returns (findings, risk_score, secure_score)."""
    findings = []
    cumulative_risk = 0
    secure_score = 100

    for rule in _RULES:
        pattern = rule["pattern"]
        requires_absence = rule.get("requires_absence")

        matched = bool(re.search(pattern, hcl, re.IGNORECASE | re.DOTALL))

        if requires_absence:
            # Fires if the trigger pattern matches AND the absence pattern does NOT
            if matched and not re.search(requires_absence, hcl, re.IGNORECASE):
                finding = _make_finding(rule, hcl)
                findings.append(finding)
                cumulative_risk += rule["risk_delta"]
                secure_score = max(0, secure_score + rule["secure_score_delta"])
        elif matched:
            finding = _make_finding(rule, hcl)
            findings.append(finding)
            cumulative_risk += rule["risk_delta"]
            secure_score = max(0, secure_score + rule["secure_score_delta"])

    risk_score = min(100, cumulative_risk)
    return findings, risk_score, secure_score


def _make_finding(rule: dict, hcl: str) -> dict:
    # Try to find the approximate line number
    try:
        match = re.search(rule["pattern"], hcl, re.IGNORECASE | re.DOTALL)
        line_hint = hcl[: match.start()].count("\n") + 1 if match else None
    except Exception:
        line_hint = None

    return {
        "id": rule["id"],
        "name": rule["name"],
        "category": rule["category"],
        "severity": rule["severity"],
        "risk_delta": rule["risk_delta"],
        "secure_score_delta": rule["secure_score_delta"],
        "frameworks": rule["frameworks"],
        "remediation": rule["remediation"],
        "line_hint": line_hint,
    }


def _decision(risk_score: int) -> str:
    if risk_score >= 70:
        return "BLOCK"
    if risk_score >= 30:
        return "WARN"
    return "APPROVE"


# ─── Pydantic models ──────────────────────────────────────────────────────────

class ReviewRequest(BaseModel):
    hcl: str = Field(..., min_length=10, max_length=200_000, description="Terraform HCL content to review")
    context: str = Field(default="", max_length=1000, description="Optional deployment context")
    classification: str = Field(default="internal", max_length=64)


class GenerateRequest(BaseModel):
    description: str = Field(..., min_length=5, max_length=2000)
    cloud: str = Field(default="azure", pattern=r"^(azure|aws|gcp)$")
    classification: str = Field(default="internal", max_length=64)


class PlanRequest(BaseModel):
    changes: list[dict] = Field(..., description="List of planned resource changes")
    context: str = Field(default="", max_length=1000)
    classification: str = Field(default="internal", max_length=64)


class TerraTaskRequest(BaseModel):
    swarm_job_id: str | None = None
    task_type: str = "scan_terraform_risk"
    input: dict = Field(default_factory=dict)
    classification: str = "internal"
    model_profile: str | None = None
    allowed_actions: list[str] = Field(default_factory=lambda: ["read", "analyze", "recommend"])


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.get("/stats", summary="TerraClaw summary statistics")
async def get_stats(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Finding).where(Finding.claw == CLAW_NAME))
    findings = result.scalars().all()
    source = _FINDINGS if not findings else []
    rows = [
        {
            "severity": (f.severity.value if hasattr(f.severity, "value") else f.severity).lower()
            if not isinstance(f, dict) else str(f.get("severity", "")).lower(),
            "status": (f.status.value if hasattr(f.status, "value") else f.status).lower()
            if not isinstance(f, dict) else str(f.get("status", "")).lower(),
        }
        for f in (findings or source)
    ]
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    open_count = 0
    for r in rows:
        sev = r["severity"]
        if sev in by_sev:
            by_sev[sev] += 1
        if r["status"] == "open":
            open_count += 1
    total = len(rows)
    secure_score = max(0, 100 - sum(
        abs(f.get("secure_score_delta", 0)) if isinstance(f, dict) else 0
        for f in source
    ))
    return {
        "total": total,
        "critical": by_sev["critical"],
        "high": by_sev["high"],
        "medium": by_sev["medium"],
        "low": by_sev["low"],
        "open": open_count,
        "resolved": total - open_count,
        "secure_score": secure_score,
        "last_scan": None,
    }


@router.get("/findings", summary="All TerraClaw findings")
async def get_findings(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Finding).where(Finding.claw == CLAW_NAME).order_by(Finding.risk_score.desc())
    )
    findings = result.scalars().all()
    if not findings:
        any_configured = any([
            await is_connector_configured(db, p["connector_type"])
            for p in PROVIDER_MAP if p.get("connector_type")
        ])
        if not any_configured:
            return _FINDINGS
        return []
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
            "resource_type": f.resource_type,
            "resource_name": f.resource_name,
            "region": f.region,
            "risk_score": f.risk_score,
            "remediation": f.remediation,
            "remediation_effort": f.remediation_effort,
            "first_seen": f.first_seen.isoformat() if f.first_seen else None,
        }
        for f in findings
    ]


@router.get("/providers", summary="TerraClaw provider connection status")
async def get_providers(db: AsyncSession = Depends(get_db)):
    from app.services.connector_check import check_providers
    return await check_providers(db, PROVIDER_MAP)


@router.post("/review", summary="Review Terraform HCL for security risks")
async def review_terraform(
    body: ReviewRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    started = datetime.utcnow()

    policy_decision = await enforce(
        db=db,
        request=ActionRequest(
            module=CLAW_NAME,
            actor_id="terraclaw-review",
            actor_name="TerraClaw Review Engine",
            actor_type="system",
            action="review_terraform_hcl",
            target="terraform_hcl",
            target_type="iac_artifact",
            context={"classification": body.classification, "context": body.context[:200]},
        ),
        ip_address=request.client.host if request.client else None,
    )
    if not policy_decision.allowed:
        raise HTTPException(
            status_code=403,
            detail={
                "message": "Terraform review blocked by Trust Fabric policy.",
                "policy": policy_decision.policy_name,
                "reason": policy_decision.reason,
            },
        )

    findings, risk_score, secure_score = _run_rules(body.hcl)
    decision = _decision(risk_score)

    # Map findings to compliance frameworks
    framework_hits: dict[str, int] = {}
    for f in findings:
        for fw in f.get("frameworks", []):
            framework_hits[fw] = framework_hits.get(fw, 0) + 1

    elapsed_ms = int((datetime.utcnow() - started).total_seconds() * 1000)
    return {
        "review_id": f"terra-review-{uuid.uuid4()}",
        "decision": decision,
        "risk_score": risk_score,
        "secure_score": secure_score,
        "finding_count": len(findings),
        "findings": findings,
        "frameworks_impacted": framework_hits,
        "recommended_actions": [f["remediation"] for f in findings[:5]],
        "policy_decision": {
            "outcome": policy_decision.outcome.value,
            "policy_name": policy_decision.policy_name,
        },
        "execution_time_ms": elapsed_ms,
    }


@router.post("/generate", summary="Generate secure Terraform from description")
async def generate_terraform(
    body: GenerateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    started = datetime.utcnow()

    policy_decision = await enforce(
        db=db,
        request=ActionRequest(
            module=CLAW_NAME,
            actor_id="terraclaw-generate",
            actor_name="TerraClaw Generate Engine",
            actor_type="system",
            action="generate_terraform_hcl",
            target="terraform_template",
            target_type="iac_artifact",
            context={"classification": body.classification, "cloud": body.cloud},
        ),
        ip_address=request.client.host if request.client else None,
    )
    if not policy_decision.allowed:
        raise HTTPException(
            status_code=403,
            detail={
                "message": "Terraform generation blocked by Trust Fabric policy.",
                "policy": policy_decision.policy_name,
                "reason": policy_decision.reason,
            },
        )

    template_key = _detect_template_key(body.description)
    terraform = _TEMPLATES.get(template_key, _TEMPLATES["azure_storage"])

    # Run review on the generated code to confirm it passes
    findings, risk_score, secure_score = _run_rules(terraform)

    elapsed_ms = int((datetime.utcnow() - started).total_seconds() * 1000)
    return {
        "generate_id": f"terra-gen-{uuid.uuid4()}",
        "decision": _decision(risk_score),
        "risk_score": risk_score,
        "secure_score": secure_score,
        "terraform": terraform,
        "template_used": template_key,
        "security_review": {
            "finding_count": len(findings),
            "findings": findings,
        },
        "notes": [
            "Review and customize variables before applying to production.",
            "Replace placeholder Key Vault/Secrets Manager references with your real resource IDs.",
            "Run terraform plan and submit output to /terraclaw/plan for pre-apply analysis.",
        ],
        "execution_time_ms": elapsed_ms,
    }


@router.post("/plan", summary="Analyze a Terraform plan for risk before apply")
async def analyze_plan(
    body: PlanRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    started = datetime.utcnow()

    policy_decision = await enforce(
        db=db,
        request=ActionRequest(
            module=CLAW_NAME,
            actor_id="terraclaw-plan",
            actor_name="TerraClaw Plan Analyzer",
            actor_type="system",
            action="analyze_terraform_plan",
            target="terraform_plan",
            target_type="iac_plan",
            context={"classification": body.classification, "change_count": len(body.changes)},
        ),
        ip_address=request.client.host if request.client else None,
    )
    if not policy_decision.allowed:
        raise HTTPException(
            status_code=403,
            detail={
                "message": "Terraform plan analysis blocked by Trust Fabric policy.",
                "policy": policy_decision.policy_name,
                "reason": policy_decision.reason,
            },
        )

    # Analyze each planned change for risk
    _HIGH_RISK_ATTRS = {
        "public_network_access_enabled": ("CRITICAL", "Enabling public network access exposes service to internet.", 35),
        "allow_blob_public_access": ("HIGH", "Public blob access enables anonymous reads of storage containers.", 22),
        "storage_encrypted": ("HIGH", "Disabling storage encryption removes at-rest data protection.", 22),
        "enable_https_traffic_only": ("HIGH", "Disabling HTTPS-only allows unencrypted connections.", 20),
        "publicly_accessible": ("CRITICAL", "Making database publicly accessible exposes it to the internet.", 35),
        "deletion_protection": ("MEDIUM", "Removing deletion protection enables accidental or malicious database deletion.", 15),
        "private_cluster_enabled": ("HIGH", "Disabling private cluster makes Kubernetes API server internet-accessible.", 25),
        "api_server_authorized_ip_ranges": ("HIGH", "Removing IP range restrictions exposes the API server to the internet.", 20),
    }

    risky_changes = []
    creates = 0
    deletes = 0
    updates = 0
    replacements = 0
    cumulative_risk = 0

    for change in body.changes:
        action = change.get("action", "no-op")
        resource_type = change.get("resource_type", "unknown")
        resource_name = change.get("resource_name", "unknown")
        attr_changes = change.get("attribute_changes", {})

        if action == "create":
            creates += 1
        elif action == "delete":
            deletes += 1
            risky_changes.append({
                "resource": f"{resource_type}.{resource_name}",
                "action": "delete",
                "severity": "HIGH",
                "reason": f"Deletion of {resource_type} is irreversible. Verify this is intentional.",
                "risk_delta": 15,
            })
            cumulative_risk += 15
        elif action == "replace":
            replacements += 1
            risky_changes.append({
                "resource": f"{resource_type}.{resource_name}",
                "action": "replace (destroy + create)",
                "severity": "HIGH",
                "reason": f"Replace destroys and recreates {resource_type}. This causes downtime and data loss risk.",
                "risk_delta": 20,
            })
            cumulative_risk += 20
        elif action == "update":
            updates += 1

        # Check attribute-level risk
        for attr, new_val in attr_changes.items():
            if attr in _HIGH_RISK_ATTRS:
                severity, reason, delta = _HIGH_RISK_ATTRS[attr]
                risky_changes.append({
                    "resource": f"{resource_type}.{resource_name}",
                    "action": f"update {attr}",
                    "new_value": str(new_val)[:200],
                    "severity": severity,
                    "reason": reason,
                    "risk_delta": delta,
                })
                cumulative_risk += delta

    risk_score = min(100, cumulative_risk)
    decision = _decision(risk_score)

    elapsed_ms = int((datetime.utcnow() - started).total_seconds() * 1000)
    return {
        "plan_id": f"terra-plan-{uuid.uuid4()}",
        "decision": decision,
        "risk_score": risk_score,
        "summary": {
            "creates": creates,
            "updates": updates,
            "deletes": deletes,
            "replacements": replacements,
            "total_changes": len(body.changes),
        },
        "risky_changes": risky_changes,
        "recommended_actions": [c["reason"] for c in risky_changes[:5]],
        "policy_decision": {
            "outcome": policy_decision.outcome.value,
            "policy_name": policy_decision.policy_name,
        },
        "execution_time_ms": elapsed_ms,
    }


@router.post("/scan", summary="Run TerraClaw scan and persist findings")
async def run_scan(db: AsyncSession = Depends(get_db)):
    from app.services.finding_pipeline import ingest_findings
    default_provider = PROVIDER_MAP[0]["provider"] if PROVIDER_MAP else "simulation"
    pipeline_findings = []
    for f in _FINDINGS:
        entry = dict(f)
        entry.setdefault("claw", CLAW_NAME)
        entry.setdefault("provider", default_provider)
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
    }


@router.post("/task", summary="Execute focused TerraClaw swarm task")
async def run_terra_task(payload: TerraTaskRequest, db: AsyncSession = Depends(get_db)):
    started = datetime.utcnow()
    any_configured = any([
        await is_connector_configured(db, p["connector_type"])
        for p in PROVIDER_MAP if p.get("connector_type")
    ])
    result = await db.execute(
        select(Finding).where(Finding.claw == CLAW_NAME).order_by(desc(Finding.risk_score)).limit(5)
    )
    findings = result.scalars().all()
    fallback = _FINDINGS[:3] if not findings else []
    max_risk_raw = max(
        [float(f.risk_score or 0.0) for f in findings],
        default=max([float(f.get("risk_score") or 0.0) for f in fallback], default=0.0),
    )
    max_risk = int(max_risk_raw * 100) if max_risk_raw <= 1.0 else int(max_risk_raw)
    severity = "critical" if max_risk >= 85 else "high" if max_risk >= 70 else "medium" if max_risk >= 40 else "low"
    confidence = 0.91 if findings else 0.78
    elapsed_ms = int((datetime.utcnow() - started).total_seconds() * 1000)
    rows = [
        {
            "title": f.title,
            "detail": f"{f.provider or 'terraclaw'} finding severity={f.severity.value if hasattr(f.severity, 'value') else f.severity}",
        }
        for f in findings[:3]
    ] or [
        {
            "title": f.get("title", "Terraform security finding"),
            "detail": (f.get("description", "")[:220] or "Simulation finding"),
        }
        for f in fallback
    ]
    return {
        "task_id": f"terra-task-{int(started.timestamp())}",
        "swarm_job_id": payload.swarm_job_id,
        "claw": CLAW_NAME,
        "status": "completed",
        "severity": severity,
        "confidence": confidence,
        "risk_score": max_risk,
        "findings": rows or [{"title": "No IaC findings", "detail": "Submit HCL via /terraclaw/review or run /terraclaw/scan."}],
        "evidence": [],
        "recommended_actions": [
            "Review Terraform modules for public network access settings.",
            "Enforce private endpoints for all data-tier resources.",
            "Scan for hardcoded secrets using tfsec or Checkov in CI.",
        ],
        "blocked_actions": [],
        "policy_decisions": [],
        "compliance_mappings": ["CIS Azure", "CIS AWS", "NIST 800-53", "SOC2"],
        "execution_time_ms": elapsed_ms,
        "data_source": "persisted_db" if findings else "seeded_fallback",
        "connector_state": "configured" if any_configured else "unconfigured",
    }


# ─── /build — Natural-language wizard ────────────────────────────────────────

_CLOUD_KEYWORDS = {
    "azure": ["azure", "azurerm", "microsoft", "entra", "defender", "sentinel",
              "aks", "cosmos", "servicebus", "blob", "keyvault", "key vault"],
    "aws":   ["aws", "amazon", "ec2", "s3", "rds", "eks", "lambda", "dynamodb",
              "cloudwatch", "cloudtrail", "iam", "vpc", "route53"],
    "gcp":   ["gcp", "google", "gke", "bigquery", "cloud run", "pubsub",
              "firestore", "cloud sql"],
}

_RESOURCE_KEYWORDS = {
    "sql":      ["sql", "database", "postgres", "mysql", "mssql", "rds", "aurora", "db"],
    "storage":  ["storage", "blob", "s3", "bucket", "file share"],
    "vm":       ["vm", "virtual machine", "ec2", "compute", "instance", "server"],
    "aks":      ["aks", "eks", "gke", "kubernetes", "k8s", "cluster", "container"],
    "function": ["function", "lambda", "serverless", "function app"],
    "vnet":     ["network", "vnet", "vpc", "subnet", "firewall", "nsg"],
    "keyvault": ["key vault", "keyvault", "secrets manager", "secrets", "kms"],
    "redis":    ["redis", "cache", "elasticache"],
    "cosmos":   ["cosmos", "documentdb", "mongodb"],
    "appservice":["web app", "app service", "webapp", "website"],
}

_ENV_KEYWORDS = {
    "prod":    ["prod", "production", "live"],
    "staging": ["staging", "stage", "uat", "pre-prod"],
    "dev":     ["dev", "development", "sandbox", "test"],
}

_REGION_MAP = {
    "azure": {
        "east us": "eastus", "west us": "westus", "west europe": "westeurope",
        "north europe": "northeurope", "uk south": "uksouth", "southeast asia": "southeastasia",
        "australia east": "australiaeast", "canada central": "canadacentral",
    },
    "aws": {
        "us east": "us-east-1", "us west": "us-west-2", "eu west": "eu-west-1",
        "eu central": "eu-central-1", "ap southeast": "ap-southeast-1",
        "ap northeast": "ap-northeast-1", "ca central": "ca-central-1",
    },
    "gcp": {
        "us east": "us-east1", "us central": "us-central1", "eu west": "europe-west1",
        "asia east": "asia-east1",
    },
}

_ALWAYS_SECURITY_MODULES = {
    "azure": [
        "azurerm_monitor_diagnostic_setting",
        "azurerm_key_vault (for secrets)",
        "Private Endpoint (no public internet access)",
        "azurerm_network_security_group",
        "Microsoft Defender for resource type",
        "azurerm_monitor_metric_alert",
    ],
    "aws": [
        "aws_cloudtrail (audit logging)",
        "AWS Secrets Manager / aws_secretsmanager_secret",
        "aws_security_group (no 0.0.0.0/0 ingress)",
        "aws_kms_key (encryption at rest)",
        "aws_cloudwatch_log_group + metric filters",
        "aws_iam_role with least-privilege policy",
    ],
    "gcp": [
        "google_project_iam_audit_config",
        "google_secret_manager_secret",
        "VPC firewall rules (no 0.0.0.0/0)",
        "google_kms_crypto_key (CMEK)",
        "google_monitoring_alert_policy",
    ],
}

# Full Terraform modules — security always included ───────────────────────────

_BUILD_MODULES: dict[str, dict[str, str]] = {
    "azure_sql": {
        "main.tf": '''terraform {
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 3.100" }
    random  = { source = "hashicorp/random",  version = "~> 3.6" }
  }
}

provider "azurerm" {
  features { key_vault { purge_soft_delete_on_destroy = false } }
}

data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "main" {
  name     = "${var.prefix}-rg"
  location = var.location
  tags     = var.tags
}

# ── Key Vault (always included — never hardcode secrets) ─────────────────────
resource "azurerm_key_vault" "main" {
  name                        = "${var.prefix}-kv"
  location                    = azurerm_resource_group.main.location
  resource_group_name         = azurerm_resource_group.main.name
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  sku_name                    = "standard"
  soft_delete_retention_days  = 90
  purge_protection_enabled    = true
  enable_rbac_authorization   = true
  tags                        = var.tags
}

resource "azurerm_key_vault_secret" "sql_admin_password" {
  name         = "sql-admin-password"
  value        = random_password.sql_admin.result
  key_vault_id = azurerm_key_vault.main.id
}

resource "random_password" "sql_admin" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# ── SQL Server (public network disabled — Private Endpoint required) ──────────
resource "azurerm_mssql_server" "main" {
  name                          = "${var.prefix}-sql"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = azurerm_resource_group.main.location
  version                       = "12.0"
  administrator_login           = var.sql_admin_username
  administrator_login_password  = azurerm_key_vault_secret.sql_admin_password.value
  minimum_tls_version           = "1.2"
  public_network_access_enabled = false   # TC-NET-004: no internet exposure

  azuread_administrator {
    login_username = var.aad_admin_username
    object_id      = var.aad_admin_object_id
  }
  tags = var.tags
}

resource "azurerm_mssql_database" "main" {
  name           = var.db_name
  server_id      = azurerm_mssql_server.main.id
  sku_name       = var.db_sku
  zone_redundant = var.environment == "prod" ? true : false
  tags           = var.tags
}

# ── Private Endpoint ──────────────────────────────────────────────────────────
resource "azurerm_private_endpoint" "sql" {
  name                = "${var.prefix}-sql-pe"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  subnet_id           = azurerm_subnet.pe.id

  private_service_connection {
    name                           = "${var.prefix}-sql-psc"
    private_connection_resource_id = azurerm_mssql_server.main.id
    subresource_names              = ["sqlServer"]
    is_manual_connection           = false
  }
  tags = var.tags
}

# ── Networking ────────────────────────────────────────────────────────────────
resource "azurerm_virtual_network" "main" {
  name                = "${var.prefix}-vnet"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  address_space       = [var.vnet_address_space]
  tags                = var.tags
}

resource "azurerm_subnet" "pe" {
  name                 = "private-endpoints"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [var.pe_subnet_prefix]

  private_endpoint_network_policies = "Disabled"
}

# ── Security: Defender + Alert Policy + Vulnerability Assessment ──────────────
resource "azurerm_mssql_server_security_alert_policy" "main" {
  resource_group_name = azurerm_resource_group.main.name
  server_name         = azurerm_mssql_server.main.name
  state               = "Enabled"
  email_account_admins = true
  email_addresses      = var.security_alert_emails
}

resource "azurerm_mssql_server_vulnerability_assessment" "main" {
  server_security_alert_policy_id = azurerm_mssql_server_security_alert_policy.main.id
  storage_container_path          = "${azurerm_storage_account.va.primary_blob_endpoint}${azurerm_storage_container.va.name}/"
  storage_account_access_key      = azurerm_storage_account.va.primary_access_key

  recurring_scans {
    enabled                   = true
    email_subscription_admins = true
    emails                    = var.security_alert_emails
  }
}

resource "azurerm_storage_account" "va" {
  name                     = "${replace(var.prefix, "-", "")}vascan"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  enable_https_traffic_only       = true
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  tags                            = var.tags
}

resource "azurerm_storage_container" "va" {
  name                  = "vulnerability-assessment"
  storage_account_name  = azurerm_storage_account.va.name
  container_access_type = "private"
}

# ── Monitoring: Diagnostic Settings ──────────────────────────────────────────
resource "azurerm_monitor_diagnostic_setting" "sql" {
  name                       = "${var.prefix}-sql-diag"
  target_resource_id         = azurerm_mssql_server.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log { category = "SQLSecurityAuditEvents" }
  metric { category = "Basic"; enabled = true }
}

resource "azurerm_log_analytics_workspace" "main" {
  name                = "${var.prefix}-law"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 90
  tags                = var.tags
}
''',
        "variables.tf": '''variable "prefix"               { type = string; description = "Resource name prefix (e.g. myapp-prod)" }
variable "location"             { type = string; default = "eastus"; description = "Azure region" }
variable "environment"          { type = string; default = "prod"; description = "Environment: prod, staging, dev" }
variable "db_name"              { type = string; default = "appdb" }
variable "db_sku"               { type = string; default = "S2" }
variable "sql_admin_username"   { type = string; default = "sqladmin" }
variable "aad_admin_username"   { type = string; description = "Azure AD admin login name" }
variable "aad_admin_object_id"  { type = string; description = "Azure AD admin object ID" }
variable "vnet_address_space"   { type = string; default = "10.0.0.0/16" }
variable "pe_subnet_prefix"     { type = string; default = "10.0.1.0/24" }
variable "security_alert_emails"{ type = list(string); default = [] }
variable "tags"                 { type = map(string); default = {} }
''',
        "outputs.tf": '''output "sql_server_id"          { value = azurerm_mssql_server.main.id }
output "sql_server_fqdn"        { value = azurerm_mssql_server.main.fully_qualified_domain_name }
output "private_endpoint_ip"    { value = azurerm_private_endpoint.sql.private_service_connection[0].private_ip_address }
output "key_vault_uri"          { value = azurerm_key_vault.main.vault_uri }
output "log_analytics_id"       { value = azurerm_log_analytics_workspace.main.id }
''',
    },
    "azure_storage": {
        "main.tf": '''terraform {
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 3.100" }
  }
}

provider "azurerm" { features {} }

data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "main" {
  name     = "${var.prefix}-rg"
  location = var.location
  tags     = var.tags
}

resource "azurerm_storage_account" "main" {
  name                     = "${replace(var.prefix, "-", "")}sa"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = var.environment == "prod" ? "ZRS" : "LRS"

  enable_https_traffic_only       = true      # TC-DATA-002
  min_tls_version                 = "TLS1_2"  # TC-DATA-004
  allow_nested_items_to_be_public = false      # TC-DATA-001
  shared_access_key_enabled       = false

  blob_properties {
    versioning_enabled  = true
    change_feed_enabled = true
    delete_retention_policy  { days = 30 }
    container_delete_retention_policy { days = 30 }
  }

  network_rules {
    default_action             = "Deny"
    ip_rules                   = var.allowed_ip_ranges
    virtual_network_subnet_ids = var.allowed_subnet_ids
    bypass                     = ["AzureServices"]
  }

  identity { type = "SystemAssigned" }
  tags     = var.tags
}

resource "azurerm_log_analytics_workspace" "main" {
  name                = "${var.prefix}-law"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 90
  tags                = var.tags
}

resource "azurerm_monitor_diagnostic_setting" "storage_blob" {
  name                       = "${var.prefix}-blob-diag"
  target_resource_id         = "${azurerm_storage_account.main.id}/blobServices/default"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log { category = "StorageRead" }
  enabled_log { category = "StorageWrite" }
  enabled_log { category = "StorageDelete" }
  metric { category = "Transaction"; enabled = true }
}
''',
        "variables.tf": '''variable "prefix"            { type = string }
variable "location"          { type = string; default = "westeurope" }
variable "environment"       { type = string; default = "prod" }
variable "allowed_ip_ranges" { type = list(string); default = [] }
variable "allowed_subnet_ids"{ type = list(string); default = [] }
variable "tags"              { type = map(string); default = {} }
''',
        "outputs.tf": '''output "storage_account_id"   { value = azurerm_storage_account.main.id }
output "storage_account_name" { value = azurerm_storage_account.main.name }
output "primary_blob_endpoint"{ value = azurerm_storage_account.main.primary_blob_endpoint }
output "log_analytics_id"     { value = azurerm_log_analytics_workspace.main.id }
''',
    },
    "aws_rds": {
        "main.tf": '''terraform {
  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 5.50" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
  }
}

provider "aws" { region = var.region }

resource "random_password" "db" {
  length  = 32
  special = false
}

resource "aws_secretsmanager_secret" "db_password" {
  name                    = "${var.identifier}-db-password"
  recovery_window_in_days = 7
  tags                    = var.tags
}

resource "aws_secretsmanager_secret_version" "db_password" {
  secret_id     = aws_secretsmanager_secret.db_password.id
  secret_string = random_password.db.result
}

resource "aws_db_subnet_group" "main" {
  name       = "${var.identifier}-subnet-group"
  subnet_ids = var.private_subnet_ids
  tags       = var.tags
}

resource "aws_security_group" "rds" {
  name        = "${var.identifier}-rds-sg"
  description = "RDS — internal app tier only, no internet"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [var.app_security_group_id]
    description     = "PostgreSQL from app tier only"
  }
  egress {
    from_port   = 0; to_port = 0; protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = var.tags
}

resource "aws_kms_key" "rds" {
  description             = "RDS encryption key — ${var.identifier}"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags                    = var.tags
}

resource "aws_db_instance" "main" {
  identifier        = var.identifier
  engine            = "postgres"
  engine_version    = "15.4"
  instance_class    = var.instance_class
  allocated_storage = var.allocated_storage
  db_name           = var.db_name
  username          = var.db_username
  password          = random_password.db.result

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  storage_encrypted   = true          # TC-DATA-003
  kms_key_id          = aws_kms_key.rds.arn
  publicly_accessible = false         # TC-NET-004
  multi_az            = var.environment == "prod" ? true : false
  backup_retention_period = 30
  deletion_protection     = true
  auto_minor_version_upgrade = true

  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn
  performance_insights_enabled          = true
  performance_insights_kms_key_id       = aws_kms_key.rds.arn
  performance_insights_retention_period = 7

  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
  tags = var.tags
}

resource "aws_iam_role" "rds_monitoring" {
  name = "${var.identifier}-rds-monitoring"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "monitoring.rds.amazonaws.com" },
                   Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "rds_monitoring" {
  role       = aws_iam_role.rds_monitoring.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

resource "aws_cloudwatch_log_group" "rds_postgresql" {
  name              = "/aws/rds/instance/${var.identifier}/postgresql"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.rds.arn
  tags              = var.tags
}
''',
        "variables.tf": '''variable "identifier"          { type = string }
variable "region"               { type = string; default = "us-east-1" }
variable "environment"          { type = string; default = "prod" }
variable "vpc_id"               { type = string }
variable "private_subnet_ids"   { type = list(string) }
variable "app_security_group_id"{ type = string }
variable "instance_class"       { type = string; default = "db.t3.medium" }
variable "allocated_storage"    { type = number; default = 100 }
variable "db_name"              { type = string; default = "appdb" }
variable "db_username"          { type = string; default = "dbadmin" }
variable "tags"                 { type = map(string); default = {} }
''',
        "outputs.tf": '''output "db_endpoint"         { value = aws_db_instance.main.endpoint }
output "db_instance_id"      { value = aws_db_instance.main.id }
output "secret_arn"          { value = aws_secretsmanager_secret.db_password.arn }
output "kms_key_id"          { value = aws_kms_key.rds.key_id }
''',
    },
    "aws_ec2": {
        "main.tf": '''terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.50" }
  }
}

provider "aws" { region = var.region }

resource "aws_security_group" "instance" {
  name        = "${var.name}-sg"
  description = "Instance — no direct internet ingress (use SSM)"
  vpc_id      = var.vpc_id

  egress {
    from_port   = 443; to_port = 443; protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS egress for SSM and AWS API calls"
  }
  tags = var.tags
}

resource "aws_iam_role" "instance" {
  name = "${var.name}-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "ec2.amazonaws.com" },
                   Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "cloudwatch" {
  role       = aws_iam_role.instance.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_instance_profile" "instance" {
  name = "${var.name}-profile"
  role = aws_iam_role.instance.name
}

resource "aws_kms_key" "ebs" {
  description             = "EBS encryption — ${var.name}"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  tags                    = var.tags
}

resource "aws_instance" "main" {
  ami                         = var.ami_id
  instance_type               = var.instance_type
  subnet_id                   = var.private_subnet_id
  vpc_security_group_ids      = [aws_security_group.instance.id]
  iam_instance_profile        = aws_iam_instance_profile.instance.name
  associate_public_ip_address = false   # TC-NET-003

  root_block_device {
    encrypted   = true          # TC-DATA-003
    kms_key_id  = aws_kms_key.ebs.arn
    volume_size = var.root_volume_size
  }

  metadata_options {
    http_tokens                 = "required"  # IMDSv2 — prevents SSRF credential theft
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 1
  }

  tags = var.tags
}

resource "aws_cloudwatch_metric_alarm" "cpu_high" {
  alarm_name          = "${var.name}-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_actions       = var.alarm_sns_topic_arns
  dimensions          = { InstanceId = aws_instance.main.id }
  tags                = var.tags
}
''',
        "variables.tf": '''variable "name"                { type = string }
variable "region"              { type = string; default = "us-east-1" }
variable "environment"         { type = string; default = "prod" }
variable "vpc_id"              { type = string }
variable "private_subnet_id"   { type = string }
variable "ami_id"              { type = string }
variable "instance_type"       { type = string; default = "t3.medium" }
variable "root_volume_size"    { type = number; default = 30 }
variable "alarm_sns_topic_arns"{ type = list(string); default = [] }
variable "tags"                { type = map(string); default = {} }
''',
        "outputs.tf": '''output "instance_id"    { value = aws_instance.main.id }
output "private_ip"     { value = aws_instance.main.private_ip }
output "kms_key_id"     { value = aws_kms_key.ebs.key_id }
''',
    },
    "aks": {
        "main.tf": '''terraform {
  required_providers {
    azurerm = { source = "hashicorp/azurerm", version = "~> 3.100" }
  }
}

provider "azurerm" { features {} }

resource "azurerm_resource_group" "main" {
  name     = "${var.prefix}-rg"
  location = var.location
  tags     = var.tags
}

resource "azurerm_log_analytics_workspace" "main" {
  name                = "${var.prefix}-law"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 90
  tags                = var.tags
}

resource "azurerm_user_assigned_identity" "aks" {
  name                = "${var.prefix}-aks-identity"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = var.tags
}

resource "azurerm_virtual_network" "main" {
  name                = "${var.prefix}-vnet"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  address_space       = [var.vnet_address_space]
  tags                = var.tags
}

resource "azurerm_subnet" "nodes" {
  name                 = "nodes"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [var.node_subnet_prefix]
}

resource "azurerm_kubernetes_cluster" "main" {
  name                = "${var.prefix}-aks"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  dns_prefix          = var.prefix
  kubernetes_version  = var.kubernetes_version

  private_cluster_enabled = true        # TC-NET-005

  default_node_pool {
    name           = "system"
    node_count     = var.system_node_count
    vm_size        = var.system_vm_size
    vnet_subnet_id = azurerm_subnet.nodes.id
    os_disk_type   = "Ephemeral"
    upgrade_settings { max_surge = "33%" }
  }

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.aks.id]
  }

  network_profile {
    network_plugin    = "azure"
    network_policy    = "azure"
    load_balancer_sku = "standard"
    outbound_type     = "userDefinedRouting"
  }

  azure_active_directory_role_based_access_control {
    managed                = true
    azure_rbac_enabled     = true
    admin_group_object_ids = var.aks_admin_group_ids
  }

  oms_agent {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  }

  microsoft_defender {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  }

  local_account_disabled = true

  key_vault_secrets_provider {
    secret_rotation_enabled = true
  }

  tags = var.tags
}
''',
        "variables.tf": '''variable "prefix"               { type = string }
variable "location"             { type = string; default = "eastus2" }
variable "environment"          { type = string; default = "prod" }
variable "kubernetes_version"   { type = string; default = "1.29" }
variable "system_node_count"    { type = number; default = 3 }
variable "system_vm_size"       { type = string; default = "Standard_D4s_v5" }
variable "vnet_address_space"   { type = string; default = "10.0.0.0/16" }
variable "node_subnet_prefix"   { type = string; default = "10.0.1.0/24" }
variable "aks_admin_group_ids"  { type = list(string); default = [] }
variable "tags"                 { type = map(string); default = {} }
''',
        "outputs.tf": '''output "cluster_id"            { value = azurerm_kubernetes_cluster.main.id }
output "kube_config"           { value = azurerm_kubernetes_cluster.main.kube_config_raw; sensitive = true }
output "cluster_fqdn"          { value = azurerm_kubernetes_cluster.main.private_fqdn }
output "log_analytics_id"      { value = azurerm_log_analytics_workspace.main.id }
''',
    },
}


def _parse_intent(description: str) -> dict:
    desc = description.lower()

    cloud = "azure"
    for c, keywords in _CLOUD_KEYWORDS.items():
        if any(k in desc for k in keywords):
            cloud = c
            break

    resource_type = "storage"
    for r, keywords in _RESOURCE_KEYWORDS.items():
        if any(k in desc for k in keywords):
            resource_type = r
            break

    environment = "prod"
    for e, keywords in _ENV_KEYWORDS.items():
        if any(k in desc for k in keywords):
            environment = e
            break

    region = ""
    for region_phrase, region_code in _REGION_MAP.get(cloud, {}).items():
        if region_phrase in desc:
            region = region_code
            break

    return {"cloud": cloud, "resource_type": resource_type, "environment": environment, "region": region}


def _module_key(cloud: str, resource_type: str) -> str:
    key = f"{cloud}_{resource_type}"
    if key in _BUILD_MODULES:
        return key
    # Fallback mappings
    fallbacks = {
        "azure_vm": "aws_ec2",
        "azure_function": "azure_storage",
        "azure_appservice": "azure_storage",
        "aws_s3": "azure_storage",
        "aws_lambda": "aws_ec2",
        "aws_eks": "aks",
        "gcp_sql": "azure_sql",
        "gcp_vm": "aws_ec2",
        "gcp_gke": "aks",
    }
    return fallbacks.get(key, "azure_storage")


def _plain_english_plan(module_key: str, intent: dict, target: dict) -> dict:
    cloud = intent["cloud"]
    env = intent.get("environment", "prod")
    region = target.get("region") or intent.get("region") or ("eastus" if cloud == "azure" else "us-east-1")
    prefix = target.get("prefix", f"myapp-{env}")

    descriptions = {
        "azure_sql": {
            "what": f"Azure SQL Server with private network access only ({env.upper()})",
            "resources": [
                f"azurerm_resource_group: {prefix}-rg ({region})",
                "azurerm_mssql_server: SQL Server 12.0, TLS 1.2, public access DISABLED",
                f"azurerm_mssql_database: {target.get('db_name', 'appdb')} ({target.get('db_sku', 'S2')})",
                "azurerm_private_endpoint: routes SQL traffic through your VNet — no internet",
                "azurerm_virtual_network + azurerm_subnet: isolated network for private endpoints",
                "azurerm_key_vault: admin password stored as KV secret, never hardcoded",
                "random_password: 32-char admin password auto-generated",
                "azurerm_mssql_server_security_alert_policy: email alerts on threats",
                "azurerm_mssql_server_vulnerability_assessment: weekly automated scans",
                "azurerm_log_analytics_workspace: 90-day audit log retention",
                "azurerm_monitor_diagnostic_setting: SQL security audit events → Log Analytics",
            ],
            "security_modules": _ALWAYS_SECURITY_MODULES["azure"],
            "deploy_steps": [
                f"az login",
                f"az account set --subscription <your-subscription-id>",
                f"terraform init",
                f"terraform plan -var='prefix={prefix}' -var='aad_admin_username=<your-admin>' -var='aad_admin_object_id=<your-object-id>'",
                f"terraform apply",
            ],
        },
        "azure_storage": {
            "what": f"Azure Storage Account with security hardening ({env.upper()})",
            "resources": [
                f"azurerm_resource_group: {prefix}-rg ({region})",
                "azurerm_storage_account: HTTPS-only, TLS 1.2, no public blob access",
                "azurerm_log_analytics_workspace: 90-day audit logs",
                "azurerm_monitor_diagnostic_setting: StorageRead/Write/Delete → Log Analytics",
            ],
            "security_modules": _ALWAYS_SECURITY_MODULES["azure"],
            "deploy_steps": [
                "az login",
                f"terraform init",
                f"terraform plan -var='prefix={prefix}'",
                "terraform apply",
            ],
        },
        "aws_rds": {
            "what": f"AWS RDS PostgreSQL 15.4, encrypted, private subnets ({env.upper()})",
            "resources": [
                f"aws_db_instance: {target.get('identifier', 'myapp-db')} (private, encrypted, multi-AZ in prod)",
                "aws_kms_key: customer-managed key for RDS encryption",
                "aws_secretsmanager_secret: DB password stored in Secrets Manager",
                "aws_db_subnet_group: private subnets only, no public access",
                "aws_security_group: port 5432 open to app tier only — no 0.0.0.0/0",
                "aws_iam_role: enhanced monitoring role",
                "aws_cloudwatch_log_group: PostgreSQL logs, 90-day retention, encrypted",
            ],
            "security_modules": _ALWAYS_SECURITY_MODULES["aws"],
            "deploy_steps": [
                "aws sso login --profile <your-profile>",
                "terraform init",
                f"terraform plan -var='identifier={target.get('identifier','myapp-db')}' -var='vpc_id=<vpc-id>' -var='private_subnet_ids=[\"subnet-xxx\",\"subnet-yyy\"]' -var='app_security_group_id=<sg-id>'",
                "terraform apply",
            ],
        },
        "aws_ec2": {
            "what": f"AWS EC2 instance, private subnet, SSM access (no SSH keys) ({env.upper()})",
            "resources": [
                f"aws_instance: {target.get('name', 'myapp')} (private subnet, no public IP)",
                "aws_kms_key: EBS volume encryption",
                "aws_security_group: no SSH/RDP ingress — use SSM Session Manager",
                "aws_iam_role: SSM + CloudWatch permissions, no hardcoded credentials",
                "aws_cloudwatch_metric_alarm: CPU high alarm",
                "IMDSv2 enforced: prevents SSRF credential theft via metadata endpoint",
            ],
            "security_modules": _ALWAYS_SECURITY_MODULES["aws"],
            "deploy_steps": [
                "aws sso login --profile <your-profile>",
                "terraform init",
                f"terraform plan -var='name={target.get('name','myapp')}' -var='vpc_id=<vpc-id>' -var='private_subnet_id=<subnet-id>' -var='ami_id=<ami-id>'",
                "terraform apply",
            ],
        },
        "aks": {
            "what": f"Private AKS cluster with Defender for Containers ({env.upper()})",
            "resources": [
                f"azurerm_kubernetes_cluster: {prefix}-aks (private API server, AAD RBAC)",
                "private_cluster_enabled = true: Kubernetes API server unreachable from internet",
                "local_account_disabled = true: Kubernetes local accounts disabled, AAD enforced",
                "azurerm_user_assigned_identity: managed identity for AKS control plane",
                "azurerm_virtual_network + azurerm_subnet: isolated node pool networking",
                "oms_agent: Azure Monitor Container Insights",
                "microsoft_defender: Defender for Containers threat detection",
                "azurerm_log_analytics_workspace: cluster audit logs, 90-day retention",
            ],
            "security_modules": _ALWAYS_SECURITY_MODULES["azure"],
            "deploy_steps": [
                "az login",
                f"terraform init",
                f"terraform plan -var='prefix={prefix}' -var='aks_admin_group_ids=[\"<aad-group-id>\"]'",
                "terraform apply",
                f"az aks get-credentials --resource-group {prefix}-rg --name {prefix}-aks",
            ],
        },
    }
    return descriptions.get(module_key, descriptions.get("azure_storage", {}))


class BuildRequest(BaseModel):
    description: str = Field(..., min_length=5, max_length=2000)
    cloud: str | None = Field(default=None, pattern=r"^(azure|aws|gcp)$")
    region: str | None = Field(default=None, max_length=64)
    environment: str | None = Field(default=None, pattern=r"^(prod|staging|dev)$")
    prefix: str | None = Field(default=None, max_length=40)
    classification: str = Field(default="internal", max_length=64)
    extra: dict = Field(default_factory=dict)


@router.post("/build", summary="Natural-language Terraform module builder with security scan")
async def build_terraform(
    body: BuildRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    started = datetime.utcnow()

    # ── Step 1: ArcClaw scan — protect against prompt injection in description ─
    agt_audit = audit_prompt(body.description)
    scan = scan_text(body.description, redact=True)
    classification = classify_prompt(body.description)

    arc_blocked = agt_audit.is_injection_risk and agt_audit.risk_score >= 60
    arc_summary = {
        "injection_risk": agt_audit.is_injection_risk,
        "risk_score": agt_audit.risk_score,
        "vectors_flagged": agt_audit.vectors_flagged,
        "sensitive_patterns": scan.findings,
        "risk_level": classification.get("risk_level", "low"),
        "agt_used": agt_audit.agt_used,
    }

    if arc_blocked:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Description blocked by ArcClaw — prompt injection risk detected.",
                "arc_scan": arc_summary,
            },
        )

    # ── Step 2: Trust Fabric enforcement ──────────────────────────────────────
    policy_decision = await enforce(
        db=db,
        request=ActionRequest(
            module=CLAW_NAME,
            actor_id="terraclaw-build",
            actor_name="TerraClaw Build Engine",
            actor_type="system",
            action="build_terraform_module",
            target="terraform_module",
            target_type="iac_artifact",
            context={"classification": body.classification},
        ),
        ip_address=request.client.host if request.client else None,
    )
    if not policy_decision.allowed:
        raise HTTPException(
            status_code=403,
            detail={
                "message": "Terraform build blocked by Trust Fabric policy.",
                "policy": policy_decision.policy_name,
                "reason": policy_decision.reason,
            },
        )

    # ── Step 3: Parse intent from description ─────────────────────────────────
    intent = _parse_intent(body.description)
    cloud = body.cloud or intent["cloud"]
    environment = body.environment or intent["environment"]
    region = body.region or intent["region"] or ("eastus" if cloud == "azure" else "us-east-1")
    prefix = body.prefix or f"myapp-{environment}"

    target = {
        "cloud": cloud,
        "region": region,
        "environment": environment,
        "prefix": prefix,
        **body.extra,
    }

    # ── Step 4: Select and build module ───────────────────────────────────────
    module_key = _module_key(cloud, intent["resource_type"])
    files = _BUILD_MODULES.get(module_key, _BUILD_MODULES["azure_storage"])

    # Substitute prefix/region/env tokens
    rendered_files = {}
    for fname, content in files.items():
        rendered_files[fname] = content

    # ── Step 5: Security scan on combined HCL ────────────────────────────────
    combined_hcl = "\n".join(rendered_files.values())
    sec_findings, risk_score, secure_score = _run_rules(combined_hcl)
    decision = _decision(risk_score)

    # ── Step 6: Provider hints from MCP (or fallback) ────────────────────────
    provider_hint = await get_provider_hints(cloud, intent["resource_type"])
    mcp_live = await mcp_available()

    # ── Step 7: Plain-English plan ────────────────────────────────────────────
    plan = _plain_english_plan(module_key, intent, target)

    elapsed_ms = int((datetime.utcnow() - started).total_seconds() * 1000)

    return {
        "build_id": f"terra-build-{uuid.uuid4()}",
        "decision": decision,
        "risk_score": risk_score,
        "secure_score": secure_score,

        "intent": {
            "detected_cloud": cloud,
            "detected_resource": intent["resource_type"],
            "detected_environment": environment,
            "detected_region": region,
            "module_generated": module_key,
        },

        "arc_scan": arc_summary,

        "module": {
            "files": rendered_files,
            "file_count": len(rendered_files),
            "deploy_target": target,
        },

        "security_review": {
            "findings": sec_findings,
            "finding_count": len(sec_findings),
            "always_included_security": _ALWAYS_SECURITY_MODULES.get(cloud, []),
        },

        "plan": plan,

        "terraform_mcp": {
            "available": mcp_live,
            "provider_hints": provider_hint,
            "configure_via": "TERRAFORM_MCP_URL environment variable",
        },

        "policy_decision": {
            "outcome": policy_decision.outcome.value,
            "policy_name": policy_decision.policy_name,
        },

        "execution_time_ms": elapsed_ms,
    }
