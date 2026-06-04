"""Terraform MCP client — connects to HashiCorp Terraform MCP server when available."""
import os
import httpx

_MCP_URL = os.getenv("TERRAFORM_MCP_URL", "").rstrip("/")
_TIMEOUT = 10.0

# ─── Provider resource schema cache (built-in fallback) ──────────────────────

_PROVIDER_HINTS = {
    "azure": {
        "sql":      "azurerm_mssql_server, azurerm_mssql_database, azurerm_private_endpoint",
        "storage":  "azurerm_storage_account, azurerm_storage_container",
        "vm":       "azurerm_linux_virtual_machine, azurerm_network_interface, azurerm_managed_disk",
        "aks":      "azurerm_kubernetes_cluster, azurerm_kubernetes_cluster_node_pool",
        "vnet":     "azurerm_virtual_network, azurerm_subnet, azurerm_network_security_group",
        "keyvault": "azurerm_key_vault, azurerm_key_vault_secret, azurerm_key_vault_access_policy",
        "function": "azurerm_linux_function_app, azurerm_service_plan, azurerm_storage_account",
        "appservice":"azurerm_linux_web_app, azurerm_service_plan",
        "cosmos":   "azurerm_cosmosdb_account, azurerm_cosmosdb_sql_database",
        "redis":    "azurerm_redis_cache, azurerm_private_endpoint",
        "servicebus":"azurerm_servicebus_namespace, azurerm_servicebus_queue",
    },
    "aws": {
        "rds":      "aws_db_instance, aws_db_subnet_group, aws_security_group",
        "ec2":      "aws_instance, aws_security_group, aws_iam_instance_profile",
        "eks":      "aws_eks_cluster, aws_eks_node_group, aws_iam_role",
        "lambda":   "aws_lambda_function, aws_iam_role, aws_cloudwatch_log_group",
        "s3":       "aws_s3_bucket, aws_s3_bucket_policy, aws_s3_bucket_versioning",
        "vpc":      "aws_vpc, aws_subnet, aws_security_group, aws_internet_gateway",
        "dynamodb": "aws_dynamodb_table",
        "sqs":      "aws_sqs_queue, aws_sqs_queue_policy",
    },
    "gcp": {
        "sql":      "google_sql_database_instance, google_sql_database, google_sql_user",
        "gke":      "google_container_cluster, google_container_node_pool",
        "vm":       "google_compute_instance, google_compute_firewall",
        "storage":  "google_storage_bucket, google_storage_bucket_iam_binding",
        "function": "google_cloudfunctions_function, google_storage_bucket",
    },
}


async def get_provider_hints(cloud: str, resource_type: str) -> str:
    """Return Terraform resource hints — live from MCP server or built-in fallback."""
    if _MCP_URL:
        try:
            async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
                r = await client.post(
                    f"{_MCP_URL}/resolveProviderDocID",
                    json={"provider": cloud, "resource": resource_type},
                )
                if r.status_code == 200:
                    data = r.json()
                    return data.get("schema_summary", "")
        except Exception:
            pass  # Fall through to built-in

    cloud_hints = _PROVIDER_HINTS.get(cloud, {})
    for key, value in cloud_hints.items():
        if key in resource_type.lower():
            return value
    return ""


async def mcp_available() -> bool:
    if not _MCP_URL:
        return False
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(f"{_MCP_URL}/health")
            return r.status_code == 200
    except Exception:
        return False
