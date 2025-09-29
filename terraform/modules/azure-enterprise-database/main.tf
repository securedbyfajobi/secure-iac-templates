# Azure Enterprise Database Security Module
# Enterprise-grade database security for Azure SQL Database, Azure SQL Managed Instance, and Cosmos DB

terraform {
  required_version = ">= 1.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = ">= 2.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0"
    }
  }
}

# =============================================================================
# LOCALS AND DATA SOURCES
# =============================================================================

locals {
  name_prefix = "${var.name_prefix}-${var.environment}"

  # Common tags for all resources
  common_tags = merge(var.common_tags, {
    Environment         = var.environment
    Module             = "azure-enterprise-database"
    DataClassification = var.data_classification
    Compliance         = join(",", var.compliance_frameworks)
    CreatedBy          = "terraform"
    LastModified       = timestamp()
  })

  # Security score weights
  security_weights = {
    encryption          = 20
    access_control     = 20
    monitoring         = 15
    compliance         = 15
    backup_recovery    = 15
    network_security   = 15
  }

  # Compliance mapping
  compliance_configs = {
    "SOC2" = {
      audit_enabled                = true
      threat_detection_enabled     = true
      vulnerability_assessment     = true
      transparent_data_encryption  = true
      private_endpoint_required    = true
      backup_retention_days        = 35
    }
    "NIST" = {
      audit_enabled                = true
      threat_detection_enabled     = true
      vulnerability_assessment     = true
      transparent_data_encryption  = true
      private_endpoint_required    = true
      backup_retention_days        = 90
    }
    "CIS" = {
      audit_enabled                = true
      threat_detection_enabled     = true
      vulnerability_assessment     = true
      transparent_data_encryption  = true
      private_endpoint_required    = true
      backup_retention_days        = 30
    }
    "PCI-DSS" = {
      audit_enabled                = true
      threat_detection_enabled     = true
      vulnerability_assessment     = true
      transparent_data_encryption  = true
      private_endpoint_required    = true
      backup_retention_days        = 365
    }
    "HIPAA" = {
      audit_enabled                = true
      threat_detection_enabled     = true
      vulnerability_assessment     = true
      transparent_data_encryption  = true
      private_endpoint_required    = true
      backup_retention_days        = 365
    }
    "ISO27001" = {
      audit_enabled                = true
      threat_detection_enabled     = true
      vulnerability_assessment     = true
      transparent_data_encryption  = true
      private_endpoint_required    = true
      backup_retention_days        = 90
    }
  }

  # Get the most restrictive compliance requirements
  max_backup_retention = length(var.compliance_frameworks) > 0 ? max([
    for framework in var.compliance_frameworks :
    local.compliance_configs[framework].backup_retention_days
  ]...) : var.backup_retention_days
}

data "azurerm_client_config" "current" {}
data "azuread_client_config" "current" {}

# =============================================================================
# RESOURCE GROUP
# =============================================================================

resource "azurerm_resource_group" "database" {
  name     = "${local.name_prefix}-database-rg"
  location = var.location
  tags     = local.common_tags
}

# =============================================================================
# KEY VAULT FOR SECRETS MANAGEMENT
# =============================================================================

resource "azurerm_key_vault" "database" {
  name                = "${local.name_prefix}-db-kv"
  location            = azurerm_resource_group.database.location
  resource_group_name = azurerm_resource_group.database.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "premium"

  enabled_for_disk_encryption     = true
  enabled_for_deployment          = false
  enabled_for_template_deployment = false
  purge_protection_enabled        = var.enable_purge_protection
  soft_delete_retention_days      = var.soft_delete_retention_days

  # Network access restrictions
  dynamic "network_acls" {
    for_each = var.enable_private_endpoint ? [1] : []
    content {
      default_action = "Deny"
      bypass         = "AzureServices"
      ip_rules       = var.allowed_ip_ranges
      virtual_network_subnet_ids = var.allowed_subnet_ids
    }
  }

  tags = local.common_tags
}

# Access policy for current user/service principal
resource "azurerm_key_vault_access_policy" "current" {
  key_vault_id = azurerm_key_vault.database.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = data.azurerm_client_config.current.object_id

  key_permissions = [
    "Get", "List", "Create", "Delete", "Update", "Decrypt", "Encrypt", "UnwrapKey", "WrapKey"
  ]

  secret_permissions = [
    "Get", "List", "Set", "Delete", "Recover", "Backup", "Restore"
  ]

  certificate_permissions = [
    "Get", "List", "Create", "Delete", "Update", "Import"
  ]
}

# =============================================================================
# AZURE SQL SERVER
# =============================================================================

resource "random_password" "sql_admin" {
  count   = var.create_sql_server && var.sql_admin_password == null ? 1 : 0
  length  = 32
  special = true
}

resource "azurerm_key_vault_secret" "sql_admin_password" {
  count        = var.create_sql_server ? 1 : 0
  name         = "${local.name_prefix}-sql-admin-password"
  value        = var.sql_admin_password != null ? var.sql_admin_password : random_password.sql_admin[0].result
  key_vault_id = azurerm_key_vault.database.id

  depends_on = [azurerm_key_vault_access_policy.current]

  tags = local.common_tags
}

resource "azurerm_mssql_server" "main" {
  count                         = var.create_sql_server ? 1 : 0
  name                          = "${local.name_prefix}-sql-server"
  resource_group_name           = azurerm_resource_group.database.name
  location                      = azurerm_resource_group.database.location
  version                       = var.sql_server_version
  administrator_login           = var.sql_admin_username
  administrator_login_password  = azurerm_key_vault_secret.sql_admin_password[0].value
  minimum_tls_version          = "1.2"
  public_network_access_enabled = !var.enable_private_endpoint

  azuread_administrator {
    login_username = var.azuread_admin_login
    object_id      = var.azuread_admin_object_id
    tenant_id      = data.azurerm_client_config.current.tenant_id
  }

  identity {
    type = "SystemAssigned"
  }

  tags = local.common_tags
}

# SQL Server firewall rules
resource "azurerm_mssql_firewall_rule" "allowed_ips" {
  count            = var.create_sql_server && !var.enable_private_endpoint ? length(var.allowed_ip_ranges) : 0
  name             = "AllowedIP-${count.index}"
  server_id        = azurerm_mssql_server.main[0].id
  start_ip_address = split("/", var.allowed_ip_ranges[count.index])[0]
  end_ip_address   = split("/", var.allowed_ip_ranges[count.index])[0]
}

# =============================================================================
# AZURE SQL DATABASE
# =============================================================================

resource "azurerm_mssql_database" "main" {
  for_each   = var.create_sql_server ? var.sql_databases : {}
  name       = each.key
  server_id  = azurerm_mssql_server.main[0].id
  sku_name   = each.value.sku_name
  max_size_gb = each.value.max_size_gb

  # Backup and retention
  short_term_retention_policy {
    retention_days = local.max_backup_retention > 35 ? 35 : local.max_backup_retention
  }

  long_term_retention_policy {
    weekly_retention  = each.value.weekly_retention
    monthly_retention = each.value.monthly_retention
    yearly_retention  = each.value.yearly_retention
    week_of_year     = each.value.week_of_year
  }

  # Threat detection
  threat_detection_policy {
    state                      = "Enabled"
    email_account_admins       = "Enabled"
    email_addresses           = var.threat_detection_email_addresses
    retention_days            = var.threat_detection_retention_days
    storage_account_access_key = var.threat_detection_storage_account != "" ? var.threat_detection_storage_account_key : null
    storage_endpoint          = var.threat_detection_storage_account != "" ? "https://${var.threat_detection_storage_account}.blob.core.windows.net/" : null
  }

  tags = local.common_tags
}

# Transparent Data Encryption
resource "azurerm_mssql_server_transparent_data_encryption" "main" {
  count     = var.create_sql_server ? 1 : 0
  server_id = azurerm_mssql_server.main[0].id
  key_vault_key_id = var.customer_managed_key_id
}

# Database auditing
resource "azurerm_mssql_server_extended_auditing_policy" "main" {
  count                               = var.create_sql_server ? 1 : 0
  server_id                          = azurerm_mssql_server.main[0].id
  storage_endpoint                   = var.audit_storage_account != "" ? "https://${var.audit_storage_account}.blob.core.windows.net/" : null
  storage_account_access_key         = var.audit_storage_account != "" ? var.audit_storage_account_key : null
  storage_account_subscription_id    = var.audit_storage_account != "" ? data.azurerm_client_config.current.subscription_id : null
  retention_in_days                  = var.audit_retention_days
  log_monitoring_enabled             = var.enable_log_analytics
}

# =============================================================================
# SQL MANAGED INSTANCE
# =============================================================================

resource "azurerm_mssql_managed_instance" "main" {
  count                        = var.create_managed_instance ? 1 : 0
  name                         = "${local.name_prefix}-sql-mi"
  resource_group_name          = azurerm_resource_group.database.name
  location                     = azurerm_resource_group.database.location
  administrator_login          = var.sql_admin_username
  administrator_login_password = var.sql_admin_password != null ? var.sql_admin_password : random_password.sql_admin[0].result
  license_type                = var.managed_instance_license_type
  sku_name                    = var.managed_instance_sku_name
  storage_size_in_gb          = var.managed_instance_storage_size
  subnet_id                   = var.managed_instance_subnet_id
  vcores                      = var.managed_instance_vcores
  minimum_tls_version         = "1.2"
  public_data_endpoint_enabled = false

  identity {
    type = "SystemAssigned"
  }

  tags = local.common_tags
}

# =============================================================================
# COSMOS DB
# =============================================================================

resource "azurerm_cosmosdb_account" "main" {
  count               = var.create_cosmos_db ? 1 : 0
  name                = "${local.name_prefix}-cosmos"
  location            = azurerm_resource_group.database.location
  resource_group_name = azurerm_resource_group.database.name
  offer_type          = "Standard"
  kind                = var.cosmos_db_kind

  enable_automatic_failover = var.cosmos_enable_automatic_failover
  enable_multiple_write_locations = var.cosmos_enable_multi_master

  consistency_policy {
    consistency_level       = var.cosmos_consistency_level
    max_interval_in_seconds = var.cosmos_max_interval_in_seconds
    max_staleness_prefix    = var.cosmos_max_staleness_prefix
  }

  dynamic "geo_location" {
    for_each = var.cosmos_geo_locations
    content {
      location          = geo_location.value.location
      failover_priority = geo_location.value.failover_priority
      zone_redundant    = geo_location.value.zone_redundant
    }
  }

  # Security configurations
  public_network_access_enabled = !var.enable_private_endpoint
  is_virtual_network_filter_enabled = var.enable_private_endpoint

  dynamic "virtual_network_rule" {
    for_each = var.enable_private_endpoint ? var.allowed_subnet_ids : []
    content {
      id                                   = virtual_network_rule.value
      ignore_missing_vnet_service_endpoint = false
    }
  }

  # IP firewall
  dynamic "ip_range_filter" {
    for_each = var.enable_private_endpoint ? [] : var.allowed_ip_ranges
    content {
      ip_range_filter = ip_range_filter.value
    }
  }

  # Backup configuration
  backup {
    type                = var.cosmos_backup_type
    interval_in_minutes = var.cosmos_backup_interval
    retention_in_hours  = var.cosmos_backup_retention
    storage_redundancy  = var.cosmos_backup_storage_redundancy
  }

  tags = local.common_tags
}

# Cosmos DB databases
resource "azurerm_cosmosdb_sql_database" "main" {
  for_each            = var.create_cosmos_db && var.cosmos_db_kind == "GlobalDocumentDB" ? var.cosmos_databases : {}
  name                = each.key
  resource_group_name = azurerm_resource_group.database.name
  account_name        = azurerm_cosmosdb_account.main[0].name
  throughput          = each.value.throughput

  dynamic "autoscale_settings" {
    for_each = each.value.autoscale_max_throughput != null ? [1] : []
    content {
      max_throughput = each.value.autoscale_max_throughput
    }
  }
}

# =============================================================================
# PRIVATE ENDPOINTS
# =============================================================================

resource "azurerm_private_endpoint" "sql_server" {
  count               = var.create_sql_server && var.enable_private_endpoint ? 1 : 0
  name                = "${local.name_prefix}-sql-pe"
  location            = azurerm_resource_group.database.location
  resource_group_name = azurerm_resource_group.database.name
  subnet_id           = var.private_endpoint_subnet_id

  private_service_connection {
    name                           = "${local.name_prefix}-sql-psc"
    private_connection_resource_id = azurerm_mssql_server.main[0].id
    subresource_names             = ["sqlServer"]
    is_manual_connection          = false
  }

  private_dns_zone_group {
    name                 = "default"
    private_dns_zone_ids = [azurerm_private_dns_zone.sql[0].id]
  }

  tags = local.common_tags
}

resource "azurerm_private_endpoint" "cosmos_db" {
  count               = var.create_cosmos_db && var.enable_private_endpoint ? 1 : 0
  name                = "${local.name_prefix}-cosmos-pe"
  location            = azurerm_resource_group.database.location
  resource_group_name = azurerm_resource_group.database.name
  subnet_id           = var.private_endpoint_subnet_id

  private_service_connection {
    name                           = "${local.name_prefix}-cosmos-psc"
    private_connection_resource_id = azurerm_cosmosdb_account.main[0].id
    subresource_names             = ["Sql"]
    is_manual_connection          = false
  }

  private_dns_zone_group {
    name                 = "default"
    private_dns_zone_ids = [azurerm_private_dns_zone.cosmos[0].id]
  }

  tags = local.common_tags
}

# =============================================================================
# PRIVATE DNS ZONES
# =============================================================================

resource "azurerm_private_dns_zone" "sql" {
  count               = var.create_sql_server && var.enable_private_endpoint ? 1 : 0
  name                = "privatelink.database.windows.net"
  resource_group_name = azurerm_resource_group.database.name

  tags = local.common_tags
}

resource "azurerm_private_dns_zone" "cosmos" {
  count               = var.create_cosmos_db && var.enable_private_endpoint ? 1 : 0
  name                = "privatelink.documents.azure.com"
  resource_group_name = azurerm_resource_group.database.name

  tags = local.common_tags
}

# Link DNS zones to virtual network
resource "azurerm_private_dns_zone_virtual_network_link" "sql" {
  count                 = var.create_sql_server && var.enable_private_endpoint ? 1 : 0
  name                  = "${local.name_prefix}-sql-dns-link"
  resource_group_name   = azurerm_resource_group.database.name
  private_dns_zone_name = azurerm_private_dns_zone.sql[0].name
  virtual_network_id    = var.virtual_network_id
  registration_enabled  = false

  tags = local.common_tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "cosmos" {
  count                 = var.create_cosmos_db && var.enable_private_endpoint ? 1 : 0
  name                  = "${local.name_prefix}-cosmos-dns-link"
  resource_group_name   = azurerm_resource_group.database.name
  private_dns_zone_name = azurerm_private_dns_zone.cosmos[0].name
  virtual_network_id    = var.virtual_network_id
  registration_enabled  = false

  tags = local.common_tags
}

# =============================================================================
# MONITORING AND ALERTING
# =============================================================================

# Log Analytics Workspace
resource "azurerm_log_analytics_workspace" "database" {
  count               = var.enable_log_analytics ? 1 : 0
  name                = "${local.name_prefix}-db-law"
  location            = azurerm_resource_group.database.location
  resource_group_name = azurerm_resource_group.database.name
  sku                 = var.log_analytics_sku
  retention_in_days   = var.log_analytics_retention_days

  tags = local.common_tags
}

# Diagnostic settings for SQL Server
resource "azurerm_monitor_diagnostic_setting" "sql_server" {
  count                      = var.create_sql_server && var.enable_log_analytics ? 1 : 0
  name                       = "${local.name_prefix}-sql-diagnostics"
  target_resource_id         = azurerm_mssql_server.main[0].id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.database[0].id

  enabled_log {
    category = "DevOpsOperationsAudit"
  }

  enabled_log {
    category = "SQLSecurityAuditEvents"
  }

  metric {
    category = "AllMetrics"
    enabled  = true
  }
}

# Diagnostic settings for Cosmos DB
resource "azurerm_monitor_diagnostic_setting" "cosmos_db" {
  count                      = var.create_cosmos_db && var.enable_log_analytics ? 1 : 0
  name                       = "${local.name_prefix}-cosmos-diagnostics"
  target_resource_id         = azurerm_cosmosdb_account.main[0].id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.database[0].id

  enabled_log {
    category = "DataPlaneRequests"
  }

  enabled_log {
    category = "QueryRuntimeStatistics"
  }

  enabled_log {
    category = "PartitionKeyStatistics"
  }

  enabled_log {
    category = "PartitionKeyRUConsumption"
  }

  metric {
    category = "Requests"
    enabled  = true
  }
}

# =============================================================================
# SECURITY CENTER AND DEFENDER
# =============================================================================

# SQL Server vulnerability assessment
resource "azurerm_mssql_server_vulnerability_assessment" "main" {
  count                           = var.create_sql_server && var.enable_vulnerability_assessment ? 1 : 0
  server_security_alert_policy_id = azurerm_mssql_server_security_alert_policy.main[0].id
  storage_container_path          = "${var.vulnerability_assessment_storage_endpoint}vulnerability-assessment/"
  storage_account_access_key      = var.vulnerability_assessment_storage_key

  recurring_scans {
    enabled                   = true
    email_subscription_admins = true
    emails                    = var.vulnerability_assessment_email_addresses
  }
}

# SQL Server security alert policy
resource "azurerm_mssql_server_security_alert_policy" "main" {
  count                      = var.create_sql_server ? 1 : 0
  resource_group_name        = azurerm_resource_group.database.name
  server_name                = azurerm_mssql_server.main[0].name
  state                      = "Enabled"
  email_account_admins       = true
  email_addresses           = var.security_alert_email_addresses
  retention_days            = var.security_alert_retention_days
  storage_account_access_key = var.security_alert_storage_account != "" ? var.security_alert_storage_account_key : null
  storage_endpoint          = var.security_alert_storage_account != "" ? "https://${var.security_alert_storage_account}.blob.core.windows.net/" : null

  disabled_alerts = []
}

# =============================================================================
# SECURITY ASSESSMENT
# =============================================================================

locals {
  # Encryption score (0-20)
  encryption_score = (
    (var.customer_managed_key_id != "" ? 10 : 0) +
    (var.enable_purge_protection ? 5 : 0) +
    (var.soft_delete_retention_days >= 90 ? 5 : 0)
  )

  # Access control score (0-20)
  access_control_score = (
    (var.enable_private_endpoint ? 10 : 0) +
    (var.azuread_admin_object_id != "" ? 5 : 0) +
    (length(var.allowed_ip_ranges) > 0 && !var.enable_private_endpoint ? 3 : 0) +
    (length(var.allowed_subnet_ids) > 0 ? 2 : 0)
  )

  # Monitoring score (0-15)
  monitoring_score = (
    (var.enable_log_analytics ? 8 : 0) +
    (var.enable_vulnerability_assessment ? 4 : 0) +
    (length(var.security_alert_email_addresses) > 0 ? 3 : 0)
  )

  # Compliance score (0-15)
  compliance_score = (
    (contains(var.compliance_frameworks, "SOC2") ? 3 : 0) +
    (contains(var.compliance_frameworks, "NIST") ? 3 : 0) +
    (contains(var.compliance_frameworks, "CIS") ? 3 : 0) +
    (contains(var.compliance_frameworks, "PCI-DSS") ? 3 : 0) +
    (contains(var.compliance_frameworks, "HIPAA") ? 3 : 0)
  )

  # Backup and recovery score (0-15)
  backup_recovery_score = (
    (local.max_backup_retention >= 30 ? 5 : 0) +
    (var.cosmos_backup_type == "Continuous" ? 5 : 0) +
    (var.cosmos_enable_automatic_failover ? 3 : 0) +
    (length(var.cosmos_geo_locations) > 1 ? 2 : 0)
  )

  # Network security score (0-15)
  network_security_score = (
    (var.enable_private_endpoint ? 10 : 0) +
    (!var.enable_private_endpoint && length(var.allowed_ip_ranges) > 0 ? 5 : 0)
  )

  # Total security score
  total_security_score = (
    local.encryption_score +
    local.access_control_score +
    local.monitoring_score +
    local.compliance_score +
    local.backup_recovery_score +
    local.network_security_score
  )
}