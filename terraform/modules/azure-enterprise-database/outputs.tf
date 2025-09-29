# Outputs for Azure Enterprise Database Security Module

# =============================================================================
# RESOURCE GROUP OUTPUTS
# =============================================================================

output "resource_group_name" {
  description = "Name of the database resource group"
  value       = azurerm_resource_group.database.name
}

output "resource_group_id" {
  description = "ID of the database resource group"
  value       = azurerm_resource_group.database.id
}

output "location" {
  description = "Azure region where resources are deployed"
  value       = azurerm_resource_group.database.location
}

# =============================================================================
# KEY VAULT OUTPUTS
# =============================================================================

output "key_vault_name" {
  description = "Name of the Key Vault"
  value       = azurerm_key_vault.database.name
}

output "key_vault_id" {
  description = "ID of the Key Vault"
  value       = azurerm_key_vault.database.id
}

output "key_vault_uri" {
  description = "URI of the Key Vault"
  value       = azurerm_key_vault.database.vault_uri
}

# =============================================================================
# SQL SERVER OUTPUTS
# =============================================================================

output "sql_server_name" {
  description = "Name of the SQL Server"
  value       = var.create_sql_server ? azurerm_mssql_server.main[0].name : null
}

output "sql_server_id" {
  description = "ID of the SQL Server"
  value       = var.create_sql_server ? azurerm_mssql_server.main[0].id : null
}

output "sql_server_fqdn" {
  description = "Fully qualified domain name of the SQL Server"
  value       = var.create_sql_server ? azurerm_mssql_server.main[0].fully_qualified_domain_name : null
}

output "sql_server_identity_principal_id" {
  description = "Principal ID of the SQL Server managed identity"
  value       = var.create_sql_server ? azurerm_mssql_server.main[0].identity[0].principal_id : null
}

output "sql_server_identity_tenant_id" {
  description = "Tenant ID of the SQL Server managed identity"
  value       = var.create_sql_server ? azurerm_mssql_server.main[0].identity[0].tenant_id : null
}

# =============================================================================
# SQL DATABASE OUTPUTS
# =============================================================================

output "sql_databases" {
  description = "Map of SQL database information"
  value = var.create_sql_server ? {
    for name, db in azurerm_mssql_database.main :
    name => {
      id                = db.id
      name              = db.name
      server_id         = db.server_id
      sku_name          = db.sku_name
      max_size_gb       = db.max_size_gb
      collation         = db.collation
      creation_date     = db.creation_date
    }
  } : {}
}

# =============================================================================
# SQL MANAGED INSTANCE OUTPUTS
# =============================================================================

output "managed_instance_name" {
  description = "Name of the SQL Managed Instance"
  value       = var.create_managed_instance ? azurerm_mssql_managed_instance.main[0].name : null
}

output "managed_instance_id" {
  description = "ID of the SQL Managed Instance"
  value       = var.create_managed_instance ? azurerm_mssql_managed_instance.main[0].id : null
}

output "managed_instance_fqdn" {
  description = "Fully qualified domain name of the SQL Managed Instance"
  value       = var.create_managed_instance ? azurerm_mssql_managed_instance.main[0].fqdn : null
}

output "managed_instance_identity_principal_id" {
  description = "Principal ID of the SQL Managed Instance managed identity"
  value       = var.create_managed_instance ? azurerm_mssql_managed_instance.main[0].identity[0].principal_id : null
}

# =============================================================================
# COSMOS DB OUTPUTS
# =============================================================================

output "cosmos_db_account_name" {
  description = "Name of the Cosmos DB account"
  value       = var.create_cosmos_db ? azurerm_cosmosdb_account.main[0].name : null
}

output "cosmos_db_account_id" {
  description = "ID of the Cosmos DB account"
  value       = var.create_cosmos_db ? azurerm_cosmosdb_account.main[0].id : null
}

output "cosmos_db_endpoint" {
  description = "Endpoint of the Cosmos DB account"
  value       = var.create_cosmos_db ? azurerm_cosmosdb_account.main[0].endpoint : null
}

output "cosmos_db_primary_key" {
  description = "Primary key of the Cosmos DB account"
  value       = var.create_cosmos_db ? azurerm_cosmosdb_account.main[0].primary_key : null
  sensitive   = true
}

output "cosmos_db_secondary_key" {
  description = "Secondary key of the Cosmos DB account"
  value       = var.create_cosmos_db ? azurerm_cosmosdb_account.main[0].secondary_key : null
  sensitive   = true
}

output "cosmos_db_connection_strings" {
  description = "Connection strings for the Cosmos DB account"
  value       = var.create_cosmos_db ? azurerm_cosmosdb_account.main[0].connection_strings : null
  sensitive   = true
}

output "cosmos_databases" {
  description = "Map of Cosmos DB SQL database information"
  value = var.create_cosmos_db && var.cosmos_db_kind == "GlobalDocumentDB" ? {
    for name, db in azurerm_cosmosdb_sql_database.main :
    name => {
      id         = db.id
      name       = db.name
      throughput = db.throughput
    }
  } : {}
}

# =============================================================================
# PRIVATE ENDPOINT OUTPUTS
# =============================================================================

output "sql_private_endpoint_id" {
  description = "ID of the SQL Server private endpoint"
  value       = var.create_sql_server && var.enable_private_endpoint ? azurerm_private_endpoint.sql_server[0].id : null
}

output "sql_private_endpoint_ip" {
  description = "Private IP address of the SQL Server private endpoint"
  value       = var.create_sql_server && var.enable_private_endpoint ? azurerm_private_endpoint.sql_server[0].private_service_connection[0].private_ip_address : null
}

output "cosmos_private_endpoint_id" {
  description = "ID of the Cosmos DB private endpoint"
  value       = var.create_cosmos_db && var.enable_private_endpoint ? azurerm_private_endpoint.cosmos_db[0].id : null
}

output "cosmos_private_endpoint_ip" {
  description = "Private IP address of the Cosmos DB private endpoint"
  value       = var.create_cosmos_db && var.enable_private_endpoint ? azurerm_private_endpoint.cosmos_db[0].private_service_connection[0].private_ip_address : null
}

# =============================================================================
# PRIVATE DNS ZONE OUTPUTS
# =============================================================================

output "sql_private_dns_zone_id" {
  description = "ID of the SQL Server private DNS zone"
  value       = var.create_sql_server && var.enable_private_endpoint ? azurerm_private_dns_zone.sql[0].id : null
}

output "cosmos_private_dns_zone_id" {
  description = "ID of the Cosmos DB private DNS zone"
  value       = var.create_cosmos_db && var.enable_private_endpoint ? azurerm_private_dns_zone.cosmos[0].id : null
}

# =============================================================================
# MONITORING OUTPUTS
# =============================================================================

output "log_analytics_workspace_name" {
  description = "Name of the Log Analytics workspace"
  value       = var.enable_log_analytics ? azurerm_log_analytics_workspace.database[0].name : null
}

output "log_analytics_workspace_id" {
  description = "ID of the Log Analytics workspace"
  value       = var.enable_log_analytics ? azurerm_log_analytics_workspace.database[0].id : null
}

output "log_analytics_workspace_workspace_id" {
  description = "Workspace ID of the Log Analytics workspace"
  value       = var.enable_log_analytics ? azurerm_log_analytics_workspace.database[0].workspace_id : null
}

output "log_analytics_primary_shared_key" {
  description = "Primary shared key of the Log Analytics workspace"
  value       = var.enable_log_analytics ? azurerm_log_analytics_workspace.database[0].primary_shared_key : null
  sensitive   = true
}

# =============================================================================
# SECURITY ASSESSMENT OUTPUTS
# =============================================================================

output "security_score" {
  description = "Overall security score (0-100)"
  value       = local.total_security_score
}

output "security_score_breakdown" {
  description = "Breakdown of security score by category"
  value = {
    encryption        = local.encryption_score
    access_control   = local.access_control_score
    monitoring       = local.monitoring_score
    compliance       = local.compliance_score
    backup_recovery  = local.backup_recovery_score
    network_security = local.network_security_score
    total           = local.total_security_score
  }
}

output "compliance_status" {
  description = "Compliance status for each framework"
  value = {
    for framework in var.compliance_frameworks :
    framework => {
      enabled = contains(var.compliance_frameworks, framework)
      config  = local.compliance_configs[framework]
    }
  }
}

# =============================================================================
# CONFIGURATION SUMMARY
# =============================================================================

output "database_configuration_summary" {
  description = "Summary of database configuration"
  value = {
    sql_server_enabled        = var.create_sql_server
    managed_instance_enabled  = var.create_managed_instance
    cosmos_db_enabled        = var.create_cosmos_db
    private_endpoints_enabled = var.enable_private_endpoint
    log_analytics_enabled    = var.enable_log_analytics
    vulnerability_assessment_enabled = var.enable_vulnerability_assessment
    backup_retention_days    = local.max_backup_retention
    sql_databases_count      = length(var.sql_databases)
    cosmos_databases_count   = length(var.cosmos_databases)
    compliance_frameworks    = var.compliance_frameworks
    data_classification      = var.data_classification
  }
}

output "network_security_summary" {
  description = "Summary of network security configuration"
  value = {
    private_endpoints_enabled = var.enable_private_endpoint
    allowed_ip_ranges_count   = length(var.allowed_ip_ranges)
    allowed_subnets_count     = length(var.allowed_subnet_ids)
    virtual_network_id        = var.virtual_network_id
    private_endpoint_subnet_id = var.private_endpoint_subnet_id
  }
}

output "encryption_summary" {
  description = "Summary of encryption configuration"
  value = {
    transparent_data_encryption = var.create_sql_server
    customer_managed_key       = var.customer_managed_key_id != ""
    key_vault_enabled         = true
    purge_protection_enabled  = var.enable_purge_protection
    soft_delete_retention_days = var.soft_delete_retention_days
  }
}

# =============================================================================
# CONNECTION INFORMATION
# =============================================================================

output "connection_strings" {
  description = "Database connection information"
  value = {
    sql_server = var.create_sql_server ? {
      server_name = azurerm_mssql_server.main[0].fully_qualified_domain_name
      admin_login = var.sql_admin_username
      databases   = [for name, _ in var.sql_databases : name]
    } : null

    managed_instance = var.create_managed_instance ? {
      fqdn        = azurerm_mssql_managed_instance.main[0].fqdn
      admin_login = var.sql_admin_username
    } : null

    cosmos_db = var.create_cosmos_db ? {
      endpoint  = azurerm_cosmosdb_account.main[0].endpoint
      databases = [for name, _ in var.cosmos_databases : name]
    } : null
  }
  sensitive = true
}

# =============================================================================
# COST OPTIMIZATION OUTPUTS
# =============================================================================

output "estimated_monthly_cost" {
  description = "Estimated monthly cost in USD (approximate)"
  value = {
    sql_server_cost = var.create_sql_server ? "Variable based on database SKUs and usage" : 0
    managed_instance_cost = var.create_managed_instance ? "Variable based on vCores and storage" : 0
    cosmos_db_cost = var.create_cosmos_db ? "Variable based on throughput and storage" : 0
    key_vault_cost = "~$0.03 per 10,000 operations"
    log_analytics_cost = var.enable_log_analytics ? "Variable based on data ingestion" : 0
    private_endpoint_cost = var.enable_private_endpoint ? "~$7.20 per endpoint per month" : 0
    storage_cost = "Variable based on backup and audit log storage"
    note = "Actual costs depend on usage patterns, data volume, and regional pricing"
  }
}

# =============================================================================
# RECOMMENDATIONS
# =============================================================================

output "security_recommendations" {
  description = "Security improvement recommendations"
  value = {
    high_priority = compact([
      local.total_security_score < 80 ? "Security score below enterprise threshold (80). Review and enhance security configurations." : "",
      !var.enable_private_endpoint ? "Enable private endpoints for enhanced network security." : "",
      var.customer_managed_key_id == "" ? "Configure customer-managed encryption keys for enhanced data protection." : "",
      !var.enable_log_analytics ? "Enable Log Analytics for security monitoring and compliance." : ""
    ])
    medium_priority = compact([
      !var.enable_vulnerability_assessment ? "Enable vulnerability assessment for proactive security management." : "",
      length(var.security_alert_email_addresses) == 0 ? "Configure security alert email notifications." : "",
      var.azuread_admin_object_id == "" ? "Configure Azure AD administrator for enhanced identity management." : "",
      local.max_backup_retention < 90 ? "Consider extending backup retention for compliance requirements." : ""
    ])
    low_priority = compact([
      !var.enable_purge_protection ? "Enable purge protection for Key Vault in production environments." : "",
      var.soft_delete_retention_days < 90 ? "Consider extending soft delete retention period." : "",
      length(var.allowed_ip_ranges) == 0 && !var.enable_private_endpoint ? "Configure IP allowlists for database access." : "",
      var.cosmos_backup_type == "Periodic" && var.create_cosmos_db ? "Consider Continuous backup for point-in-time recovery." : ""
    ])
  }
}

output "compliance_gaps" {
  description = "Identified compliance gaps and remediation steps"
  value = {
    for framework in ["SOC2", "NIST", "CIS", "PCI-DSS", "HIPAA", "ISO27001"] :
    framework => {
      required     = contains(var.compliance_frameworks, framework)
      configured   = contains(var.compliance_frameworks, framework)
      requirements = local.compliance_configs[framework]
      gap_analysis = !contains(var.compliance_frameworks, framework) ? "Framework not configured" : "Compliant"
      remediation  = !contains(var.compliance_frameworks, framework) ? "Add ${framework} to compliance_frameworks variable" : "No action required"
    }
  }
}

# =============================================================================
# DISASTER RECOVERY INFORMATION
# =============================================================================

output "disaster_recovery_summary" {
  description = "Disaster recovery configuration summary"
  value = {
    sql_backup_retention     = local.max_backup_retention
    cosmos_geo_replication  = var.create_cosmos_db ? length(var.cosmos_geo_locations) > 1 : false
    cosmos_automatic_failover = var.cosmos_enable_automatic_failover
    key_vault_soft_delete   = var.soft_delete_retention_days
    audit_log_retention     = var.audit_retention_days
    monitoring_retention    = var.log_analytics_retention_days
  }
}