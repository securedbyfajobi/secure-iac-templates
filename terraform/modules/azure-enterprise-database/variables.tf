# Variables for Azure Enterprise Database Security Module

# =============================================================================
# BASIC CONFIGURATION
# =============================================================================

variable "name_prefix" {
  description = "Name prefix for all resources"
  type        = string
  validation {
    condition     = length(var.name_prefix) <= 20 && can(regex("^[a-zA-Z][a-zA-Z0-9-]*$", var.name_prefix))
    error_message = "Name prefix must be <= 20 characters and start with a letter."
  }
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod", "development", "production"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod, development, production."
  }
}

variable "location" {
  description = "Azure region for resources"
  type        = string
  default     = "East US"
}

variable "data_classification" {
  description = "Data classification level for the database"
  type        = string
  default     = "confidential"
  validation {
    condition     = contains(["public", "internal", "confidential", "restricted"], var.data_classification)
    error_message = "Data classification must be one of: public, internal, confidential, restricted."
  }
}

# =============================================================================
# COMPLIANCE FRAMEWORKS
# =============================================================================

variable "compliance_frameworks" {
  description = "List of compliance frameworks to adhere to"
  type        = list(string)
  default     = ["SOC2", "NIST"]
  validation {
    condition = alltrue([
      for framework in var.compliance_frameworks :
      contains(["SOC2", "NIST", "CIS", "PCI-DSS", "HIPAA", "ISO27001"], framework)
    ])
    error_message = "Compliance frameworks must be from: SOC2, NIST, CIS, PCI-DSS, HIPAA, ISO27001."
  }
}

# =============================================================================
# NETWORK CONFIGURATION
# =============================================================================

variable "virtual_network_id" {
  description = "Virtual network ID for private endpoints"
  type        = string
  default     = ""
}

variable "private_endpoint_subnet_id" {
  description = "Subnet ID for private endpoints"
  type        = string
  default     = ""
}

variable "enable_private_endpoint" {
  description = "Enable private endpoints for databases"
  type        = bool
  default     = true
}

variable "allowed_ip_ranges" {
  description = "List of allowed IP ranges in CIDR notation"
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for ip in var.allowed_ip_ranges : can(cidrhost(ip, 0))
    ])
    error_message = "All IP ranges must be valid CIDR blocks."
  }
}

variable "allowed_subnet_ids" {
  description = "List of allowed subnet IDs for database access"
  type        = list(string)
  default     = []
}

# =============================================================================
# KEY VAULT CONFIGURATION
# =============================================================================

variable "enable_purge_protection" {
  description = "Enable purge protection for Key Vault"
  type        = bool
  default     = true
}

variable "soft_delete_retention_days" {
  description = "Soft delete retention period in days"
  type        = number
  default     = 90
  validation {
    condition     = var.soft_delete_retention_days >= 7 && var.soft_delete_retention_days <= 90
    error_message = "Soft delete retention must be between 7 and 90 days."
  }
}

variable "customer_managed_key_id" {
  description = "Key Vault key ID for customer-managed encryption"
  type        = string
  default     = ""
}

# =============================================================================
# SQL SERVER CONFIGURATION
# =============================================================================

variable "create_sql_server" {
  description = "Create Azure SQL Server"
  type        = bool
  default     = true
}

variable "sql_server_version" {
  description = "SQL Server version"
  type        = string
  default     = "12.0"
  validation {
    condition     = contains(["12.0"], var.sql_server_version)
    error_message = "SQL Server version must be 12.0."
  }
}

variable "sql_admin_username" {
  description = "SQL Server administrator username"
  type        = string
  default     = "sqladmin"
  validation {
    condition     = length(var.sql_admin_username) >= 1 && length(var.sql_admin_username) <= 128
    error_message = "SQL admin username must be between 1 and 128 characters."
  }
}

variable "sql_admin_password" {
  description = "SQL Server administrator password (if null, will generate random password)"
  type        = string
  default     = null
  sensitive   = true
}

variable "azuread_admin_login" {
  description = "Azure AD administrator login name"
  type        = string
  default     = ""
}

variable "azuread_admin_object_id" {
  description = "Azure AD administrator object ID"
  type        = string
  default     = ""
}

# =============================================================================
# SQL DATABASE CONFIGURATION
# =============================================================================

variable "sql_databases" {
  description = "Map of SQL databases to create"
  type = map(object({
    sku_name          = string
    max_size_gb       = optional(number, 50)
    weekly_retention  = optional(string, "P1W")
    monthly_retention = optional(string, "P1M")
    yearly_retention  = optional(string, "P1Y")
    week_of_year     = optional(number, 1)
  }))
  default = {}
}

variable "backup_retention_days" {
  description = "Backup retention period in days"
  type        = number
  default     = 35
  validation {
    condition     = var.backup_retention_days >= 7 && var.backup_retention_days <= 35
    error_message = "Backup retention must be between 7 and 35 days."
  }
}

# =============================================================================
# SQL MANAGED INSTANCE CONFIGURATION
# =============================================================================

variable "create_managed_instance" {
  description = "Create SQL Managed Instance"
  type        = bool
  default     = false
}

variable "managed_instance_sku_name" {
  description = "SKU name for SQL Managed Instance"
  type        = string
  default     = "GP_Gen5"
  validation {
    condition = contains([
      "GP_Gen4", "GP_Gen5", "BC_Gen4", "BC_Gen5"
    ], var.managed_instance_sku_name)
    error_message = "SKU must be a valid Managed Instance SKU."
  }
}

variable "managed_instance_license_type" {
  description = "License type for SQL Managed Instance"
  type        = string
  default     = "LicenseIncluded"
  validation {
    condition     = contains(["LicenseIncluded", "BasePrice"], var.managed_instance_license_type)
    error_message = "License type must be LicenseIncluded or BasePrice."
  }
}

variable "managed_instance_vcores" {
  description = "Number of vCores for SQL Managed Instance"
  type        = number
  default     = 4
  validation {
    condition     = contains([4, 8, 16, 24, 32, 40, 64, 80], var.managed_instance_vcores)
    error_message = "vCores must be a valid Managed Instance size."
  }
}

variable "managed_instance_storage_size" {
  description = "Storage size in GB for SQL Managed Instance"
  type        = number
  default     = 32
  validation {
    condition     = var.managed_instance_storage_size >= 32 && var.managed_instance_storage_size <= 8192
    error_message = "Storage size must be between 32 and 8192 GB."
  }
}

variable "managed_instance_subnet_id" {
  description = "Subnet ID for SQL Managed Instance"
  type        = string
  default     = ""
}

# =============================================================================
# COSMOS DB CONFIGURATION
# =============================================================================

variable "create_cosmos_db" {
  description = "Create Cosmos DB account"
  type        = bool
  default     = false
}

variable "cosmos_db_kind" {
  description = "Cosmos DB kind"
  type        = string
  default     = "GlobalDocumentDB"
  validation {
    condition = contains([
      "GlobalDocumentDB", "MongoDB", "Parse"
    ], var.cosmos_db_kind)
    error_message = "Cosmos DB kind must be GlobalDocumentDB, MongoDB, or Parse."
  }
}

variable "cosmos_consistency_level" {
  description = "Cosmos DB consistency level"
  type        = string
  default     = "Session"
  validation {
    condition = contains([
      "Eventual", "Session", "BoundedStaleness", "Strong", "ConsistentPrefix"
    ], var.cosmos_consistency_level)
    error_message = "Consistency level must be a valid Cosmos DB consistency level."
  }
}

variable "cosmos_max_interval_in_seconds" {
  description = "Maximum interval in seconds for BoundedStaleness consistency"
  type        = number
  default     = 300
  validation {
    condition     = var.cosmos_max_interval_in_seconds >= 5 && var.cosmos_max_interval_in_seconds <= 86400
    error_message = "Max interval must be between 5 and 86400 seconds."
  }
}

variable "cosmos_max_staleness_prefix" {
  description = "Maximum staleness prefix for BoundedStaleness consistency"
  type        = number
  default     = 100000
  validation {
    condition     = var.cosmos_max_staleness_prefix >= 10 && var.cosmos_max_staleness_prefix <= 2147483647
    error_message = "Max staleness prefix must be between 10 and 2147483647."
  }
}

variable "cosmos_enable_automatic_failover" {
  description = "Enable automatic failover for Cosmos DB"
  type        = bool
  default     = true
}

variable "cosmos_enable_multi_master" {
  description = "Enable multi-master for Cosmos DB"
  type        = bool
  default     = false
}

variable "cosmos_geo_locations" {
  description = "Geo locations for Cosmos DB"
  type = list(object({
    location          = string
    failover_priority = number
    zone_redundant    = optional(bool, false)
  }))
  default = []
}

variable "cosmos_databases" {
  description = "Map of Cosmos DB SQL databases to create"
  type = map(object({
    throughput                = optional(number)
    autoscale_max_throughput = optional(number)
  }))
  default = {}
}

variable "cosmos_backup_type" {
  description = "Cosmos DB backup type"
  type        = string
  default     = "Periodic"
  validation {
    condition     = contains(["Periodic", "Continuous"], var.cosmos_backup_type)
    error_message = "Backup type must be Periodic or Continuous."
  }
}

variable "cosmos_backup_interval" {
  description = "Cosmos DB backup interval in minutes"
  type        = number
  default     = 240
  validation {
    condition     = var.cosmos_backup_interval >= 60 && var.cosmos_backup_interval <= 1440
    error_message = "Backup interval must be between 60 and 1440 minutes."
  }
}

variable "cosmos_backup_retention" {
  description = "Cosmos DB backup retention in hours"
  type        = number
  default     = 720
  validation {
    condition     = var.cosmos_backup_retention >= 8 && var.cosmos_backup_retention <= 720
    error_message = "Backup retention must be between 8 and 720 hours."
  }
}

variable "cosmos_backup_storage_redundancy" {
  description = "Cosmos DB backup storage redundancy"
  type        = string
  default     = "Geo"
  validation {
    condition     = contains(["Geo", "Local", "Zone"], var.cosmos_backup_storage_redundancy)
    error_message = "Backup storage redundancy must be Geo, Local, or Zone."
  }
}

# =============================================================================
# MONITORING AND AUDITING
# =============================================================================

variable "enable_log_analytics" {
  description = "Enable Log Analytics workspace"
  type        = bool
  default     = true
}

variable "log_analytics_sku" {
  description = "Log Analytics workspace SKU"
  type        = string
  default     = "PerGB2018"
  validation {
    condition = contains([
      "Free", "Standalone", "PerNode", "PerGB2018"
    ], var.log_analytics_sku)
    error_message = "Log Analytics SKU must be Free, Standalone, PerNode, or PerGB2018."
  }
}

variable "log_analytics_retention_days" {
  description = "Log Analytics retention period in days"
  type        = number
  default     = 90
  validation {
    condition     = var.log_analytics_retention_days >= 30 && var.log_analytics_retention_days <= 730
    error_message = "Log Analytics retention must be between 30 and 730 days."
  }
}

variable "audit_storage_account" {
  description = "Storage account name for audit logs"
  type        = string
  default     = ""
}

variable "audit_storage_account_key" {
  description = "Storage account access key for audit logs"
  type        = string
  default     = ""
  sensitive   = true
}

variable "audit_retention_days" {
  description = "Audit log retention period in days"
  type        = number
  default     = 90
  validation {
    condition     = var.audit_retention_days >= 0 && var.audit_retention_days <= 3285
    error_message = "Audit retention must be between 0 and 3285 days."
  }
}

# =============================================================================
# SECURITY CONFIGURATION
# =============================================================================

variable "enable_vulnerability_assessment" {
  description = "Enable vulnerability assessment"
  type        = bool
  default     = true
}

variable "vulnerability_assessment_storage_endpoint" {
  description = "Storage endpoint for vulnerability assessment"
  type        = string
  default     = ""
}

variable "vulnerability_assessment_storage_key" {
  description = "Storage account key for vulnerability assessment"
  type        = string
  default     = ""
  sensitive   = true
}

variable "vulnerability_assessment_email_addresses" {
  description = "Email addresses for vulnerability assessment notifications"
  type        = list(string)
  default     = []
}

variable "security_alert_email_addresses" {
  description = "Email addresses for security alert notifications"
  type        = list(string)
  default     = []
}

variable "security_alert_storage_account" {
  description = "Storage account name for security alerts"
  type        = string
  default     = ""
}

variable "security_alert_storage_account_key" {
  description = "Storage account access key for security alerts"
  type        = string
  default     = ""
  sensitive   = true
}

variable "security_alert_retention_days" {
  description = "Security alert retention period in days"
  type        = number
  default     = 90
  validation {
    condition     = var.security_alert_retention_days >= 0 && var.security_alert_retention_days <= 3285
    error_message = "Security alert retention must be between 0 and 3285 days."
  }
}

variable "threat_detection_email_addresses" {
  description = "Email addresses for threat detection notifications"
  type        = list(string)
  default     = []
}

variable "threat_detection_storage_account" {
  description = "Storage account name for threat detection"
  type        = string
  default     = ""
}

variable "threat_detection_storage_account_key" {
  description = "Storage account access key for threat detection"
  type        = string
  default     = ""
  sensitive   = true
}

variable "threat_detection_retention_days" {
  description = "Threat detection retention period in days"
  type        = number
  default     = 90
  validation {
    condition     = var.threat_detection_retention_days >= 0 && var.threat_detection_retention_days <= 3285
    error_message = "Threat detection retention must be between 0 and 3285 days."
  }
}

# =============================================================================
# TAGGING
# =============================================================================

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Terraform   = "true"
    Module      = "azure-enterprise-database"
    Owner       = ""
    Project     = ""
    CostCenter  = ""
    Environment = ""
  }
}