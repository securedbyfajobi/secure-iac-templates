# Enterprise Secrets Management Module Variables

# =============================================================================
# CORE CONFIGURATION
# =============================================================================

variable "name_prefix" {
  description = "Prefix for all resource names"
  type        = string
  validation {
    condition     = can(regex("^[a-z0-9-]+$", var.name_prefix))
    error_message = "Name prefix must contain only lowercase letters, numbers, and hyphens."
  }
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}

variable "compliance_frameworks" {
  description = "List of compliance frameworks to adhere to"
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for framework in var.compliance_frameworks :
      contains(["SOC2", "PCI-DSS", "HIPAA", "NIST", "FIPS"], framework)
    ])
    error_message = "Compliance frameworks must be one of: SOC2, PCI-DSS, HIPAA, NIST, FIPS."
  }
}

# =============================================================================
# CLOUD PROVIDER ENABLEMENT
# =============================================================================

variable "enable_aws_secrets" {
  description = "Enable AWS Secrets Manager integration"
  type        = bool
  default     = true
}

variable "enable_azure_secrets" {
  description = "Enable Azure Key Vault integration"
  type        = bool
  default     = false
}

variable "enable_gcp_secrets" {
  description = "Enable Google Secret Manager integration"
  type        = bool
  default     = false
}

variable "enable_vault_integration" {
  description = "Enable HashiCorp Vault integration"
  type        = bool
  default     = false
}

# =============================================================================
# AWS SECRETS MANAGER CONFIGURATION
# =============================================================================

variable "database_secrets" {
  description = "Map of database secrets to manage in AWS Secrets Manager"
  type = map(object({
    description = string
    category    = string # critical, high, medium, low
    username    = string
    password    = string
    engine      = string
    host        = string
    port        = number
    dbname      = string
  }))
  default   = {}
  sensitive = true
}

variable "api_secrets" {
  description = "Map of API secrets to manage in AWS Secrets Manager"
  type = map(object({
    description = string
    category    = string # critical, high, medium, low
    api_key     = string
    secret_key  = string
    endpoint    = string
  }))
  default   = {}
  sensitive = true
}

variable "application_secrets" {
  description = "Map of application configuration secrets"
  type = map(object({
    description = string
    category    = string # critical, high, medium, low
    config_data = map(string)
  }))
  default   = {}
  sensitive = true
}

variable "secret_recovery_window_days" {
  description = "Number of days to retain deleted secrets for recovery"
  type        = number
  default     = 30
  validation {
    condition     = var.secret_recovery_window_days >= 7 && var.secret_recovery_window_days <= 30
    error_message = "Recovery window must be between 7 and 30 days."
  }
}

variable "enable_cross_region_secrets" {
  description = "Enable cross-region secret replication"
  type        = bool
  default     = true
}

variable "aws_replica_region" {
  description = "AWS region for secret replication"
  type        = string
  default     = "us-west-2"
}

# =============================================================================
# AZURE KEY VAULT CONFIGURATION
# =============================================================================

variable "azure_location" {
  description = "Azure region for Key Vault"
  type        = string
  default     = "East US"
}

variable "azure_resource_group_name" {
  description = "Azure resource group name for Key Vault"
  type        = string
  default     = ""
}

variable "azure_database_secrets" {
  description = "Map of database secrets for Azure Key Vault"
  type = map(object({
    connection_string = string
    category         = string # critical, high, medium, low
  }))
  default   = {}
  sensitive = true
}

variable "azure_api_secrets" {
  description = "Map of API secrets for Azure Key Vault"
  type = map(object({
    api_key  = string
    category = string # critical, high, medium, low
  }))
  default   = {}
  sensitive = true
}

variable "enable_purge_protection" {
  description = "Enable purge protection for Azure Key Vault"
  type        = bool
  default     = true
}

variable "azure_soft_delete_retention_days" {
  description = "Soft delete retention period for Azure Key Vault"
  type        = number
  default     = 90
  validation {
    condition     = var.azure_soft_delete_retention_days >= 7 && var.azure_soft_delete_retention_days <= 90
    error_message = "Soft delete retention must be between 7 and 90 days."
  }
}

variable "azure_public_access_enabled" {
  description = "Enable public network access to Azure Key Vault"
  type        = bool
  default     = false
}

variable "azure_allowed_ips" {
  description = "List of allowed IP addresses for Azure Key Vault access"
  type        = list(string)
  default     = []
}

variable "azure_allowed_subnets" {
  description = "List of allowed subnet IDs for Azure Key Vault access"
  type        = list(string)
  default     = []
}

# =============================================================================
# GCP SECRET MANAGER CONFIGURATION
# =============================================================================

variable "gcp_project_id" {
  description = "GCP project ID for Secret Manager"
  type        = string
  default     = ""
}

variable "gcp_database_secrets" {
  description = "Map of database secrets for GCP Secret Manager"
  type = map(object({
    username = string
    password = string
    host     = string
    port     = number
    database = string
    category = string # critical, high, medium, low
  }))
  default   = {}
  sensitive = true
}

variable "gcp_api_secrets" {
  description = "Map of API secrets for GCP Secret Manager"
  type = map(object({
    api_key  = string
    category = string # critical, high, medium, low
  }))
  default   = {}
  sensitive = true
}

# =============================================================================
# AUTOMATIC ROTATION CONFIGURATION
# =============================================================================

variable "enable_automatic_rotation" {
  description = "Enable automatic secret rotation"
  type        = bool
  default     = true
}

variable "default_rotation_days" {
  description = "Default number of days between secret rotations"
  type        = number
  default     = 90
  validation {
    condition     = var.default_rotation_days >= 30 && var.default_rotation_days <= 365
    error_message = "Rotation days must be between 30 and 365."
  }
}

variable "critical_rotation_days" {
  description = "Rotation interval for critical secrets (days)"
  type        = number
  default     = 30
  validation {
    condition     = var.critical_rotation_days >= 7 && var.critical_rotation_days <= 90
    error_message = "Critical rotation days must be between 7 and 90."
  }
}

variable "high_rotation_days" {
  description = "Rotation interval for high priority secrets (days)"
  type        = number
  default     = 60
  validation {
    condition     = var.high_rotation_days >= 30 && var.high_rotation_days <= 180
    error_message = "High priority rotation days must be between 30 and 180."
  }
}

# =============================================================================
# SECURITY CONFIGURATION
# =============================================================================

variable "enable_encryption_at_rest" {
  description = "Enable encryption at rest for all secrets"
  type        = bool
  default     = true
}

variable "enable_encryption_in_transit" {
  description = "Enable encryption in transit for secret access"
  type        = bool
  default     = true
}

variable "kms_key_rotation_enabled" {
  description = "Enable automatic rotation of KMS keys"
  type        = bool
  default     = true
}

variable "secret_access_logging" {
  description = "Enable detailed logging of secret access"
  type        = bool
  default     = true
}

variable "enable_secret_versioning" {
  description = "Enable versioning for secrets"
  type        = bool
  default     = true
}

variable "max_secret_versions" {
  description = "Maximum number of secret versions to retain"
  type        = number
  default     = 10
  validation {
    condition     = var.max_secret_versions >= 2 && var.max_secret_versions <= 100
    error_message = "Max secret versions must be between 2 and 100."
  }
}

# =============================================================================
# ACCESS CONTROL CONFIGURATION
# =============================================================================

variable "secret_access_policies" {
  description = "Map of IAM policies for secret access"
  type = map(object({
    principals   = list(string)
    actions      = list(string)
    conditions   = map(any)
    secret_arns  = list(string)
  }))
  default = {}
}

variable "enable_least_privilege_access" {
  description = "Enforce least privilege access to secrets"
  type        = bool
  default     = true
}

variable "secret_access_review_days" {
  description = "Days between access reviews for secrets"
  type        = number
  default     = 30
  validation {
    condition     = var.secret_access_review_days >= 7 && var.secret_access_review_days <= 90
    error_message = "Access review days must be between 7 and 90."
  }
}

variable "enable_just_in_time_access" {
  description = "Enable just-in-time access for secrets"
  type        = bool
  default     = false
}

variable "jit_access_duration_hours" {
  description = "Duration of just-in-time access in hours"
  type        = number
  default     = 4
  validation {
    condition     = var.jit_access_duration_hours >= 1 && var.jit_access_duration_hours <= 24
    error_message = "JIT access duration must be between 1 and 24 hours."
  }
}

# =============================================================================
# MONITORING AND ALERTING
# =============================================================================

variable "enable_secrets_monitoring" {
  description = "Enable comprehensive secrets monitoring"
  type        = bool
  default     = true
}

variable "notification_topic_arn" {
  description = "SNS topic ARN for secrets management notifications"
  type        = string
  default     = ""
}

variable "alert_on_secret_access" {
  description = "Generate alerts for secret access events"
  type        = bool
  default     = false
}

variable "alert_on_rotation_failure" {
  description = "Generate alerts for rotation failures"
  type        = bool
  default     = true
}

variable "alert_on_expired_secrets" {
  description = "Generate alerts for expired secrets"
  type        = bool
  default     = true
}

variable "secret_expiry_warning_days" {
  description = "Days before expiry to send warning alerts"
  type        = number
  default     = 7
  validation {
    condition     = var.secret_expiry_warning_days >= 1 && var.secret_expiry_warning_days <= 30
    error_message = "Expiry warning days must be between 1 and 30."
  }
}

# =============================================================================
# COMPLIANCE MONITORING
# =============================================================================

variable "enable_compliance_monitoring" {
  description = "Enable automated compliance monitoring for secrets"
  type        = bool
  default     = true
}

variable "compliance_check_schedule" {
  description = "CloudWatch Events schedule for compliance checks"
  type        = string
  default     = "cron(0 9 * * ? *)"  # Daily at 9 AM
  validation {
    condition     = can(regex("^cron\\(.*\\)$", var.compliance_check_schedule))
    error_message = "Compliance check schedule must be a valid cron expression."
  }
}

variable "compliance_report_frequency" {
  description = "Frequency of compliance reports (daily, weekly, monthly)"
  type        = string
  default     = "weekly"
  validation {
    condition     = contains(["daily", "weekly", "monthly"], var.compliance_report_frequency)
    error_message = "Compliance report frequency must be daily, weekly, or monthly."
  }
}

variable "enable_compliance_remediation" {
  description = "Enable automatic remediation of compliance violations"
  type        = bool
  default     = false
}

# =============================================================================
# INTEGRATION SETTINGS
# =============================================================================

variable "integrate_with_iam" {
  description = "Integrate with existing IAM security module"
  type        = bool
  default     = true
}

variable "integrate_with_backup" {
  description = "Integrate with backup and DR module"
  type        = bool
  default     = true
}

variable "secret_backup_enabled" {
  description = "Enable backup of secret metadata and configurations"
  type        = bool
  default     = true
}

variable "cross_account_secret_sharing" {
  description = "Enable cross-account secret sharing capabilities"
  type        = bool
  default     = false
}

variable "external_secret_sources" {
  description = "List of external secret management systems to integrate"
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for source in var.external_secret_sources :
      contains(["vault", "kubernetes", "cyberark", "thycotic"], source)
    ])
    error_message = "External sources must be one of: vault, kubernetes, cyberark, thycotic."
  }
}

# =============================================================================
# PERFORMANCE AND SCALING
# =============================================================================

variable "secret_cache_ttl_seconds" {
  description = "TTL for secret caching in seconds"
  type        = number
  default     = 300
  validation {
    condition     = var.secret_cache_ttl_seconds >= 60 && var.secret_cache_ttl_seconds <= 3600
    error_message = "Cache TTL must be between 60 and 3600 seconds."
  }
}

variable "max_concurrent_rotations" {
  description = "Maximum number of concurrent secret rotations"
  type        = number
  default     = 5
  validation {
    condition     = var.max_concurrent_rotations >= 1 && var.max_concurrent_rotations <= 20
    error_message = "Max concurrent rotations must be between 1 and 20."
  }
}

variable "enable_secret_batching" {
  description = "Enable batching of secret operations for performance"
  type        = bool
  default     = true
}

variable "batch_size" {
  description = "Number of secrets to process in each batch"
  type        = number
  default     = 10
  validation {
    condition     = var.batch_size >= 1 && var.batch_size <= 50
    error_message = "Batch size must be between 1 and 50."
  }
}

# =============================================================================
# DISASTER RECOVERY
# =============================================================================

variable "enable_secret_dr" {
  description = "Enable disaster recovery capabilities for secrets"
  type        = bool
  default     = true
}

variable "secret_dr_region" {
  description = "Disaster recovery region for secrets"
  type        = string
  default     = "us-west-2"
}

variable "secret_dr_sync_frequency" {
  description = "Frequency of DR synchronization (hours)"
  type        = number
  default     = 6
  validation {
    condition     = var.secret_dr_sync_frequency >= 1 && var.secret_dr_sync_frequency <= 24
    error_message = "DR sync frequency must be between 1 and 24 hours."
  }
}

variable "enable_secret_dr_testing" {
  description = "Enable automated DR testing for secrets"
  type        = bool
  default     = true
}

# =============================================================================
# COST OPTIMIZATION
# =============================================================================

variable "enable_cost_optimization" {
  description = "Enable cost optimization features"
  type        = bool
  default     = true
}

variable "secret_lifecycle_management" {
  description = "Enable lifecycle management for unused secrets"
  type        = bool
  default     = true
}

variable "unused_secret_threshold_days" {
  description = "Days after which unused secrets are flagged for cleanup"
  type        = number
  default     = 90
  validation {
    condition     = var.unused_secret_threshold_days >= 30 && var.unused_secret_threshold_days <= 365
    error_message = "Unused secret threshold must be between 30 and 365 days."
  }
}

variable "enable_secret_compression" {
  description = "Enable compression for large secret values"
  type        = bool
  default     = true
}