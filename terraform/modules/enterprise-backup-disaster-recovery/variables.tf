# Enterprise Backup and Disaster Recovery Module Variables

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
      contains(["SOC2", "PCI-DSS", "HIPAA", "NIST", "ISO27001"], framework)
    ])
    error_message = "Compliance frameworks must be one of: SOC2, PCI-DSS, HIPAA, NIST, ISO27001."
  }
}

# =============================================================================
# BACKUP TIER CONFIGURATION
# =============================================================================

variable "backup_tiers" {
  description = "List of backup tiers to enable (critical, high, medium, low)"
  type        = list(string)
  default     = ["critical", "high", "medium"]
  validation {
    condition = alltrue([
      for tier in var.backup_tiers :
      contains(["critical", "high", "medium", "low"], tier)
    ])
    error_message = "Backup tiers must be one of: critical, high, medium, low."
  }
}

variable "default_daily_retention" {
  description = "Default daily backup retention in days"
  type        = number
  default     = 30
  validation {
    condition     = var.default_daily_retention >= 7 && var.default_daily_retention <= 365
    error_message = "Daily retention must be between 7 and 365 days."
  }
}

variable "default_weekly_retention" {
  description = "Default weekly backup retention in weeks"
  type        = number
  default     = 12
  validation {
    condition     = var.default_weekly_retention >= 4 && var.default_weekly_retention <= 104
    error_message = "Weekly retention must be between 4 and 104 weeks."
  }
}

# =============================================================================
# AWS CONFIGURATION
# =============================================================================

variable "enable_aws_dr" {
  description = "Enable AWS disaster recovery capabilities"
  type        = bool
  default     = true
}

variable "aws_backup_resources" {
  description = "Map of backup tier to list of AWS resource ARNs to backup"
  type        = map(list(string))
  default = {
    critical = []
    high     = []
    medium   = []
    low      = []
  }
}

variable "enable_cross_region_backup" {
  description = "Enable cross-region backup replication"
  type        = bool
  default     = true
}

variable "aws_dr_region" {
  description = "AWS disaster recovery region"
  type        = string
  default     = "us-west-2"
}

# =============================================================================
# AZURE CONFIGURATION
# =============================================================================

variable "enable_azure_dr" {
  description = "Enable Azure disaster recovery capabilities"
  type        = bool
  default     = false
}

variable "azure_primary_location" {
  description = "Primary Azure region"
  type        = string
  default     = "East US"
}

variable "azure_dr_location" {
  description = "Azure disaster recovery region"
  type        = string
  default     = "West US 2"
}

variable "azure_resource_group_name" {
  description = "Azure resource group name for backup resources"
  type        = string
  default     = ""
}

variable "azure_encryption_key_id" {
  description = "Azure Key Vault key ID for backup encryption"
  type        = string
  default     = ""
}

variable "azure_timezone" {
  description = "Timezone for Azure backup schedules"
  type        = string
  default     = "UTC"
}

# =============================================================================
# GCP CONFIGURATION
# =============================================================================

variable "enable_gcp_dr" {
  description = "Enable GCP disaster recovery capabilities"
  type        = bool
  default     = false
}

variable "gcp_project_id" {
  description = "GCP project ID"
  type        = string
  default     = ""
}

variable "gcp_primary_region" {
  description = "Primary GCP region"
  type        = string
  default     = "us-central1"
}

variable "gcp_dr_region" {
  description = "GCP disaster recovery region"
  type        = string
  default     = "us-east1"
}

variable "gcp_kms_key_name" {
  description = "GCP KMS key name for backup encryption"
  type        = string
  default     = ""
}

# =============================================================================
# DR AUTOMATION CONFIGURATION
# =============================================================================

variable "enable_dr_automation" {
  description = "Enable automated disaster recovery orchestration"
  type        = bool
  default     = true
}

variable "dr_test_schedule" {
  description = "CloudWatch Events schedule expression for DR testing"
  type        = string
  default     = "cron(0 6 ? * SUN *)"  # Every Sunday at 6 AM
  validation {
    condition     = can(regex("^cron\\(.*\\)$", var.dr_test_schedule))
    error_message = "DR test schedule must be a valid cron expression."
  }
}

variable "notification_topic_arn" {
  description = "SNS topic ARN for backup and DR notifications"
  type        = string
  default     = ""
}

# =============================================================================
# RTO/RPO REQUIREMENTS
# =============================================================================

variable "critical_rto_minutes" {
  description = "Recovery Time Objective for critical tier (minutes)"
  type        = number
  default     = 15
  validation {
    condition     = var.critical_rto_minutes >= 5 && var.critical_rto_minutes <= 240
    error_message = "Critical RTO must be between 5 and 240 minutes."
  }
}

variable "critical_rpo_minutes" {
  description = "Recovery Point Objective for critical tier (minutes)"
  type        = number
  default     = 5
  validation {
    condition     = var.critical_rpo_minutes >= 1 && var.critical_rpo_minutes <= 60
    error_message = "Critical RPO must be between 1 and 60 minutes."
  }
}

variable "high_rto_minutes" {
  description = "Recovery Time Objective for high tier (minutes)"
  type        = number
  default     = 60
  validation {
    condition     = var.high_rto_minutes >= 15 && var.high_rto_minutes <= 480
    error_message = "High RTO must be between 15 and 480 minutes."
  }
}

variable "high_rpo_minutes" {
  description = "Recovery Point Objective for high tier (minutes)"
  type        = number
  default     = 30
  validation {
    condition     = var.high_rpo_minutes >= 5 && var.high_rpo_minutes <= 240
    error_message = "High RPO must be between 5 and 240 minutes."
  }
}

# =============================================================================
# COST OPTIMIZATION
# =============================================================================

variable "enable_backup_lifecycle" {
  description = "Enable backup lifecycle policies for cost optimization"
  type        = bool
  default     = true
}

variable "cold_storage_transition_days" {
  description = "Days after which backups transition to cold storage"
  type        = number
  default     = 30
  validation {
    condition     = var.cold_storage_transition_days >= 30
    error_message = "Cold storage transition must be at least 30 days."
  }
}

variable "archive_transition_days" {
  description = "Days after which backups transition to archive storage"
  type        = number
  default     = 90
  validation {
    condition     = var.archive_transition_days >= var.cold_storage_transition_days
    error_message = "Archive transition must be greater than or equal to cold storage transition."
  }
}

# =============================================================================
# SECURITY CONFIGURATION
# =============================================================================

variable "backup_encryption_enabled" {
  description = "Enable encryption for backup data"
  type        = bool
  default     = true
}

variable "cross_account_backup_enabled" {
  description = "Enable cross-account backup capabilities"
  type        = bool
  default     = false
}

variable "backup_vault_lock_enabled" {
  description = "Enable backup vault lock for compliance"
  type        = bool
  default     = false
}

variable "backup_vault_lock_days" {
  description = "Minimum retention period for vault lock (days)"
  type        = number
  default     = 365
  validation {
    condition     = var.backup_vault_lock_days >= 1
    error_message = "Vault lock retention must be at least 1 day."
  }
}

# =============================================================================
# MONITORING AND ALERTING
# =============================================================================

variable "enable_backup_monitoring" {
  description = "Enable comprehensive backup monitoring and alerting"
  type        = bool
  default     = true
}

variable "backup_failure_alert_threshold" {
  description = "Number of backup failures before alerting"
  type        = number
  default     = 1
  validation {
    condition     = var.backup_failure_alert_threshold >= 1
    error_message = "Backup failure alert threshold must be at least 1."
  }
}

variable "backup_sla_threshold_hours" {
  description = "Backup SLA threshold in hours"
  type        = number
  default     = 24
  validation {
    condition     = var.backup_sla_threshold_hours >= 1
    error_message = "Backup SLA threshold must be at least 1 hour."
  }
}

# =============================================================================
# ADVANCED FEATURES
# =============================================================================

variable "enable_immutable_backups" {
  description = "Enable immutable backup capabilities where supported"
  type        = bool
  default     = false
}

variable "enable_backup_deduplication" {
  description = "Enable backup deduplication for cost savings"
  type        = bool
  default     = true
}

variable "enable_backup_compression" {
  description = "Enable backup compression for storage efficiency"
  type        = bool
  default     = true
}

variable "backup_verification_enabled" {
  description = "Enable automated backup verification"
  type        = bool
  default     = true
}

variable "dr_runbook_automation" {
  description = "Enable automated DR runbook execution"
  type        = bool
  default     = false
}

# =============================================================================
# INTEGRATION SETTINGS
# =============================================================================

variable "integrate_with_existing_backups" {
  description = "Integrate with existing database backup configurations"
  type        = bool
  default     = true
}

variable "existing_backup_vault_arn" {
  description = "ARN of existing backup vault to integrate with"
  type        = string
  default     = ""
}

variable "backup_policy_inheritance" {
  description = "Inherit backup policies from parent resources"
  type        = bool
  default     = true
}