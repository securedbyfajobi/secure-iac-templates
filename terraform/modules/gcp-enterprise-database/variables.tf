# Variables for GCP Enterprise Database Security Module

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

variable "region" {
  description = "GCP region for resources"
  type        = string
  default     = "us-central1"
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

variable "deletion_protection" {
  description = "Enable deletion protection for databases"
  type        = bool
  default     = true
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
      contains(["SOC2", "NIST", "CIS", "PCI-DSS", "HIPAA", "FedRAMP"], framework)
    ])
    error_message = "Compliance frameworks must be from: SOC2, NIST, CIS, PCI-DSS, HIPAA, FedRAMP."
  }
}

# =============================================================================
# ENCRYPTION CONFIGURATION
# =============================================================================

variable "kms_location" {
  description = "Location for KMS key ring"
  type        = string
  default     = "global"
}

variable "kms_protection_level" {
  description = "Protection level for KMS keys"
  type        = string
  default     = "SOFTWARE"
  validation {
    condition     = contains(["SOFTWARE", "HSM"], var.kms_protection_level)
    error_message = "KMS protection level must be SOFTWARE or HSM."
  }
}

variable "kms_rotation_period" {
  description = "Rotation period for KMS keys"
  type        = string
  default     = "2592000s"  # 30 days
  validation {
    condition     = can(regex("^[0-9]+s$", var.kms_rotation_period))
    error_message = "KMS rotation period must be in seconds format (e.g., 2592000s)."
  }
}

# =============================================================================
# NETWORK CONFIGURATION
# =============================================================================

variable "vpc_network_id" {
  description = "VPC network ID for private IP configuration"
  type        = string
  default     = ""
}

variable "enable_private_ip" {
  description = "Enable private IP for database instances"
  type        = bool
  default     = true
}

variable "private_ip_prefix_length" {
  description = "Prefix length for private IP range"
  type        = number
  default     = 16
  validation {
    condition     = var.private_ip_prefix_length >= 16 && var.private_ip_prefix_length <= 24
    error_message = "Private IP prefix length must be between 16 and 24."
  }
}

variable "authorized_networks" {
  description = "List of authorized networks for database access"
  type = list(object({
    name  = string
    value = string
  }))
  default = []
}

# =============================================================================
# CLOUD SQL CONFIGURATION
# =============================================================================

variable "sql_instances" {
  description = "Map of Cloud SQL instances to create"
  type = map(object({
    database_version               = string
    tier                          = string
    availability_type             = optional(string, "ZONAL")
    disk_type                     = optional(string, "PD_SSD")
    disk_size                     = optional(number, 20)
    disk_autoresize              = optional(bool, true)
    disk_autoresize_limit        = optional(number, 0)
    admin_username               = optional(string, "admin")
    transaction_log_retention_days = optional(number, 7)
    database_flags = optional(list(object({
      name  = string
      value = string
    })), [])
    databases = optional(map(object({
      name      = string
      charset   = optional(string, "utf8")
      collation = optional(string, "utf8_general_ci")
    })), {})
  }))
  default = {}
}

variable "backup_start_time" {
  description = "Start time for automated backups in HH:MM format"
  type        = string
  default     = "03:00"
  validation {
    condition     = can(regex("^([01]?[0-9]|2[0-3]):[0-5][0-9]$", var.backup_start_time))
    error_message = "Backup start time must be in HH:MM format."
  }
}

variable "backup_location" {
  description = "Location for database backups"
  type        = string
  default     = "us"
}

variable "backup_retention_days" {
  description = "Backup retention period in days"
  type        = number
  default     = 30
  validation {
    condition     = var.backup_retention_days >= 1 && var.backup_retention_days <= 365
    error_message = "Backup retention must be between 1 and 365 days."
  }
}

variable "maintenance_window_day" {
  description = "Day of week for maintenance window (1-7, Monday is 1)"
  type        = number
  default     = 7  # Sunday
  validation {
    condition     = var.maintenance_window_day >= 1 && var.maintenance_window_day <= 7
    error_message = "Maintenance window day must be between 1 and 7."
  }
}

variable "maintenance_window_hour" {
  description = "Hour of day for maintenance window (0-23)"
  type        = number
  default     = 3
  validation {
    condition     = var.maintenance_window_hour >= 0 && var.maintenance_window_hour <= 23
    error_message = "Maintenance window hour must be between 0 and 23."
  }
}

variable "maintenance_update_track" {
  description = "Update track for maintenance"
  type        = string
  default     = "stable"
  validation {
    condition     = contains(["canary", "stable"], var.maintenance_update_track)
    error_message = "Maintenance update track must be canary or stable."
  }
}

# =============================================================================
# CLOUD SPANNER CONFIGURATION
# =============================================================================

variable "create_spanner_instance" {
  description = "Create Cloud Spanner instance"
  type        = bool
  default     = false
}

variable "spanner_config" {
  description = "Spanner configuration (region or multi-region)"
  type        = string
  default     = "regional-us-central1"
}

variable "spanner_num_nodes" {
  description = "Number of nodes for Spanner instance"
  type        = number
  default     = null
  validation {
    condition     = var.spanner_num_nodes == null || (var.spanner_num_nodes >= 1 && var.spanner_num_nodes <= 2000)
    error_message = "Spanner num_nodes must be between 1 and 2000 when specified."
  }
}

variable "spanner_processing_units" {
  description = "Processing units for Spanner instance"
  type        = number
  default     = 1000
  validation {
    condition     = var.spanner_processing_units >= 100 && var.spanner_processing_units <= 4000000
    error_message = "Spanner processing units must be between 100 and 4,000,000."
  }
}

variable "spanner_databases" {
  description = "Map of Spanner databases to create"
  type = map(object({
    version_retention_period = optional(string, "1h")
    ddl_statements          = optional(list(string), [])
  }))
  default = {}
}

# =============================================================================
# FIRESTORE CONFIGURATION
# =============================================================================

variable "create_firestore_database" {
  description = "Create Firestore database"
  type        = bool
  default     = false
}

variable "firestore_database_id" {
  description = "Database ID for Firestore"
  type        = string
  default     = "(default)"
}

variable "firestore_location_id" {
  description = "Location ID for Firestore database"
  type        = string
  default     = "nam5"  # North America
}

variable "firestore_type" {
  description = "Type of Firestore database"
  type        = string
  default     = "FIRESTORE_NATIVE"
  validation {
    condition     = contains(["FIRESTORE_NATIVE", "DATASTORE_MODE"], var.firestore_type)
    error_message = "Firestore type must be FIRESTORE_NATIVE or DATASTORE_MODE."
  }
}

variable "firestore_concurrency_mode" {
  description = "Concurrency mode for Firestore"
  type        = string
  default     = "OPTIMISTIC"
  validation {
    condition     = contains(["OPTIMISTIC", "PESSIMISTIC"], var.firestore_concurrency_mode)
    error_message = "Firestore concurrency mode must be OPTIMISTIC or PESSIMISTIC."
  }
}

variable "firestore_app_engine_integration_mode" {
  description = "App Engine integration mode for Firestore"
  type        = string
  default     = "DISABLED"
  validation {
    condition     = contains(["ENABLED", "DISABLED"], var.firestore_app_engine_integration_mode)
    error_message = "Firestore App Engine integration mode must be ENABLED or DISABLED."
  }
}

variable "firestore_point_in_time_recovery" {
  description = "Enable point-in-time recovery for Firestore"
  type        = bool
  default     = true
}

# =============================================================================
# MONITORING AND ALERTING
# =============================================================================

variable "enable_monitoring_dashboard" {
  description = "Enable monitoring dashboard"
  type        = bool
  default     = true
}

variable "enable_alerting" {
  description = "Enable alerting policies"
  type        = bool
  default     = true
}

variable "cpu_alert_threshold" {
  description = "CPU utilization threshold for alerts (%)"
  type        = number
  default     = 80
  validation {
    condition     = var.cpu_alert_threshold >= 50 && var.cpu_alert_threshold <= 100
    error_message = "CPU alert threshold must be between 50 and 100."
  }
}

variable "memory_alert_threshold" {
  description = "Memory utilization threshold for alerts (%)"
  type        = number
  default     = 85
  validation {
    condition     = var.memory_alert_threshold >= 50 && var.memory_alert_threshold <= 100
    error_message = "Memory alert threshold must be between 50 and 100."
  }
}

variable "connections_alert_threshold" {
  description = "Database connections threshold for alerts"
  type        = number
  default     = 80
  validation {
    condition     = var.connections_alert_threshold >= 10 && var.connections_alert_threshold <= 1000
    error_message = "Connections alert threshold must be between 10 and 1000."
  }
}

variable "notification_channels" {
  description = "List of notification channel IDs for alerts"
  type        = list(string)
  default     = []
}

# =============================================================================
# SECURITY CONFIGURATION
# =============================================================================

variable "enable_security_center" {
  description = "Enable Security Command Center notifications"
  type        = bool
  default     = true
}

variable "organization_id" {
  description = "Organization ID for Security Command Center"
  type        = string
  default     = ""
}

variable "security_notification_topic" {
  description = "Pub/Sub topic for security notifications"
  type        = string
  default     = ""
}

variable "create_custom_roles" {
  description = "Create custom IAM roles for database access"
  type        = bool
  default     = true
}

# =============================================================================
# BACKUP AND DISASTER RECOVERY
# =============================================================================

variable "create_export_bucket" {
  description = "Create Cloud Storage bucket for database exports"
  type        = bool
  default     = true
}

variable "export_lifecycle_days" {
  description = "Lifecycle policy days for database exports"
  type        = number
  default     = 90
  validation {
    condition     = var.export_lifecycle_days >= 1 && var.export_lifecycle_days <= 3650
    error_message = "Export lifecycle days must be between 1 and 3650."
  }
}

# =============================================================================
# TAGGING
# =============================================================================

variable "common_labels" {
  description = "Common labels to apply to all resources"
  type        = map(string)
  default = {
    terraform   = "true"
    module      = "gcp-enterprise-database"
    owner       = ""
    project     = ""
    cost-center = ""
    environment = ""
  }
}