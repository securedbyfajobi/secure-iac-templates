# Variables for Advanced Compliance and Monitoring Infrastructure Module

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

variable "data_classification" {
  description = "Data classification level for compliance monitoring"
  type        = string
  default     = "internal"
  validation {
    condition     = contains(["public", "internal", "confidential", "restricted"], var.data_classification)
    error_message = "Data classification must be one of: public, internal, confidential, restricted."
  }
}

# =============================================================================
# COMPLIANCE FRAMEWORKS
# =============================================================================

variable "compliance_frameworks" {
  description = "List of compliance frameworks to monitor"
  type        = list(string)
  default     = ["SOC2", "NIST", "CIS"]
  validation {
    condition = alltrue([
      for framework in var.compliance_frameworks :
      contains(["SOC2", "NIST", "CIS", "PCI-DSS", "HIPAA", "FedRAMP", "ISO27001"], framework)
    ])
    error_message = "Compliance frameworks must be from: SOC2, NIST, CIS, PCI-DSS, HIPAA, FedRAMP, ISO27001."
  }
}

variable "compliance_report_frequency" {
  description = "Frequency of compliance reports (daily, weekly, monthly)"
  type        = string
  default     = "weekly"
  validation {
    condition     = contains(["daily", "weekly", "monthly"], var.compliance_report_frequency)
    error_message = "Compliance report frequency must be: daily, weekly, or monthly."
  }
}

variable "compliance_report_schedule" {
  description = "Cron schedule for compliance reports"
  type        = string
  default     = "cron(0 9 ? * MON *)" # Every Monday at 9 AM UTC
}

# =============================================================================
# MULTI-CLOUD ENABLEMENT
# =============================================================================

variable "enable_aws_monitoring" {
  description = "Enable AWS compliance monitoring"
  type        = bool
  default     = true
}

variable "enable_azure_monitoring" {
  description = "Enable Azure compliance monitoring"
  type        = bool
  default     = false
}

variable "enable_gcp_monitoring" {
  description = "Enable Google Cloud compliance monitoring"
  type        = bool
  default     = false
}

# =============================================================================
# AWS CONFIGURATION
# =============================================================================

variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "aws_account_id" {
  description = "AWS account ID"
  type        = string
  default     = ""
}

# =============================================================================
# AZURE CONFIGURATION
# =============================================================================

variable "azure_resource_group_name" {
  description = "Azure resource group name"
  type        = string
  default     = ""
}

variable "azure_location" {
  description = "Azure location for resources"
  type        = string
  default     = "East US"
}

variable "azure_management_group_id" {
  description = "Azure management group ID for policy assignment"
  type        = string
  default     = ""
}

variable "azure_subscription_id" {
  description = "Azure subscription ID"
  type        = string
  default     = ""
}

# =============================================================================
# GOOGLE CLOUD CONFIGURATION
# =============================================================================

variable "gcp_project_id" {
  description = "Google Cloud project ID"
  type        = string
  default     = ""
}

variable "gcp_region" {
  description = "Google Cloud region for resources"
  type        = string
  default     = "us-central1"
}

variable "gcp_organization_id" {
  description = "Google Cloud organization ID"
  type        = string
  default     = ""
}

# =============================================================================
# LOGGING AND RETENTION
# =============================================================================

variable "log_retention_days" {
  description = "Log retention period in days"
  type        = number
  default     = 90
  validation {
    condition     = var.log_retention_days >= 30 && var.log_retention_days <= 2557
    error_message = "Log retention must be between 30 and 2557 days (7 years)."
  }
}

variable "enable_log_encryption" {
  description = "Enable encryption for logs at rest"
  type        = bool
  default     = true
}

variable "enable_kms_encryption" {
  description = "Enable KMS encryption for compliance data"
  type        = bool
  default     = true
}

# =============================================================================
# ALERTING AND NOTIFICATIONS
# =============================================================================

variable "alert_email_addresses" {
  description = "List of email addresses for compliance alerts"
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for email in var.alert_email_addresses : can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", email))
    ])
    error_message = "All email addresses must be valid."
  }
}

variable "webhook_endpoints" {
  description = "List of webhook endpoints for alerts"
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for webhook in var.webhook_endpoints : can(regex("^https?://", webhook))
    ])
    error_message = "All webhook endpoints must be valid HTTP/HTTPS URLs."
  }
}

variable "slack_webhook_urls" {
  description = "List of Slack webhook URLs for notifications"
  type        = list(string)
  default     = []
  sensitive   = true
}

variable "teams_webhook_urls" {
  description = "List of Microsoft Teams webhook URLs for notifications"
  type        = list(string)
  default     = []
  sensitive   = true
}

variable "pagerduty_integration_keys" {
  description = "List of PagerDuty integration keys"
  type        = list(string)
  default     = []
  sensitive   = true
}

# =============================================================================
# MONITORING CONFIGURATION
# =============================================================================

variable "enable_real_time_monitoring" {
  description = "Enable real-time compliance monitoring"
  type        = bool
  default     = true
}

variable "monitoring_interval_minutes" {
  description = "Monitoring check interval in minutes"
  type        = number
  default     = 15
  validation {
    condition     = var.monitoring_interval_minutes >= 5 && var.monitoring_interval_minutes <= 1440
    error_message = "Monitoring interval must be between 5 and 1440 minutes (24 hours)."
  }
}

variable "enable_custom_metrics" {
  description = "Enable custom compliance metrics"
  type        = bool
  default     = true
}

variable "metrics_retention_days" {
  description = "Metrics retention period in days"
  type        = number
  default     = 365
  validation {
    condition     = var.metrics_retention_days >= 90 && var.metrics_retention_days <= 2557
    error_message = "Metrics retention must be between 90 and 2557 days."
  }
}

# =============================================================================
# SECURITY THRESHOLDS
# =============================================================================

variable "failed_login_threshold" {
  description = "Threshold for failed login attempts per hour"
  type        = number
  default     = 50
  validation {
    condition     = var.failed_login_threshold >= 1 && var.failed_login_threshold <= 1000
    error_message = "Failed login threshold must be between 1 and 1000."
  }
}

variable "privilege_escalation_threshold" {
  description = "Threshold for privilege escalation events"
  type        = number
  default     = 5
  validation {
    condition     = var.privilege_escalation_threshold >= 1 && var.privilege_escalation_threshold <= 100
    error_message = "Privilege escalation threshold must be between 1 and 100."
  }
}

variable "data_exfiltration_threshold_gb" {
  description = "Threshold for data exfiltration in GB"
  type        = number
  default     = 1
  validation {
    condition     = var.data_exfiltration_threshold_gb >= 0.1 && var.data_exfiltration_threshold_gb <= 1000
    error_message = "Data exfiltration threshold must be between 0.1 and 1000 GB."
  }
}

variable "vulnerability_score_threshold" {
  description = "CVSS threshold for vulnerability alerts"
  type        = number
  default     = 7.0
  validation {
    condition     = var.vulnerability_score_threshold >= 0.0 && var.vulnerability_score_threshold <= 10.0
    error_message = "Vulnerability score threshold must be between 0.0 and 10.0."
  }
}

# =============================================================================
# REMEDIATION
# =============================================================================

variable "enable_auto_remediation" {
  description = "Enable automated remediation for compliance violations"
  type        = bool
  default     = false
}

variable "remediation_dry_run" {
  description = "Run remediation in dry-run mode (log only, no changes)"
  type        = bool
  default     = true
}

variable "auto_remediation_frameworks" {
  description = "Frameworks for which auto-remediation is enabled"
  type        = list(string)
  default     = ["CIS"]
  validation {
    condition = alltrue([
      for framework in var.auto_remediation_frameworks :
      contains(["SOC2", "NIST", "CIS", "PCI-DSS", "HIPAA", "FedRAMP"], framework)
    ])
    error_message = "Auto-remediation frameworks must be from supported list."
  }
}

variable "remediation_approval_required" {
  description = "Require manual approval for remediation actions"
  type        = bool
  default     = true
}

# =============================================================================
# THREAT INTELLIGENCE
# =============================================================================

variable "enable_threat_intelligence" {
  description = "Enable threat intelligence integration"
  type        = bool
  default     = true
}

variable "threat_intel_feeds" {
  description = "List of threat intelligence feed URLs"
  type        = list(string)
  default     = []
}

variable "threat_intel_update_frequency" {
  description = "Frequency of threat intelligence updates (hours)"
  type        = number
  default     = 4
  validation {
    condition     = var.threat_intel_update_frequency >= 1 && var.threat_intel_update_frequency <= 24
    error_message = "Threat intelligence update frequency must be between 1 and 24 hours."
  }
}

# =============================================================================
# INTEGRATION
# =============================================================================

variable "enable_siem_integration" {
  description = "Enable SIEM integration"
  type        = bool
  default     = false
}

variable "siem_endpoint" {
  description = "SIEM endpoint URL"
  type        = string
  default     = ""
  sensitive   = true
}

variable "enable_soar_integration" {
  description = "Enable SOAR (Security Orchestration) integration"
  type        = bool
  default     = false
}

variable "soar_endpoint" {
  description = "SOAR platform endpoint URL"
  type        = string
  default     = ""
  sensitive   = true
}

variable "enable_datadog_integration" {
  description = "Enable Datadog integration"
  type        = bool
  default     = false
}

variable "datadog_api_key" {
  description = "Datadog API key"
  type        = string
  default     = ""
  sensitive   = true
}

variable "enable_splunk_integration" {
  description = "Enable Splunk integration"
  type        = bool
  default     = false
}

variable "splunk_hec_endpoint" {
  description = "Splunk HTTP Event Collector endpoint"
  type        = string
  default     = ""
  sensitive   = true
}

variable "splunk_hec_token" {
  description = "Splunk HTTP Event Collector token"
  type        = string
  default     = ""
  sensitive   = true
}

# =============================================================================
# COST OPTIMIZATION
# =============================================================================

variable "cost_optimization_level" {
  description = "Level of cost optimization (low, medium, high)"
  type        = string
  default     = "medium"
  validation {
    condition     = contains(["low", "medium", "high"], var.cost_optimization_level)
    error_message = "Cost optimization level must be: low, medium, or high."
  }
}

variable "enable_cost_alerts" {
  description = "Enable cost monitoring alerts"
  type        = bool
  default     = true
}

variable "monthly_cost_threshold" {
  description = "Monthly cost threshold for alerts (USD)"
  type        = number
  default     = 1000
  validation {
    condition     = var.monthly_cost_threshold >= 100 && var.monthly_cost_threshold <= 100000
    error_message = "Monthly cost threshold must be between $100 and $100,000."
  }
}

# =============================================================================
# BACKUP AND DISASTER RECOVERY
# =============================================================================

variable "enable_cross_region_backup" {
  description = "Enable cross-region backup for compliance data"
  type        = bool
  default     = true
}

variable "backup_retention_years" {
  description = "Backup retention period in years"
  type        = number
  default     = 7
  validation {
    condition     = var.backup_retention_years >= 1 && var.backup_retention_years <= 10
    error_message = "Backup retention must be between 1 and 10 years."
  }
}

variable "enable_disaster_recovery_testing" {
  description = "Enable automated disaster recovery testing"
  type        = bool
  default     = false
}

variable "dr_testing_frequency" {
  description = "Disaster recovery testing frequency (monthly, quarterly, yearly)"
  type        = string
  default     = "quarterly"
  validation {
    condition     = contains(["monthly", "quarterly", "yearly"], var.dr_testing_frequency)
    error_message = "DR testing frequency must be: monthly, quarterly, or yearly."
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
    Module      = "compliance-monitoring"
    Owner       = ""
    Project     = ""
    CostCenter  = ""
    Environment = ""
  }
}

# =============================================================================
# ADVANCED FEATURES
# =============================================================================

variable "enable_ai_anomaly_detection" {
  description = "Enable AI-powered anomaly detection"
  type        = bool
  default     = false
}

variable "enable_predictive_analytics" {
  description = "Enable predictive compliance analytics"
  type        = bool
  default     = false
}

variable "enable_behavioral_analysis" {
  description = "Enable user behavioral analysis"
  type        = bool
  default     = false
}

variable "enable_zero_trust_validation" {
  description = "Enable zero-trust architecture validation"
  type        = bool
  default     = true
}

# =============================================================================
# REPORTING
# =============================================================================

variable "enable_executive_dashboard" {
  description = "Enable executive compliance dashboard"
  type        = bool
  default     = true
}

variable "enable_detailed_reporting" {
  description = "Enable detailed compliance reporting"
  type        = bool
  default     = true
}

variable "report_distribution_list" {
  description = "List of email addresses for report distribution"
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for email in var.report_distribution_list : can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", email))
    ])
    error_message = "All email addresses must be valid."
  }
}

variable "enable_compliance_scorecard" {
  description = "Enable compliance scorecard generation"
  type        = bool
  default     = true
}

# =============================================================================
# SECURITY
# =============================================================================

variable "enable_encryption_at_rest" {
  description = "Enable encryption at rest for all data"
  type        = bool
  default     = true
}

variable "enable_encryption_in_transit" {
  description = "Enable encryption in transit for all communications"
  type        = bool
  default     = true
}

variable "key_rotation_days" {
  description = "Number of days between key rotations"
  type        = number
  default     = 90
  validation {
    condition     = var.key_rotation_days >= 30 && var.key_rotation_days <= 365
    error_message = "Key rotation period must be between 30 and 365 days."
  }
}

variable "access_control_model" {
  description = "Access control model (RBAC, ABAC, MAC)"
  type        = string
  default     = "RBAC"
  validation {
    condition     = contains(["RBAC", "ABAC", "MAC"], var.access_control_model)
    error_message = "Access control model must be: RBAC, ABAC, or MAC."
  }
}

# =============================================================================
# PERFORMANCE
# =============================================================================

variable "performance_tier" {
  description = "Performance tier for monitoring (basic, standard, premium)"
  type        = string
  default     = "standard"
  validation {
    condition     = contains(["basic", "standard", "premium"], var.performance_tier)
    error_message = "Performance tier must be: basic, standard, or premium."
  }
}

variable "max_concurrent_checks" {
  description = "Maximum number of concurrent compliance checks"
  type        = number
  default     = 100
  validation {
    condition     = var.max_concurrent_checks >= 10 && var.max_concurrent_checks <= 1000
    error_message = "Max concurrent checks must be between 10 and 1000."
  }
}