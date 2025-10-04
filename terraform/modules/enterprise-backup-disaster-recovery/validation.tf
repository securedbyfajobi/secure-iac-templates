# Enterprise Backup and Disaster Recovery Module Validation

# =============================================================================
# BACKUP TIER VALIDATION
# =============================================================================

# Validate that backup tiers have corresponding resource configurations
locals {
  tier_resource_validation = {
    for tier in var.backup_tiers :
    tier => length(var.aws_backup_resources[tier]) > 0 || !var.enable_aws_dr
  }
}

# Check that at least one cloud provider is enabled
resource "terraform_data" "cloud_provider_validation" {
  lifecycle {
    precondition {
      condition = var.enable_aws_dr || var.enable_azure_dr || var.enable_gcp_dr
      error_message = "At least one cloud provider (AWS, Azure, or GCP) must be enabled for disaster recovery."
    }
  }
}

# Validate RTO/RPO consistency across tiers
resource "terraform_data" "rto_rpo_validation" {
  lifecycle {
    precondition {
      condition = var.critical_rpo_minutes <= var.critical_rto_minutes
      error_message = "Critical RPO must be less than or equal to Critical RTO."
    }

    precondition {
      condition = var.high_rpo_minutes <= var.high_rto_minutes
      error_message = "High RPO must be less than or equal to High RTO."
    }

    precondition {
      condition = var.critical_rto_minutes <= var.high_rto_minutes
      error_message = "Critical RTO must be less than or equal to High RTO."
    }
  }
}

# =============================================================================
# RETENTION POLICY VALIDATION
# =============================================================================

# Validate lifecycle policy consistency
resource "terraform_data" "lifecycle_validation" {
  count = var.enable_backup_lifecycle ? 1 : 0

  lifecycle {
    precondition {
      condition = var.cold_storage_transition_days < var.archive_transition_days
      error_message = "Cold storage transition must occur before archive transition."
    }

    precondition {
      condition = var.archive_transition_days <= var.default_daily_retention
      error_message = "Archive transition must occur before backup deletion."
    }
  }
}

# Validate compliance framework retention requirements
resource "terraform_data" "compliance_retention_validation" {
  count = length(var.compliance_frameworks) > 0 ? 1 : 0

  lifecycle {
    precondition {
      condition = local.max_daily_retention >= 7
      error_message = "Compliance frameworks require minimum 7 days retention."
    }

    precondition {
      condition = contains(var.compliance_frameworks, "PCI-DSS") ? local.max_daily_retention >= 365 : true
      error_message = "PCI-DSS compliance requires minimum 365 days retention."
    }

    precondition {
      condition = contains(var.compliance_frameworks, "HIPAA") ? local.max_daily_retention >= 365 : true
      error_message = "HIPAA compliance requires minimum 365 days retention."
    }
  }
}

# =============================================================================
# SECURITY VALIDATION
# =============================================================================

# Validate encryption requirements for compliance
resource "terraform_data" "encryption_validation" {
  count = length(var.compliance_frameworks) > 0 ? 1 : 0

  lifecycle {
    precondition {
      condition = var.backup_encryption_enabled
      error_message = "Backup encryption is required when compliance frameworks are specified."
    }

    precondition {
      condition = var.enable_aws_dr ? aws_kms_key.backup_encryption[0].enable_key_rotation : true
      error_message = "KMS key rotation must be enabled for compliance requirements."
    }
  }
}

# Validate cross-region security requirements
resource "terraform_data" "cross_region_security_validation" {
  count = var.enable_cross_region_backup ? 1 : 0

  lifecycle {
    precondition {
      condition = var.backup_encryption_enabled
      error_message = "Encryption is required for cross-region backup replication."
    }
  }
}

# =============================================================================
# AZURE CONFIGURATION VALIDATION
# =============================================================================

# Validate Azure configuration when enabled
resource "terraform_data" "azure_config_validation" {
  count = var.enable_azure_dr ? 1 : 0

  lifecycle {
    precondition {
      condition = var.azure_resource_group_name != ""
      error_message = "Azure resource group name is required when Azure DR is enabled."
    }

    precondition {
      condition = var.azure_primary_location != var.azure_dr_location
      error_message = "Azure primary and DR locations must be different."
    }

    precondition {
      condition = var.azure_encryption_key_id != "" || !contains(var.compliance_frameworks, "PCI-DSS")
      error_message = "Azure encryption key ID is required for PCI-DSS compliance."
    }
  }
}

# =============================================================================
# GCP CONFIGURATION VALIDATION
# =============================================================================

# Validate GCP configuration when enabled
resource "terraform_data" "gcp_config_validation" {
  count = var.enable_gcp_dr ? 1 : 0

  lifecycle {
    precondition {
      condition = var.gcp_project_id != ""
      error_message = "GCP project ID is required when GCP DR is enabled."
    }

    precondition {
      condition = var.gcp_primary_region != var.gcp_dr_region
      error_message = "GCP primary and DR regions must be different."
    }

    precondition {
      condition = var.gcp_kms_key_name != "" || !var.backup_encryption_enabled
      error_message = "GCP KMS key name is required when backup encryption is enabled."
    }
  }
}

# =============================================================================
# DR AUTOMATION VALIDATION
# =============================================================================

# Validate DR automation configuration
resource "terraform_data" "dr_automation_validation" {
  count = var.enable_dr_automation ? 1 : 0

  lifecycle {
    precondition {
      condition = var.notification_topic_arn != ""
      error_message = "SNS topic ARN is required when DR automation is enabled."
    }

    precondition {
      condition = can(regex("^cron\\(.*\\)$", var.dr_test_schedule))
      error_message = "DR test schedule must be a valid CloudWatch Events cron expression."
    }
  }
}

# =============================================================================
# RESOURCE CAPACITY VALIDATION
# =============================================================================

# Validate backup resource limits
resource "terraform_data" "resource_limits_validation" {
  lifecycle {
    precondition {
      condition = length(flatten(values(var.aws_backup_resources))) <= 1000
      error_message = "Total number of AWS backup resources cannot exceed 1000."
    }

    precondition {
      condition = length(var.backup_tiers) <= 4
      error_message = "Maximum of 4 backup tiers are supported."
    }
  }
}

# =============================================================================
# MONITORING VALIDATION
# =============================================================================

# Validate monitoring configuration
resource "terraform_data" "monitoring_validation" {
  count = var.enable_backup_monitoring ? 1 : 0

  lifecycle {
    precondition {
      condition = var.backup_failure_alert_threshold >= 1 && var.backup_failure_alert_threshold <= 10
      error_message = "Backup failure alert threshold must be between 1 and 10."
    }

    precondition {
      condition = var.backup_sla_threshold_hours >= 1 && var.backup_sla_threshold_hours <= 168
      error_message = "Backup SLA threshold must be between 1 and 168 hours."
    }
  }
}

# =============================================================================
# COST OPTIMIZATION VALIDATION
# =============================================================================

# Validate cost optimization settings
resource "terraform_data" "cost_optimization_validation" {
  count = var.enable_backup_lifecycle ? 1 : 0

  lifecycle {
    precondition {
      condition = var.cold_storage_transition_days >= 30
      error_message = "Cold storage transition must be at least 30 days (AWS requirement)."
    }

    precondition {
      condition = var.archive_transition_days >= 90
      error_message = "Archive transition must be at least 90 days for cost effectiveness."
    }
  }
}

# =============================================================================
# INTEGRATION VALIDATION
# =============================================================================

# Validate integration with existing resources
resource "terraform_data" "integration_validation" {
  count = var.integrate_with_existing_backups ? 1 : 0

  lifecycle {
    precondition {
      condition = var.existing_backup_vault_arn == "" || can(regex("^arn:aws:backup:", var.existing_backup_vault_arn))
      error_message = "Existing backup vault ARN must be a valid AWS Backup vault ARN."
    }
  }
}

# =============================================================================
# ADVANCED FEATURES VALIDATION
# =============================================================================

# Validate immutable backup configuration
resource "terraform_data" "immutable_backup_validation" {
  count = var.enable_immutable_backups ? 1 : 0

  lifecycle {
    precondition {
      condition = var.backup_vault_lock_enabled
      error_message = "Backup vault lock must be enabled for immutable backups."
    }

    precondition {
      condition = var.backup_vault_lock_days >= 1
      error_message = "Vault lock retention must be at least 1 day."
    }
  }
}

# Validate cross-account backup configuration
resource "terraform_data" "cross_account_validation" {
  count = var.cross_account_backup_enabled ? 1 : 0

  lifecycle {
    precondition {
      condition = var.backup_encryption_enabled
      error_message = "Encryption is required for cross-account backup capabilities."
    }
  }
}

# =============================================================================
# BUSINESS CONTINUITY VALIDATION
# =============================================================================

# Validate business continuity requirements
resource "terraform_data" "business_continuity_validation" {
  lifecycle {
    precondition {
      condition = contains(var.backup_tiers, "critical") ? var.critical_rto_minutes <= 60 : true
      error_message = "Critical tier RTO should not exceed 60 minutes for business continuity."
    }

    precondition {
      condition = contains(var.backup_tiers, "critical") ? var.critical_rpo_minutes <= 30 : true
      error_message = "Critical tier RPO should not exceed 30 minutes for business continuity."
    }

    precondition {
      condition = var.enable_cross_region_backup || length(var.backup_tiers) == 0 || !contains(var.backup_tiers, "critical")
      error_message = "Cross-region backup is recommended for critical tier resources."
    }
  }
}