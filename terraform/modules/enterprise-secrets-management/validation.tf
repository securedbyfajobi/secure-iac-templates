# Enterprise Secrets Management Module Validation

# =============================================================================
# CLOUD PROVIDER VALIDATION
# =============================================================================

# Ensure at least one cloud provider is enabled
resource "terraform_data" "cloud_provider_validation" {
  lifecycle {
    precondition {
      condition = var.enable_aws_secrets || var.enable_azure_secrets || var.enable_gcp_secrets || var.enable_vault_integration
      error_message = "At least one secrets management provider (AWS, Azure, GCP, or Vault) must be enabled."
    }
  }
}

# Validate Azure configuration when enabled
resource "terraform_data" "azure_config_validation" {
  count = var.enable_azure_secrets ? 1 : 0

  lifecycle {
    precondition {
      condition = var.azure_resource_group_name != ""
      error_message = "Azure resource group name is required when Azure Key Vault is enabled."
    }

    precondition {
      condition = var.azure_location != ""
      error_message = "Azure location is required when Azure Key Vault is enabled."
    }
  }
}

# Validate GCP configuration when enabled
resource "terraform_data" "gcp_config_validation" {
  count = var.enable_gcp_secrets ? 1 : 0

  lifecycle {
    precondition {
      condition = var.gcp_project_id != ""
      error_message = "GCP project ID is required when GCP Secret Manager is enabled."
    }
  }
}

# =============================================================================
# SECRET CATEGORY VALIDATION
# =============================================================================

# Validate database secrets have valid categories
resource "terraform_data" "database_secrets_validation" {
  count = length(var.database_secrets) > 0 ? 1 : 0

  lifecycle {
    precondition {
      condition = alltrue([
        for secret in var.database_secrets :
        contains(["critical", "high", "medium", "low"], secret.category)
      ])
      error_message = "All database secrets must have a valid category: critical, high, medium, or low."
    }

    precondition {
      condition = alltrue([
        for secret in var.database_secrets :
        secret.username != "" && secret.password != ""
      ])
      error_message = "Database secrets must have non-empty username and password."
    }

    precondition {
      condition = alltrue([
        for secret in var.database_secrets :
        secret.port > 0 && secret.port < 65536
      ])
      error_message = "Database port must be between 1 and 65535."
    }
  }
}

# Validate API secrets have valid categories
resource "terraform_data" "api_secrets_validation" {
  count = length(var.api_secrets) > 0 ? 1 : 0

  lifecycle {
    precondition {
      condition = alltrue([
        for secret in var.api_secrets :
        contains(["critical", "high", "medium", "low"], secret.category)
      ])
      error_message = "All API secrets must have a valid category: critical, high, medium, or low."
    }

    precondition {
      condition = alltrue([
        for secret in var.api_secrets :
        secret.api_key != "" && secret.secret_key != ""
      ])
      error_message = "API secrets must have non-empty api_key and secret_key."
    }
  }
}

# =============================================================================
# COMPLIANCE VALIDATION
# =============================================================================

# Validate compliance requirements
resource "terraform_data" "compliance_validation" {
  count = length(var.compliance_frameworks) > 0 ? 1 : 0

  lifecycle {
    precondition {
      condition = var.enable_encryption_at_rest
      error_message = "Encryption at rest is required when compliance frameworks are specified."
    }

    precondition {
      condition = var.enable_encryption_in_transit
      error_message = "Encryption in transit is required when compliance frameworks are specified."
    }

    precondition {
      condition = var.secret_access_logging
      error_message = "Secret access logging is required when compliance frameworks are specified."
    }

    precondition {
      condition = var.enable_automatic_rotation
      error_message = "Automatic rotation is required when compliance frameworks are specified."
    }
  }
}

# Validate PCI-DSS specific requirements
resource "terraform_data" "pci_dss_validation" {
  count = contains(var.compliance_frameworks, "PCI-DSS") ? 1 : 0

  lifecycle {
    precondition {
      condition = var.critical_rotation_days <= 90
      error_message = "PCI-DSS requires critical secrets to be rotated at least every 90 days."
    }

    precondition {
      condition = var.secret_access_review_days <= 15
      error_message = "PCI-DSS requires access reviews at least every 15 days."
    }

    precondition {
      condition = var.enable_secret_versioning
      error_message = "PCI-DSS requires secret versioning to be enabled."
    }

    precondition {
      condition = var.azure_public_access_enabled == false || !var.enable_azure_secrets
      error_message = "PCI-DSS requires Azure Key Vault public access to be disabled."
    }
  }
}

# Validate HIPAA specific requirements
resource "terraform_data" "hipaa_validation" {
  count = contains(var.compliance_frameworks, "HIPAA") ? 1 : 0

  lifecycle {
    precondition {
      condition = var.enable_purge_protection || !var.enable_azure_secrets
      error_message = "HIPAA requires Azure Key Vault purge protection to be enabled."
    }

    precondition {
      condition = var.secret_recovery_window_days >= 30
      error_message = "HIPAA requires minimum 30-day recovery window for deleted secrets."
    }

    precondition {
      condition = var.enable_secret_dr
      error_message = "HIPAA requires disaster recovery capabilities for secrets."
    }
  }
}

# Validate FIPS compliance requirements
resource "terraform_data" "fips_validation" {
  count = contains(var.compliance_frameworks, "FIPS") ? 1 : 0

  lifecycle {
    precondition {
      condition = var.kms_key_rotation_enabled
      error_message = "FIPS requires automatic KMS key rotation to be enabled."
    }

    precondition {
      condition = var.critical_rotation_days <= 30
      error_message = "FIPS requires critical secrets to be rotated at least every 30 days."
    }
  }
}

# =============================================================================
# ROTATION CONFIGURATION VALIDATION
# =============================================================================

# Validate rotation intervals are logical
resource "terraform_data" "rotation_intervals_validation" {
  count = var.enable_automatic_rotation ? 1 : 0

  lifecycle {
    precondition {
      condition = var.critical_rotation_days <= var.high_rotation_days
      error_message = "Critical rotation days must be less than or equal to high rotation days."
    }

    precondition {
      condition = var.high_rotation_days <= var.default_rotation_days
      error_message = "High rotation days must be less than or equal to default rotation days."
    }

    precondition {
      condition = var.critical_rotation_days >= 7
      error_message = "Critical rotation interval must be at least 7 days to prevent excessive rotation."
    }
  }
}

# Validate rotation is feasible with compliance requirements
resource "terraform_data" "rotation_compliance_validation" {
  count = var.enable_automatic_rotation && length(var.compliance_frameworks) > 0 ? 1 : 0

  lifecycle {
    precondition {
      condition = var.default_rotation_days <= local.strictest_rotation_days
      error_message = "Default rotation days must comply with the strictest compliance framework requirement."
    }

    precondition {
      condition = var.max_concurrent_rotations >= 1
      error_message = "At least one concurrent rotation must be allowed."
    }
  }
}

# =============================================================================
# SECURITY CONFIGURATION VALIDATION
# =============================================================================

# Validate encryption configuration
resource "terraform_data" "encryption_validation" {
  count = var.enable_encryption_at_rest ? 1 : 0

  lifecycle {
    precondition {
      condition = var.kms_key_rotation_enabled
      error_message = "KMS key rotation should be enabled when encryption at rest is enabled."
    }
  }
}

# Validate access control configuration
resource "terraform_data" "access_control_validation" {
  count = var.enable_least_privilege_access ? 1 : 0

  lifecycle {
    precondition {
      condition = var.secret_access_logging
      error_message = "Access logging must be enabled when least privilege access is enforced."
    }

    precondition {
      condition = var.secret_access_review_days <= 90
      error_message = "Access review interval must not exceed 90 days for least privilege access."
    }
  }
}

# Validate JIT access configuration
resource "terraform_data" "jit_access_validation" {
  count = var.enable_just_in_time_access ? 1 : 0

  lifecycle {
    precondition {
      condition = var.jit_access_duration_hours >= 1 && var.jit_access_duration_hours <= 24
      error_message = "JIT access duration must be between 1 and 24 hours."
    }

    precondition {
      condition = var.secret_access_logging
      error_message = "Access logging must be enabled when JIT access is used."
    }
  }
}

# =============================================================================
# CROSS-REGION AND DR VALIDATION
# =============================================================================

# Validate cross-region configuration
resource "terraform_data" "cross_region_validation" {
  count = var.enable_cross_region_secrets ? 1 : 0

  lifecycle {
    precondition {
      condition = var.aws_replica_region != ""
      error_message = "AWS replica region must be specified when cross-region secrets are enabled."
    }

    precondition {
      condition = var.enable_encryption_at_rest
      error_message = "Encryption must be enabled for cross-region secret replication."
    }
  }
}

# Validate DR configuration
resource "terraform_data" "dr_validation" {
  count = var.enable_secret_dr ? 1 : 0

  lifecycle {
    precondition {
      condition = var.secret_dr_region != ""
      error_message = "DR region must be specified when secret DR is enabled."
    }

    precondition {
      condition = var.secret_dr_sync_frequency >= 1 && var.secret_dr_sync_frequency <= 24
      error_message = "DR sync frequency must be between 1 and 24 hours."
    }

    precondition {
      condition = var.enable_cross_region_secrets || !var.enable_aws_secrets
      error_message = "Cross-region replication should be enabled when DR is enabled for AWS secrets."
    }
  }
}

# =============================================================================
# MONITORING AND ALERTING VALIDATION
# =============================================================================

# Validate monitoring configuration
resource "terraform_data" "monitoring_validation" {
  count = var.enable_secrets_monitoring ? 1 : 0

  lifecycle {
    precondition {
      condition = var.notification_topic_arn != "" || (!var.alert_on_secret_access && !var.alert_on_rotation_failure && !var.alert_on_expired_secrets)
      error_message = "SNS topic ARN must be provided when alerting is enabled."
    }

    precondition {
      condition = var.secret_expiry_warning_days >= 1 && var.secret_expiry_warning_days <= 30
      error_message = "Secret expiry warning days must be between 1 and 30."
    }
  }
}

# Validate compliance monitoring configuration
resource "terraform_data" "compliance_monitoring_validation" {
  count = var.enable_compliance_monitoring ? 1 : 0

  lifecycle {
    precondition {
      condition = length(var.compliance_frameworks) > 0
      error_message = "Compliance frameworks must be specified when compliance monitoring is enabled."
    }

    precondition {
      condition = can(regex("^cron\\(.*\\)$", var.compliance_check_schedule))
      error_message = "Compliance check schedule must be a valid cron expression."
    }

    precondition {
      condition = contains(["daily", "weekly", "monthly"], var.compliance_report_frequency)
      error_message = "Compliance report frequency must be daily, weekly, or monthly."
    }
  }
}

# =============================================================================
# PERFORMANCE AND SCALING VALIDATION
# =============================================================================

# Validate performance configuration
resource "terraform_data" "performance_validation" {
  lifecycle {
    precondition {
      condition = var.secret_cache_ttl_seconds >= 60 && var.secret_cache_ttl_seconds <= 3600
      error_message = "Secret cache TTL must be between 60 and 3600 seconds."
    }

    precondition {
      condition = var.max_concurrent_rotations >= 1 && var.max_concurrent_rotations <= 20
      error_message = "Max concurrent rotations must be between 1 and 20."
    }

    precondition {
      condition = var.batch_size >= 1 && var.batch_size <= 50
      error_message = "Batch size must be between 1 and 50."
    }
  }
}

# Validate secret limits
resource "terraform_data" "secret_limits_validation" {
  lifecycle {
    precondition {
      condition = length(var.database_secrets) <= 100
      error_message = "Maximum of 100 database secrets supported per module instance."
    }

    precondition {
      condition = length(var.api_secrets) <= 100
      error_message = "Maximum of 100 API secrets supported per module instance."
    }

    precondition {
      condition = length(var.application_secrets) <= 50
      error_message = "Maximum of 50 application secrets supported per module instance."
    }

    precondition {
      condition = var.max_secret_versions >= 2 && var.max_secret_versions <= 100
      error_message = "Max secret versions must be between 2 and 100."
    }
  }
}

# =============================================================================
# COST OPTIMIZATION VALIDATION
# =============================================================================

# Validate cost optimization settings
resource "terraform_data" "cost_optimization_validation" {
  count = var.enable_cost_optimization ? 1 : 0

  lifecycle {
    precondition {
      condition = var.unused_secret_threshold_days >= 30
      error_message = "Unused secret threshold must be at least 30 days to prevent premature cleanup."
    }

    precondition {
      condition = var.unused_secret_threshold_days <= var.default_rotation_days
      error_message = "Unused secret threshold should not exceed default rotation interval."
    }
  }
}

# =============================================================================
# INTEGRATION VALIDATION
# =============================================================================

# Validate external integrations
resource "terraform_data" "integration_validation" {
  count = length(var.external_secret_sources) > 0 ? 1 : 0

  lifecycle {
    precondition {
      condition = alltrue([
        for source in var.external_secret_sources :
        contains(["vault", "kubernetes", "cyberark", "thycotic"], source)
      ])
      error_message = "External secret sources must be one of: vault, kubernetes, cyberark, thycotic."
    }
  }
}

# Validate Vault integration requirements
resource "terraform_data" "vault_integration_validation" {
  count = var.enable_vault_integration ? 1 : 0

  lifecycle {
    precondition {
      condition = var.enable_aws_secrets
      error_message = "AWS Secrets Manager must be enabled for Vault integration (AWS auth backend)."
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
      condition = var.secret_recovery_window_days >= 7
      error_message = "Minimum 7-day recovery window required for business continuity."
    }

    precondition {
      condition = !var.enable_compliance_remediation || var.enable_compliance_monitoring
      error_message = "Compliance monitoring must be enabled when auto-remediation is enabled."
    }

    precondition {
      condition = var.enable_secret_versioning || !var.enable_automatic_rotation
      error_message = "Secret versioning should be enabled when automatic rotation is used."
    }
  }
}

# =============================================================================
# NETWORK SECURITY VALIDATION
# =============================================================================

# Validate Azure network security when public access is disabled
resource "terraform_data" "azure_network_validation" {
  count = var.enable_azure_secrets && !var.azure_public_access_enabled ? 1 : 0

  lifecycle {
    precondition {
      condition = length(var.azure_allowed_subnets) > 0 || length(var.azure_allowed_ips) > 0
      error_message = "When Azure Key Vault public access is disabled, at least one allowed subnet or IP must be specified."
    }
  }
}

# Validate IP addresses format
resource "terraform_data" "ip_validation" {
  count = length(var.azure_allowed_ips) > 0 ? 1 : 0

  lifecycle {
    precondition {
      condition = alltrue([
        for ip in var.azure_allowed_ips :
        can(regex("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}(?:\\/[0-9]{1,2})?$", ip))
      ])
      error_message = "Azure allowed IPs must be valid IPv4 addresses or CIDR blocks."
    }
  }
}