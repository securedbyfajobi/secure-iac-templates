# Enterprise Secrets Management Module Outputs

# =============================================================================
# AWS SECRETS MANAGER OUTPUTS
# =============================================================================

output "aws_secrets_kms_key_id" {
  description = "ID of the KMS key used for AWS secrets encryption"
  value       = var.enable_aws_secrets ? aws_kms_key.secrets_encryption[0].key_id : null
}

output "aws_secrets_kms_key_arn" {
  description = "ARN of the KMS key used for AWS secrets encryption"
  value       = var.enable_aws_secrets ? aws_kms_key.secrets_encryption[0].arn : null
}

output "database_secret_arns" {
  description = "Map of database secret ARNs"
  value = var.enable_aws_secrets ? {
    for name, secret in aws_secretsmanager_secret.database_credentials :
    name => secret.arn
  } : {}
}

output "api_secret_arns" {
  description = "Map of API secret ARNs"
  value = var.enable_aws_secrets ? {
    for name, secret in aws_secretsmanager_secret.api_credentials :
    name => secret.arn
  } : {}
}

output "application_secret_arns" {
  description = "Map of application secret ARNs"
  value = var.enable_aws_secrets ? {
    for name, secret in aws_secretsmanager_secret.application_config :
    name => secret.arn
  } : {}
}

output "rotation_lambda_arn" {
  description = "ARN of the secret rotation Lambda function"
  value       = var.enable_aws_secrets && var.enable_automatic_rotation ? aws_lambda_function.rotation_lambda[0].arn : null
}

output "rotation_lambda_name" {
  description = "Name of the secret rotation Lambda function"
  value       = var.enable_aws_secrets && var.enable_automatic_rotation ? aws_lambda_function.rotation_lambda[0].function_name : null
}

# =============================================================================
# AZURE KEY VAULT OUTPUTS
# =============================================================================

output "azure_key_vault_id" {
  description = "ID of the Azure Key Vault"
  value       = var.enable_azure_secrets ? azurerm_key_vault.enterprise_vault[0].id : null
}

output "azure_key_vault_uri" {
  description = "URI of the Azure Key Vault"
  value       = var.enable_azure_secrets ? azurerm_key_vault.enterprise_vault[0].vault_uri : null
}

output "azure_key_vault_name" {
  description = "Name of the Azure Key Vault"
  value       = var.enable_azure_secrets ? azurerm_key_vault.enterprise_vault[0].name : null
}

output "azure_database_secret_ids" {
  description = "Map of Azure database secret IDs"
  value = var.enable_azure_secrets ? {
    for name, secret in azurerm_key_vault_secret.database_secrets :
    name => secret.id
  } : {}
}

output "azure_api_secret_ids" {
  description = "Map of Azure API secret IDs"
  value = var.enable_azure_secrets ? {
    for name, secret in azurerm_key_vault_secret.api_secrets :
    name => secret.id
  } : {}
}

# =============================================================================
# GCP SECRET MANAGER OUTPUTS
# =============================================================================

output "gcp_database_secret_ids" {
  description = "Map of GCP database secret IDs"
  value = var.enable_gcp_secrets ? {
    for name, secret in google_secret_manager_secret.database_secrets :
    name => secret.id
  } : {}
}

output "gcp_api_secret_ids" {
  description = "Map of GCP API secret IDs"
  value = var.enable_gcp_secrets ? {
    for name, secret in google_secret_manager_secret.api_secrets :
    name => secret.id
  } : {}
}

# =============================================================================
# HASHICORP VAULT OUTPUTS
# =============================================================================

output "vault_auth_backend_path" {
  description = "Path of the Vault authentication backend"
  value       = var.enable_vault_integration ? vault_auth_backend.aws[0].path : null
}

output "vault_policy_name" {
  description = "Name of the Vault policy for secrets access"
  value       = var.enable_vault_integration ? vault_policy.secrets_policy[0].name : null
}

output "vault_database_mount_path" {
  description = "Path of the Vault database secrets mount"
  value       = var.enable_vault_integration ? vault_database_secrets_mount.db[0].path : null
}

# =============================================================================
# MONITORING AND ALERTING OUTPUTS
# =============================================================================

output "rotation_failure_alarm_arn" {
  description = "ARN of the CloudWatch alarm for rotation failures"
  value       = var.enable_aws_secrets && var.enable_automatic_rotation ? aws_cloudwatch_metric_alarm.rotation_failures[0].arn : null
}

output "secrets_dashboard_url" {
  description = "URL of the secrets management CloudWatch dashboard"
  value       = var.enable_aws_secrets ? "https://${data.aws_region.current[0].name}.console.aws.amazon.com/cloudwatch/home?region=${data.aws_region.current[0].name}#dashboards:name=${aws_cloudwatch_dashboard.secrets_dashboard[0].dashboard_name}" : null
}

output "compliance_monitor_function_arn" {
  description = "ARN of the compliance monitoring Lambda function"
  value       = var.enable_compliance_monitoring ? aws_lambda_function.compliance_monitor[0].arn : null
}

# =============================================================================
# SECURITY CONFIGURATION OUTPUTS
# =============================================================================

output "secret_categories_configuration" {
  description = "Secret categories and their security configurations"
  value = {
    for category, config in local.secret_categories :
    category => {
      rotation_days    = config.rotation_days
      max_age_hours    = config.max_age_hours
      encryption_level = config.encryption_level
      audit_level      = config.audit_level
      cross_region     = config.cross_region
    }
  }
}

output "compliance_requirements" {
  description = "Active compliance requirements and their configurations"
  value = {
    frameworks_enabled = var.compliance_frameworks
    strictest_rotation_days = local.strictest_rotation_days
    strictest_access_review_days = local.strictest_access_review_days
    encryption_required = length(var.compliance_frameworks) > 0 ? true : var.enable_encryption_at_rest
  }
}

output "encryption_configuration" {
  description = "Encryption configuration summary"
  value = {
    at_rest_enabled = var.enable_encryption_at_rest
    in_transit_enabled = var.enable_encryption_in_transit
    kms_rotation_enabled = var.kms_key_rotation_enabled
    aws_kms_enabled = var.enable_aws_secrets
    azure_cmk_enabled = var.enable_azure_secrets
    gcp_cmek_enabled = var.enable_gcp_secrets
  }
}

# =============================================================================
# ACCESS CONTROL OUTPUTS
# =============================================================================

output "access_control_configuration" {
  description = "Access control configuration summary"
  value = {
    least_privilege_enabled = var.enable_least_privilege_access
    jit_access_enabled = var.enable_just_in_time_access
    access_review_days = var.secret_access_review_days
    access_logging_enabled = var.secret_access_logging
  }
}

output "secret_access_policies" {
  description = "Configured secret access policies"
  value       = var.secret_access_policies
  sensitive   = true
}

# =============================================================================
# ROTATION CONFIGURATION OUTPUTS
# =============================================================================

output "rotation_configuration" {
  description = "Secret rotation configuration summary"
  value = {
    automatic_rotation_enabled = var.enable_automatic_rotation
    default_rotation_days = var.default_rotation_days
    critical_rotation_days = var.critical_rotation_days
    high_rotation_days = var.high_rotation_days
    max_concurrent_rotations = var.max_concurrent_rotations
  }
}

output "rotation_schedule_summary" {
  description = "Summary of rotation schedules by secret category"
  value = {
    for category, config in local.secret_categories :
    category => {
      rotation_days = config.rotation_days
      next_rotation_estimate = "${config.rotation_days} days from creation"
    }
  }
}

# =============================================================================
# DISASTER RECOVERY OUTPUTS
# =============================================================================

output "disaster_recovery_configuration" {
  description = "Disaster recovery configuration for secrets"
  value = {
    dr_enabled = var.enable_secret_dr
    cross_region_replication = var.enable_cross_region_secrets
    dr_region = var.secret_dr_region
    sync_frequency_hours = var.secret_dr_sync_frequency
    dr_testing_enabled = var.enable_secret_dr_testing
  }
}

output "cross_region_replication_status" {
  description = "Status of cross-region secret replication"
  value = {
    aws_enabled = var.enable_aws_secrets && var.enable_cross_region_secrets
    replica_region = var.aws_replica_region
    replica_kms_key_arn = var.enable_aws_secrets && var.enable_cross_region_secrets ? aws_kms_key.secrets_encryption_replica[0].arn : null
  }
}

# =============================================================================
# INTEGRATION OUTPUTS
# =============================================================================

output "integration_status" {
  description = "Status of integrations with other modules"
  value = {
    iam_integration_enabled = var.integrate_with_iam
    backup_integration_enabled = var.integrate_with_backup
    vault_integration_enabled = var.enable_vault_integration
    external_sources = var.external_secret_sources
  }
}

output "secret_backup_configuration" {
  description = "Secret backup and recovery configuration"
  value = {
    backup_enabled = var.secret_backup_enabled
    recovery_window_days = var.secret_recovery_window_days
    versioning_enabled = var.enable_secret_versioning
    max_versions = var.max_secret_versions
  }
}

# =============================================================================
# PERFORMANCE AND COST OUTPUTS
# =============================================================================

output "performance_configuration" {
  description = "Performance optimization configuration"
  value = {
    caching_enabled = var.secret_cache_ttl_seconds > 0
    cache_ttl_seconds = var.secret_cache_ttl_seconds
    batching_enabled = var.enable_secret_batching
    batch_size = var.batch_size
    compression_enabled = var.enable_secret_compression
  }
}

output "cost_optimization_configuration" {
  description = "Cost optimization features configuration"
  value = {
    cost_optimization_enabled = var.enable_cost_optimization
    lifecycle_management_enabled = var.secret_lifecycle_management
    unused_threshold_days = var.unused_secret_threshold_days
    compression_enabled = var.enable_secret_compression
  }
}

# =============================================================================
# COMPLIANCE MONITORING OUTPUTS
# =============================================================================

output "compliance_monitoring_configuration" {
  description = "Compliance monitoring configuration"
  value = {
    monitoring_enabled = var.enable_compliance_monitoring
    check_schedule = var.compliance_check_schedule
    report_frequency = var.compliance_report_frequency
    auto_remediation_enabled = var.enable_compliance_remediation
  }
}

output "secrets_security_score" {
  description = "Calculated security score based on configuration"
  value = {
    encryption_score = var.enable_encryption_at_rest ? 25 : 0
    rotation_score = var.enable_automatic_rotation ? 20 : 0
    compliance_score = length(var.compliance_frameworks) * 10
    access_control_score = var.enable_least_privilege_access ? 15 : 0
    monitoring_score = var.enable_secrets_monitoring ? 10 : 0
    dr_score = var.enable_secret_dr ? 10 : 0
    vault_integration_score = var.enable_vault_integration ? 5 : 0
    cross_region_score = var.enable_cross_region_secrets ? 5 : 0
    total_score = (
      (var.enable_encryption_at_rest ? 25 : 0) +
      (var.enable_automatic_rotation ? 20 : 0) +
      (length(var.compliance_frameworks) * 10) +
      (var.enable_least_privilege_access ? 15 : 0) +
      (var.enable_secrets_monitoring ? 10 : 0) +
      (var.enable_secret_dr ? 10 : 0) +
      (var.enable_vault_integration ? 5 : 0) +
      (var.enable_cross_region_secrets ? 5 : 0)
    )
  }
}

# =============================================================================
# OPERATIONAL OUTPUTS
# =============================================================================

output "secret_inventory" {
  description = "Inventory of managed secrets by type and category"
  value = {
    database_secrets_count = length(var.database_secrets)
    api_secrets_count = length(var.api_secrets)
    application_secrets_count = length(var.application_secrets)
    azure_database_secrets_count = length(var.azure_database_secrets)
    azure_api_secrets_count = length(var.azure_api_secrets)
    gcp_database_secrets_count = length(var.gcp_database_secrets)
    gcp_api_secrets_count = length(var.gcp_api_secrets)
    total_secrets_managed = (
      length(var.database_secrets) +
      length(var.api_secrets) +
      length(var.application_secrets) +
      length(var.azure_database_secrets) +
      length(var.azure_api_secrets) +
      length(var.gcp_database_secrets) +
      length(var.gcp_api_secrets)
    )
  }
}

output "notification_configuration" {
  description = "Notification and alerting configuration"
  value = {
    notification_topic_configured = var.notification_topic_arn != ""
    alert_on_access = var.alert_on_secret_access
    alert_on_rotation_failure = var.alert_on_rotation_failure
    alert_on_expiry = var.alert_on_expired_secrets
    expiry_warning_days = var.secret_expiry_warning_days
  }
}