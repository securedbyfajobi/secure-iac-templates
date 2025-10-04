# Enterprise Backup and Disaster Recovery Module Outputs

# =============================================================================
# AWS BACKUP OUTPUTS
# =============================================================================

output "aws_backup_vault_arn" {
  description = "ARN of the primary AWS backup vault"
  value       = var.enable_aws_dr ? aws_backup_vault.primary[0].arn : null
}

output "aws_backup_vault_name" {
  description = "Name of the primary AWS backup vault"
  value       = var.enable_aws_dr ? aws_backup_vault.primary[0].name : null
}

output "aws_dr_backup_vault_arn" {
  description = "ARN of the DR region backup vault"
  value       = var.enable_aws_dr && var.enable_cross_region_backup ? aws_backup_vault.dr_region[0].arn : null
}

output "aws_backup_plan_id" {
  description = "ID of the AWS backup plan"
  value       = var.enable_aws_dr ? aws_backup_plan.enterprise_plan[0].id : null
}

output "aws_backup_plan_arn" {
  description = "ARN of the AWS backup plan"
  value       = var.enable_aws_dr ? aws_backup_plan.enterprise_plan[0].arn : null
}

output "aws_backup_role_arn" {
  description = "ARN of the AWS backup service role"
  value       = var.enable_aws_dr ? aws_iam_role.backup_service_role[0].arn : null
}

output "aws_backup_kms_key_id" {
  description = "ID of the KMS key used for backup encryption"
  value       = var.enable_aws_dr ? aws_kms_key.backup_encryption[0].key_id : null
}

output "aws_backup_kms_key_arn" {
  description = "ARN of the KMS key used for backup encryption"
  value       = var.enable_aws_dr ? aws_kms_key.backup_encryption[0].arn : null
}

# =============================================================================
# AZURE BACKUP OUTPUTS
# =============================================================================

output "azure_recovery_vault_id" {
  description = "ID of the Azure Recovery Services vault"
  value       = var.enable_azure_dr ? azurerm_recovery_services_vault.primary[0].id : null
}

output "azure_recovery_vault_name" {
  description = "Name of the Azure Recovery Services vault"
  value       = var.enable_azure_dr ? azurerm_recovery_services_vault.primary[0].name : null
}

output "azure_backup_policies" {
  description = "Map of Azure backup policy IDs by tier"
  value = var.enable_azure_dr ? {
    for tier in var.backup_tiers :
    tier => azurerm_backup_policy_vm.tier_policies[tier].id
  } : {}
}

# =============================================================================
# GCP BACKUP OUTPUTS
# =============================================================================

output "gcp_backup_bucket_name" {
  description = "Name of the primary GCP backup bucket"
  value       = var.enable_gcp_dr ? google_storage_bucket.primary_backup[0].name : null
}

output "gcp_backup_bucket_url" {
  description = "URL of the primary GCP backup bucket"
  value       = var.enable_gcp_dr ? google_storage_bucket.primary_backup[0].url : null
}

output "gcp_dr_backup_bucket_name" {
  description = "Name of the GCP DR backup bucket"
  value       = var.enable_gcp_dr && var.enable_cross_region_backup ? google_storage_bucket.dr_backup[0].name : null
}

# =============================================================================
# DR AUTOMATION OUTPUTS
# =============================================================================

output "dr_coordinator_function_arn" {
  description = "ARN of the DR coordinator Lambda function"
  value       = var.enable_aws_dr && var.enable_dr_automation ? aws_lambda_function.dr_coordinator[0].arn : null
}

output "dr_coordinator_function_name" {
  description = "Name of the DR coordinator Lambda function"
  value       = var.enable_aws_dr && var.enable_dr_automation ? aws_lambda_function.dr_coordinator[0].function_name : null
}

output "dr_test_schedule_arn" {
  description = "ARN of the CloudWatch Events rule for DR testing"
  value       = var.enable_aws_dr && var.enable_dr_automation ? aws_cloudwatch_event_rule.dr_test_schedule[0].arn : null
}

# =============================================================================
# MONITORING OUTPUTS
# =============================================================================

output "backup_failure_alarm_arn" {
  description = "ARN of the backup failure CloudWatch alarm"
  value       = var.enable_aws_dr ? aws_cloudwatch_metric_alarm.backup_job_failures[0].arn : null
}

output "dr_dashboard_url" {
  description = "URL of the DR CloudWatch dashboard"
  value       = var.enable_aws_dr ? "https://${data.aws_region.current[0].name}.console.aws.amazon.com/cloudwatch/home?region=${data.aws_region.current[0].name}#dashboards:name=${aws_cloudwatch_dashboard.dr_dashboard[0].dashboard_name}" : null
}

# =============================================================================
# CONFIGURATION OUTPUTS
# =============================================================================

output "backup_tier_configurations" {
  description = "Backup tier configurations with RTO/RPO requirements"
  value = {
    for tier in var.backup_tiers :
    tier => {
      rto_minutes = local.tier_requirements[tier].rto_minutes
      rpo_minutes = local.tier_requirements[tier].rpo_minutes
      frequency   = local.tier_requirements[tier].backup_frequency
    }
  }
}

output "compliance_retention_policies" {
  description = "Calculated retention policies based on compliance frameworks"
  value = {
    daily_retention   = local.max_daily_retention
    weekly_retention  = local.max_weekly_retention
    frameworks_applied = var.compliance_frameworks
  }
}

output "cross_region_configuration" {
  description = "Cross-region backup and DR configuration"
  value = {
    enabled     = var.enable_cross_region_backup
    aws_regions = var.enable_aws_dr ? {
      primary = data.aws_region.current[0].name
      dr      = var.aws_dr_region
    } : null
    azure_regions = var.enable_azure_dr ? {
      primary = var.azure_primary_location
      dr      = var.azure_dr_location
    } : null
    gcp_regions = var.enable_gcp_dr ? {
      primary = var.gcp_primary_region
      dr      = var.gcp_dr_region
    } : null
  }
}

# =============================================================================
# SECURITY OUTPUTS
# =============================================================================

output "encryption_configuration" {
  description = "Backup encryption configuration details"
  value = {
    aws_kms_enabled    = var.enable_aws_dr && var.backup_encryption_enabled
    azure_cmk_enabled  = var.enable_azure_dr && var.azure_encryption_key_id != ""
    gcp_cmek_enabled   = var.enable_gcp_dr && var.gcp_kms_key_name != ""
  }
}

output "backup_security_score" {
  description = "Calculated backup security score based on configuration"
  value = {
    encryption_score = var.backup_encryption_enabled ? 25 : 0
    compliance_score = length(var.compliance_frameworks) * 10
    cross_region_score = var.enable_cross_region_backup ? 20 : 0
    automation_score = var.enable_dr_automation ? 15 : 0
    monitoring_score = var.enable_backup_monitoring ? 10 : 0
    total_score = (
      (var.backup_encryption_enabled ? 25 : 0) +
      (length(var.compliance_frameworks) * 10) +
      (var.enable_cross_region_backup ? 20 : 0) +
      (var.enable_dr_automation ? 15 : 0) +
      (var.enable_backup_monitoring ? 10 : 0)
    )
  }
}

# =============================================================================
# INTEGRATION OUTPUTS
# =============================================================================

output "backup_selections" {
  description = "Map of backup selections by tier"
  value = var.enable_aws_dr ? {
    for tier in var.backup_tiers :
    tier => aws_backup_selection.enterprise_selection[tier].id
  } : {}
}

output "resource_integration_status" {
  description = "Status of integration with existing backup resources"
  value = {
    existing_vault_integrated = var.existing_backup_vault_arn != ""
    database_backups_integrated = var.integrate_with_existing_backups
    policy_inheritance_enabled = var.backup_policy_inheritance
  }
}

# =============================================================================
# COST OPTIMIZATION OUTPUTS
# =============================================================================

output "lifecycle_policies" {
  description = "Backup lifecycle policies for cost optimization"
  value = {
    cold_storage_days = var.cold_storage_transition_days
    archive_days     = var.archive_transition_days
    lifecycle_enabled = var.enable_backup_lifecycle
  }
}

output "estimated_monthly_savings" {
  description = "Estimated monthly cost savings from lifecycle policies"
  value = var.enable_backup_lifecycle ? {
    cold_storage_savings_percent = 50
    archive_savings_percent      = 80
    deduplication_savings_percent = var.enable_backup_deduplication ? 30 : 0
    compression_savings_percent   = var.enable_backup_compression ? 20 : 0
  } : null
}