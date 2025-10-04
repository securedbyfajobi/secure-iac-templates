# Enterprise Backup and Disaster Recovery Module
# Comprehensive cross-cloud backup orchestration and disaster recovery automation
# Complements existing database backup features with enterprise-grade DR coordination

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

# =============================================================================
# LOCALS AND DATA SOURCES
# =============================================================================

locals {
  name_prefix = "${var.name_prefix}-${var.environment}"

  common_tags = merge(var.common_tags, {
    Environment = var.environment
    Module      = "enterprise-backup-dr"
    CreatedBy   = "terraform"
    Purpose     = "disaster-recovery"
    Compliance  = join(",", var.compliance_frameworks)
  })

  # Compliance-based backup retention policies
  compliance_retention = {
    "SOC2" = {
      daily_retention   = 30
      weekly_retention  = 12
      monthly_retention = 36
      yearly_retention  = 7
    }
    "PCI-DSS" = {
      daily_retention   = 365
      weekly_retention  = 52
      monthly_retention = 120
      yearly_retention  = 10
    }
    "HIPAA" = {
      daily_retention   = 365
      weekly_retention  = 52
      monthly_retention = 84
      yearly_retention  = 6
    }
    "NIST" = {
      daily_retention   = 90
      weekly_retention  = 26
      monthly_retention = 60
      yearly_retention  = 7
    }
    "ISO27001" = {
      daily_retention   = 90
      weekly_retention  = 26
      monthly_retention = 36
      yearly_retention  = 5
    }
  }

  # Calculate maximum retention based on compliance frameworks
  max_daily_retention = length(var.compliance_frameworks) > 0 ? max([
    for framework in var.compliance_frameworks :
    local.compliance_retention[framework].daily_retention
  ]...) : var.default_daily_retention

  max_weekly_retention = length(var.compliance_frameworks) > 0 ? max([
    for framework in var.compliance_frameworks :
    local.compliance_retention[framework].weekly_retention
  ]...) : var.default_weekly_retention

  # RTO/RPO requirements based on tier
  tier_requirements = {
    "critical" = {
      rto_minutes = 15
      rpo_minutes = 5
      backup_frequency = "hourly"
    }
    "high" = {
      rto_minutes = 60
      rpo_minutes = 30
      backup_frequency = "6hourly"
    }
    "medium" = {
      rto_minutes = 240
      rpo_minutes = 120
      backup_frequency = "daily"
    }
    "low" = {
      rto_minutes = 1440
      rpo_minutes = 720
      backup_frequency = "weekly"
    }
  }

  # Cross-region mapping for DR
  dr_region_mapping = {
    "us-east-1" = "us-west-2"
    "us-west-2" = "us-east-1"
    "eu-west-1" = "eu-central-1"
    "ap-southeast-1" = "ap-northeast-1"
  }
}

data "aws_caller_identity" "current" {
  count = var.enable_aws_dr ? 1 : 0
}

data "aws_region" "current" {
  count = var.enable_aws_dr ? 1 : 0
}

data "azurerm_client_config" "current" {
  count = var.enable_azure_dr ? 1 : 0
}

# =============================================================================
# AWS BACKUP AND DR INFRASTRUCTURE
# =============================================================================

# Primary backup vault with cross-region replication
resource "aws_backup_vault" "primary" {
  count       = var.enable_aws_dr ? 1 : 0
  name        = "${local.name_prefix}-primary-vault"
  kms_key_arn = aws_kms_key.backup_encryption[0].arn

  tags = local.common_tags
}

# DR region backup vault
resource "aws_backup_vault" "dr_region" {
  count    = var.enable_aws_dr && var.enable_cross_region_backup ? 1 : 0
  provider = aws.dr_region
  name     = "${local.name_prefix}-dr-vault"
  kms_key_arn = aws_kms_key.dr_backup_encryption[0].arn

  tags = local.common_tags
}

# KMS keys for backup encryption
resource "aws_kms_key" "backup_encryption" {
  count                   = var.enable_aws_dr ? 1 : 0
  description             = "Enterprise backup encryption key"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current[0].account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow AWS Backup"
        Effect = "Allow"
        Principal = {
          Service = "backup.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:ReEncrypt*",
          "kms:CreateGrant"
        ]
        Resource = "*"
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_kms_key" "dr_backup_encryption" {
  count    = var.enable_aws_dr && var.enable_cross_region_backup ? 1 : 0
  provider = aws.dr_region
  description             = "DR region backup encryption key"
  deletion_window_in_days = 10
  enable_key_rotation     = true

  tags = local.common_tags
}

resource "aws_kms_alias" "backup_key_alias" {
  count         = var.enable_aws_dr ? 1 : 0
  name          = "alias/${local.name_prefix}-backup"
  target_key_id = aws_kms_key.backup_encryption[0].key_id
}

# IAM role for AWS Backup service
resource "aws_iam_role" "backup_service_role" {
  count = var.enable_aws_dr ? 1 : 0
  name  = "${local.name_prefix}-backup-service-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "backup.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "backup_service_policy" {
  count      = var.enable_aws_dr ? 1 : 0
  role       = aws_iam_role.backup_service_role[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForBackup"
}

resource "aws_iam_role_policy_attachment" "backup_restore_policy" {
  count      = var.enable_aws_dr ? 1 : 0
  role       = aws_iam_role.backup_service_role[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSBackupServiceRolePolicyForRestores"
}

# Enterprise backup plan with tier-based policies
resource "aws_backup_plan" "enterprise_plan" {
  count = var.enable_aws_dr ? 1 : 0
  name  = "${local.name_prefix}-enterprise-backup-plan"

  # Critical tier - hourly backups
  dynamic "rule" {
    for_each = contains(var.backup_tiers, "critical") ? [1] : []
    content {
      rule_name         = "critical-tier-backup"
      target_vault_name = aws_backup_vault.primary[0].name
      schedule          = "cron(0 * * * ? *)"  # Every hour
      start_window      = 60
      completion_window = 120

      recovery_point_tags = merge(local.common_tags, {
        BackupTier = "critical"
        RTO        = "${local.tier_requirements.critical.rto_minutes}min"
        RPO        = "${local.tier_requirements.critical.rpo_minutes}min"
      })

      lifecycle {
        cold_storage_after = 30
        delete_after       = local.max_daily_retention
      }

      dynamic "copy_action" {
        for_each = var.enable_cross_region_backup ? [1] : []
        content {
          destination_vault_arn = aws_backup_vault.dr_region[0].arn
          lifecycle {
            cold_storage_after = 7
            delete_after       = local.max_daily_retention
          }
        }
      }
    }
  }

  # High tier - 6-hourly backups
  dynamic "rule" {
    for_each = contains(var.backup_tiers, "high") ? [1] : []
    content {
      rule_name         = "high-tier-backup"
      target_vault_name = aws_backup_vault.primary[0].name
      schedule          = "cron(0 */6 * * ? *)"  # Every 6 hours
      start_window      = 60
      completion_window = 180

      recovery_point_tags = merge(local.common_tags, {
        BackupTier = "high"
        RTO        = "${local.tier_requirements.high.rto_minutes}min"
        RPO        = "${local.tier_requirements.high.rpo_minutes}min"
      })

      lifecycle {
        cold_storage_after = 30
        delete_after       = local.max_daily_retention
      }
    }
  }

  # Medium tier - daily backups
  dynamic "rule" {
    for_each = contains(var.backup_tiers, "medium") ? [1] : []
    content {
      rule_name         = "medium-tier-backup"
      target_vault_name = aws_backup_vault.primary[0].name
      schedule          = "cron(0 2 * * ? *)"  # Daily at 2 AM
      start_window      = 60
      completion_window = 300

      recovery_point_tags = merge(local.common_tags, {
        BackupTier = "medium"
        RTO        = "${local.tier_requirements.medium.rto_minutes}min"
        RPO        = "${local.tier_requirements.medium.rpo_minutes}min"
      })

      lifecycle {
        cold_storage_after = 30
        delete_after       = local.max_daily_retention
      }
    }
  }

  # Weekly retention rule
  rule {
    rule_name         = "weekly-retention"
    target_vault_name = aws_backup_vault.primary[0].name
    schedule          = "cron(0 3 ? * SUN *)"  # Weekly on Sunday at 3 AM
    start_window      = 60
    completion_window = 300

    recovery_point_tags = merge(local.common_tags, {
      BackupType = "weekly"
    })

    lifecycle {
      cold_storage_after = 30
      delete_after       = local.max_weekly_retention * 7
    }
  }

  tags = local.common_tags
}

# Backup selections for different tiers
resource "aws_backup_selection" "enterprise_selection" {
  for_each = var.enable_aws_dr ? toset(var.backup_tiers) : []

  iam_role_arn = aws_iam_role.backup_service_role[0].arn
  name         = "${local.name_prefix}-${each.key}-selection"
  plan_id      = aws_backup_plan.enterprise_plan[0].id

  resources = var.aws_backup_resources[each.key]

  condition {
    string_equals {
      key   = "BackupTier"
      value = each.key
    }
  }
}

# =============================================================================
# AZURE BACKUP AND DR INFRASTRUCTURE
# =============================================================================

resource "azurerm_recovery_services_vault" "primary" {
  count               = var.enable_azure_dr ? 1 : 0
  name                = "${local.name_prefix}-recovery-vault"
  location            = var.azure_primary_location
  resource_group_name = var.azure_resource_group_name
  sku                 = "Standard"

  storage_mode_type         = "GeoRedundant"
  cross_region_restore      = var.enable_cross_region_backup
  soft_delete_enabled       = true
  immutability              = "Locked"

  encryption {
    key_id                            = var.azure_encryption_key_id
    infrastructure_encryption_enabled = true
  }

  tags = local.common_tags
}

# VM backup policies for different tiers
resource "azurerm_backup_policy_vm" "tier_policies" {
  for_each = var.enable_azure_dr ? toset(var.backup_tiers) : {}

  name                = "${local.name_prefix}-${each.key}-vm-policy"
  resource_group_name = var.azure_resource_group_name
  recovery_vault_name = azurerm_recovery_services_vault.primary[0].name

  timezone = var.azure_timezone

  backup {
    frequency = each.key == "critical" ? "Daily" : "Daily"
    time      = each.key == "critical" ? "02:00" : "23:00"
  }

  retention_daily {
    count = local.tier_requirements[each.key].rto_minutes < 60 ? local.max_daily_retention : 30
  }

  retention_weekly {
    count    = local.max_weekly_retention
    weekdays = ["Sunday"]
  }

  retention_monthly {
    count    = 12
    weekdays = ["Sunday"]
    weeks    = ["First"]
  }

  dynamic "retention_yearly" {
    for_each = contains(["critical", "high"], each.key) ? [1] : []
    content {
      count    = 7
      weekdays = ["Sunday"]
      weeks    = ["First"]
      months   = ["January"]
    }
  }
}

# =============================================================================
# GCP BACKUP AND DR INFRASTRUCTURE
# =============================================================================

# Primary backup bucket with lifecycle management
resource "google_storage_bucket" "primary_backup" {
  count    = var.enable_gcp_dr ? 1 : 0
  name     = "${local.name_prefix}-backup-${random_id.bucket_suffix[0].hex}"
  location = var.gcp_primary_region

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  encryption {
    default_kms_key_name = var.gcp_kms_key_name
  }

  # Lifecycle rules for cost optimization
  lifecycle_rule {
    condition {
      age = 30
    }
    action {
      type          = "SetStorageClass"
      storage_class = "NEARLINE"
    }
  }

  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type          = "SetStorageClass"
      storage_class = "COLDLINE"
    }
  }

  lifecycle_rule {
    condition {
      age = local.max_daily_retention
    }
    action {
      type = "Delete"
    }
  }

  labels = merge(local.common_tags, {
    purpose = "enterprise-backup"
  })
}

# DR region backup bucket
resource "google_storage_bucket" "dr_backup" {
  count    = var.enable_gcp_dr && var.enable_cross_region_backup ? 1 : 0
  name     = "${local.name_prefix}-dr-backup-${random_id.bucket_suffix[0].hex}"
  location = var.gcp_dr_region

  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  encryption {
    default_kms_key_name = var.gcp_kms_key_name
  }

  labels = merge(local.common_tags, {
    purpose = "disaster-recovery"
  })
}

resource "random_id" "bucket_suffix" {
  count       = var.enable_gcp_dr ? 1 : 0
  byte_length = 4
}

# =============================================================================
# CROSS-CLOUD DR ORCHESTRATION
# =============================================================================

# Lambda function for DR coordination
resource "aws_lambda_function" "dr_coordinator" {
  count            = var.enable_aws_dr && var.enable_dr_automation ? 1 : 0
  filename         = "dr_coordinator.zip"
  function_name    = "${local.name_prefix}-dr-coordinator"
  role            = aws_iam_role.lambda_dr_role[0].arn
  handler         = "dr_coordinator.lambda_handler"
  source_code_hash = data.archive_file.dr_coordinator_zip[0].output_base64sha256
  runtime         = "python3.9"
  timeout         = 900

  environment {
    variables = {
      ENVIRONMENT         = var.environment
      PROJECT_NAME        = var.name_prefix
      BACKUP_VAULT_ARN    = var.enable_aws_dr ? aws_backup_vault.primary[0].arn : ""
      SNS_TOPIC_ARN       = var.notification_topic_arn
      CROSS_REGION_ENABLED = var.enable_cross_region_backup
    }
  }

  tags = local.common_tags
}

data "archive_file" "dr_coordinator_zip" {
  count       = var.enable_aws_dr && var.enable_dr_automation ? 1 : 0
  type        = "zip"
  output_path = "dr_coordinator.zip"

  source {
    content = templatefile("${path.module}/templates/dr_coordinator.py", {
      project_name = var.name_prefix
      environment  = var.environment
    })
    filename = "dr_coordinator.py"
  }
}

# IAM role for Lambda DR coordinator
resource "aws_iam_role" "lambda_dr_role" {
  count = var.enable_aws_dr && var.enable_dr_automation ? 1 : 0
  name  = "${local.name_prefix}-lambda-dr-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "lambda_dr_policy" {
  count = var.enable_aws_dr && var.enable_dr_automation ? 1 : 0
  name  = "${local.name_prefix}-lambda-dr-policy"
  role  = aws_iam_role.lambda_dr_role[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "backup:ListBackupJobs",
          "backup:ListRecoveryPoints",
          "backup:DescribeBackupJob",
          "backup:StartBackupJob",
          "backup:StartRestoreJob"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "sns:Publish"
        ]
        Resource = var.notification_topic_arn
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeVolumes",
          "rds:DescribeDBInstances"
        ]
        Resource = "*"
      }
    ]
  })
}

# CloudWatch Events for automated DR testing
resource "aws_cloudwatch_event_rule" "dr_test_schedule" {
  count               = var.enable_aws_dr && var.enable_dr_automation ? 1 : 0
  name                = "${local.name_prefix}-dr-test-schedule"
  description         = "Automated DR testing schedule"
  schedule_expression = var.dr_test_schedule

  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "lambda_dr_test" {
  count     = var.enable_aws_dr && var.enable_dr_automation ? 1 : 0
  rule      = aws_cloudwatch_event_rule.dr_test_schedule[0].name
  target_id = "DRTestTarget"
  arn       = aws_lambda_function.dr_coordinator[0].arn

  input = jsonencode({
    action = "test_dr"
    tier   = "high"
  })
}

resource "aws_lambda_permission" "allow_dr_test_trigger" {
  count         = var.enable_aws_dr && var.enable_dr_automation ? 1 : 0
  statement_id  = "AllowExecutionFromCloudWatchDRTest"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.dr_coordinator[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.dr_test_schedule[0].arn
}

# =============================================================================
# MONITORING AND ALERTING
# =============================================================================

# CloudWatch alarms for backup job failures
resource "aws_cloudwatch_metric_alarm" "backup_job_failures" {
  count               = var.enable_aws_dr ? 1 : 0
  alarm_name          = "${local.name_prefix}-backup-job-failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "NumberOfBackupJobsFailed"
  namespace           = "AWS/Backup"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "This metric monitors backup job failures"
  alarm_actions       = [var.notification_topic_arn]

  tags = local.common_tags
}

# CloudWatch dashboard for DR metrics
resource "aws_cloudwatch_dashboard" "dr_dashboard" {
  count          = var.enable_aws_dr ? 1 : 0
  dashboard_name = "${local.name_prefix}-dr-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/Backup", "NumberOfBackupJobsCompleted"],
            [".", "NumberOfBackupJobsFailed"],
            [".", "NumberOfRestoreJobsCompleted"],
            [".", "NumberOfRestoreJobsFailed"]
          ]
          view    = "timeSeries"
          stacked = false
          region  = data.aws_region.current[0].name
          title   = "Backup and Restore Job Status"
        }
      }
    ]
  })
}