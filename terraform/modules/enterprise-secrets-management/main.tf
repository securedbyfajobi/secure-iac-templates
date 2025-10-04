# Enterprise Secrets Management Module
# Comprehensive multi-cloud secrets management with automated rotation, compliance, and security

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
    vault = {
      source  = "hashicorp/vault"
      version = "~> 3.0"
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
    Module      = "enterprise-secrets-management"
    CreatedBy   = "terraform"
    Purpose     = "secrets-management"
    Compliance  = join(",", var.compliance_frameworks)
  })

  # Secret categorization for different security levels
  secret_categories = {
    "critical" = {
      rotation_days     = 30
      max_age_hours     = 720   # 30 days
      encryption_level  = "AES-256"
      audit_level      = "detailed"
      cross_region     = true
    }
    "high" = {
      rotation_days     = 60
      max_age_hours     = 1440  # 60 days
      encryption_level  = "AES-256"
      audit_level      = "standard"
      cross_region     = true
    }
    "medium" = {
      rotation_days     = 90
      max_age_hours     = 2160  # 90 days
      encryption_level  = "AES-256"
      audit_level      = "standard"
      cross_region     = false
    }
    "low" = {
      rotation_days     = 180
      max_age_hours     = 4320  # 180 days
      encryption_level  = "AES-128"
      audit_level      = "basic"
      cross_region     = false
    }
  }

  # Compliance-based secret requirements
  compliance_requirements = {
    "SOC2" = {
      encryption_required    = true
      rotation_max_days     = 90
      audit_logging         = true
      access_review_days    = 30
    }
    "PCI-DSS" = {
      encryption_required    = true
      rotation_max_days     = 90
      audit_logging         = true
      access_review_days    = 15
    }
    "HIPAA" = {
      encryption_required    = true
      rotation_max_days     = 60
      audit_logging         = true
      access_review_days    = 30
    }
    "NIST" = {
      encryption_required    = true
      rotation_max_days     = 60
      audit_logging         = true
      access_review_days    = 30
    }
    "FIPS" = {
      encryption_required    = true
      rotation_max_days     = 30
      audit_logging         = true
      access_review_days    = 15
    }
  }

  # Calculate strictest compliance requirements
  strictest_rotation_days = length(var.compliance_frameworks) > 0 ? min([
    for framework in var.compliance_frameworks :
    local.compliance_requirements[framework].rotation_max_days
  ]...) : 90

  strictest_access_review_days = length(var.compliance_frameworks) > 0 ? min([
    for framework in var.compliance_frameworks :
    local.compliance_requirements[framework].access_review_days
  ]...) : 30
}

data "aws_caller_identity" "current" {
  count = var.enable_aws_secrets ? 1 : 0
}

data "aws_region" "current" {
  count = var.enable_aws_secrets ? 1 : 0
}

data "azurerm_client_config" "current" {
  count = var.enable_azure_secrets ? 1 : 0
}

# =============================================================================
# AWS SECRETS MANAGER
# =============================================================================

# KMS key for AWS Secrets Manager encryption
resource "aws_kms_key" "secrets_encryption" {
  count                   = var.enable_aws_secrets ? 1 : 0
  description             = "Enterprise secrets encryption key"
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
        Sid    = "Allow Secrets Manager"
        Effect = "Allow"
        Principal = {
          Service = "secretsmanager.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:ReEncrypt*"
        ]
        Resource = "*"
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_kms_alias" "secrets_key_alias" {
  count         = var.enable_aws_secrets ? 1 : 0
  name          = "alias/${local.name_prefix}-secrets"
  target_key_id = aws_kms_key.secrets_encryption[0].key_id
}

# Database credentials with automatic rotation
resource "aws_secretsmanager_secret" "database_credentials" {
  for_each = var.enable_aws_secrets ? var.database_secrets : {}

  name                    = "${local.name_prefix}-db-${each.key}"
  description             = "Database credentials for ${each.key} - ${each.value.description}"
  kms_key_id             = aws_kms_key.secrets_encryption[0].arn
  recovery_window_in_days = var.secret_recovery_window_days

  replica {
    region     = var.aws_replica_region
    kms_key_id = var.enable_cross_region_secrets ? aws_kms_key.secrets_encryption_replica[0].arn : null
  }

  tags = merge(local.common_tags, {
    SecretType     = "database"
    Category       = each.value.category
    RotationDays   = local.secret_categories[each.value.category].rotation_days
    Environment    = var.environment
  })
}

resource "aws_secretsmanager_secret_version" "database_credentials" {
  for_each = var.enable_aws_secrets ? var.database_secrets : {}

  secret_id = aws_secretsmanager_secret.database_credentials[each.key].id
  secret_string = jsonencode({
    username = each.value.username
    password = each.value.password
    engine   = each.value.engine
    host     = each.value.host
    port     = each.value.port
    dbname   = each.value.dbname
  })

  lifecycle {
    ignore_changes = [secret_string]
  }
}

# Automatic rotation for database secrets
resource "aws_secretsmanager_secret_rotation" "database_rotation" {
  for_each = var.enable_aws_secrets && var.enable_automatic_rotation ? var.database_secrets : {}

  secret_id           = aws_secretsmanager_secret.database_credentials[each.key].id
  rotation_lambda_arn = aws_lambda_function.rotation_lambda[0].arn

  rotation_rules {
    automatically_after_days = local.secret_categories[each.value.category].rotation_days
  }

  depends_on = [aws_lambda_permission.allow_secrets_manager]
}

# Cross-region KMS key for secret replication
resource "aws_kms_key" "secrets_encryption_replica" {
  count    = var.enable_aws_secrets && var.enable_cross_region_secrets ? 1 : 0
  provider = aws.replica

  description             = "Enterprise secrets encryption key (replica)"
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
      }
    ]
  })

  tags = local.common_tags
}

# API keys and service credentials
resource "aws_secretsmanager_secret" "api_credentials" {
  for_each = var.enable_aws_secrets ? var.api_secrets : {}

  name                    = "${local.name_prefix}-api-${each.key}"
  description             = "API credentials for ${each.key} - ${each.value.description}"
  kms_key_id             = aws_kms_key.secrets_encryption[0].arn
  recovery_window_in_days = var.secret_recovery_window_days

  tags = merge(local.common_tags, {
    SecretType     = "api"
    Category       = each.value.category
    Service        = each.key
  })
}

resource "aws_secretsmanager_secret_version" "api_credentials" {
  for_each = var.enable_aws_secrets ? var.api_secrets : {}

  secret_id = aws_secretsmanager_secret.api_credentials[each.key].id
  secret_string = jsonencode({
    api_key    = each.value.api_key
    secret_key = each.value.secret_key
    endpoint   = each.value.endpoint
  })

  lifecycle {
    ignore_changes = [secret_string]
  }
}

# Application configuration secrets
resource "aws_secretsmanager_secret" "application_config" {
  for_each = var.enable_aws_secrets ? var.application_secrets : {}

  name                    = "${local.name_prefix}-app-${each.key}"
  description             = "Application configuration for ${each.key}"
  kms_key_id             = aws_kms_key.secrets_encryption[0].arn
  recovery_window_in_days = var.secret_recovery_window_days

  tags = merge(local.common_tags, {
    SecretType     = "application"
    Category       = each.value.category
    Application    = each.key
  })
}

# =============================================================================
# AZURE KEY VAULT
# =============================================================================

# Azure Key Vault
resource "azurerm_key_vault" "enterprise_vault" {
  count               = var.enable_azure_secrets ? 1 : 0
  name                = "${local.name_prefix}-kv"
  location            = var.azure_location
  resource_group_name = var.azure_resource_group_name
  tenant_id           = data.azurerm_client_config.current[0].tenant_id
  sku_name            = "premium"

  enabled_for_disk_encryption     = true
  enabled_for_deployment          = false
  enabled_for_template_deployment = false
  purge_protection_enabled        = var.enable_purge_protection
  soft_delete_retention_days      = var.azure_soft_delete_retention_days

  # Network access restrictions
  public_network_access_enabled = var.azure_public_access_enabled
  default_action                = "Deny"

  dynamic "ip_rule" {
    for_each = var.azure_allowed_ips
    content {
      ip_or_cidr = ip_rule.value
    }
  }

  dynamic "virtual_network_subnet_ids" {
    for_each = var.azure_allowed_subnets
    content {
      subnet_id = virtual_network_subnet_ids.value
    }
  }

  # Access policies
  access_policy {
    tenant_id = data.azurerm_client_config.current[0].tenant_id
    object_id = data.azurerm_client_config.current[0].object_id

    key_permissions = [
      "Create", "Delete", "Get", "List", "Update", "Import", "Backup", "Restore"
    ]

    secret_permissions = [
      "Set", "Get", "Delete", "List", "Recover", "Backup", "Restore"
    ]

    certificate_permissions = [
      "Create", "Delete", "Get", "List", "Update", "Import"
    ]
  }

  tags = local.common_tags
}

# Database secrets in Azure Key Vault
resource "azurerm_key_vault_secret" "database_secrets" {
  for_each = var.enable_azure_secrets ? var.azure_database_secrets : {}

  name         = "${each.key}-connection-string"
  value        = each.value.connection_string
  key_vault_id = azurerm_key_vault.enterprise_vault[0].id

  expiration_date = timeadd(timestamp(), "${local.secret_categories[each.value.category].rotation_days * 24}h")

  tags = merge(local.common_tags, {
    SecretType = "database"
    Category   = each.value.category
  })
}

# API keys in Azure Key Vault
resource "azurerm_key_vault_secret" "api_secrets" {
  for_each = var.enable_azure_secrets ? var.azure_api_secrets : {}

  name         = "${each.key}-api-key"
  value        = each.value.api_key
  key_vault_id = azurerm_key_vault.enterprise_vault[0].id

  expiration_date = timeadd(timestamp(), "${local.secret_categories[each.value.category].rotation_days * 24}h")

  tags = merge(local.common_tags, {
    SecretType = "api"
    Category   = each.value.category
  })
}

# =============================================================================
# GOOGLE SECRET MANAGER
# =============================================================================

# Database secrets in Google Secret Manager
resource "google_secret_manager_secret" "database_secrets" {
  for_each = var.enable_gcp_secrets ? var.gcp_database_secrets : {}

  project   = var.gcp_project_id
  secret_id = "${local.name_prefix}-db-${each.key}"

  replication {
    automatic = true
  }

  labels = merge(local.common_tags, {
    secret_type = "database"
    category    = each.value.category
  })
}

resource "google_secret_manager_secret_version" "database_secrets" {
  for_each = var.enable_gcp_secrets ? var.gcp_database_secrets : {}

  secret      = google_secret_manager_secret.database_secrets[each.key].id
  secret_data = jsonencode({
    username = each.value.username
    password = each.value.password
    host     = each.value.host
    port     = each.value.port
    database = each.value.database
  })
}

# API secrets in Google Secret Manager
resource "google_secret_manager_secret" "api_secrets" {
  for_each = var.enable_gcp_secrets ? var.gcp_api_secrets : {}

  project   = var.gcp_project_id
  secret_id = "${local.name_prefix}-api-${each.key}"

  replication {
    automatic = true
  }

  labels = merge(local.common_tags, {
    secret_type = "api"
    category    = each.value.category
  })
}

# =============================================================================
# HASHICORP VAULT INTEGRATION
# =============================================================================

# Vault authentication backend for AWS
resource "vault_auth_backend" "aws" {
  count = var.enable_vault_integration ? 1 : 0
  type  = "aws"
  path  = "aws"

  description = "AWS authentication backend for enterprise secrets"
}

# Vault policy for secrets access
resource "vault_policy" "secrets_policy" {
  count = var.enable_vault_integration ? 1 : 0
  name  = "${local.name_prefix}-secrets-policy"

  policy = templatefile("${path.module}/templates/vault_policy.hcl", {
    environment = var.environment
    name_prefix = local.name_prefix
  })
}

# Database secrets engine
resource "vault_database_secrets_mount" "db" {
  count = var.enable_vault_integration ? 1 : 0
  path  = "${local.name_prefix}-database"

  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds     = 86400
}

# =============================================================================
# SECRET ROTATION AUTOMATION
# =============================================================================

# Lambda function for secret rotation
resource "aws_lambda_function" "rotation_lambda" {
  count            = var.enable_aws_secrets && var.enable_automatic_rotation ? 1 : 0
  filename         = "secret_rotation.zip"
  function_name    = "${local.name_prefix}-secret-rotation"
  role            = aws_iam_role.rotation_lambda_role[0].arn
  handler         = "rotation.lambda_handler"
  source_code_hash = data.archive_file.rotation_lambda_zip[0].output_base64sha256
  runtime         = "python3.9"
  timeout         = 300

  environment {
    variables = {
      SECRETS_MANAGER_ENDPOINT = "https://secretsmanager.${data.aws_region.current[0].name}.amazonaws.com"
      ENVIRONMENT             = var.environment
      KMS_KEY_ID              = aws_kms_key.secrets_encryption[0].key_id
    }
  }

  tags = local.common_tags
}

data "archive_file" "rotation_lambda_zip" {
  count       = var.enable_aws_secrets && var.enable_automatic_rotation ? 1 : 0
  type        = "zip"
  output_path = "secret_rotation.zip"

  source {
    content = templatefile("${path.module}/templates/rotation.py", {
      environment = var.environment
    })
    filename = "rotation.py"
  }
}

# IAM role for rotation Lambda
resource "aws_iam_role" "rotation_lambda_role" {
  count = var.enable_aws_secrets && var.enable_automatic_rotation ? 1 : 0
  name  = "${local.name_prefix}-rotation-lambda-role"

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

resource "aws_iam_role_policy" "rotation_lambda_policy" {
  count = var.enable_aws_secrets && var.enable_automatic_rotation ? 1 : 0
  name  = "${local.name_prefix}-rotation-lambda-policy"
  role  = aws_iam_role.rotation_lambda_role[0].id

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
          "secretsmanager:DescribeSecret",
          "secretsmanager:GetSecretValue",
          "secretsmanager:PutSecretValue",
          "secretsmanager:UpdateSecretVersionStage"
        ]
        Resource = "arn:aws:secretsmanager:*:*:secret:${local.name_prefix}-*"
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:ReEncrypt*"
        ]
        Resource = aws_kms_key.secrets_encryption[0].arn
      }
    ]
  })
}

resource "aws_lambda_permission" "allow_secrets_manager" {
  count         = var.enable_aws_secrets && var.enable_automatic_rotation ? 1 : 0
  statement_id  = "AllowExecutionFromSecretsManager"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.rotation_lambda[0].function_name
  principal     = "secretsmanager.amazonaws.com"
}

# =============================================================================
# SECRETS MONITORING AND ALERTING
# =============================================================================

# CloudWatch alarm for failed secret rotations
resource "aws_cloudwatch_metric_alarm" "rotation_failures" {
  count               = var.enable_aws_secrets && var.enable_automatic_rotation ? 1 : 0
  alarm_name          = "${local.name_prefix}-secret-rotation-failures"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "300"
  statistic           = "Sum"
  threshold           = "0"
  alarm_description   = "This metric monitors secret rotation failures"
  alarm_actions       = [var.notification_topic_arn]

  dimensions = {
    FunctionName = aws_lambda_function.rotation_lambda[0].function_name
  }

  tags = local.common_tags
}

# CloudWatch dashboard for secrets management
resource "aws_cloudwatch_dashboard" "secrets_dashboard" {
  count          = var.enable_aws_secrets ? 1 : 0
  dashboard_name = "${local.name_prefix}-secrets-dashboard"

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
            ["AWS/SecretsManager", "RotationCompleted"],
            [".", "RotationFailed"],
            ["AWS/Lambda", "Invocations", "FunctionName", var.enable_automatic_rotation ? aws_lambda_function.rotation_lambda[0].function_name : ""],
            [".", "Errors", "FunctionName", var.enable_automatic_rotation ? aws_lambda_function.rotation_lambda[0].function_name : ""]
          ]
          view    = "timeSeries"
          stacked = false
          region  = data.aws_region.current[0].name
          title   = "Secrets Management Metrics"
        }
      }
    ]
  })
}

# =============================================================================
# COMPLIANCE MONITORING
# =============================================================================

# Lambda function for compliance monitoring
resource "aws_lambda_function" "compliance_monitor" {
  count            = var.enable_compliance_monitoring ? 1 : 0
  filename         = "compliance_monitor.zip"
  function_name    = "${local.name_prefix}-compliance-monitor"
  role            = aws_iam_role.compliance_monitor_role[0].arn
  handler         = "compliance.lambda_handler"
  source_code_hash = data.archive_file.compliance_monitor_zip[0].output_base64sha256
  runtime         = "python3.9"
  timeout         = 900

  environment {
    variables = {
      ENVIRONMENT             = var.environment
      COMPLIANCE_FRAMEWORKS   = join(",", var.compliance_frameworks)
      NOTIFICATION_TOPIC      = var.notification_topic_arn
      STRICTEST_ROTATION_DAYS = local.strictest_rotation_days
    }
  }

  tags = local.common_tags
}

data "archive_file" "compliance_monitor_zip" {
  count       = var.enable_compliance_monitoring ? 1 : 0
  type        = "zip"
  output_path = "compliance_monitor.zip"

  source {
    content = templatefile("${path.module}/templates/compliance_monitor.py", {
      environment         = var.environment
      compliance_frameworks = var.compliance_frameworks
    })
    filename = "compliance.py"
  }
}

# IAM role for compliance monitoring Lambda
resource "aws_iam_role" "compliance_monitor_role" {
  count = var.enable_compliance_monitoring ? 1 : 0
  name  = "${local.name_prefix}-compliance-monitor-role"

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

# CloudWatch Events rule for compliance monitoring
resource "aws_cloudwatch_event_rule" "compliance_schedule" {
  count               = var.enable_compliance_monitoring ? 1 : 0
  name                = "${local.name_prefix}-compliance-schedule"
  description         = "Scheduled compliance monitoring for secrets"
  schedule_expression = var.compliance_check_schedule

  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "compliance_target" {
  count     = var.enable_compliance_monitoring ? 1 : 0
  rule      = aws_cloudwatch_event_rule.compliance_schedule[0].name
  target_id = "ComplianceMonitorTarget"
  arn       = aws_lambda_function.compliance_monitor[0].arn
}

resource "aws_lambda_permission" "allow_compliance_trigger" {
  count         = var.enable_compliance_monitoring ? 1 : 0
  statement_id  = "AllowExecutionFromCloudWatchCompliance"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.compliance_monitor[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.compliance_schedule[0].arn
}