# Advanced Compliance and Monitoring Infrastructure Module
# Enterprise-grade compliance automation and security monitoring

terraform {
  required_version = ">= 1.6.0"
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
      version = "~> 5.0"
    }
    datadog = {
      source  = "DataDog/datadog"
      version = "~> 3.0"
    }
    splunk = {
      source  = "splunk/splunk"
      version = "~> 1.4"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.4"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.9"
    }
  }
}

# =============================================================================
# LOCALS AND DATA SOURCES
# =============================================================================

locals {
  # Common tags for all resources
  common_tags = merge(var.common_tags, {
    Module              = "compliance-monitoring"
    CreatedBy          = "terraform"
    LastModified       = timestamp()
    ComplianceRequired = "true"
    Environment        = var.environment
    DataClassification = var.data_classification
  })

  # Compliance framework configurations
  compliance_configs = {
    SOC2 = {
      controls = [
        "CC1.1", "CC1.2", "CC1.3", "CC1.4", "CC1.5",
        "CC2.1", "CC2.2", "CC2.3", "CC3.1", "CC3.2", "CC3.3", "CC3.4",
        "CC4.1", "CC4.2", "CC5.1", "CC5.2", "CC5.3",
        "CC6.1", "CC6.2", "CC6.3", "CC6.4", "CC6.5", "CC6.6", "CC6.7", "CC6.8",
        "CC7.1", "CC7.2", "CC7.3", "CC7.4", "CC7.5",
        "CC8.1", "CC8.2", "CC8.3", "CC8.4", "CC8.5", "CC8.6", "CC8.7", "CC8.8"
      ]
      monitoring_requirements = {
        access_logging      = true
        change_management   = true
        vulnerability_mgmt  = true
        incident_response   = true
        backup_testing     = true
      }
    }
    NIST = {
      controls = [
        "AC-1", "AC-2", "AC-3", "AC-4", "AC-5", "AC-6", "AC-7", "AC-8",
        "AU-1", "AU-2", "AU-3", "AU-4", "AU-5", "AU-6", "AU-7", "AU-8", "AU-9",
        "CA-1", "CA-2", "CA-3", "CA-5", "CA-6", "CA-7", "CA-8", "CA-9",
        "CM-1", "CM-2", "CM-3", "CM-4", "CM-5", "CM-6", "CM-7", "CM-8",
        "CP-1", "CP-2", "CP-3", "CP-4", "CP-6", "CP-7", "CP-8", "CP-9", "CP-10",
        "IA-1", "IA-2", "IA-3", "IA-4", "IA-5", "IA-6", "IA-7", "IA-8",
        "IR-1", "IR-2", "IR-3", "IR-4", "IR-5", "IR-6", "IR-7", "IR-8",
        "MA-1", "MA-2", "MA-3", "MA-4", "MA-5", "MA-6",
        "MP-1", "MP-2", "MP-3", "MP-4", "MP-5", "MP-6", "MP-7",
        "PE-1", "PE-2", "PE-3", "PE-4", "PE-5", "PE-6",
        "PL-1", "PL-2", "PL-4", "PL-7", "PL-8",
        "PS-1", "PS-2", "PS-3", "PS-4", "PS-5", "PS-6", "PS-7", "PS-8",
        "RA-1", "RA-2", "RA-3", "RA-5",
        "SA-1", "SA-2", "SA-3", "SA-4", "SA-5", "SA-8", "SA-9", "SA-10",
        "SC-1", "SC-2", "SC-3", "SC-4", "SC-5", "SC-7", "SC-8", "SC-12", "SC-13",
        "SI-1", "SI-2", "SI-3", "SI-4", "SI-5", "SI-6", "SI-7", "SI-10", "SI-11"
      ]
      monitoring_requirements = {
        continuous_monitoring = true
        risk_assessment      = true
        security_assessment  = true
        incident_handling    = true
        system_monitoring    = true
      }
    }
    CIS = {
      controls = [
        "1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7", "1.8", "1.9", "1.10",
        "2.1", "2.2", "2.3", "2.4", "2.5", "2.6", "2.7", "2.8", "2.9", "2.10",
        "3.1", "3.2", "3.3", "3.4", "3.5", "3.6", "3.7", "3.8", "3.9", "3.10",
        "4.1", "4.2", "4.3", "4.4", "4.5", "4.6", "4.7", "4.8", "4.9", "4.10",
        "5.1", "5.2", "5.3", "5.4", "5.5", "5.6", "5.7", "5.8", "5.9", "5.10",
        "6.1", "6.2", "6.3", "6.4", "6.5", "6.6", "6.7", "6.8", "6.9", "6.10"
      ]
      monitoring_requirements = {
        asset_inventory     = true
        vulnerability_mgmt  = true
        access_control     = true
        secure_config      = true
        logging_monitoring = true
      }
    }
    "PCI-DSS" = {
      controls = [
        "1.1.1", "1.1.2", "1.1.3", "1.1.4", "1.1.5", "1.1.6", "1.1.7",
        "2.1", "2.2", "2.3", "2.4", "2.5", "2.6",
        "3.1", "3.2", "3.3", "3.4", "3.5", "3.6", "3.7",
        "4.1", "4.2", "4.3", "4.4", "4.5", "4.6",
        "5.1", "5.2", "5.3", "5.4", "5.5", "5.6",
        "6.1", "6.2", "6.3", "6.4", "6.5", "6.6", "6.7", "6.8",
        "7.1", "7.2", "7.3", "7.4", "7.5",
        "8.1", "8.2", "8.3", "8.4", "8.5", "8.6", "8.7", "8.8",
        "9.1", "9.2", "9.3", "9.4", "9.5", "9.6", "9.7", "9.8", "9.9", "9.10",
        "10.1", "10.2", "10.3", "10.4", "10.5", "10.6", "10.7", "10.8", "10.9",
        "11.1", "11.2", "11.3", "11.4", "11.5", "11.6",
        "12.1", "12.2", "12.3", "12.4", "12.5", "12.6", "12.7", "12.8", "12.9", "12.10"
      ]
      monitoring_requirements = {
        network_monitoring    = true
        access_control_mgmt  = true
        vulnerability_mgmt   = true
        security_testing     = true
        compliance_monitoring = true
      }
    }
    HIPAA = {
      controls = [
        "164.308(a)(1)", "164.308(a)(2)", "164.308(a)(3)", "164.308(a)(4)",
        "164.308(a)(5)", "164.308(a)(6)", "164.308(a)(7)", "164.308(a)(8)",
        "164.310(a)(1)", "164.310(a)(2)", "164.310(b)", "164.310(c)",
        "164.310(d)(1)", "164.310(d)(2)", "164.312(a)(1)", "164.312(a)(2)",
        "164.312(b)", "164.312(c)(1)", "164.312(c)(2)", "164.312(d)",
        "164.312(e)(1)", "164.312(e)(2)", "164.314(a)(1)", "164.314(a)(2)",
        "164.314(b)(1)", "164.314(b)(2)"
      ]
      monitoring_requirements = {
        access_management   = true
        audit_controls     = true
        integrity          = true
        transmission_security = true
        breach_notification = true
      }
    }
    FedRAMP = {
      controls = [
        "AC-1", "AC-2", "AC-3", "AC-4", "AC-5", "AC-6", "AC-7", "AC-8", "AC-14", "AC-17", "AC-18", "AC-19", "AC-20", "AC-21", "AC-22",
        "AT-1", "AT-2", "AT-3", "AT-4", "AT-5",
        "AU-1", "AU-2", "AU-3", "AU-4", "AU-5", "AU-6", "AU-7", "AU-8", "AU-9", "AU-11", "AU-12",
        "CA-1", "CA-2", "CA-3", "CA-5", "CA-6", "CA-7", "CA-8", "CA-9",
        "CM-1", "CM-2", "CM-3", "CM-4", "CM-5", "CM-6", "CM-7", "CM-8", "CM-9", "CM-10", "CM-11",
        "CP-1", "CP-2", "CP-3", "CP-4", "CP-6", "CP-7", "CP-8", "CP-9", "CP-10",
        "IA-1", "IA-2", "IA-3", "IA-4", "IA-5", "IA-6", "IA-7", "IA-8",
        "IR-1", "IR-2", "IR-3", "IR-4", "IR-5", "IR-6", "IR-7", "IR-8",
        "MA-1", "MA-2", "MA-3", "MA-4", "MA-5", "MA-6",
        "MP-1", "MP-2", "MP-3", "MP-4", "MP-5", "MP-6", "MP-7",
        "PE-1", "PE-2", "PE-3", "PE-4", "PE-5", "PE-6", "PE-8", "PE-9", "PE-10", "PE-11", "PE-12", "PE-13", "PE-14", "PE-15", "PE-16",
        "PL-1", "PL-2", "PL-4", "PL-7", "PL-8",
        "PS-1", "PS-2", "PS-3", "PS-4", "PS-5", "PS-6", "PS-7", "PS-8",
        "RA-1", "RA-2", "RA-3", "RA-5",
        "SA-1", "SA-2", "SA-3", "SA-4", "SA-5", "SA-8", "SA-9", "SA-10", "SA-11", "SA-12", "SA-15", "SA-16", "SA-17",
        "SC-1", "SC-2", "SC-3", "SC-4", "SC-5", "SC-7", "SC-8", "SC-10", "SC-12", "SC-13", "SC-15", "SC-17", "SC-18", "SC-19", "SC-20", "SC-21", "SC-22", "SC-23", "SC-28", "SC-39",
        "SI-1", "SI-2", "SI-3", "SI-4", "SI-5", "SI-6", "SI-7", "SI-10", "SI-11", "SI-12", "SI-16"
      ]
      monitoring_requirements = {
        continuous_monitoring   = true
        security_assessment    = true
        incident_response      = true
        configuration_mgmt     = true
        vulnerability_scanning = true
      }
    }
  }

  # Alert severity mapping
  alert_severity_map = {
    critical = {
      priority = 1
      sla_hours = 1
      escalation_minutes = 15
    }
    high = {
      priority = 2
      sla_hours = 4
      escalation_minutes = 30
    }
    medium = {
      priority = 3
      sla_hours = 24
      escalation_minutes = 60
    }
    low = {
      priority = 4
      sla_hours = 72
      escalation_minutes = 240
    }
  }

  # Compliance score calculation
  total_controls = sum([
    for framework in var.compliance_frameworks :
    length(local.compliance_configs[framework].controls)
  ])

  # Security metrics thresholds
  security_thresholds = {
    failed_logins_per_hour     = 50
    privilege_escalations      = 5
    unauthorized_access_attempts = 10
    data_exfiltration_bytes    = 1000000000 # 1GB
    malware_detections         = 1
    vulnerability_score        = 7.0
    configuration_drift        = 10
    certificate_expiry_days    = 30
  }
}

# Random suffix for unique resource names
resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

# =============================================================================
# AWS COMPLIANCE AND MONITORING (Multi-Cloud Support)
# =============================================================================

# AWS Config for compliance monitoring
resource "aws_config_configuration_recorder" "main" {
  count    = var.enable_aws_monitoring ? 1 : 0
  name     = "${var.name_prefix}-config-recorder"
  role_arn = aws_iam_role.config[0].arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }

  depends_on = [aws_config_delivery_channel.main]
}

resource "aws_config_delivery_channel" "main" {
  count           = var.enable_aws_monitoring ? 1 : 0
  name            = "${var.name_prefix}-config-delivery"
  s3_bucket_name  = aws_s3_bucket.config[0].bucket
  s3_key_prefix   = "config"
  sns_topic_arn   = aws_sns_topic.compliance_alerts[0].arn

  snapshot_delivery_properties {
    delivery_frequency = "TwentyFour_Hours"
  }
}

# S3 bucket for AWS Config
resource "aws_s3_bucket" "config" {
  count  = var.enable_aws_monitoring ? 1 : 0
  bucket = "${var.name_prefix}-config-${random_string.suffix.result}"

  force_destroy = var.environment != "prod"
}

resource "aws_s3_bucket_versioning" "config" {
  count  = var.enable_aws_monitoring ? 1 : 0
  bucket = aws_s3_bucket.config[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "config" {
  count  = var.enable_aws_monitoring ? 1 : 0
  bucket = aws_s3_bucket.config[0].id

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.compliance[0].arn
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "config" {
  count  = var.enable_aws_monitoring ? 1 : 0
  bucket = aws_s3_bucket.config[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# KMS key for compliance data encryption
resource "aws_kms_key" "compliance" {
  count                   = var.enable_aws_monitoring ? 1 : 0
  description             = "KMS key for compliance monitoring data"
  deletion_window_in_days = var.environment == "prod" ? 30 : 7
  enable_key_rotation     = true

  tags = local.common_tags
}

resource "aws_kms_alias" "compliance" {
  count         = var.enable_aws_monitoring ? 1 : 0
  name          = "alias/${var.name_prefix}-compliance"
  target_key_id = aws_kms_key.compliance[0].key_id
}

# IAM role for AWS Config
resource "aws_iam_role" "config" {
  count = var.enable_aws_monitoring ? 1 : 0
  name  = "${var.name_prefix}-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "config" {
  count      = var.enable_aws_monitoring ? 1 : 0
  role       = aws_iam_role.config[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/ConfigRole"
}

# SNS topic for compliance alerts
resource "aws_sns_topic" "compliance_alerts" {
  count = var.enable_aws_monitoring ? 1 : 0
  name  = "${var.name_prefix}-compliance-alerts"

  kms_master_key_id = aws_kms_key.compliance[0].arn

  tags = local.common_tags
}

# CloudWatch Log Groups for centralized logging
resource "aws_cloudwatch_log_group" "compliance" {
  count             = var.enable_aws_monitoring ? 1 : 0
  name              = "/aws/compliance/${var.name_prefix}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.compliance[0].arn

  tags = local.common_tags
}

resource "aws_cloudwatch_log_group" "security_events" {
  count             = var.enable_aws_monitoring ? 1 : 0
  name              = "/aws/security-events/${var.name_prefix}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.compliance[0].arn

  tags = local.common_tags
}

# AWS SecurityHub for centralized security findings
resource "aws_securityhub_account" "main" {
  count                    = var.enable_aws_monitoring ? 1 : 0
  enable_default_standards = true
}

# GuardDuty for threat detection
resource "aws_guardduty_detector" "main" {
  count  = var.enable_aws_monitoring ? 1 : 0
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  tags = local.common_tags
}

# =============================================================================
# AZURE COMPLIANCE AND MONITORING
# =============================================================================

# Azure Policy for compliance
resource "azurerm_policy_set_definition" "compliance" {
  count                 = var.enable_azure_monitoring ? 1 : 0
  name                  = "${var.name_prefix}-compliance-policy"
  policy_type           = "Custom"
  display_name          = "${var.name_prefix} Compliance Policy Set"
  description           = "Policy set for ${join(", ", var.compliance_frameworks)} compliance"
  management_group_id   = var.azure_management_group_id

  # Example policies for each compliance framework
  policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/404c3081-a854-4457-ae30-26a93ef643f9"
    parameter_values = jsonencode({
      requiredRetentionDays = {
        value = var.log_retention_days
      }
    })
  }

  policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/013e242c-8828-4970-87b3-ab247555486d"
  }

  policy_definition_reference {
    policy_definition_id = "/providers/Microsoft.Authorization/policyDefinitions/1f314764-cb73-4fc9-b863-8eca98ac36e9"
  }

  metadata = jsonencode({
    category = "Compliance"
    frameworks = var.compliance_frameworks
  })
}

# Azure Monitor Action Group
resource "azurerm_monitor_action_group" "compliance_alerts" {
  count               = var.enable_azure_monitoring ? 1 : 0
  name                = "${var.name_prefix}-compliance-alerts"
  resource_group_name = var.azure_resource_group_name
  short_name          = substr("${var.name_prefix}-comp", 0, 12)

  dynamic "email_receiver" {
    for_each = var.alert_email_addresses
    content {
      name          = "email-${email_receiver.key}"
      email_address = email_receiver.value
    }
  }

  dynamic "webhook_receiver" {
    for_each = var.webhook_endpoints
    content {
      name        = "webhook-${webhook_receiver.key}"
      service_uri = webhook_receiver.value
    }
  }

  tags = local.common_tags
}

# Azure Security Center assessments
resource "azurerm_security_center_subscription_pricing" "main" {
  count         = var.enable_azure_monitoring ? 1 : 0
  tier          = "Standard"
  resource_type = "VirtualMachines"
}

resource "azurerm_security_center_subscription_pricing" "storage" {
  count         = var.enable_azure_monitoring ? 1 : 0
  tier          = "Standard"
  resource_type = "StorageAccounts"
}

resource "azurerm_security_center_subscription_pricing" "sql" {
  count         = var.enable_azure_monitoring ? 1 : 0
  tier          = "Standard"
  resource_type = "SqlServers"
}

# =============================================================================
# GOOGLE CLOUD COMPLIANCE AND MONITORING
# =============================================================================

# Cloud Security Command Center for GCP
resource "google_security_center_notification_config" "compliance_notifications" {
  count           = var.enable_gcp_monitoring ? 1 : 0
  config_id       = "${var.name_prefix}-compliance-notifications"
  organization    = var.gcp_organization_id
  description     = "Compliance and security notifications"
  pubsub_topic    = google_pubsub_topic.compliance_alerts[0].id
  streaming_config {
    filter = "state=\"ACTIVE\" AND category=\"COMPLIANCE\""
  }
}

resource "google_pubsub_topic" "compliance_alerts" {
  count   = var.enable_gcp_monitoring ? 1 : 0
  name    = "${var.name_prefix}-compliance-alerts"
  project = var.gcp_project_id

  message_retention_duration = "604800s" # 7 days

  kms_key_name = var.enable_kms_encryption ? google_kms_crypto_key.compliance[0].id : null
}

resource "google_kms_crypto_key" "compliance" {
  count           = var.enable_gcp_monitoring && var.enable_kms_encryption ? 1 : 0
  name            = "${var.name_prefix}-compliance-key"
  key_ring        = google_kms_key_ring.compliance[0].id
  rotation_period = "2592000s" # 30 days

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_key_ring" "compliance" {
  count    = var.enable_gcp_monitoring && var.enable_kms_encryption ? 1 : 0
  name     = "${var.name_prefix}-compliance-keyring"
  location = var.gcp_region
  project  = var.gcp_project_id
}

# Cloud Asset Inventory for compliance tracking
resource "google_cloud_asset_organization_feed" "compliance_feed" {
  count            = var.enable_gcp_monitoring ? 1 : 0
  billing_project  = var.gcp_project_id
  org_id          = var.gcp_organization_id
  feed_id         = "${var.name_prefix}-compliance-feed"
  content_type    = "RESOURCE"

  asset_types = [
    "compute.googleapis.com/Instance",
    "storage.googleapis.com/Bucket",
    "container.googleapis.com/Cluster",
    "sqladmin.googleapis.com/Instance"
  ]

  feed_output_config {
    pubsub_destination {
      topic = google_pubsub_topic.compliance_alerts[0].id
    }
  }

  condition {
    expression = "!temporal_asset.deleted && temporal_asset.asset.iam_policy.bindings.exists(b, b.role.startsWith('roles/owner') || b.role.startsWith('roles/editor'))"
    title      = "High privilege access changes"
    description = "Monitor changes to high privilege access"
  }
}

# =============================================================================
# COMPLIANCE RULES ENGINE
# =============================================================================

# AWS Config Rules for compliance frameworks
resource "aws_config_config_rule" "compliance_rules" {
  for_each = var.enable_aws_monitoring ? {
    # SOC2 Controls
    "soc2-encrypted-volumes" = {
      name        = "${var.name_prefix}-soc2-encrypted-volumes"
      source_identifier = "ENCRYPTED_VOLUMES"
      description = "SOC2 CC6.1 - Check if EBS volumes are encrypted"
    }
    "soc2-mfa-enabled" = {
      name        = "${var.name_prefix}-soc2-mfa-enabled"
      source_identifier = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
      description = "SOC2 CC6.1 - Check if MFA is enabled for console access"
    }

    # NIST Controls
    "nist-access-logging" = {
      name        = "${var.name_prefix}-nist-access-logging"
      source_identifier = "CLOUDTRAIL_ENABLED"
      description = "NIST AU-2 - Check if CloudTrail is enabled"
    }
    "nist-network-acls" = {
      name        = "${var.name_prefix}-nist-network-acls"
      source_identifier = "NACL_NO_UNRESTRICTED_SSH_RDP"
      description = "NIST AC-4 - Check network ACLs for unrestricted access"
    }

    # CIS Controls
    "cis-security-groups" = {
      name        = "${var.name_prefix}-cis-security-groups"
      source_identifier = "INCOMING_SSH_DISABLED"
      description = "CIS 4.1 - Ensure no security groups allow ingress from 0.0.0.0/0 to port 22"
    }
    "cis-s3-encryption" = {
      name        = "${var.name_prefix}-cis-s3-encryption"
      source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
      description = "CIS 2.1.1 - Ensure S3 bucket is encrypted"
    }

    # PCI-DSS Controls
    "pci-database-encryption" = {
      name        = "${var.name_prefix}-pci-database-encryption"
      source_identifier = "RDS_STORAGE_ENCRYPTED"
      description = "PCI-DSS 3.4 - Check if RDS instances are encrypted"
    }
    "pci-network-logging" = {
      name        = "${var.name_prefix}-pci-network-logging"
      source_identifier = "VPC_FLOW_LOGS_ENABLED"
      description = "PCI-DSS 10.5 - Check if VPC Flow Logs are enabled"
    }
  } : {}

  name = each.value.name

  source {
    owner             = "AWS"
    source_identifier = each.value.source_identifier
  }

  description = each.value.description

  depends_on = [aws_config_configuration_recorder.main]

  tags = merge(local.common_tags, {
    ComplianceRule = "true"
    Framework     = split("-", each.key)[0]
  })
}

# =============================================================================
# SECURITY METRICS AND DASHBOARDS
# =============================================================================

# CloudWatch Dashboard for compliance metrics
resource "aws_cloudwatch_dashboard" "compliance" {
  count          = var.enable_aws_monitoring ? 1 : 0
  dashboard_name = "${var.name_prefix}-compliance-dashboard"

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
            ["AWS/Config", "ComplianceByConfigRule", "RuleName", "soc2-encrypted-volumes"],
            [".", ".", ".", "soc2-mfa-enabled"],
            [".", ".", ".", "nist-access-logging"],
            [".", ".", ".", "cis-security-groups"]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "Compliance Rule Status"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/GuardDuty", "FindingCount", "DetectorId", aws_guardduty_detector.main[0].id]
          ]
          view    = "timeSeries"
          stacked = false
          region  = var.aws_region
          title   = "Security Findings"
          period  = 300
        }
      }
    ]
  })
}

# =============================================================================
# AUTOMATED REMEDIATION
# =============================================================================

# Lambda function for automated remediation
resource "aws_lambda_function" "compliance_remediation" {
  count            = var.enable_aws_monitoring && var.enable_auto_remediation ? 1 : 0
  filename         = "compliance_remediation.zip"
  function_name    = "${var.name_prefix}-compliance-remediation"
  role            = aws_iam_role.lambda_remediation[0].arn
  handler         = "index.handler"
  source_code_hash = data.archive_file.lambda_zip[0].output_base64sha256
  runtime         = "python3.9"
  timeout         = 300

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.compliance_alerts[0].arn
      DRY_RUN      = var.remediation_dry_run ? "true" : "false"
    }
  }

  tags = local.common_tags
}

data "archive_file" "lambda_zip" {
  count       = var.enable_aws_monitoring && var.enable_auto_remediation ? 1 : 0
  type        = "zip"
  output_path = "compliance_remediation.zip"
  source {
    content = templatefile("${path.module}/templates/remediation_lambda.py", {
      frameworks = var.compliance_frameworks
    })
    filename = "index.py"
  }
}

resource "aws_iam_role" "lambda_remediation" {
  count = var.enable_aws_monitoring && var.enable_auto_remediation ? 1 : 0
  name  = "${var.name_prefix}-lambda-remediation-role"

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

resource "aws_iam_role_policy" "lambda_remediation" {
  count = var.enable_aws_monitoring && var.enable_auto_remediation ? 1 : 0
  name  = "${var.name_prefix}-lambda-remediation-policy"
  role  = aws_iam_role.lambda_remediation[0].id

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
          "config:PutEvaluations",
          "config:GetResourceConfigHistory",
          "ec2:*",
          "s3:*",
          "rds:*",
          "iam:*",
          "sns:Publish"
        ]
        Resource = "*"
      }
    ]
  })
}

# EventBridge rule for compliance violations
resource "aws_cloudwatch_event_rule" "compliance_violations" {
  count       = var.enable_aws_monitoring ? 1 : 0
  name        = "${var.name_prefix}-compliance-violations"
  description = "Trigger on compliance violations"

  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      messageType      = ["ComplianceChangeNotification"]
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })

  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "compliance_lambda" {
  count     = var.enable_aws_monitoring && var.enable_auto_remediation ? 1 : 0
  rule      = aws_cloudwatch_event_rule.compliance_violations[0].name
  target_id = "ComplianceRemediationTarget"
  arn       = aws_lambda_function.compliance_remediation[0].arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  count         = var.enable_aws_monitoring && var.enable_auto_remediation ? 1 : 0
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.compliance_remediation[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.compliance_violations[0].arn
}

# =============================================================================
# THREAT INTELLIGENCE INTEGRATION
# =============================================================================

# Integration with external threat intelligence feeds
resource "aws_cloudwatch_log_stream" "threat_intel" {
  count          = var.enable_aws_monitoring && var.enable_threat_intelligence ? 1 : 0
  name           = "${var.name_prefix}-threat-intel"
  log_group_name = aws_cloudwatch_log_group.security_events[0].name
}

# =============================================================================
# COMPLIANCE REPORTING
# =============================================================================

# S3 bucket for compliance reports
resource "aws_s3_bucket" "compliance_reports" {
  count  = var.enable_aws_monitoring ? 1 : 0
  bucket = "${var.name_prefix}-compliance-reports-${random_string.suffix.result}"

  force_destroy = var.environment != "prod"
}

resource "aws_s3_bucket_versioning" "compliance_reports" {
  count  = var.enable_aws_monitoring ? 1 : 0
  bucket = aws_s3_bucket.compliance_reports[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "compliance_reports" {
  count  = var.enable_aws_monitoring ? 1 : 0
  bucket = aws_s3_bucket.compliance_reports[0].id

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.compliance[0].arn
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

# Lambda function for generating compliance reports
resource "aws_lambda_function" "compliance_reporting" {
  count            = var.enable_aws_monitoring ? 1 : 0
  filename         = "compliance_reporting.zip"
  function_name    = "${var.name_prefix}-compliance-reporting"
  role            = aws_iam_role.lambda_reporting[0].arn
  handler         = "index.handler"
  source_code_hash = data.archive_file.reporting_lambda_zip[0].output_base64sha256
  runtime         = "python3.9"
  timeout         = 900

  environment {
    variables = {
      BUCKET_NAME       = aws_s3_bucket.compliance_reports[0].bucket
      FRAMEWORKS       = jsonencode(var.compliance_frameworks)
      REPORT_FREQUENCY = var.compliance_report_frequency
    }
  }

  tags = local.common_tags
}

data "archive_file" "reporting_lambda_zip" {
  count       = var.enable_aws_monitoring ? 1 : 0
  type        = "zip"
  output_path = "compliance_reporting.zip"
  source {
    content = templatefile("${path.module}/templates/reporting_lambda.py", {
      frameworks = var.compliance_frameworks
      controls   = local.compliance_configs
    })
    filename = "index.py"
  }
}

resource "aws_iam_role" "lambda_reporting" {
  count = var.enable_aws_monitoring ? 1 : 0
  name  = "${var.name_prefix}-lambda-reporting-role"

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

resource "aws_iam_role_policy" "lambda_reporting" {
  count = var.enable_aws_monitoring ? 1 : 0
  name  = "${var.name_prefix}-lambda-reporting-policy"
  role  = aws_iam_role.lambda_reporting[0].id

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
          "config:GetComplianceDetailsByConfigRule",
          "config:GetComplianceSummaryByConfigRule",
          "config:DescribeConfigRules",
          "s3:PutObject",
          "s3:GetObject",
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })
}

# Schedule compliance reports
resource "aws_cloudwatch_event_rule" "compliance_reporting" {
  count               = var.enable_aws_monitoring ? 1 : 0
  name                = "${var.name_prefix}-compliance-reporting"
  description         = "Schedule compliance reporting"
  schedule_expression = var.compliance_report_schedule

  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "compliance_reporting" {
  count     = var.enable_aws_monitoring ? 1 : 0
  rule      = aws_cloudwatch_event_rule.compliance_reporting[0].name
  target_id = "ComplianceReportingTarget"
  arn       = aws_lambda_function.compliance_reporting[0].arn
}

resource "aws_lambda_permission" "allow_eventbridge_reporting" {
  count         = var.enable_aws_monitoring ? 1 : 0
  statement_id  = "AllowExecutionFromEventBridgeReporting"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.compliance_reporting[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.compliance_reporting[0].arn
}