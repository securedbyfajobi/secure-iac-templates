# Validation rules for GCP Enterprise Database Security Module
# Enterprise-grade compliance and security validation

# =============================================================================
# COMPLIANCE FRAMEWORK VALIDATION
# =============================================================================

# SOC2 Compliance Validation
locals {
  soc2_requirements = {
    audit_enabled              = true  # Audit logs are always enabled in GCP
    private_ip_required        = var.enable_private_ip
    encryption_at_rest        = true  # Always enabled with KMS
    backup_retention_adequate  = local.max_backup_retention >= 35
    point_in_time_recovery    = length(var.sql_instances) == 0 || alltrue([for instance in var.sql_instances : true])  # Always enabled for Cloud SQL
    automated_backups         = true  # Always enabled for Cloud SQL
    monitoring_enabled        = var.enable_monitoring_dashboard
    deletion_protection       = var.deletion_protection
  }

  soc2_compliance_score = length([for req, met in local.soc2_requirements : req if met])
  soc2_max_score       = length(local.soc2_requirements)
}

# NIST Cybersecurity Framework Validation
locals {
  nist_requirements = {
    identify_assets            = var.enable_monitoring_dashboard
    protect_data              = var.enable_private_ip && var.kms_protection_level != ""
    detect_events             = var.enable_alerting && var.enable_security_center
    respond_incidents         = length(var.notification_channels) > 0
    recover_operations        = local.max_backup_retention >= 90 && var.create_export_bucket
    govern_risk_management    = length(var.compliance_frameworks) > 0
    supply_chain_security     = var.deletion_protection
    workforce_security        = var.create_custom_roles
  }

  nist_compliance_score = length([for req, met in local.nist_requirements : req if met])
  nist_max_score       = length(local.nist_requirements)
}

# CIS Controls Validation
locals {
  cis_requirements = {
    inventory_control         = var.enable_monitoring_dashboard
    secure_configuration      = var.enable_private_ip && var.kms_protection_level == "HSM"
    continuous_monitoring     = var.enable_alerting && var.enable_monitoring_dashboard
    controlled_access         = var.create_custom_roles && var.enable_private_ip
    malware_defenses         = var.enable_security_center
    data_recovery            = local.max_backup_retention >= 30 && var.create_export_bucket
    boundary_defense         = var.enable_private_ip && length(var.authorized_networks) == 0
    data_protection          = var.kms_protection_level != ""
  }

  cis_compliance_score = length([for req, met in local.cis_requirements : req if met])
  cis_max_score       = length(local.cis_requirements)
}

# PCI-DSS Validation
locals {
  pci_dss_requirements = {
    network_segmentation      = var.enable_private_ip
    strong_access_control     = var.create_custom_roles && length(var.authorized_networks) == 0
    protect_cardholder_data   = var.kms_protection_level == "HSM"
    encrypt_transmission      = var.enable_private_ip
    vulnerability_management  = var.enable_monitoring_dashboard && var.enable_alerting
    monitoring_testing        = var.enable_security_center && var.enable_alerting
    maintain_policy          = length(var.compliance_frameworks) > 0
    regular_testing          = var.enable_alerting
  }

  pci_dss_compliance_score = length([for req, met in local.pci_dss_requirements : req if met])
  pci_dss_max_score       = length(local.pci_dss_requirements)
}

# HIPAA Validation
locals {
  hipaa_requirements = {
    access_control           = var.create_custom_roles && var.enable_private_ip
    audit_controls          = true  # Audit logs always enabled
    integrity_controls      = var.enable_monitoring_dashboard && var.enable_alerting
    transmission_security   = var.enable_private_ip && var.kms_protection_level != ""
    assigned_security       = length(var.notification_channels) > 0
    info_access_management  = var.enable_private_ip && length(var.authorized_networks) == 0
    workstation_security    = var.enable_private_ip
    device_controls         = var.deletion_protection
  }

  hipaa_compliance_score = length([for req, met in local.hipaa_requirements : req if met])
  hipaa_max_score       = length(local.hipaa_requirements)
}

# FedRAMP Validation
locals {
  fedramp_requirements = {
    access_control          = var.create_custom_roles && var.enable_private_ip
    audit_accountability    = true  # Audit logs always enabled
    config_management       = var.enable_monitoring_dashboard
    incident_response       = var.enable_alerting && length(var.notification_channels) > 0
    risk_assessment        = var.enable_security_center
    system_protection      = var.kms_protection_level == "HSM"
    media_protection       = var.create_export_bucket && var.deletion_protection
    personnel_security     = var.create_custom_roles
  }

  fedramp_compliance_score = length([for req, met in local.fedramp_requirements : req if met])
  fedramp_max_score       = length(local.fedramp_requirements)
}

# =============================================================================
# SECURITY VALIDATION RULES
# =============================================================================

# Enterprise Security Requirements
locals {
  security_validations = {
    # High severity requirements
    private_ip_required = {
      condition = var.enable_private_ip || var.environment != "prod"
      message   = "Private IP is required for production environments"
      severity  = "HIGH"
      category  = "Network Security"
    }

    hsm_encryption_required = {
      condition = var.kms_protection_level == "HSM" || var.data_classification != "restricted"
      message   = "HSM protection is required for restricted data classification"
      severity  = "HIGH"
      category  = "Data Protection"
    }

    monitoring_enabled = {
      condition = var.enable_monitoring_dashboard
      message   = "Monitoring dashboard must be enabled for enterprise security"
      severity  = "HIGH"
      category  = "Monitoring"
    }

    deletion_protection_enabled = {
      condition = var.deletion_protection || var.environment != "prod"
      message   = "Deletion protection must be enabled in production environments"
      severity  = "HIGH"
      category  = "Data Protection"
    }

    # Medium severity requirements
    alerting_configured = {
      condition = var.enable_alerting
      message   = "Alerting policies should be configured for proactive monitoring"
      severity  = "MEDIUM"
      category  = "Monitoring"
    }

    custom_roles_created = {
      condition = var.create_custom_roles
      message   = "Custom IAM roles should be created for principle of least privilege"
      severity  = "MEDIUM"
      category  = "Access Control"
    }

    backup_retention_adequate = {
      condition = local.max_backup_retention >= 30
      message   = "Backup retention should be at least 30 days for enterprise environments"
      severity  = "MEDIUM"
      category  = "Data Protection"
    }

    notification_channels_configured = {
      condition = length(var.notification_channels) > 0 || var.environment == "dev"
      message   = "Notification channels should be configured for alerting"
      severity  = "MEDIUM"
      category  = "Incident Response"
    }

    # Low severity recommendations
    security_center_enabled = {
      condition = var.enable_security_center || var.environment == "dev"
      message   = "Security Command Center should be enabled for threat detection"
      severity  = "LOW"
      category  = "Security Monitoring"
    }

    export_bucket_created = {
      condition = var.create_export_bucket || var.environment == "dev"
      message   = "Export bucket should be created for disaster recovery capabilities"
      severity  = "LOW"
      category  = "Disaster Recovery"
    }

    authorized_networks_removed = {
      condition = !var.enable_private_ip || length(var.authorized_networks) == 0
      message   = "Authorized networks should be removed when using private IP"
      severity  = "LOW"
      category  = "Network Security"
    }

    stable_update_track = {
      condition = var.maintenance_update_track == "stable" || var.environment == "dev"
      message   = "Stable update track should be used for production environments"
      severity  = "LOW"
      category  = "Operational Security"
    }
  }

  # Categorize validation results
  validation_results = {
    for name, validation in local.security_validations :
    name => {
      passed   = validation.condition
      message  = validation.message
      severity = validation.severity
      category = validation.category
    }
  }

  # Count failures by severity
  high_severity_failures   = length([for name, result in local.validation_results : name if !result.passed && result.severity == "HIGH"])
  medium_severity_failures = length([for name, result in local.validation_results : name if !result.passed && result.severity == "MEDIUM"])
  low_severity_failures    = length([for name, result in local.validation_results : name if !result.passed && result.severity == "LOW"])
}

# =============================================================================
# COMPLIANCE SCORE CALCULATION
# =============================================================================

locals {
  # Framework-specific compliance percentages
  compliance_percentages = {
    SOC2    = contains(var.compliance_frameworks, "SOC2") ? (local.soc2_compliance_score / local.soc2_max_score) * 100 : 0
    NIST    = contains(var.compliance_frameworks, "NIST") ? (local.nist_compliance_score / local.nist_max_score) * 100 : 0
    CIS     = contains(var.compliance_frameworks, "CIS") ? (local.cis_compliance_score / local.cis_max_score) * 100 : 0
    PCI-DSS = contains(var.compliance_frameworks, "PCI-DSS") ? (local.pci_dss_compliance_score / local.pci_dss_max_score) * 100 : 0
    HIPAA   = contains(var.compliance_frameworks, "HIPAA") ? (local.hipaa_compliance_score / local.hipaa_max_score) * 100 : 0
    FedRAMP = contains(var.compliance_frameworks, "FedRAMP") ? (local.fedramp_compliance_score / local.fedramp_max_score) * 100 : 0
  }

  # Overall compliance score (average of enabled frameworks)
  enabled_frameworks = [for framework in var.compliance_frameworks : local.compliance_percentages[framework]]
  overall_compliance_score = length(enabled_frameworks) > 0 ? sum(enabled_frameworks) / length(enabled_frameworks) : 0

  # Security posture assessment
  security_posture = local.overall_compliance_score >= 90 ? "EXCELLENT" : (
    local.overall_compliance_score >= 80 ? "GOOD" : (
      local.overall_compliance_score >= 70 ? "FAIR" : "POOR"
    )
  )
}

# =============================================================================
# VALIDATION CHECKS AND ASSERTIONS
# =============================================================================

# Enterprise security validation check
check "enterprise_security_requirements" {
  assert {
    condition = local.high_severity_failures == 0
    error_message = format(
      "Enterprise security requirements not met. High severity failures: %d. Failed checks: %s",
      local.high_severity_failures,
      join(", ", [for name, result in local.validation_results : name if !result.passed && result.severity == "HIGH"])
    )
  }
}

# Compliance threshold validation
check "compliance_threshold" {
  assert {
    condition = local.overall_compliance_score >= 80
    error_message = format(
      "Compliance score (%0.1f%%) below enterprise threshold (80%%). Framework scores: %s",
      local.overall_compliance_score,
      jsonencode(local.compliance_percentages)
    )
  }
}

# Production environment security validation
check "production_security" {
  assert {
    condition = var.environment != "prod" || (
      var.enable_private_ip &&
      var.enable_monitoring_dashboard &&
      var.enable_alerting &&
      var.deletion_protection
    )
    error_message = "Production environment requires private IP, monitoring, alerting, and deletion protection"
  }
}

# Data classification security validation
check "data_classification_security" {
  assert {
    condition = var.data_classification != "restricted" || (
      var.kms_protection_level == "HSM" &&
      var.enable_private_ip &&
      var.enable_monitoring_dashboard &&
      local.max_backup_retention >= 90
    )
    error_message = "Restricted data classification requires HSM encryption, private IP, monitoring, and extended backup retention"
  }
}

# Network security validation
check "network_security" {
  assert {
    condition = var.enable_private_ip || (
      length(var.authorized_networks) > 0 &&
      var.vpc_network_id != ""
    )
    error_message = "Database access must be restricted via private IP or authorized networks"
  }
}

# KMS configuration validation
check "kms_configuration" {
  assert {
    condition = var.kms_rotation_period != "" && can(regex("^[0-9]+s$", var.kms_rotation_period))
    error_message = "KMS rotation period must be specified in seconds format (e.g., 2592000s)"
  }
}

# SQL instances configuration validation
check "sql_instances_configuration" {
  assert {
    condition = length(var.sql_instances) == 0 || alltrue([
      for name, instance in var.sql_instances :
      contains(["MYSQL_5_7", "MYSQL_8_0", "POSTGRES_11", "POSTGRES_12", "POSTGRES_13", "POSTGRES_14", "SQLSERVER_2017_STANDARD", "SQLSERVER_2017_ENTERPRISE", "SQLSERVER_2017_EXPRESS", "SQLSERVER_2017_WEB", "SQLSERVER_2019_STANDARD", "SQLSERVER_2019_ENTERPRISE", "SQLSERVER_2019_EXPRESS", "SQLSERVER_2019_WEB"], instance.database_version)
    ])
    error_message = "All SQL instances must use supported database versions"
  }
}

# Spanner configuration validation
check "spanner_configuration" {
  assert {
    condition = !var.create_spanner_instance || (
      (var.spanner_num_nodes == null) != (var.spanner_processing_units == null)
    )
    error_message = "Spanner instance must specify either num_nodes or processing_units, but not both"
  }
}

# =============================================================================
# CONFIGURATION VALIDATION
# =============================================================================

# Validate VPC network configuration
check "vpc_network_configuration" {
  assert {
    condition = !var.enable_private_ip || var.vpc_network_id != ""
    error_message = "VPC network ID must be specified when private IP is enabled"
  }
}

# Validate backup configuration
check "backup_configuration" {
  assert {
    condition = can(regex("^([01]?[0-9]|2[0-3]):[0-5][0-9]$", var.backup_start_time))
    error_message = "Backup start time must be in HH:MM format"
  }
}

# Validate maintenance window configuration
check "maintenance_window_configuration" {
  assert {
    condition = var.maintenance_window_day >= 1 && var.maintenance_window_day <= 7 &&
                var.maintenance_window_hour >= 0 && var.maintenance_window_hour <= 23
    error_message = "Maintenance window day must be 1-7 and hour must be 0-23"
  }
}

# Validate alert threshold configuration
check "alert_threshold_configuration" {
  assert {
    condition = var.cpu_alert_threshold >= 50 && var.cpu_alert_threshold <= 100 &&
                var.memory_alert_threshold >= 50 && var.memory_alert_threshold <= 100 &&
                var.connections_alert_threshold >= 10 && var.connections_alert_threshold <= 1000
    error_message = "Alert thresholds must be within valid ranges"
  }
}

# =============================================================================
# OUTPUT VALIDATION SUMMARY
# =============================================================================

# Generate validation report
locals {
  validation_report = {
    timestamp = timestamp()
    overall_status = local.high_severity_failures == 0 ? "PASS" : "FAIL"
    security_score = local.total_security_score
    compliance_score = local.overall_compliance_score
    security_posture = local.security_posture

    failures_summary = {
      high_severity   = local.high_severity_failures
      medium_severity = local.medium_severity_failures
      low_severity    = local.low_severity_failures
      total_failures  = local.high_severity_failures + local.medium_severity_failures + local.low_severity_failures
    }

    compliance_summary = {
      for framework in var.compliance_frameworks :
      framework => {
        score      = local.compliance_percentages[framework]
        status     = local.compliance_percentages[framework] >= 80 ? "COMPLIANT" : "NON_COMPLIANT"
        threshold  = 80
      }
    }

    failed_validations = {
      for name, result in local.validation_results :
      name => result if !result.passed
    }

    recommendations = {
      immediate = [
        for name, result in local.validation_results :
        result.message if !result.passed && result.severity == "HIGH"
      ]
      planned = [
        for name, result in local.validation_results :
        result.message if !result.passed && result.severity == "MEDIUM"
      ]
      optional = [
        for name, result in local.validation_results :
        result.message if !result.passed && result.severity == "LOW"
      ]
    }

    configuration_summary = {
      databases_configured = {
        sql_instances_count    = length(var.sql_instances)
        spanner_enabled       = var.create_spanner_instance
        firestore_enabled     = var.create_firestore_database
      }
      security_features = {
        private_ip_enabled    = var.enable_private_ip
        kms_protection_level  = var.kms_protection_level
        deletion_protection   = var.deletion_protection
        monitoring_enabled    = var.enable_monitoring_dashboard
        alerting_enabled      = var.enable_alerting
        security_center       = var.enable_security_center
      }
      compliance_configuration = {
        frameworks_count      = length(var.compliance_frameworks)
        data_classification   = var.data_classification
        backup_retention      = local.max_backup_retention
        export_bucket_enabled = var.create_export_bucket
      }
    }
  }
}

# Export validation results
output "validation_report" {
  description = "Comprehensive validation report for GCP database security configuration"
  value       = local.validation_report
}