# Validation rules for Azure Enterprise Database Security Module
# Enterprise-grade compliance and security validation

# =============================================================================
# COMPLIANCE FRAMEWORK VALIDATION
# =============================================================================

# SOC2 Compliance Validation
locals {
  soc2_requirements = {
    audit_enabled                = var.enable_log_analytics
    threat_detection_enabled     = var.create_sql_server ? true : var.create_cosmos_db
    vulnerability_assessment     = var.enable_vulnerability_assessment
    transparent_data_encryption  = var.create_sql_server
    private_endpoint_required    = var.enable_private_endpoint
    backup_retention_adequate    = local.max_backup_retention >= 35
    key_management               = var.customer_managed_key_id != ""
    access_control_enabled       = var.azuread_admin_object_id != ""
  }

  soc2_compliance_score = length([for req, met in local.soc2_requirements : req if met])
  soc2_max_score       = length(local.soc2_requirements)
}

# NIST Cybersecurity Framework Validation
locals {
  nist_requirements = {
    identify_assets             = var.enable_log_analytics
    protect_data               = var.customer_managed_key_id != "" && var.enable_private_endpoint
    detect_events              = var.enable_vulnerability_assessment
    respond_incidents          = length(var.security_alert_email_addresses) > 0
    recover_operations         = local.max_backup_retention >= 90
    govern_risk_management     = length(var.compliance_frameworks) > 0
    supply_chain_security      = var.enable_purge_protection
    workforce_security         = var.azuread_admin_object_id != ""
  }

  nist_compliance_score = length([for req, met in local.nist_requirements : req if met])
  nist_max_score       = length(local.nist_requirements)
}

# CIS Controls Validation
locals {
  cis_requirements = {
    inventory_control          = var.enable_log_analytics
    secure_configuration       = var.enable_private_endpoint && var.customer_managed_key_id != ""
    continuous_monitoring      = var.enable_vulnerability_assessment && var.enable_log_analytics
    controlled_access          = var.azuread_admin_object_id != "" && var.enable_private_endpoint
    malware_defenses          = var.enable_vulnerability_assessment
    data_recovery             = local.max_backup_retention >= 30
    boundary_defense          = var.enable_private_endpoint
    data_protection           = var.customer_managed_key_id != ""
  }

  cis_compliance_score = length([for req, met in local.cis_requirements : req if met])
  cis_max_score       = length(local.cis_requirements)
}

# PCI-DSS Validation
locals {
  pci_dss_requirements = {
    network_segmentation       = var.enable_private_endpoint
    strong_access_control      = var.azuread_admin_object_id != "" && length(var.allowed_ip_ranges) > 0
    protect_cardholder_data    = var.customer_managed_key_id != ""
    encrypt_transmission       = var.enable_private_endpoint
    vulnerability_management   = var.enable_vulnerability_assessment
    monitoring_testing         = var.enable_log_analytics
    maintain_policy           = length(var.compliance_frameworks) > 0
    regular_testing           = var.enable_vulnerability_assessment
  }

  pci_dss_compliance_score = length([for req, met in local.pci_dss_requirements : req if met])
  pci_dss_max_score       = length(local.pci_dss_requirements)
}

# HIPAA Validation
locals {
  hipaa_requirements = {
    access_control            = var.azuread_admin_object_id != "" && var.enable_private_endpoint
    audit_controls           = var.enable_log_analytics && var.audit_retention_days >= 90
    integrity_controls       = var.enable_vulnerability_assessment
    transmission_security    = var.enable_private_endpoint && var.customer_managed_key_id != ""
    assigned_security        = length(var.security_alert_email_addresses) > 0
    info_access_management   = var.enable_private_endpoint && length(var.allowed_ip_ranges) > 0
    workstation_security     = var.enable_private_endpoint
    device_controls          = var.enable_purge_protection
  }

  hipaa_compliance_score = length([for req, met in local.hipaa_requirements : req if met])
  hipaa_max_score       = length(local.hipaa_requirements)
}

# ISO27001 Validation
locals {
  iso27001_requirements = {
    information_security_policies = length(var.compliance_frameworks) > 0
    organization_security         = var.azuread_admin_object_id != ""
    human_resource_security       = var.azuread_admin_object_id != ""
    asset_management             = var.enable_log_analytics
    access_control               = var.enable_private_endpoint && var.azuread_admin_object_id != ""
    cryptography                 = var.customer_managed_key_id != ""
    physical_security            = var.enable_private_endpoint
    operations_security          = var.enable_vulnerability_assessment
    communications_security      = var.enable_private_endpoint
    acquisition_development      = var.enable_log_analytics
    supplier_relationships       = var.enable_purge_protection
    incident_management          = length(var.security_alert_email_addresses) > 0
    business_continuity          = local.max_backup_retention >= 90
    compliance                   = var.enable_log_analytics && var.audit_retention_days >= 90
  }

  iso27001_compliance_score = length([for req, met in local.iso27001_requirements : req if met])
  iso27001_max_score       = length(local.iso27001_requirements)
}

# =============================================================================
# SECURITY VALIDATION RULES
# =============================================================================

# Enterprise Security Requirements
locals {
  security_validations = {
    # High severity requirements
    private_endpoints_required = {
      condition = var.enable_private_endpoint || var.environment != "prod"
      message   = "Private endpoints are required for production environments"
      severity  = "HIGH"
      category  = "Network Security"
    }

    encryption_required = {
      condition = var.customer_managed_key_id != "" || var.data_classification != "restricted"
      message   = "Customer-managed encryption keys are required for restricted data"
      severity  = "HIGH"
      category  = "Data Protection"
    }

    monitoring_enabled = {
      condition = var.enable_log_analytics
      message   = "Log Analytics monitoring must be enabled for enterprise security"
      severity  = "HIGH"
      category  = "Monitoring"
    }

    vulnerability_assessment_enabled = {
      condition = var.enable_vulnerability_assessment || !var.create_sql_server
      message   = "Vulnerability assessment must be enabled for SQL Server"
      severity  = "HIGH"
      category  = "Security Assessment"
    }

    # Medium severity requirements
    aad_admin_configured = {
      condition = var.azuread_admin_object_id != "" || !var.create_sql_server
      message   = "Azure AD administrator should be configured for SQL Server"
      severity  = "MEDIUM"
      category  = "Access Control"
    }

    backup_retention_adequate = {
      condition = local.max_backup_retention >= 30
      message   = "Backup retention should be at least 30 days for enterprise environments"
      severity  = "MEDIUM"
      category  = "Data Protection"
    }

    purge_protection_enabled = {
      condition = var.enable_purge_protection || var.environment != "prod"
      message   = "Purge protection should be enabled in production environments"
      severity  = "MEDIUM"
      category  = "Data Protection"
    }

    security_alerts_configured = {
      condition = length(var.security_alert_email_addresses) > 0 || var.environment == "dev"
      message   = "Security alert email addresses should be configured"
      severity  = "MEDIUM"
      category  = "Incident Response"
    }

    # Low severity recommendations
    geo_redundancy_enabled = {
      condition = !var.create_cosmos_db || length(var.cosmos_geo_locations) > 1 || var.environment == "dev"
      message   = "Geographic redundancy should be enabled for Cosmos DB in production"
      severity  = "LOW"
      category  = "Availability"
    }

    continuous_backup = {
      condition = !var.create_cosmos_db || var.cosmos_backup_type == "Continuous" || var.environment == "dev"
      message   = "Continuous backup should be enabled for Cosmos DB in production"
      severity  = "LOW"
      category  = "Data Protection"
    }

    network_restrictions = {
      condition = var.enable_private_endpoint || length(var.allowed_ip_ranges) > 0 || var.environment == "dev"
      message   = "Network access restrictions should be configured"
      severity  = "LOW"
      category  = "Network Security"
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
    SOC2     = contains(var.compliance_frameworks, "SOC2") ? (local.soc2_compliance_score / local.soc2_max_score) * 100 : 0
    NIST     = contains(var.compliance_frameworks, "NIST") ? (local.nist_compliance_score / local.nist_max_score) * 100 : 0
    CIS      = contains(var.compliance_frameworks, "CIS") ? (local.cis_compliance_score / local.cis_max_score) * 100 : 0
    PCI-DSS  = contains(var.compliance_frameworks, "PCI-DSS") ? (local.pci_dss_compliance_score / local.pci_dss_max_score) * 100 : 0
    HIPAA    = contains(var.compliance_frameworks, "HIPAA") ? (local.hipaa_compliance_score / local.hipaa_max_score) * 100 : 0
    ISO27001 = contains(var.compliance_frameworks, "ISO27001") ? (local.iso27001_compliance_score / local.iso27001_max_score) * 100 : 0
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
      var.enable_private_endpoint &&
      var.enable_log_analytics &&
      var.enable_vulnerability_assessment &&
      var.enable_purge_protection
    )
    error_message = "Production environment requires private endpoints, monitoring, vulnerability assessment, and purge protection"
  }
}

# Data classification security validation
check "data_classification_security" {
  assert {
    condition = var.data_classification != "restricted" || (
      var.customer_managed_key_id != "" &&
      var.enable_private_endpoint &&
      var.enable_log_analytics &&
      local.max_backup_retention >= 90
    )
    error_message = "Restricted data classification requires customer-managed encryption, private endpoints, monitoring, and extended backup retention"
  }
}

# SQL Server security validation
check "sql_server_security" {
  assert {
    condition = !var.create_sql_server || (
      var.sql_server_version == "12.0" &&
      var.azuread_admin_object_id != "" &&
      var.enable_vulnerability_assessment
    )
    error_message = "SQL Server requires latest version, Azure AD admin, and vulnerability assessment"
  }
}

# Cosmos DB security validation
check "cosmos_db_security" {
  assert {
    condition = !var.create_cosmos_db || (
      var.cosmos_backup_type == "Continuous" ||
      var.environment == "dev" ||
      length(var.cosmos_geo_locations) > 1
    )
    error_message = "Cosmos DB in production should have continuous backup or geo-redundancy"
  }
}

# Network security validation
check "network_security" {
  assert {
    condition = var.enable_private_endpoint || (
      length(var.allowed_ip_ranges) > 0 &&
      length(var.allowed_subnet_ids) > 0
    )
    error_message = "Database access must be restricted via private endpoints or network ACLs"
  }
}

# =============================================================================
# CONFIGURATION VALIDATION
# =============================================================================

# Validate private endpoint configuration
check "private_endpoint_configuration" {
  assert {
    condition = !var.enable_private_endpoint || (
      var.virtual_network_id != "" &&
      var.private_endpoint_subnet_id != ""
    )
    error_message = "Private endpoints require virtual network ID and subnet ID configuration"
  }
}

# Validate storage account configuration for auditing
check "audit_storage_configuration" {
  assert {
    condition = !var.create_sql_server || var.audit_storage_account == "" || (
      var.audit_storage_account != "" &&
      var.audit_storage_account_key != ""
    )
    error_message = "Audit storage account requires both account name and access key"
  }
}

# Validate vulnerability assessment configuration
check "vulnerability_assessment_configuration" {
  assert {
    condition = !var.enable_vulnerability_assessment || (
      var.vulnerability_assessment_storage_endpoint != "" &&
      var.vulnerability_assessment_storage_key != ""
    )
    error_message = "Vulnerability assessment requires storage endpoint and access key"
  }
}

# Validate compliance framework consistency
check "compliance_framework_consistency" {
  assert {
    condition = length(var.compliance_frameworks) == 0 || alltrue([
      for framework in var.compliance_frameworks :
      contains(["SOC2", "NIST", "CIS", "PCI-DSS", "HIPAA", "ISO27001"], framework)
    ])
    error_message = "All compliance frameworks must be valid and supported"
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
        sql_server        = var.create_sql_server
        managed_instance  = var.create_managed_instance
        cosmos_db        = var.create_cosmos_db
      }
      security_features = {
        private_endpoints        = var.enable_private_endpoint
        customer_managed_keys   = var.customer_managed_key_id != ""
        vulnerability_assessment = var.enable_vulnerability_assessment
        log_analytics           = var.enable_log_analytics
        purge_protection        = var.enable_purge_protection
      }
      compliance_configuration = {
        frameworks_count = length(var.compliance_frameworks)
        data_classification = var.data_classification
        backup_retention = local.max_backup_retention
        audit_retention = var.audit_retention_days
      }
    }
  }
}

# Export validation results
output "validation_report" {
  description = "Comprehensive validation report for Azure database security configuration"
  value       = local.validation_report
}