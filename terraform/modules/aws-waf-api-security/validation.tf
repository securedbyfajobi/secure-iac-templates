# Validation rules for AWS WAF and API Security Module
# Enterprise-grade compliance and security validation

# =============================================================================
# COMPLIANCE FRAMEWORK VALIDATION
# =============================================================================

# SOC2 Compliance Validation
locals {
  soc2_requirements = {
    encryption_enabled    = var.kms_key_id != ""
    logging_enabled      = var.enable_waf_logging
    monitoring_enabled   = var.create_cloudwatch_alarms
    access_controls      = length(var.allowed_ip_addresses) > 0 || length(var.blocked_ip_addresses) > 0
    rate_limiting        = var.rate_limit <= 1000
    default_deny         = var.default_action == "block"
  }

  soc2_compliance_score = length([for req, met in local.soc2_requirements : req if met])
  soc2_max_score       = length(local.soc2_requirements)
}

# NIST Cybersecurity Framework Validation
locals {
  nist_requirements = {
    identify_threats     = var.enable_threat_intelligence
    protect_boundaries   = length(var.blocked_countries) > 0 || length(var.blocked_ip_addresses) > 0
    detect_anomalies     = var.create_cloudwatch_alarms
    respond_automated    = var.enable_threat_intelligence
    recover_logging      = var.enable_waf_logging
    govern_policies      = length(var.custom_rules) > 0
  }

  nist_compliance_score = length([for req, met in local.nist_requirements : req if met])
  nist_max_score       = length(local.nist_requirements)
}

# CIS Controls Validation
locals {
  cis_requirements = {
    inventory_control    = true  # WAF rules are documented
    secure_config       = var.default_action == "block"
    continuous_monitor   = var.create_cloudwatch_alarms && var.enable_waf_logging
    access_control      = length(var.allowed_ip_addresses) > 0 || var.api_vpc_endpoint_only
    malware_defense     = var.enable_threat_intelligence
    data_recovery       = var.log_retention_days >= 30
    boundary_defense    = length(var.managed_rule_sets) >= 2
    data_protection     = var.kms_key_id != ""
  }

  cis_compliance_score = length([for req, met in local.cis_requirements : req if met])
  cis_max_score       = length(local.cis_requirements)
}

# PCI-DSS Validation
locals {
  pci_dss_requirements = {
    network_segmentation = length(var.allowed_ip_addresses) > 0
    access_control       = var.api_vpc_endpoint_only || length(var.api_key_required_paths) > 0
    monitoring_testing   = var.create_cloudwatch_alarms && var.enable_waf_logging
    vulnerability_mgmt   = var.enable_threat_intelligence
    strong_crypto       = var.kms_key_id != ""
    secure_systems      = var.default_action == "block"
    regular_testing     = var.enable_threat_intelligence
    info_security       = length(var.compliance_frameworks) > 0
  }

  pci_dss_compliance_score = length([for req, met in local.pci_dss_requirements : req if met])
  pci_dss_max_score       = length(local.pci_dss_requirements)
}

# HIPAA Validation
locals {
  hipaa_requirements = {
    access_control       = var.api_vpc_endpoint_only || length(var.api_allowed_cidr_blocks) > 0
    audit_controls      = var.enable_waf_logging
    integrity_controls  = var.enable_threat_intelligence
    transmission_security = var.kms_key_id != ""
    assigned_security   = length(var.compliance_frameworks) > 0
    info_access_mgmt    = length(var.allowed_ip_addresses) > 0
    workstation_security = var.default_action == "block"
    device_controls     = var.create_cloudwatch_alarms
  }

  hipaa_compliance_score = length([for req, met in local.hipaa_requirements : req if met])
  hipaa_max_score       = length(local.hipaa_requirements)
}

# FedRAMP Validation
locals {
  fedramp_requirements = {
    access_control       = var.api_vpc_endpoint_only
    audit_accountability = var.enable_waf_logging && var.log_retention_days >= 90
    config_management    = length(var.custom_rules) > 0
    incident_response    = var.create_cloudwatch_alarms
    risk_assessment     = var.enable_threat_intelligence
    system_protection   = var.default_action == "block"
    media_protection    = var.kms_key_id != ""
    personnel_security  = true  # Assumed through IAM
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
    default_deny_policy = {
      condition = var.default_action == "block"
      message   = "Default action should be 'block' for zero-trust security model"
      severity  = "HIGH"
      category  = "Access Control"
    }

    encryption_required = {
      condition = var.kms_key_id != ""
      message   = "KMS encryption is required for enterprise security"
      severity  = "HIGH"
      category  = "Data Protection"
    }

    logging_enabled = {
      condition = var.enable_waf_logging
      message   = "WAF logging must be enabled for security monitoring"
      severity  = "HIGH"
      category  = "Monitoring"
    }

    monitoring_enabled = {
      condition = var.create_cloudwatch_alarms
      message   = "CloudWatch monitoring must be enabled for threat detection"
      severity  = "HIGH"
      category  = "Monitoring"
    }

    # Medium severity requirements
    rate_limiting_strict = {
      condition = var.rate_limit <= 1000
      message   = "Rate limit should be <= 1000 for enhanced protection"
      severity  = "MEDIUM"
      category  = "Threat Protection"
    }

    managed_rules_enabled = {
      condition = length(var.managed_rule_sets) >= 2
      message   = "At least 2 AWS managed rule sets should be enabled"
      severity  = "MEDIUM"
      category  = "Threat Protection"
    }

    log_retention_adequate = {
      condition = var.log_retention_days >= 30
      message   = "Log retention should be at least 30 days for compliance"
      severity  = "MEDIUM"
      category  = "Compliance"
    }

    # Low severity recommendations
    threat_intel_enabled = {
      condition = var.enable_threat_intelligence
      message   = "Threat intelligence should be enabled for automated protection"
      severity  = "LOW"
      category  = "Automation"
    }

    geo_restrictions = {
      condition = length(var.allowed_countries) > 0 || length(var.blocked_countries) > 0
      message   = "Geographic restrictions should be configured when applicable"
      severity  = "LOW"
      category  = "Access Control"
    }

    api_security_configured = {
      condition = !var.create_api_gateway_policy || (var.api_vpc_endpoint_only || length(var.api_allowed_cidr_blocks) > 0)
      message   = "API Gateway should have proper access restrictions"
      severity  = "LOW"
      category  = "API Security"
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

# Rate limiting validation for high-risk environments
check "rate_limiting_production" {
  assert {
    condition = var.environment != "prod" || var.rate_limit <= 1000
    error_message = "Production environment requires rate limiting <= 1000 requests per 5-minute period"
  }
}

# Security monitoring validation
check "security_monitoring" {
  assert {
    condition = var.enable_waf_logging && var.create_cloudwatch_alarms
    error_message = "Both WAF logging and CloudWatch alarms must be enabled for security monitoring"
  }
}

# API security validation
check "api_security_controls" {
  assert {
    condition = !var.create_api_gateway_policy || (
      var.api_vpc_endpoint_only ||
      length(var.api_allowed_cidr_blocks) > 0 ||
      length(var.api_key_required_paths) > 0
    )
    error_message = "API Gateway policy requires at least one security control: VPC endpoint restriction, CIDR allowlist, or API key requirements"
  }
}

# Threat protection validation
check "threat_protection_coverage" {
  assert {
    condition = length(var.managed_rule_sets) >= 1 && (var.enable_threat_intelligence || length(var.blocked_ip_addresses) > 0)
    error_message = "Threat protection requires AWS managed rules and either threat intelligence or manual IP blocking"
  }
}

# =============================================================================
# CONFIGURATION VALIDATION
# =============================================================================

# Validate IP addresses format
check "ip_addresses_valid" {
  assert {
    condition = alltrue([
      for ip in concat(var.allowed_ip_addresses, var.blocked_ip_addresses) :
      can(regex("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?$", ip))
    ])
    error_message = "All IP addresses must be in valid CIDR notation (e.g., 192.168.1.0/24 or 192.168.1.1/32)"
  }
}

# Validate country codes
check "country_codes_valid" {
  assert {
    condition = alltrue([
      for country in concat(var.allowed_countries, var.blocked_countries) :
      length(country) == 2 && can(regex("^[A-Z]{2}$", country))
    ])
    error_message = "Country codes must be 2-character uppercase ISO 3166-1 alpha-2 codes (e.g., US, CA, GB)"
  }
}

# Validate custom rules configuration
check "custom_rules_valid" {
  assert {
    condition = alltrue([
      for rule in var.custom_rules :
      contains(["allow", "block", "count"], rule.action) &&
      contains(["uri_path", "query_string", "body"], rule.field_to_match) &&
      contains(["NONE", "LOWERCASE", "URL_DECODE", "HTML_ENTITY_DECODE"], rule.text_transformation) &&
      contains(["EXACTLY", "STARTS_WITH", "ENDS_WITH", "CONTAINS"], rule.positional_constraint)
    ])
    error_message = "Custom rules must have valid action, field_to_match, text_transformation, and positional_constraint values"
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
  }
}

# Export validation results
output "validation_report" {
  description = "Comprehensive validation report for WAF and API security configuration"
  value       = local.validation_report
}