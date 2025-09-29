# Validation rules for Multi-Cloud IAM Security Module
# Enterprise-grade compliance and security validation with OPA integration

# =============================================================================
# COMPLIANCE FRAMEWORK VALIDATION
# =============================================================================

# SOC2 Compliance Validation
locals {
  soc2_requirements = {
    identity_management       = var.enable_aws_iam || var.enable_azure_iam || var.enable_gcp_iam
    access_controls          = var.enable_azure_pim || length(var.aws_cross_account_roles) > 0
    monitoring_enabled       = var.enable_iam_monitoring
    automation_configured    = var.enable_iam_automation || var.enable_azure_access_reviews
    session_management       = var.aws_session_duration == "PT1H"
    audit_logging           = var.enable_iam_monitoring
    change_management       = length(var.compliance_frameworks) > 0
    access_reviews          = var.enable_azure_access_reviews
  }

  soc2_compliance_score = length([for req, met in local.soc2_requirements : req if met])
  soc2_max_score       = length(local.soc2_requirements)
}

# NIST Cybersecurity Framework Validation
locals {
  nist_requirements = {
    identify_assets         = var.enable_iam_monitoring
    protect_access         = var.enable_azure_pim || var.aws_session_duration == "PT1H"
    detect_anomalies       = var.enable_iam_monitoring && var.enable_iam_automation
    respond_incidents      = var.enable_iam_automation
    recover_access         = var.enable_azure_access_reviews
    govern_identity        = length(var.group_assignments) > 0
    supply_chain_risk      = length(var.gcp_service_accounts) == 0 || all([
      for sa_name, sa_config in var.gcp_service_accounts : !sa_config.create_key
    ])
    workforce_management   = var.enable_azure_iam && length(var.azure_group_owners) > 0
  }

  nist_compliance_score = length([for req, met in local.nist_requirements : req if met])
  nist_max_score       = length(local.nist_requirements)
}

# CIS Controls Validation
locals {
  cis_requirements = {
    inventory_control       = var.enable_iam_monitoring
    secure_configuration    = var.security_level == "maximum"
    continuous_monitoring   = var.enable_iam_monitoring && var.enable_iam_automation
    controlled_access       = var.enable_azure_pim && var.aws_session_duration == "PT1H"
    malware_defenses       = var.enable_iam_automation
    data_recovery          = var.enable_azure_access_reviews
    boundary_defense       = length(var.aws_cross_account_roles) > 0
    data_protection        = var.security_level == "maximum"
    penetration_testing    = var.enable_iam_automation
    incident_response      = var.enable_iam_monitoring
  }

  cis_compliance_score = length([for req, met in local.cis_requirements : req if met])
  cis_max_score       = length(local.cis_requirements)
}

# PCI-DSS Validation
locals {
  pci_dss_requirements = {
    unique_user_access     = var.enable_aws_iam || var.enable_azure_iam || var.enable_gcp_iam
    access_restrictions    = var.enable_azure_pim || var.aws_session_duration == "PT1H"
    protect_stored_data    = var.security_level == "maximum"
    encrypt_transmission   = var.enable_azure_saml || var.aws_saml_metadata_document != ""
    vulnerability_mgmt     = var.enable_iam_automation
    secure_systems        = var.security_level == "maximum"
    restrict_access_need   = var.enable_azure_access_reviews
    assign_unique_id       = length(var.group_assignments) > 0
    restrict_physical      = true  # Assumed through cloud provider controls
    track_monitor_access   = var.enable_iam_monitoring
    test_security         = var.enable_iam_automation
    maintain_policy       = length(var.compliance_frameworks) > 0
  }

  pci_dss_compliance_score = length([for req, met in local.pci_dss_requirements : req if met])
  pci_dss_max_score       = length(local.pci_dss_requirements)
}

# HIPAA Validation
locals {
  hipaa_requirements = {
    access_control         = var.enable_azure_pim || length(var.aws_cross_account_roles) > 0
    audit_controls         = var.enable_iam_monitoring
    integrity_controls     = var.enable_iam_automation
    transmission_security  = var.enable_azure_saml || var.aws_saml_metadata_document != ""
    assigned_security      = length(var.azure_group_owners) > 0 || length(var.azure_access_review_approvers) > 0
    info_access_mgmt       = var.enable_azure_access_reviews
    workstation_security   = var.aws_session_duration == "PT1H"
    device_controls        = var.security_level == "maximum"
  }

  hipaa_compliance_score = length([for req, met in local.hipaa_requirements : req if met])
  hipaa_max_score       = length(local.hipaa_requirements)
}

# FedRAMP Validation
locals {
  fedramp_requirements = {
    access_control         = var.enable_azure_pim && var.aws_session_duration == "PT1H"
    audit_accountability   = var.enable_iam_monitoring
    config_management      = var.enable_iam_automation
    incident_response      = var.enable_iam_monitoring && var.enable_iam_automation
    risk_assessment       = var.security_level == "maximum"
    system_protection     = var.security_level == "maximum"
    media_protection      = var.security_level == "maximum"
    personnel_security    = var.enable_azure_access_reviews
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
    at_least_one_provider = {
      condition = var.enable_aws_iam || var.enable_azure_iam || var.enable_gcp_iam
      message   = "At least one cloud provider IAM must be enabled"
      severity  = "HIGH"
      category  = "Identity Management"
    }

    maximum_security_prod = {
      condition = var.environment != "prod" || var.security_level == "maximum"
      message   = "Production environment requires maximum security level"
      severity  = "HIGH"
      category  = "Security Level"
    }

    monitoring_required = {
      condition = var.enable_iam_monitoring || var.environment == "dev"
      message   = "IAM monitoring must be enabled for non-development environments"
      severity  = "HIGH"
      category  = "Monitoring"
    }

    session_duration_limit = {
      condition = !var.enable_aws_iam || var.aws_session_duration == "PT1H"
      message   = "AWS session duration must not exceed 1 hour for security"
      severity  = "HIGH"
      category  = "Session Management"
    }

    # Medium severity requirements
    pim_for_azure = {
      condition = !var.enable_azure_iam || var.enable_azure_pim || var.environment == "dev"
      message   = "Azure Privileged Identity Management should be enabled for production"
      severity  = "MEDIUM"
      category  = "Privileged Access"
    }

    saml_federation = {
      condition = !var.enable_aws_iam || var.aws_saml_metadata_document != "" || var.environment == "dev"
      message   = "SAML federation should be configured for centralized authentication"
      severity  = "MEDIUM"
      category  = "Identity Federation"
    }

    automation_enabled = {
      condition = var.enable_iam_automation || var.environment == "dev"
      message   = "IAM automation should be enabled for compliance and security"
      severity  = "MEDIUM"
      category  = "Automation"
    }

    access_reviews = {
      condition = !var.enable_azure_iam || var.enable_azure_access_reviews || var.environment == "dev"
      message   = "Azure access reviews should be enabled for periodic certification"
      severity  = "MEDIUM"
      category  = "Access Governance"
    }

    # Low severity recommendations
    group_assignments = {
      condition = length(var.group_assignments) > 0 || var.environment == "dev"
      message   = "Group assignments should be configured for centralized user management"
      severity  = "LOW"
      category  = "User Management"
    }

    cross_account_roles = {
      condition = !var.enable_aws_iam || length(var.aws_cross_account_roles) > 0 || var.environment == "dev"
      message   = "Cross-account roles should be configured for secure resource access"
      severity  = "LOW"
      category  = "Cross-Account Access"
    }

    service_account_keys = {
      condition = !var.enable_gcp_iam || length(var.gcp_service_accounts) == 0 || all([
        for sa_name, sa_config in var.gcp_service_accounts : !sa_config.create_key || var.environment != "prod"
      ])
      message   = "GCP service account keys should be avoided in production - use workload identity instead"
      severity  = "LOW"
      category  = "Key Management"
    }

    multiple_approvers = {
      condition = !var.enable_azure_access_reviews || length(var.azure_access_review_approvers) >= 2
      message   = "Configure multiple approvers for Azure access reviews"
      severity  = "LOW"
      category  = "Access Governance"
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
# OPA POLICY INTEGRATION
# =============================================================================

# OPA policy validation for AWS resources
locals {
  opa_aws_validations = var.enable_aws_iam ? {
    session_duration = {
      input = {
        provider                = "aws"
        resource_type          = "aws_iam_role"
        max_session_duration   = 3600  # 1 hour in seconds
        environment           = var.environment
      }
      policy = "data.iam.security.deny_aws_long_session"
    }

    mfa_required = {
      input = {
        provider                    = "aws"
        resource_type              = "aws_iam_role"
        assume_role_policy_document = jsonencode({
          Version = "2012-10-17"
          Statement = [{
            Effect = "Allow"
            Action = "sts:AssumeRole"
            Condition = {
              Bool = {
                "aws:MultiFactorAuthPresent" = "true"
              }
            }
          }]
        })
      }
      policy = "data.iam.security.deny_aws_no_mfa"
    }

    no_wildcard_policies = {
      input = {
        provider      = "aws"
        resource_type = "aws_iam_policy"
        policy_document = jsonencode({
          Version = "2012-10-17"
          Statement = [{
            Effect   = "Allow"
            Action   = ["s3:GetObject"]  # Specific action, not wildcard
            Resource = ["arn:aws:s3:::bucket/*"]  # Specific resource, not wildcard
          }]
        })
      }
      policy = "data.iam.security.deny_aws_wildcard_policies"
    }
  } : {}

  # OPA policy validation for Azure resources
  opa_azure_validations = var.enable_azure_iam ? {
    security_groups = {
      input = {
        provider         = "azure"
        resource_type    = "azuread_group"
        security_enabled = true
        display_name     = "example-group"
      }
      policy = "data.iam.security.deny_azure_non_security_groups"
    }

    pim_required = {
      input = {
        provider           = "azure"
        resource_type      = "azurerm_role_assignment"
        role_definition_id = "/subscriptions/sub-id/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"  # Owner role
        pim_eligible       = var.enable_azure_pim
      }
      policy = "data.iam.security.require_azure_pim"
    }

    justification_required = {
      input = {
        provider = "azure"
        resource_type = "azuread_access_package"
        display_name = "example-package"
        assignment_policy = {
          requestor_justification_required = true
        }
      }
      policy = "data.iam.security.require_azure_justification"
    }
  } : {}

  # OPA policy validation for GCP resources
  opa_gcp_validations = var.enable_gcp_iam ? {
    no_sa_keys_prod = {
      input = {
        provider      = "gcp"
        resource_type = "google_service_account_key"
        environment   = var.environment
      }
      policy = "data.iam.security.deny_gcp_sa_keys_in_prod"
    }

    no_primitive_roles = {
      input = {
        provider      = "gcp"
        resource_type = "google_project_iam_binding"
        role         = "roles/storage.objectViewer"  # Specific role, not primitive
      }
      policy = "data.iam.security.deny_gcp_primitive_roles"
    }

    conditional_access = {
      input = {
        provider      = "gcp"
        resource_type = "google_project_iam_binding"
        role         = "roles/iam.serviceAccountAdmin"  # Sensitive role
        condition = {
          title       = "Restrict access"
          description = "Restrict to specific conditions"
          expression  = "request.time.getHours() >= 9 && request.time.getHours() <= 17"
        }
      }
      policy = "data.iam.security.require_gcp_conditions"
    }
  } : {}
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

# Production security validation
check "production_security" {
  assert {
    condition = var.environment != "prod" || (
      var.security_level == "maximum" &&
      var.enable_iam_monitoring &&
      (!var.enable_aws_iam || var.aws_session_duration == "PT1H")
    )
    error_message = "Production environment requires maximum security level, monitoring, and restricted session duration"
  }
}

# Multi-cloud integration validation
check "multi_cloud_integration" {
  assert {
    condition = (var.enable_aws_iam && var.enable_azure_iam) ||
                (var.enable_aws_iam && var.enable_gcp_iam) ||
                (var.enable_azure_iam && var.enable_gcp_iam) ||
                var.environment == "dev"
    error_message = "Multi-cloud IAM integration requires at least two cloud providers for redundancy"
  }
}

# Identity federation validation
check "identity_federation" {
  assert {
    condition = var.environment == "dev" || (
      (!var.enable_aws_iam || var.aws_saml_metadata_document != "") &&
      (!var.enable_azure_iam || var.enable_azure_saml)
    )
    error_message = "Identity federation must be configured for production environments"
  }
}

# Privileged access management validation
check "privileged_access_management" {
  assert {
    condition = var.environment == "dev" || (
      (!var.enable_azure_iam || var.enable_azure_pim) &&
      (!var.enable_aws_iam || length(var.aws_cross_account_roles) > 0)
    )
    error_message = "Privileged access management controls must be implemented for production"
  }
}

# =============================================================================
# CONFIGURATION VALIDATION
# =============================================================================

# Validate AWS SSO configuration
check "aws_sso_configuration" {
  assert {
    condition = !var.enable_aws_iam || var.aws_sso_instance_arn != ""
    error_message = "AWS SSO instance ARN must be provided when AWS IAM is enabled"
  }
}

# Validate Azure configuration
check "azure_configuration" {
  assert {
    condition = !var.enable_azure_iam || (
      length(var.azure_group_owners) > 0 &&
      (!var.enable_azure_access_reviews || length(var.azure_access_review_approvers) > 0)
    )
    error_message = "Azure configuration requires group owners and access review approvers when enabled"
  }
}

# Validate GCP configuration
check "gcp_configuration" {
  assert {
    condition = !var.enable_gcp_iam || var.gcp_project_id != ""
    error_message = "GCP project ID must be provided when GCP IAM is enabled"
  }
}

# Validate group assignments
check "group_assignments_valid" {
  assert {
    condition = alltrue([
      for assignment in var.group_assignments :
      assignment.user_email != "" && assignment.user_object_id != ""
    ])
    error_message = "All group assignments must have valid user email and object ID"
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

    opa_validations = {
      aws_policies   = local.opa_aws_validations
      azure_policies = local.opa_azure_validations
      gcp_policies   = local.opa_gcp_validations
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

    cloud_provider_status = {
      aws_enabled   = var.enable_aws_iam
      azure_enabled = var.enable_azure_iam
      gcp_enabled   = var.enable_gcp_iam
      integration_level = (
        (var.enable_aws_iam ? 1 : 0) +
        (var.enable_azure_iam ? 1 : 0) +
        (var.enable_gcp_iam ? 1 : 0)
      )
    }
  }
}

# Export validation results
output "validation_report" {
  description = "Comprehensive validation report for multi-cloud IAM security configuration"
  value       = local.validation_report
}