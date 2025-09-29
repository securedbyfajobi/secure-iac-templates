# Outputs for Multi-Cloud IAM Security Module

# =============================================================================
# AWS IAM OUTPUTS
# =============================================================================

output "aws_permission_sets" {
  description = "AWS SSO permission sets"
  value = var.enable_aws_iam ? {
    for name, ps in aws_ssoadmin_permission_set.this :
    name => {
      arn          = ps.arn
      name         = ps.name
      description  = ps.description
      session_duration = ps.session_duration
    }
  } : {}
}

output "aws_cross_account_roles" {
  description = "AWS cross-account IAM roles"
  value = var.enable_aws_iam ? {
    for name, role in aws_iam_role.cross_account :
    name => {
      arn                  = role.arn
      name                 = role.name
      max_session_duration = role.max_session_duration
    }
  } : {}
}

output "aws_saml_provider_arn" {
  description = "AWS SAML identity provider ARN"
  value       = var.enable_aws_iam && length(aws_iam_saml_identity_provider.this) > 0 ? aws_iam_saml_identity_provider.this[0].arn : null
}

output "aws_cloudtrail_arn" {
  description = "AWS CloudTrail ARN for IAM auditing"
  value       = var.enable_aws_iam && length(aws_cloudtrail.iam_audit) > 0 ? aws_cloudtrail.iam_audit[0].arn : null
}

# =============================================================================
# AZURE IAM OUTPUTS
# =============================================================================

output "azure_ad_groups" {
  description = "Azure AD groups"
  value = var.enable_azure_iam ? {
    for name, group in azuread_group.this :
    name => {
      object_id    = group.object_id
      display_name = group.display_name
      description  = group.description
    }
  } : {}
}

output "azure_custom_roles" {
  description = "Azure custom role definitions"
  value = var.enable_azure_iam ? {
    for name, role in azurerm_role_definition.custom :
    name => {
      id          = role.id
      name        = role.name
      description = role.description
      scope       = role.scope
    }
  } : {}
}

output "azure_saml_application" {
  description = "Azure SAML application details"
  value = var.enable_azure_iam && length(azuread_application.saml) > 0 ? {
    application_id = azuread_application.saml[0].application_id
    object_id     = azuread_application.saml[0].object_id
    display_name  = azuread_application.saml[0].display_name
  } : null
}

output "azure_access_packages" {
  description = "Azure AD access packages"
  value = var.enable_azure_iam && var.enable_azure_access_reviews ? {
    for name, package in azuread_access_package.this :
    name => {
      id           = package.id
      display_name = package.display_name
      description  = package.description
    }
  } : {}
}

# =============================================================================
# GCP IAM OUTPUTS
# =============================================================================

output "gcp_custom_roles" {
  description = "GCP custom roles"
  value = var.enable_gcp_iam ? {
    for name, role in google_project_iam_custom_role.this :
    name => {
      id          = role.id
      role_id     = role.role_id
      title       = role.title
      description = role.description
    }
  } : {}
}

output "gcp_service_accounts" {
  description = "GCP service accounts"
  value = var.enable_gcp_iam ? {
    for name, sa in google_service_account.cross_cloud :
    name => {
      id           = sa.id
      email        = sa.email
      unique_id    = sa.unique_id
      display_name = sa.display_name
    }
  } : {}
  sensitive = true
}

output "gcp_service_account_keys" {
  description = "GCP service account keys"
  value = var.enable_gcp_iam ? {
    for name, key in google_service_account_key.cross_cloud :
    name => {
      id               = key.id
      name             = key.name
      key_algorithm    = key.key_algorithm
      public_key       = key.public_key
    }
  } : {}
  sensitive = true
}

output "gcp_audit_log_sink" {
  description = "GCP audit log sink"
  value = var.enable_gcp_iam && length(google_logging_project_sink.iam_audit) > 0 ? {
    id          = google_logging_project_sink.iam_audit[0].id
    name        = google_logging_project_sink.iam_audit[0].name
    destination = google_logging_project_sink.iam_audit[0].destination
  } : null
}

# =============================================================================
# SECURITY ASSESSMENT OUTPUTS
# =============================================================================

output "security_score" {
  description = "Overall IAM security score (0-100)"
  value       = local.total_security_score
}

output "security_score_breakdown" {
  description = "Breakdown of security score by category"
  value = {
    identity_federation = local.identity_federation_score
    access_control     = local.access_control_score
    monitoring         = local.monitoring_score
    compliance         = local.compliance_score
    automation         = local.automation_score
    key_management     = local.key_management_score
    total             = local.total_security_score
  }
}

output "compliance_status" {
  description = "Compliance status for each framework"
  value = {
    for framework in var.compliance_frameworks :
    framework => {
      enabled = contains(var.compliance_frameworks, framework)
      score   = contains(var.compliance_frameworks, framework) ? 5 : 0
    }
  }
}

# =============================================================================
# CONFIGURATION SUMMARY
# =============================================================================

output "iam_configuration_summary" {
  description = "Summary of IAM configuration across cloud providers"
  value = {
    aws_enabled    = var.enable_aws_iam
    azure_enabled  = var.enable_azure_iam
    gcp_enabled    = var.enable_gcp_iam
    security_level = var.security_level

    aws_features = var.enable_aws_iam ? {
      sso_configured           = var.aws_sso_instance_arn != ""
      saml_configured         = var.aws_saml_metadata_document != ""
      cross_account_roles     = length(var.aws_cross_account_roles)
      cloudtrail_enabled      = var.enable_iam_monitoring
      automation_enabled      = var.enable_iam_automation
    } : null

    azure_features = var.enable_azure_iam ? {
      groups_configured       = length(local.standard_roles)
      custom_roles           = length(var.azure_custom_roles)
      pim_enabled            = var.enable_azure_pim
      saml_configured        = var.enable_azure_saml
      access_reviews_enabled = var.enable_azure_access_reviews
    } : null

    gcp_features = var.enable_gcp_iam ? {
      custom_roles          = length(var.gcp_custom_roles)
      service_accounts      = length(var.gcp_service_accounts)
      iam_bindings         = length(var.gcp_iam_bindings)
      audit_logging        = var.enable_iam_monitoring
    } : null

    compliance_frameworks = var.compliance_frameworks
    group_assignments    = length(var.group_assignments)
  }
}

# =============================================================================
# CROSS-CLOUD INTEGRATION
# =============================================================================

output "cross_cloud_integration" {
  description = "Cross-cloud integration capabilities"
  value = {
    identity_federation = {
      aws_saml_enabled   = var.aws_saml_metadata_document != ""
      azure_saml_enabled = var.enable_azure_saml
      gcp_service_accounts = length(var.gcp_service_accounts)
    }

    centralized_monitoring = {
      aws_cloudtrail    = var.enable_aws_iam && var.enable_iam_monitoring
      azure_activity_log = var.enable_azure_iam && var.enable_iam_monitoring
      gcp_audit_logs    = var.enable_gcp_iam && var.enable_iam_monitoring
    }

    automation_capabilities = {
      aws_lambda_automation = var.enable_aws_iam && var.enable_iam_automation
      azure_access_reviews  = var.enable_azure_iam && var.enable_azure_access_reviews
      gcp_service_accounts  = var.enable_gcp_iam && length(var.gcp_service_accounts) > 0
    }
  }
}

# =============================================================================
# OPERATIONAL INFORMATION
# =============================================================================

output "operational_guidance" {
  description = "Operational guidance for IAM management"
  value = {
    aws_operations = var.enable_aws_iam ? {
      sso_instance_arn     = var.aws_sso_instance_arn
      session_duration     = var.aws_session_duration
      permission_sets_count = length(local.standard_roles)
      next_steps = [
        "Configure user assignments in AWS SSO console",
        "Set up MFA requirements for privileged access",
        "Review and test cross-account role assumptions",
        "Configure CloudTrail log analysis and alerting"
      ]
    } : null

    azure_operations = var.enable_azure_iam ? {
      groups_created       = length(local.standard_roles)
      pim_enabled         = var.enable_azure_pim
      access_reviews      = var.enable_azure_access_reviews
      next_steps = [
        "Assign users to appropriate Azure AD groups",
        "Configure Conditional Access policies",
        "Set up PIM activation workflows if enabled",
        "Configure access review schedules and approvers"
      ]
    } : null

    gcp_operations = var.enable_gcp_iam ? {
      project_id          = var.gcp_project_id
      custom_roles_count  = length(var.gcp_custom_roles)
      service_accounts    = length(var.gcp_service_accounts)
      next_steps = [
        "Configure Google Workspace integration",
        "Set up Organization policies",
        "Configure service account key rotation",
        "Set up audit log monitoring and alerting"
      ]
    } : null

    general_recommendations = [
      "Implement principle of least privilege across all platforms",
      "Enable MFA for all privileged accounts",
      "Regular access reviews and certifications",
      "Monitor cross-cloud authentication patterns",
      "Implement break-glass procedures for emergency access"
    ]
  }
}

# =============================================================================
# COST OPTIMIZATION
# =============================================================================

output "estimated_monthly_cost" {
  description = "Estimated monthly cost in USD (approximate)"
  value = {
    aws_costs = var.enable_aws_iam ? {
      sso_cost           = "Free (included in AWS account)"
      cloudtrail_cost    = var.enable_iam_monitoring ? "~$2.00 per 100,000 events" : 0
      lambda_cost        = var.enable_iam_automation ? "~$0.20 per 1M requests" : 0
    } : null

    azure_costs = var.enable_azure_iam ? {
      azure_ad_free      = "Free tier available"
      azure_ad_premium   = var.enable_azure_pim ? "~$6 per user per month" : 0
      activity_log_cost  = var.enable_iam_monitoring ? "~$2.76 per GB" : 0
    } : null

    gcp_costs = var.enable_gcp_iam ? {
      iam_cost          = "Free (included in GCP project)"
      audit_log_cost    = var.enable_iam_monitoring ? "~$0.50 per GB" : 0
      service_account   = "Free for basic usage"
    } : null

    total_estimated = "Variable based on usage and premium features enabled"
    optimization_tips = [
      "Use Azure AD Free tier when premium features not required",
      "Optimize CloudTrail data events to reduce costs",
      "Use service account keys sparingly in GCP",
      "Implement log retention policies to manage storage costs"
    ]
  }
}

# =============================================================================
# SECURITY RECOMMENDATIONS
# =============================================================================

output "security_recommendations" {
  description = "Security improvement recommendations"
  value = {
    high_priority = compact([
      local.total_security_score < 80 ? "IAM security score below enterprise threshold (80). Review and enhance configurations." : "",
      var.security_level != "maximum" && var.environment == "prod" ? "Consider upgrading to maximum security level for production." : "",
      !var.enable_iam_monitoring ? "Enable IAM monitoring across all cloud providers for security visibility." : "",
      var.aws_session_duration == "PT12H" ? "Reduce AWS session duration to maximum 1 hour for enhanced security." : ""
    ])

    medium_priority = compact([
      !var.enable_azure_pim && var.enable_azure_iam ? "Enable Azure Privileged Identity Management for just-in-time access." : "",
      !var.enable_iam_automation ? "Enable IAM automation for consistent policy enforcement." : "",
      length(var.azure_access_review_approvers) < 2 ? "Configure multiple approvers for Azure access reviews." : "",
      var.aws_saml_metadata_document == "" && var.enable_aws_iam ? "Configure SAML federation for centralized authentication." : ""
    ])

    low_priority = compact([
      !var.enable_azure_access_reviews ? "Enable Azure AD access reviews for periodic access certification." : "",
      length(var.gcp_service_accounts) == 0 && var.enable_gcp_iam ? "Consider creating service accounts for cross-cloud integration." : "",
      length(var.group_assignments) == 0 ? "Configure group assignments for centralized user management." : "",
      length(var.compliance_frameworks) < 3 ? "Consider additional compliance frameworks for comprehensive coverage." : ""
    ])
  }
}

# =============================================================================
# COMPLIANCE REPORTING
# =============================================================================

output "compliance_report" {
  description = "Detailed compliance status report"
  value = {
    overall_score = local.total_security_score
    security_level = var.security_level

    framework_compliance = {
      for framework in ["SOC2", "NIST", "CIS", "PCI-DSS", "HIPAA", "FedRAMP"] :
      framework => {
        required = contains(var.compliance_frameworks, framework)
        implemented = contains(var.compliance_frameworks, framework)
        score = contains(var.compliance_frameworks, framework) ? 5 : 0

        requirements = framework == "SOC2" ? {
          access_controls = var.enable_azure_pim || length(var.aws_cross_account_roles) > 0
          monitoring = var.enable_iam_monitoring
          documentation = true
        } : framework == "NIST" ? {
          identity_management = var.enable_aws_iam || var.enable_azure_iam || var.enable_gcp_iam
          access_control = length(var.azure_custom_roles) > 0 || length(var.gcp_custom_roles) > 0
          audit_logging = var.enable_iam_monitoring
        } : framework == "PCI-DSS" ? {
          unique_user_ids = true
          access_restrictions = var.enable_azure_pim || var.aws_session_duration == "PT1H"
          monitoring = var.enable_iam_monitoring
        } : {}
      }
    }

    remediation_plan = {
      immediate_actions = [
        for framework in var.compliance_frameworks :
        "Ensure ${framework} requirements are fully implemented and documented"
      ]
      quarterly_reviews = [
        "Conduct access certification reviews",
        "Review and update custom role definitions",
        "Validate cross-cloud integration security"
      ]
      annual_assessments = [
        "Third-party security assessment",
        "Compliance framework gap analysis",
        "Business continuity testing for IAM systems"
      ]
    }
  }
}