# Multi-Cloud IAM Security Module
# Enterprise-grade identity and access management across AWS, Azure, and GCP

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = ">= 2.0"
    }
    google = {
      source  = "hashicorp/google"
      version = ">= 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0"
    }
    time = {
      source  = "hashicorp/time"
      version = ">= 0.9"
    }
  }
}

# =============================================================================
# LOCALS AND DATA SOURCES
# =============================================================================

locals {
  name_prefix = "${var.name_prefix}-${var.environment}"

  # Common tags/labels for all resources
  common_tags = merge(var.common_tags, {
    Environment     = var.environment
    Module          = "multi-cloud-iam-security"
    Compliance      = join(",", var.compliance_frameworks)
    SecurityLevel   = var.security_level
    CreatedBy       = "terraform"
    LastModified    = timestamp()
  })

  # Security score weights
  security_weights = {
    identity_federation    = 25
    access_control        = 20
    monitoring           = 15
    compliance           = 15
    automation           = 15
    key_management       = 10
  }

  # Role definitions for each cloud provider
  standard_roles = {
    admin = {
      description = "Administrative access with full permissions"
      permissions = "admin"
    }
    developer = {
      description = "Developer access with limited administrative permissions"
      permissions = "developer"
    }
    operator = {
      description = "Operations team access for monitoring and maintenance"
      permissions = "operator"
    }
    reader = {
      description = "Read-only access for auditing and compliance"
      permissions = "reader"
    }
    security = {
      description = "Security team access for security operations"
      permissions = "security"
    }
  }

  # Group memberships mapping
  group_assignments = {
    for assignment in var.group_assignments :
    "${assignment.group_name}-${assignment.user_email}" => assignment
  }
}

# Data sources
data "aws_caller_identity" "current" {
  count = var.enable_aws_iam ? 1 : 0
}

data "azurerm_client_config" "current" {
  count = var.enable_azure_iam ? 1 : 0
}

data "google_client_config" "current" {
  count = var.enable_gcp_iam ? 1 : 0
}

# =============================================================================
# AWS IAM CONFIGURATION
# =============================================================================

# AWS IAM Identity Center (SSO) configuration
resource "aws_ssoadmin_permission_set" "this" {
  for_each = var.enable_aws_iam ? local.standard_roles : {}

  name               = "${local.name_prefix}-${each.key}"
  description        = each.value.description
  instance_arn       = var.aws_sso_instance_arn
  session_duration   = var.aws_session_duration
  relay_state        = var.aws_relay_state

  tags = local.common_tags
}

# AWS IAM policies for permission sets
resource "aws_ssoadmin_managed_policy_attachment" "aws_managed" {
  for_each = var.enable_aws_iam ? {
    for combo in flatten([
      for role_name, role_config in local.standard_roles : [
        for policy in var.aws_role_policies[role_config.permissions] : {
          key    = "${role_name}-${policy}"
          role   = role_name
          policy = policy
        }
      ]
    ]) : combo.key => combo
  } : {}

  instance_arn       = var.aws_sso_instance_arn
  managed_policy_arn = each.value.policy
  permission_set_arn = aws_ssoadmin_permission_set.this[each.value.role].arn
}

# AWS custom inline policies
resource "aws_ssoadmin_permission_set_inline_policy" "custom" {
  for_each = var.enable_aws_iam ? var.aws_custom_policies : {}

  instance_arn       = var.aws_sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this[each.key].arn
  inline_policy      = each.value
}

# AWS account assignments
resource "aws_ssoadmin_account_assignment" "this" {
  for_each = var.enable_aws_iam ? {
    for assignment in var.aws_account_assignments :
    "${assignment.permission_set}-${assignment.principal_id}-${assignment.target_id}" => assignment
  } : {}

  instance_arn       = var.aws_sso_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.this[each.value.permission_set].arn
  principal_id       = each.value.principal_id
  principal_type     = each.value.principal_type
  target_id          = each.value.target_id
  target_type        = "AWS_ACCOUNT"
}

# AWS IAM roles for cross-account access
resource "aws_iam_role" "cross_account" {
  for_each = var.enable_aws_iam ? var.aws_cross_account_roles : {}

  name               = "${local.name_prefix}-${each.key}"
  description        = each.value.description
  max_session_duration = each.value.max_session_duration

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = each.value.trusted_entities
        }
        Condition = {
          StringEquals = {
            "sts:ExternalId" = each.value.external_id
          }
          IpAddress = length(each.value.source_ip_conditions) > 0 ? {
            "aws:SourceIp" = each.value.source_ip_conditions
          } : null
          Bool = {
            "aws:MultiFactorAuthPresent" = "true"
          }
        }
      }
    ]
  })

  tags = local.common_tags
}

# Attach policies to cross-account roles
resource "aws_iam_role_policy_attachment" "cross_account" {
  for_each = var.enable_aws_iam ? {
    for combo in flatten([
      for role_name, role_config in var.aws_cross_account_roles : [
        for policy_arn in role_config.policy_arns : {
          key        = "${role_name}-${basename(policy_arn)}"
          role_name  = role_name
          policy_arn = policy_arn
        }
      ]
    ]) : combo.key => combo
  } : {}

  role       = aws_iam_role.cross_account[each.value.role_name].name
  policy_arn = each.value.policy_arn
}

# =============================================================================
# AZURE AD CONFIGURATION
# =============================================================================

# Azure AD groups
resource "azuread_group" "this" {
  for_each = var.enable_azure_iam ? local.standard_roles : {}

  display_name            = "${local.name_prefix}-${each.key}"
  description            = each.value.description
  security_enabled       = true
  assignable_to_role     = true
  prevent_duplicate_names = true

  owners = var.azure_group_owners
}

# Azure AD group memberships
resource "azuread_group_member" "this" {
  for_each = var.enable_azure_iam ? local.group_assignments : {}

  group_object_id  = azuread_group.this[each.value.group_name].object_id
  member_object_id = each.value.user_object_id
}

# Azure custom roles
resource "azurerm_role_definition" "custom" {
  for_each = var.enable_azure_iam ? var.azure_custom_roles : {}

  name        = "${local.name_prefix}-${each.key}"
  scope       = each.value.scope
  description = each.value.description

  permissions {
    actions          = each.value.actions
    not_actions      = each.value.not_actions
    data_actions     = each.value.data_actions
    not_data_actions = each.value.not_data_actions
  }

  assignable_scopes = each.value.assignable_scopes
}

# Azure role assignments
resource "azurerm_role_assignment" "group_assignments" {
  for_each = var.enable_azure_iam ? {
    for assignment in var.azure_role_assignments :
    "${assignment.group_name}-${assignment.role_definition_id}-${assignment.scope}" => assignment
  } : {}

  scope                = each.value.scope
  role_definition_id   = each.value.role_definition_id
  principal_id         = azuread_group.this[each.value.group_name].object_id
  condition           = each.value.condition
  condition_version   = each.value.condition_version
}

# Azure Privileged Identity Management (PIM) eligible assignments
resource "azurerm_pim_eligible_role_assignment" "this" {
  for_each = var.enable_azure_iam && var.enable_azure_pim ? {
    for assignment in var.azure_pim_assignments :
    "${assignment.group_name}-${assignment.role_definition_id}-${assignment.scope}" => assignment
  } : {}

  scope              = each.value.scope
  role_definition_id = each.value.role_definition_id
  principal_id       = azuread_group.this[each.value.group_name].object_id

  schedule {
    start_date_time = each.value.start_date_time
    expiration {
      duration_days = each.value.duration_days
    }
  }

  ticket {
    number = each.value.ticket_number
    system = each.value.ticket_system
  }

  justification = each.value.justification
}

# =============================================================================
# GOOGLE CLOUD IAM CONFIGURATION
# =============================================================================

# GCP custom roles
resource "google_project_iam_custom_role" "this" {
  for_each = var.enable_gcp_iam ? var.gcp_custom_roles : {}

  role_id     = "${replace(local.name_prefix, "-", "_")}_${each.key}"
  title       = "${local.name_prefix}-${each.key}"
  description = each.value.description
  permissions = each.value.permissions
  stage       = each.value.stage
  project     = var.gcp_project_id
}

# GCP IAM bindings for groups
resource "google_project_iam_binding" "group_bindings" {
  for_each = var.enable_gcp_iam ? var.gcp_iam_bindings : {}

  project = var.gcp_project_id
  role    = each.value.role
  members = each.value.members

  dynamic "condition" {
    for_each = each.value.condition != null ? [each.value.condition] : []
    content {
      title       = condition.value.title
      description = condition.value.description
      expression  = condition.value.expression
    }
  }
}

# GCP service accounts for cross-cloud authentication
resource "google_service_account" "cross_cloud" {
  for_each = var.enable_gcp_iam ? var.gcp_service_accounts : {}

  account_id   = "${local.name_prefix}-${each.key}"
  display_name = each.value.display_name
  description  = each.value.description
  project      = var.gcp_project_id
}

# GCP service account keys
resource "google_service_account_key" "cross_cloud" {
  for_each = var.enable_gcp_iam ? {
    for name, sa in var.gcp_service_accounts :
    name => sa if sa.create_key
  } : {}

  service_account_id = google_service_account.cross_cloud[each.key].name
  key_algorithm      = "KEY_ALG_RSA_2048"
}

# GCP IAM bindings for service accounts
resource "google_project_iam_member" "service_account_bindings" {
  for_each = var.enable_gcp_iam ? {
    for combo in flatten([
      for sa_name, sa_config in var.gcp_service_accounts : [
        for role in sa_config.roles : {
          key     = "${sa_name}-${role}"
          sa_name = sa_name
          role    = role
        }
      ]
    ]) : combo.key => combo
  } : {}

  project = var.gcp_project_id
  role    = each.value.role
  member  = "serviceAccount:${google_service_account.cross_cloud[each.value.sa_name].email}"
}

# =============================================================================
# IDENTITY FEDERATION AND SAML
# =============================================================================

# AWS SAML Identity Provider
resource "aws_iam_saml_identity_provider" "this" {
  count = var.enable_aws_iam && var.aws_saml_metadata_document != "" ? 1 : 0

  name                   = "${local.name_prefix}-saml-provider"
  saml_metadata_document = var.aws_saml_metadata_document

  tags = local.common_tags
}

# Azure AD application for SAML
resource "azuread_application" "saml" {
  count = var.enable_azure_iam && var.enable_azure_saml ? 1 : 0

  display_name = "${local.name_prefix}-saml-app"
  description  = "SAML application for cross-cloud identity federation"

  web {
    redirect_uris = var.azure_saml_redirect_uris
  }

  required_resource_access {
    resource_app_id = "00000003-0000-0000-c000-000000000000" # Microsoft Graph

    resource_access {
      id   = "df021288-bdef-4463-88db-98f22de89214" # User.Read.All
      type = "Role"
    }

    resource_access {
      id   = "b4e74841-8e56-480b-be8b-910348b18b4c" # User.ReadWrite.All
      type = "Role"
    }
  }

  owners = var.azure_application_owners
}

# Azure AD application service principal
resource "azuread_service_principal" "saml" {
  count = var.enable_azure_iam && var.enable_azure_saml ? 1 : 0

  application_id               = azuread_application.saml[0].application_id
  app_role_assignment_required = true
  owners                      = var.azure_application_owners

  saml_single_sign_on {
    relay_state = var.azure_saml_relay_state
  }
}

# =============================================================================
# MONITORING AND COMPLIANCE
# =============================================================================

# AWS CloudTrail for IAM monitoring
resource "aws_cloudtrail" "iam_audit" {
  count = var.enable_aws_iam && var.enable_iam_monitoring ? 1 : 0

  name           = "${local.name_prefix}-iam-audit"
  s3_bucket_name = var.aws_cloudtrail_bucket

  event_selector {
    read_write_type                 = "All"
    include_management_events       = true
    exclude_management_event_sources = []

    data_resource {
      type   = "AWS::IAM::Role"
      values = ["*"]
    }

    data_resource {
      type   = "AWS::IAM::User"
      values = ["*"]
    }

    data_resource {
      type   = "AWS::IAM::Policy"
      values = ["*"]
    }
  }

  tags = local.common_tags
}

# Azure Activity Log alerts
resource "azurerm_monitor_activity_log_alert" "iam_changes" {
  count = var.enable_azure_iam && var.enable_iam_monitoring ? 1 : 0

  name                = "${local.name_prefix}-iam-changes"
  resource_group_name = var.azure_resource_group_name
  scopes              = ["/subscriptions/${data.azurerm_client_config.current[0].subscription_id}"]

  criteria {
    category       = "Administrative"
    operation_name = "Microsoft.Authorization/roleAssignments/write"
  }

  criteria {
    category       = "Administrative"
    operation_name = "Microsoft.Authorization/roleDefinitions/write"
  }

  action {
    action_group_id = var.azure_action_group_id
  }

  tags = local.common_tags
}

# GCP audit log sink
resource "google_logging_project_sink" "iam_audit" {
  count = var.enable_gcp_iam && var.enable_iam_monitoring ? 1 : 0

  name        = "${local.name_prefix}-iam-audit"
  destination = "storage.googleapis.com/${var.gcp_audit_bucket}"
  filter      = "protoPayload.serviceName=\"iam.googleapis.com\" OR protoPayload.serviceName=\"cloudresourcemanager.googleapis.com\""

  unique_writer_identity = true
}

# =============================================================================
# ACCESS REVIEWS AND AUTOMATION
# =============================================================================

# Azure AD access reviews
resource "azuread_access_package" "this" {
  for_each = var.enable_azure_iam && var.enable_azure_access_reviews ? local.standard_roles : {}

  display_name = "${local.name_prefix}-${each.key}-access"
  description  = "Access package for ${each.value.description}"
  catalog_id   = var.azure_access_package_catalog_id
  hidden       = false

  assignment_policy {
    display_name = "Assignment policy for ${each.key}"
    description  = "Assignment policy for ${each.value.description}"

    approval_settings {
      approval_required = true
      approval_required_for_extension = true
      requestor_justification_required = true

      approval_stage {
        approval_timeout_in_days = 14
        approver_justification_required = true
        escalation_timeout_in_days = 7

        primary_approver {
          object_id = var.azure_access_review_approvers[0]
        }

        dynamic "escalation_approver" {
          for_each = length(var.azure_access_review_approvers) > 1 ? [var.azure_access_review_approvers[1]] : []
          content {
            object_id = escalation_approver.value
          }
        }
      }
    }

    assignment_review_settings {
      enabled = true
      review_frequency = "quarterly"
      duration_in_days = 30
      review_type = "Self"
      access_review_timeout_behavior = "keepAccess"
      approver_justification_required = true

      reviewer {
        object_id = var.azure_access_review_approvers[0]
      }
    }

    requestor_settings {
      scope_type = "SpecificDirectoryUsers"
      accepted_requestors {
        object_id = var.azure_access_review_requestors[0]
      }
    }
  }
}

# Lambda function for AWS IAM automation
resource "aws_lambda_function" "iam_automation" {
  count = var.enable_aws_iam && var.enable_iam_automation ? 1 : 0

  filename         = data.archive_file.iam_automation[0].output_path
  function_name    = "${local.name_prefix}-iam-automation"
  role            = aws_iam_role.lambda_execution[0].arn
  handler         = "index.handler"
  source_code_hash = data.archive_file.iam_automation[0].output_base64sha256
  runtime         = "python3.9"
  timeout         = 300

  environment {
    variables = {
      SSO_INSTANCE_ARN = var.aws_sso_instance_arn
      ENVIRONMENT      = var.environment
    }
  }

  tags = local.common_tags
}

data "archive_file" "iam_automation" {
  count = var.enable_aws_iam && var.enable_iam_automation ? 1 : 0

  type        = "zip"
  output_path = "/tmp/iam_automation.zip"
  source {
    content = templatefile("${path.module}/templates/iam_automation.py", {
      sso_instance_arn = var.aws_sso_instance_arn
    })
    filename = "index.py"
  }
}

# IAM role for Lambda execution
resource "aws_iam_role" "lambda_execution" {
  count = var.enable_aws_iam && var.enable_iam_automation ? 1 : 0

  name = "${local.name_prefix}-lambda-execution-role"

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

resource "aws_iam_role_policy" "lambda_execution" {
  count = var.enable_aws_iam && var.enable_iam_automation ? 1 : 0

  name = "${local.name_prefix}-lambda-execution-policy"
  role = aws_iam_role.lambda_execution[0].id

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
          "sso-admin:DescribeInstanceAccessControlAttributeConfiguration",
          "sso-admin:DescribePermissionSet",
          "sso-admin:ListAccountAssignments",
          "sso-admin:ListPermissionSets"
        ]
        Resource = "*"
      }
    ]
  })
}

# =============================================================================
# SECURITY ASSESSMENT
# =============================================================================

locals {
  # Identity federation score (0-25)
  identity_federation_score = (
    (var.aws_saml_metadata_document != "" ? 8 : 0) +
    (var.enable_azure_saml ? 8 : 0) +
    (var.enable_gcp_iam && length(var.gcp_service_accounts) > 0 ? 9 : 0)
  )

  # Access control score (0-20)
  access_control_score = (
    (var.enable_azure_pim ? 8 : 0) +
    (length(var.aws_cross_account_roles) > 0 ? 6 : 0) +
    (length(var.azure_custom_roles) > 0 ? 3 : 0) +
    (length(var.gcp_custom_roles) > 0 ? 3 : 0)
  )

  # Monitoring score (0-15)
  monitoring_score = (
    (var.enable_iam_monitoring ? 10 : 0) +
    (var.enable_azure_access_reviews ? 5 : 0)
  )

  # Compliance score (0-15)
  compliance_score = (
    (contains(var.compliance_frameworks, "SOC2") ? 3 : 0) +
    (contains(var.compliance_frameworks, "NIST") ? 3 : 0) +
    (contains(var.compliance_frameworks, "CIS") ? 3 : 0) +
    (contains(var.compliance_frameworks, "PCI-DSS") ? 3 : 0) +
    (contains(var.compliance_frameworks, "HIPAA") ? 3 : 0)
  )

  # Automation score (0-15)
  automation_score = (
    (var.enable_iam_automation ? 8 : 0) +
    (var.enable_azure_access_reviews ? 4 : 0) +
    (length(var.azure_pim_assignments) > 0 ? 3 : 0)
  )

  # Key management score (0-10)
  key_management_score = (
    (length(var.gcp_service_accounts) > 0 ? 5 : 0) +
    (var.aws_session_duration <= 3600 ? 3 : 0) +
    (length(var.azure_access_review_approvers) >= 2 ? 2 : 0)
  )

  # Total security score
  total_security_score = (
    local.identity_federation_score +
    local.access_control_score +
    local.monitoring_score +
    local.compliance_score +
    local.automation_score +
    local.key_management_score
  )
}