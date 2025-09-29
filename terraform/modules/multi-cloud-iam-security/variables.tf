# Variables for Multi-Cloud IAM Security Module

# =============================================================================
# BASIC CONFIGURATION
# =============================================================================

variable "name_prefix" {
  description = "Name prefix for all resources"
  type        = string
  validation {
    condition     = length(var.name_prefix) <= 20 && can(regex("^[a-zA-Z][a-zA-Z0-9-]*$", var.name_prefix))
    error_message = "Name prefix must be <= 20 characters and start with a letter."
  }
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod", "development", "production"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod, development, production."
  }
}

variable "security_level" {
  description = "Security level for IAM configuration"
  type        = string
  default     = "high"
  validation {
    condition     = contains(["standard", "high", "maximum"], var.security_level)
    error_message = "Security level must be one of: standard, high, maximum."
  }
}

# =============================================================================
# COMPLIANCE FRAMEWORKS
# =============================================================================

variable "compliance_frameworks" {
  description = "List of compliance frameworks to adhere to"
  type        = list(string)
  default     = ["SOC2", "NIST"]
  validation {
    condition = alltrue([
      for framework in var.compliance_frameworks :
      contains(["SOC2", "NIST", "CIS", "PCI-DSS", "HIPAA", "FedRAMP"], framework)
    ])
    error_message = "Compliance frameworks must be from: SOC2, NIST, CIS, PCI-DSS, HIPAA, FedRAMP."
  }
}

# =============================================================================
# CLOUD PROVIDER ENABLEMENT
# =============================================================================

variable "enable_aws_iam" {
  description = "Enable AWS IAM configuration"
  type        = bool
  default     = true
}

variable "enable_azure_iam" {
  description = "Enable Azure IAM configuration"
  type        = bool
  default     = true
}

variable "enable_gcp_iam" {
  description = "Enable GCP IAM configuration"
  type        = bool
  default     = true
}

# =============================================================================
# AWS IAM CONFIGURATION
# =============================================================================

variable "aws_sso_instance_arn" {
  description = "AWS SSO instance ARN"
  type        = string
  default     = ""
}

variable "aws_session_duration" {
  description = "Session duration for AWS IAM roles (in ISO 8601 format)"
  type        = string
  default     = "PT1H"
  validation {
    condition     = can(regex("^PT[1-9][0-9]*[HM]$", var.aws_session_duration))
    error_message = "Session duration must be in ISO 8601 format (e.g., PT1H, PT30M)."
  }
}

variable "aws_relay_state" {
  description = "Relay state URL for AWS SSO"
  type        = string
  default     = ""
}

variable "aws_role_policies" {
  description = "AWS managed policies for each role type"
  type = map(list(string))
  default = {
    admin = [
      "arn:aws:iam::aws:policy/AdministratorAccess"
    ]
    developer = [
      "arn:aws:iam::aws:policy/PowerUserAccess",
      "arn:aws:iam::aws:policy/IAMReadOnlyAccess"
    ]
    operator = [
      "arn:aws:iam::aws:policy/ReadOnlyAccess",
      "arn:aws:iam::aws:policy/job-function/SystemAdministrator"
    ]
    reader = [
      "arn:aws:iam::aws:policy/ReadOnlyAccess"
    ]
    security = [
      "arn:aws:iam::aws:policy/SecurityAudit",
      "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess"
    ]
  }
}

variable "aws_custom_policies" {
  description = "Custom inline policies for AWS permission sets"
  type        = map(string)
  default     = {}
}

variable "aws_account_assignments" {
  description = "AWS SSO account assignments"
  type = list(object({
    permission_set  = string
    principal_id    = string
    principal_type  = string
    target_id       = string
  }))
  default = []
}

variable "aws_cross_account_roles" {
  description = "AWS cross-account IAM roles"
  type = map(object({
    description             = string
    max_session_duration   = optional(number, 3600)
    trusted_entities       = list(string)
    external_id           = optional(string, "")
    source_ip_conditions  = optional(list(string), [])
    policy_arns           = list(string)
  }))
  default = {}
}

variable "aws_saml_metadata_document" {
  description = "SAML metadata document for AWS identity provider"
  type        = string
  default     = ""
}

variable "aws_cloudtrail_bucket" {
  description = "S3 bucket name for AWS CloudTrail logs"
  type        = string
  default     = ""
}

# =============================================================================
# AZURE IAM CONFIGURATION
# =============================================================================

variable "azure_resource_group_name" {
  description = "Azure resource group name for monitoring resources"
  type        = string
  default     = ""
}

variable "azure_group_owners" {
  description = "Object IDs of Azure AD group owners"
  type        = list(string)
  default     = []
}

variable "azure_custom_roles" {
  description = "Azure custom role definitions"
  type = map(object({
    description       = string
    scope            = string
    actions          = list(string)
    not_actions      = optional(list(string), [])
    data_actions     = optional(list(string), [])
    not_data_actions = optional(list(string), [])
    assignable_scopes = list(string)
  }))
  default = {}
}

variable "azure_role_assignments" {
  description = "Azure role assignments for groups"
  type = list(object({
    group_name         = string
    role_definition_id = string
    scope             = string
    condition         = optional(string)
    condition_version = optional(string)
  }))
  default = []
}

variable "enable_azure_pim" {
  description = "Enable Azure Privileged Identity Management"
  type        = bool
  default     = false
}

variable "azure_pim_assignments" {
  description = "Azure PIM eligible role assignments"
  type = list(object({
    group_name         = string
    role_definition_id = string
    scope             = string
    start_date_time   = string
    duration_days     = number
    ticket_number     = optional(string)
    ticket_system     = optional(string)
    justification     = string
  }))
  default = []
}

variable "enable_azure_saml" {
  description = "Enable Azure SAML application"
  type        = bool
  default     = false
}

variable "azure_saml_redirect_uris" {
  description = "Redirect URIs for Azure SAML application"
  type        = list(string)
  default     = []
}

variable "azure_saml_relay_state" {
  description = "Relay state for Azure SAML SSO"
  type        = string
  default     = ""
}

variable "azure_application_owners" {
  description = "Object IDs of Azure application owners"
  type        = list(string)
  default     = []
}

variable "azure_action_group_id" {
  description = "Azure action group ID for monitoring alerts"
  type        = string
  default     = ""
}

variable "enable_azure_access_reviews" {
  description = "Enable Azure AD access reviews"
  type        = bool
  default     = false
}

variable "azure_access_package_catalog_id" {
  description = "Azure AD access package catalog ID"
  type        = string
  default     = ""
}

variable "azure_access_review_approvers" {
  description = "Object IDs of access review approvers"
  type        = list(string)
  default     = []
}

variable "azure_access_review_requestors" {
  description = "Object IDs of access review requestors"
  type        = list(string)
  default     = []
}

# =============================================================================
# GCP IAM CONFIGURATION
# =============================================================================

variable "gcp_project_id" {
  description = "GCP project ID"
  type        = string
  default     = ""
}

variable "gcp_custom_roles" {
  description = "GCP custom role definitions"
  type = map(object({
    description = string
    permissions = list(string)
    stage      = optional(string, "GA")
  }))
  default = {}
}

variable "gcp_iam_bindings" {
  description = "GCP IAM bindings for groups"
  type = map(object({
    role    = string
    members = list(string)
    condition = optional(object({
      title       = string
      description = string
      expression  = string
    }))
  }))
  default = {}
}

variable "gcp_service_accounts" {
  description = "GCP service accounts for cross-cloud authentication"
  type = map(object({
    display_name = string
    description  = string
    create_key   = optional(bool, false)
    roles       = list(string)
  }))
  default = {}
}

variable "gcp_audit_bucket" {
  description = "GCS bucket name for audit logs"
  type        = string
  default     = ""
}

# =============================================================================
# GROUP ASSIGNMENTS
# =============================================================================

variable "group_assignments" {
  description = "User assignments to groups across cloud providers"
  type = list(object({
    group_name       = string
    user_email       = string
    user_object_id   = string
    cloud_provider   = string
  }))
  default = []
  validation {
    condition = alltrue([
      for assignment in var.group_assignments :
      contains(["aws", "azure", "gcp"], assignment.cloud_provider)
    ])
    error_message = "Cloud provider must be one of: aws, azure, gcp."
  }
}

# =============================================================================
# MONITORING AND AUTOMATION
# =============================================================================

variable "enable_iam_monitoring" {
  description = "Enable IAM monitoring and auditing"
  type        = bool
  default     = true
}

variable "enable_iam_automation" {
  description = "Enable IAM automation and workflows"
  type        = bool
  default     = false
}

# =============================================================================
# TAGGING
# =============================================================================

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Terraform   = "true"
    Module      = "multi-cloud-iam-security"
    Owner       = ""
    Project     = ""
    CostCenter  = ""
    Environment = ""
  }
}