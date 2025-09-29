# OPA Policies for Multi-Cloud IAM Security
# Enterprise-grade policy-as-code for identity and access management

package iam.security

import rego.v1

# =============================================================================
# AWS IAM SECURITY POLICIES
# =============================================================================

# Deny AWS IAM roles with overly permissive session duration
deny_aws_long_session[msg] {
    input.provider == "aws"
    input.resource_type == "aws_iam_role"
    input.max_session_duration > 3600  # 1 hour
    msg := sprintf("AWS IAM role '%s' has session duration longer than 1 hour (%d seconds)", [input.name, input.max_session_duration])
}

# Require MFA for AWS cross-account roles
deny_aws_no_mfa[msg] {
    input.provider == "aws"
    input.resource_type == "aws_iam_role"
    input.assume_role_policy_document
    not contains_mfa_condition(input.assume_role_policy_document)
    msg := sprintf("AWS IAM role '%s' does not require MFA for assume role", [input.name])
}

# Deny overly broad AWS IAM policies
deny_aws_wildcard_policies[msg] {
    input.provider == "aws"
    input.resource_type == "aws_iam_policy"
    input.policy_document
    has_wildcard_permissions(input.policy_document)
    msg := sprintf("AWS IAM policy '%s' contains overly broad wildcard permissions", [input.name])
}

# Require external ID for cross-account roles
deny_aws_no_external_id[msg] {
    input.provider == "aws"
    input.resource_type == "aws_iam_role"
    input.assume_role_policy_document
    has_external_principal(input.assume_role_policy_document)
    not has_external_id_condition(input.assume_role_policy_document)
    msg := sprintf("AWS IAM role '%s' allows cross-account access without external ID", [input.name])
}

# Deny AWS IAM users in production (should use SSO)
deny_aws_iam_users_in_prod[msg] {
    input.provider == "aws"
    input.resource_type == "aws_iam_user"
    input.environment == "prod"
    not is_service_account(input.name)
    msg := sprintf("AWS IAM user '%s' not allowed in production environment - use SSO instead", [input.name])
}

# =============================================================================
# AZURE IAM SECURITY POLICIES
# =============================================================================

# Require Azure AD groups to be security enabled
deny_azure_non_security_groups[msg] {
    input.provider == "azure"
    input.resource_type == "azuread_group"
    input.security_enabled == false
    msg := sprintf("Azure AD group '%s' must be security enabled", [input.display_name])
}

# Require PIM for privileged Azure roles
require_azure_pim[msg] {
    input.provider == "azure"
    input.resource_type == "azurerm_role_assignment"
    is_privileged_azure_role(input.role_definition_id)
    not input.pim_eligible
    msg := sprintf("Azure role assignment for '%s' should use PIM for privileged role", [input.role_definition_id])
}

# Deny overly broad Azure custom roles
deny_azure_broad_roles[msg] {
    input.provider == "azure"
    input.resource_type == "azurerm_role_definition"
    input.permissions
    has_broad_azure_permissions(input.permissions)
    msg := sprintf("Azure custom role '%s' has overly broad permissions", [input.name])
}

# Require justified access for Azure access packages
require_azure_justification[msg] {
    input.provider == "azure"
    input.resource_type == "azuread_access_package"
    input.assignment_policy
    not requires_justification(input.assignment_policy)
    msg := sprintf("Azure access package '%s' should require requestor justification", [input.display_name])
}

# =============================================================================
# GCP IAM SECURITY POLICIES
# =============================================================================

# Deny GCP service account keys in production
deny_gcp_sa_keys_in_prod[msg] {
    input.provider == "gcp"
    input.resource_type == "google_service_account_key"
    input.environment == "prod"
    msg := sprintf("GCP service account key creation not recommended in production - use workload identity instead")
}

# Require specific permissions for GCP custom roles
deny_gcp_broad_roles[msg] {
    input.provider == "gcp"
    input.resource_type == "google_project_iam_custom_role"
    input.permissions
    has_broad_gcp_permissions(input.permissions)
    msg := sprintf("GCP custom role '%s' has overly broad permissions", [input.role_id])
}

# Require conditions for sensitive GCP IAM bindings
require_gcp_conditions[msg] {
    input.provider == "gcp"
    input.resource_type == "google_project_iam_binding"
    is_sensitive_gcp_role(input.role)
    not input.condition
    msg := sprintf("GCP IAM binding for role '%s' should have conditions for enhanced security", [input.role])
}

# Deny primitive GCP roles
deny_gcp_primitive_roles[msg] {
    input.provider == "gcp"
    input.resource_type in ["google_project_iam_binding", "google_project_iam_member"]
    startswith(input.role, "roles/editor") or
    startswith(input.role, "roles/owner") or
    startswith(input.role, "roles/viewer")
    msg := sprintf("GCP primitive role '%s' should be replaced with specific predefined or custom roles", [input.role])
}

# =============================================================================
# MULTI-CLOUD SECURITY POLICIES
# =============================================================================

# Require strong authentication across all providers
require_strong_auth[msg] {
    input.resource_type in [
        "aws_iam_role",
        "azurerm_role_assignment",
        "google_project_iam_binding"
    ]
    is_privileged_access(input)
    not has_strong_authentication(input)
    msg := sprintf("Resource '%s' requires strong authentication (MFA, conditional access, etc.)", [input.name])
}

# Enforce least privilege principle
enforce_least_privilege[msg] {
    input.resource_type in [
        "aws_iam_policy",
        "azurerm_role_definition",
        "google_project_iam_custom_role"
    ]
    violates_least_privilege(input)
    msg := sprintf("Resource '%s' violates least privilege principle - review and minimize permissions", [input.name])
}

# Require compliance framework tags/labels
require_compliance_labels[msg] {
    input.resource_type in [
        "aws_iam_role",
        "azuread_group",
        "google_service_account"
    ]
    not has_compliance_labels(input)
    msg := sprintf("Resource '%s' must have compliance framework labels/tags", [input.name])
}

# Enforce security monitoring
require_security_monitoring[msg] {
    input.resource_type in [
        "aws_cloudtrail",
        "azurerm_monitor_activity_log_alert",
        "google_logging_project_sink"
    ]
    input.environment == "prod"
    not has_security_monitoring_config(input)
    msg := sprintf("Security monitoring resource '%s' must be properly configured for production", [input.name])
}

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

# Check if AWS IAM policy document contains MFA condition
contains_mfa_condition(policy_doc) if {
    policy := json.unmarshal(policy_doc)
    statement := policy.Statement[_]
    statement.Condition["Bool"]["aws:MultiFactorAuthPresent"] == "true"
}

# Check if AWS IAM policy has wildcard permissions
has_wildcard_permissions(policy_doc) if {
    policy := json.unmarshal(policy_doc)
    statement := policy.Statement[_]
    statement.Effect == "Allow"
    statement.Action == "*"
    statement.Resource == "*"
}

# Check if AWS IAM policy has external principal
has_external_principal(policy_doc) if {
    policy := json.unmarshal(policy_doc)
    statement := policy.Statement[_]
    principal := statement.Principal.AWS[_]
    not startswith(principal, sprintf("arn:aws:iam::%s:", [input.account_id]))
}

# Check if AWS IAM policy has external ID condition
has_external_id_condition(policy_doc) if {
    policy := json.unmarshal(policy_doc)
    statement := policy.Statement[_]
    statement.Condition.StringEquals["sts:ExternalId"]
}

# Check if name indicates service account
is_service_account(name) if {
    startswith(name, "svc-")
}

is_service_account(name) if {
    startswith(name, "service-")
}

is_service_account(name) if {
    endswith(name, "-service")
}

# Check if Azure role is privileged
is_privileged_azure_role(role_id) if {
    role_id in [
        "/subscriptions/{subscription-id}/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635", # Owner
        "/subscriptions/{subscription-id}/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c", # Contributor
        "/subscriptions/{subscription-id}/providers/Microsoft.Authorization/roleDefinitions/18d7d88d-d35e-4fb5-a5c3-7773c20a72d9"  # User Access Administrator
    ]
}

# Check if Azure permissions are too broad
has_broad_azure_permissions(permissions) if {
    permissions.actions[_] == "*"
}

# Check if Azure assignment policy requires justification
requires_justification(policy) if {
    policy.requestor_justification_required == true
}

# Check if GCP permissions are too broad
has_broad_gcp_permissions(permissions) if {
    permissions[_] == "*"
}

has_broad_gcp_permissions(permissions) if {
    count([p | p := permissions[_]; endswith(p, "*")]) > 10
}

# Check if GCP role is sensitive
is_sensitive_gcp_role(role) if {
    startswith(role, "roles/iam.")
}

is_sensitive_gcp_role(role) if {
    startswith(role, "roles/resourcemanager.")
}

is_sensitive_gcp_role(role) if {
    startswith(role, "roles/security.")
}

# Check if access is privileged
is_privileged_access(resource) if {
    resource.provider == "aws"
    resource.resource_type == "aws_iam_role"
    contains(resource.name, "admin")
}

is_privileged_access(resource) if {
    resource.provider == "azure"
    resource.resource_type == "azurerm_role_assignment"
    is_privileged_azure_role(resource.role_definition_id)
}

is_privileged_access(resource) if {
    resource.provider == "gcp"
    resource.resource_type == "google_project_iam_binding"
    is_sensitive_gcp_role(resource.role)
}

# Check if resource has strong authentication
has_strong_authentication(resource) if {
    resource.provider == "aws"
    contains_mfa_condition(resource.assume_role_policy_document)
}

has_strong_authentication(resource) if {
    resource.provider == "azure"
    resource.conditional_access_enabled == true
}

has_strong_authentication(resource) if {
    resource.provider == "gcp"
    resource.condition
}

# Check if resource violates least privilege
violates_least_privilege(resource) if {
    resource.provider == "aws"
    has_wildcard_permissions(resource.policy_document)
}

violates_least_privilege(resource) if {
    resource.provider == "azure"
    has_broad_azure_permissions(resource.permissions)
}

violates_least_privilege(resource) if {
    resource.provider == "gcp"
    has_broad_gcp_permissions(resource.permissions)
}

# Check if resource has compliance labels
has_compliance_labels(resource) if {
    resource.tags.Compliance
}

has_compliance_labels(resource) if {
    resource.labels.compliance
}

# Check if monitoring is properly configured
has_security_monitoring_config(resource) if {
    resource.provider == "aws"
    resource.resource_type == "aws_cloudtrail"
    resource.include_global_service_events == true
    resource.is_multi_region_trail == true
}

has_security_monitoring_config(resource) if {
    resource.provider == "azure"
    resource.resource_type == "azurerm_monitor_activity_log_alert"
    resource.enabled == true
}

has_security_monitoring_config(resource) if {
    resource.provider == "gcp"
    resource.resource_type == "google_logging_project_sink"
    resource.unique_writer_identity == true
}

# =============================================================================
# COMPLIANCE SPECIFIC POLICIES
# =============================================================================

# SOC2 Type II Requirements
soc2_compliance[msg] {
    input.compliance_frameworks[_] == "SOC2"
    not meets_soc2_requirements(input)
    msg := sprintf("Resource '%s' does not meet SOC2 Type II requirements", [input.name])
}

meets_soc2_requirements(resource) if {
    has_access_controls(resource)
    has_audit_logging(resource)
    has_change_management(resource)
}

# NIST Cybersecurity Framework
nist_compliance[msg] {
    input.compliance_frameworks[_] == "NIST"
    not meets_nist_requirements(input)
    msg := sprintf("Resource '%s' does not meet NIST Cybersecurity Framework requirements", [input.name])
}

meets_nist_requirements(resource) if {
    has_identity_management(resource)
    has_access_control(resource)
    has_audit_logging(resource)
}

# PCI-DSS Requirements
pci_dss_compliance[msg] {
    input.compliance_frameworks[_] == "PCI-DSS"
    input.data_classification == "restricted"
    not meets_pci_dss_requirements(input)
    msg := sprintf("Resource '%s' handling restricted data does not meet PCI-DSS requirements", [input.name])
}

meets_pci_dss_requirements(resource) if {
    has_strong_authentication(resource)
    has_access_restrictions(resource)
    has_security_monitoring_config(resource)
}

# Helper functions for compliance
has_access_controls(resource) if {
    not violates_least_privilege(resource)
}

has_audit_logging(resource) if {
    resource.audit_enabled == true
}

has_change_management(resource) if {
    resource.tags.ChangeControl
}

has_identity_management(resource) if {
    resource.resource_type in [
        "aws_ssoadmin_permission_set",
        "azuread_group",
        "google_service_account"
    ]
}

has_access_control(resource) if {
    not violates_least_privilege(resource)
    has_strong_authentication(resource)
}

has_access_restrictions(resource) if {
    resource.provider == "aws"
    has_external_id_condition(resource.assume_role_policy_document)
}

has_access_restrictions(resource) if {
    resource.provider == "azure"
    resource.conditional_access_enabled == true
}

has_access_restrictions(resource) if {
    resource.provider == "gcp"
    resource.condition != null
}