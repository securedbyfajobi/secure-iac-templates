# Multi-Cloud IAM Security Module

Enterprise-grade identity and access management module for AWS, Azure, and GCP with centralized governance, policy-as-code validation, and comprehensive security controls.

## Features

### 🛡️ Multi-Cloud Identity Management
- **AWS Identity Center (SSO)** with permission sets and account assignments
- **Azure Active Directory** with security groups and custom roles
- **Google Cloud IAM** with custom roles and service accounts
- **Cross-cloud identity federation** with SAML integration
- **Centralized user and group management** across all platforms

### 🔐 Advanced Security Controls
- **Privileged Identity Management (PIM)** for Azure with just-in-time access
- **Multi-factor authentication** enforcement across all platforms
- **Session duration limits** and conditional access policies
- **Cross-account role security** with external ID and IP restrictions
- **Service account security** with minimal key usage in production

### 📋 Policy-as-Code Governance
- **Open Policy Agent (OPA)** integration for automated policy validation
- **Custom security policies** for each cloud provider
- **Compliance-driven policy enforcement** with multiple frameworks
- **Automated policy violations detection** and remediation guidance
- **Real-time policy evaluation** during infrastructure deployment

### 📊 Compliance & Auditing
- **Multi-framework compliance** (SOC2, NIST, CIS, PCI-DSS, HIPAA, FedRAMP)
- **Comprehensive audit logging** with CloudTrail, Activity Logs, and Audit Logs
- **Access reviews and certifications** with automated workflows
- **Security score calculation** with detailed breakdowns
- **Compliance gap analysis** and remediation planning

### 🤖 Automation & Monitoring
- **IAM automation Lambda** for AWS with policy enforcement
- **Azure access reviews** with automated approval workflows
- **Security monitoring** and alerting across all platforms
- **Unused resource cleanup** and security hygiene automation
- **Cross-cloud integration** monitoring and management

## Usage

### Basic Multi-Cloud Implementation

```hcl
module "multi_cloud_iam" {
  source = "./modules/multi-cloud-iam-security"

  name_prefix            = "enterprise"
  environment           = "prod"
  security_level        = "maximum"
  compliance_frameworks = ["SOC2", "NIST", "PCI-DSS"]

  # Enable all cloud providers
  enable_aws_iam   = true
  enable_azure_iam = true
  enable_gcp_iam   = true

  # AWS Configuration
  aws_sso_instance_arn = "arn:aws:sso:::instance/ssoins-1234567890abcdef"
  aws_session_duration = "PT1H"
  aws_saml_metadata_document = file("saml-metadata.xml")

  # Azure Configuration
  azure_group_owners = ["user1@company.com", "user2@company.com"]
  enable_azure_pim   = true
  enable_azure_saml  = true

  # GCP Configuration
  gcp_project_id = "my-enterprise-project"

  # Cross-cloud user assignments
  group_assignments = [
    {
      group_name       = "admin"
      user_email       = "admin@company.com"
      user_object_id   = "12345678-1234-1234-1234-123456789012"
      cloud_provider   = "azure"
    },
    {
      group_name       = "developer"
      user_email       = "dev@company.com"
      user_object_id   = "87654321-4321-4321-4321-210987654321"
      cloud_provider   = "azure"
    }
  ]

  # Enable monitoring and automation
  enable_iam_monitoring = true
  enable_iam_automation = true

  common_tags = {
    Environment = "prod"
    Project     = "enterprise-iam"
    Owner       = "security-team"
  }
}
```

### Advanced Enterprise Configuration

```hcl
module "enterprise_iam" {
  source = "./modules/multi-cloud-iam-security"

  name_prefix            = "enterprise"
  environment           = "prod"
  security_level        = "maximum"
  compliance_frameworks = ["SOC2", "NIST", "CIS", "PCI-DSS", "HIPAA", "FedRAMP"]

  # AWS Identity Center Configuration
  enable_aws_iam       = true
  aws_sso_instance_arn = "arn:aws:sso:::instance/ssoins-1234567890abcdef"
  aws_session_duration = "PT1H"
  aws_relay_state      = "https://console.aws.amazon.com/"
  aws_saml_metadata_document = file("corporate-saml-metadata.xml")

  # AWS Cross-Account Roles
  aws_cross_account_roles = {
    "prod-read-only" = {
      description           = "Read-only access to production accounts"
      max_session_duration  = 3600
      trusted_entities      = ["arn:aws:iam::123456789012:root"]
      external_id          = "unique-external-id-123"
      source_ip_conditions = ["203.0.113.0/24"]
      policy_arns = [
        "arn:aws:iam::aws:policy/ReadOnlyAccess"
      ]
    }
    "security-audit" = {
      description           = "Security audit access"
      max_session_duration  = 1800
      trusted_entities      = ["arn:aws:iam::234567890123:root"]
      external_id          = "audit-external-id-456"
      policy_arns = [
        "arn:aws:iam::aws:policy/SecurityAudit"
      ]
    }
  }

  # Custom AWS policies for specific use cases
  aws_custom_policies = {
    "developer" = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Effect = "Allow"
          Action = [
            "ec2:DescribeInstances",
            "s3:GetObject",
            "s3:ListBucket"
          ]
          Resource = "*"
          Condition = {
            StringEquals = {
              "aws:RequestedRegion" = ["us-east-1", "us-west-2"]
            }
          }
        }
      ]
    })
  }

  # Azure AD Configuration
  enable_azure_iam         = true
  azure_resource_group_name = "enterprise-iam-rg"
  azure_group_owners       = [
    "admin1@company.com",
    "admin2@company.com"
  ]

  # Azure PIM Configuration
  enable_azure_pim = true
  azure_pim_assignments = [
    {
      group_name         = "admin"
      role_definition_id = "/subscriptions/sub-id/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
      scope             = "/subscriptions/sub-id"
      start_date_time   = "2024-01-01T00:00:00Z"
      duration_days     = 365
      justification     = "Enterprise administrator access"
      ticket_number     = "TICKET-12345"
      ticket_system     = "ServiceNow"
    }
  ]

  # Azure Custom Roles
  azure_custom_roles = {
    "database-operator" = {
      description = "Database operations role"
      scope      = "/subscriptions/sub-id"
      actions = [
        "Microsoft.Sql/servers/databases/read",
        "Microsoft.Sql/servers/databases/write",
        "Microsoft.DocumentDB/databaseAccounts/read"
      ]
      assignable_scopes = ["/subscriptions/sub-id"]
    }
  }

  # Azure SAML Configuration
  enable_azure_saml = true
  azure_saml_redirect_uris = [
    "https://portal.azure.com/",
    "https://myapps.microsoft.com/"
  ]
  azure_application_owners = [
    "app-admin@company.com"
  ]

  # Azure Access Reviews
  enable_azure_access_reviews     = true
  azure_access_package_catalog_id = "catalog-id-123"
  azure_access_review_approvers = [
    "manager@company.com",
    "security@company.com"
  ]
  azure_access_review_requestors = [
    "user@company.com"
  ]

  # GCP Configuration
  enable_gcp_iam   = true
  gcp_project_id   = "enterprise-project-123"

  # GCP Custom Roles
  gcp_custom_roles = {
    "database-admin" = {
      description = "Database administrator role"
      permissions = [
        "cloudsql.instances.create",
        "cloudsql.instances.delete",
        "cloudsql.instances.get",
        "cloudsql.instances.list",
        "cloudsql.instances.update"
      ]
      stage = "GA"
    }
    "security-reader" = {
      description = "Security monitoring read-only role"
      permissions = [
        "logging.logs.list",
        "monitoring.alertPolicies.list",
        "securitycenter.findings.list"
      ]
    }
  }

  # GCP IAM Bindings with Conditions
  gcp_iam_bindings = {
    "time-restricted-admin" = {
      role    = "roles/compute.admin"
      members = ["group:admins@company.com"]
      condition = {
        title       = "Business hours only"
        description = "Access restricted to business hours"
        expression  = "request.time.getHours() >= 9 && request.time.getHours() <= 17"
      }
    }
  }

  # GCP Service Accounts (minimal usage)
  gcp_service_accounts = {
    "automation-sa" = {
      display_name = "Automation Service Account"
      description  = "Service account for CI/CD automation"
      create_key   = false  # Use workload identity instead
      roles = [
        "roles/storage.objectViewer",
        "roles/cloudbuild.builds.builder"
      ]
    }
  }

  # Cross-cloud Group Assignments
  group_assignments = [
    {
      group_name     = "admin"
      user_email     = "admin@company.com"
      user_object_id = "12345678-1234-1234-1234-123456789012"
      cloud_provider = "azure"
    },
    {
      group_name     = "developer"
      user_email     = "dev1@company.com"
      user_object_id = "87654321-4321-4321-4321-210987654321"
      cloud_provider = "azure"
    },
    {
      group_name     = "operator"
      user_email     = "ops@company.com"
      user_object_id = "11111111-2222-3333-4444-555555555555"
      cloud_provider = "azure"
    }
  ]

  # Monitoring and Automation
  enable_iam_monitoring = true
  enable_iam_automation = true
  aws_cloudtrail_bucket = "enterprise-cloudtrail-bucket"
  azure_action_group_id = "action-group-id"
  gcp_audit_bucket     = "enterprise-gcp-audit-bucket"

  common_tags = {
    Environment        = "prod"
    DataClassification = "restricted"
    ComplianceScope    = "SOC2,PCI-DSS,HIPAA"
    SecurityTeam       = "enterprise-security"
    CostCenter         = "security-operations"
  }
}
```

### Development Environment Configuration

```hcl
module "dev_iam" {
  source = "./modules/multi-cloud-iam-security"

  name_prefix            = "dev"
  environment           = "dev"
  security_level        = "standard"
  compliance_frameworks = ["SOC2"]

  # Simplified configuration for development
  enable_aws_iam   = true
  enable_azure_iam = true
  enable_gcp_iam   = false

  # AWS Basic Configuration
  aws_sso_instance_arn = "arn:aws:sso:::instance/ssoins-dev123456789"
  aws_session_duration = "PT4H"  # Longer for development

  # Azure Basic Configuration
  azure_group_owners = ["dev-admin@company.com"]
  enable_azure_pim   = false
  enable_azure_saml  = false

  # Basic monitoring only
  enable_iam_monitoring = true
  enable_iam_automation = false

  common_tags = {
    Environment = "dev"
    Project     = "development"
  }
}
```

## Configuration Options

### Core Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `name_prefix` | string | - | Name prefix for all resources |
| `environment` | string | - | Environment (dev/staging/prod) |
| `security_level` | string | `"high"` | Security level (standard/high/maximum) |
| `compliance_frameworks` | list(string) | `["SOC2", "NIST"]` | Compliance frameworks |

### Cloud Provider Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `enable_aws_iam` | bool | `true` | Enable AWS IAM configuration |
| `enable_azure_iam` | bool | `true` | Enable Azure IAM configuration |
| `enable_gcp_iam` | bool | `true` | Enable GCP IAM configuration |

### AWS IAM Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `aws_sso_instance_arn` | string | `""` | AWS SSO instance ARN |
| `aws_session_duration` | string | `"PT1H"` | Session duration (ISO 8601) |
| `aws_saml_metadata_document` | string | `""` | SAML metadata for federation |
| `aws_cross_account_roles` | map(object) | `{}` | Cross-account IAM roles |

### Azure IAM Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `azure_group_owners` | list(string) | `[]` | Azure AD group owners |
| `enable_azure_pim` | bool | `false` | Enable Privileged Identity Management |
| `enable_azure_saml` | bool | `false` | Enable SAML application |
| `azure_custom_roles` | map(object) | `{}` | Custom Azure role definitions |

### GCP IAM Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `gcp_project_id` | string | `""` | GCP project ID |
| `gcp_custom_roles` | map(object) | `{}` | Custom GCP role definitions |
| `gcp_service_accounts` | map(object) | `{}` | GCP service accounts |

## OPA Policy Integration

### Policy Validation

The module includes comprehensive OPA (Open Policy Agent) policies for automated validation:

```rego
# Example policy rule from policies/opa/iam-security.rego
deny_aws_long_session[msg] {
    input.provider == "aws"
    input.resource_type == "aws_iam_role"
    input.max_session_duration > 3600  # 1 hour
    msg := sprintf("AWS IAM role '%s' has session duration longer than 1 hour", [input.name])
}
```

### Supported Policy Categories

1. **AWS Policies**
   - Session duration limits
   - MFA requirements
   - Wildcard permission restrictions
   - Cross-account security
   - IAM user restrictions in production

2. **Azure Policies**
   - Security group requirements
   - PIM enforcement for privileged roles
   - Custom role validation
   - Access package justification

3. **GCP Policies**
   - Service account key restrictions
   - Primitive role prohibitions
   - Conditional access requirements
   - Custom role permission validation

4. **Multi-Cloud Policies**
   - Strong authentication requirements
   - Least privilege enforcement
   - Compliance labeling
   - Security monitoring validation

## Outputs

### Identity Resources
- `aws_permission_sets` - AWS SSO permission sets
- `azure_ad_groups` - Azure AD security groups
- `gcp_custom_roles` - GCP custom roles
- `gcp_service_accounts` - GCP service accounts

### Security Assessment
- `security_score` - Overall security score (0-100)
- `security_score_breakdown` - Detailed score breakdown
- `compliance_status` - Compliance status by framework
- `validation_report` - Comprehensive validation report with OPA results

### Cross-Cloud Integration
- `cross_cloud_integration` - Integration capabilities summary
- `operational_guidance` - Step-by-step operational guidance

## Security Features

### 🔒 Identity Federation
- **SAML 2.0 integration** with corporate identity providers
- **Cross-cloud SSO** with consistent user experience
- **Multi-factor authentication** enforcement
- **Conditional access policies** based on risk and context
- **Session management** with appropriate timeout controls

### 👥 Access Management
- **Role-based access control (RBAC)** across all platforms
- **Attribute-based access control (ABAC)** with conditions
- **Just-in-time access** through Azure PIM
- **Emergency access procedures** with break-glass accounts
- **Regular access reviews** and certifications

### 🛡️ Security Controls
- **Principle of least privilege** enforcement
- **Segregation of duties** through role separation
- **Defense in depth** with multiple security layers
- **Zero-trust architecture** principles
- **Continuous security monitoring** and alerting

### 📋 Governance & Compliance
- **Policy-as-code** with OPA integration
- **Automated compliance validation** against multiple frameworks
- **Audit trail** with immutable logging
- **Risk assessment** and management
- **Incident response** procedures

## Best Practices

### 🏗️ Implementation
1. **Start with minimal permissions** and gradually expand based on need
2. **Enable all security features** in production environments
3. **Use identity federation** instead of local accounts
4. **Implement just-in-time access** for privileged operations
5. **Regular security assessments** and penetration testing

### 🔧 Configuration
1. **Use consistent naming conventions** across all platforms
2. **Apply security labels/tags** for compliance tracking
3. **Configure session limits** appropriate for security level
4. **Enable comprehensive logging** for audit and monitoring
5. **Implement emergency access** procedures

### 📊 Monitoring
1. **Monitor cross-cloud authentication** patterns
2. **Set up alerting** for suspicious activities
3. **Regular access reviews** and certifications
4. **Track compliance status** continuously
5. **Performance monitoring** for identity services

### 🔄 Maintenance
1. **Regular policy updates** and validation
2. **Access certification** and cleanup
3. **Security control testing** and validation
4. **Incident response** testing and improvement
5. **Training and awareness** programs

## Troubleshooting

### Common Issues
1. **Federation setup** - Verify SAML metadata and trust relationships
2. **Permission propagation** - Allow time for replication across regions
3. **OPA policy violations** - Review validation report for specific issues
4. **Cross-account access** - Verify trust relationships and external IDs
5. **Service account keys** - Use workload identity when possible

### Debugging
1. **Check validation report** for specific compliance gaps
2. **Review OPA policy results** for automated validation issues
3. **Monitor authentication logs** for access patterns
4. **Test role assumptions** and permissions
5. **Validate network connectivity** for federation

## Support

For issues, questions, or contributions:
- Review the validation report for configuration guidance
- Check OPA policy results for automated validation
- Monitor security scores for compliance status
- Follow cloud provider security best practices
- Implement regular security assessments and reviews