# Enterprise Secrets Management Module

A comprehensive, enterprise-grade Terraform module for managing secrets across multiple cloud providers with automated rotation, compliance monitoring, and advanced security features.

## Features

### 🔐 **Multi-Cloud Secrets Management**
- **AWS Secrets Manager**: Automated rotation, cross-region replication
- **Azure Key Vault**: Premium tier with network restrictions
- **Google Secret Manager**: Automatic replication and lifecycle management
- **HashiCorp Vault**: Enterprise-grade centralized secrets management

### 🛡️ **Security Categories**
- **Critical**: 30-day rotation, AES-256, daily audits, cross-region backup
- **High**: 60-day rotation, AES-256, weekly audits, cross-region backup
- **Medium**: 90-day rotation, AES-256, monthly audits
- **Low**: 180-day rotation, AES-128, quarterly audits

### ⚖️ **Compliance Frameworks**
- **SOC 2**: 90-day rotation, encryption, audit logging
- **PCI-DSS**: 90-day rotation, 15-day access reviews, enhanced monitoring
- **HIPAA**: 60-day rotation, data integrity checks, disaster recovery
- **NIST**: 60-day rotation, incident response integration
- **FIPS**: 30-day rotation, FIPS 140-2 Level 2 compliance

### 🔄 **Automated Rotation**
- Multi-database engine support (MySQL, PostgreSQL, Oracle, SQL Server)
- Secure password generation with complexity requirements
- Comprehensive rotation testing and validation
- Rollback capabilities and version management

### 📊 **Compliance Monitoring**
- Real-time compliance violations detection
- Automated remediation recommendations
- Comprehensive audit trails and reporting
- Framework-specific compliance checks

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Enterprise Secrets Management                │
└─────────────────────────────────────────────────────────────────┘
                                │
                ┌───────────────┼───────────────┐
                │               │               │
        ┌───────▼──────┐ ┌──────▼──────┐ ┌─────▼──────┐
        │     AWS      │ │    Azure    │ │    GCP     │
        │   Secrets    │ │ Key Vault   │ │  Secret    │
        │   Manager    │ │             │ │  Manager   │
        └──────────────┘ └─────────────┘ └────────────┘
                │               │               │
        ┌───────▼──────┐ ┌──────▼──────┐ ┌─────▼──────┐
        │   KMS Keys   │ │  Key Vault  │ │   Cloud    │
        │  & Rotation  │ │ Access Ctrl │ │    KMS     │
        └──────────────┘ └─────────────┘ └────────────┘
                                │
                    ┌───────────▼───────────┐
                    │   HashiCorp Vault     │
                    │   (Optional)          │
                    └───────────────────────┘
                                │
                ┌───────────────┼───────────────┐
                │               │               │
        ┌───────▼──────┐ ┌──────▼──────┐ ┌─────▼──────┐
        │  Rotation    │ │ Compliance  │ │ Monitoring │
        │  Automation  │ │ Monitoring  │ │ & Alerts   │
        │  (Lambda)    │ │  (Lambda)   │ │(CloudWatch)│
        └──────────────┘ └─────────────┘ └────────────┘
```

## Quick Start

### Basic Configuration

```hcl
module "enterprise_secrets" {
  source = "./terraform/modules/enterprise-secrets-management"

  name_prefix  = "mycompany"
  environment  = "prod"

  # Enable cloud providers
  enable_aws_secrets   = true
  enable_azure_secrets = true
  enable_gcp_secrets   = true

  # Compliance requirements
  compliance_frameworks = ["SOC2", "PCI-DSS"]

  # Database secrets (AWS)
  database_secrets = {
    "prod-mysql" = {
      description = "Production MySQL database"
      category    = "critical"
      username    = "app_user"
      password    = "initial-password-will-be-rotated"
      engine      = "mysql"
      host        = "mysql.prod.internal"
      port        = 3306
      dbname      = "production"
    }
    "analytics-postgres" = {
      description = "Analytics PostgreSQL database"
      category    = "high"
      username    = "analytics_user"
      password    = "initial-password"
      engine      = "postgres"
      host        = "postgres.analytics.internal"
      port        = 5432
      dbname      = "analytics"
    }
  }

  # API secrets
  api_secrets = {
    "stripe-api" = {
      description = "Stripe payment API credentials"
      category    = "critical"
      api_key     = "pk_test_..."
      secret_key  = "sk_test_..."
      endpoint    = "https://api.stripe.com"
    }
  }

  # Automatic rotation
  enable_automatic_rotation = true
  critical_rotation_days    = 30
  high_rotation_days       = 60

  # Azure configuration
  azure_resource_group_name = "rg-secrets-prod"
  azure_location           = "East US"

  # GCP configuration
  gcp_project_id = "my-project-prod"

  # Monitoring
  notification_topic_arn = aws_sns_topic.secrets_alerts.arn

  common_tags = {
    Project     = "MyProject"
    Owner       = "Security Team"
    Environment = "production"
  }
}
```

### Advanced Configuration with Vault Integration

```hcl
module "enterprise_secrets" {
  source = "./terraform/modules/enterprise-secrets-management"

  name_prefix = "enterprise"
  environment = "prod"

  # Enable all providers including Vault
  enable_aws_secrets      = true
  enable_azure_secrets    = true
  enable_gcp_secrets     = true
  enable_vault_integration = true

  # Strict compliance requirements
  compliance_frameworks = ["PCI-DSS", "HIPAA", "FIPS"]

  # Advanced security features
  enable_encryption_at_rest    = true
  enable_encryption_in_transit = true
  kms_key_rotation_enabled    = true

  # Access control
  enable_least_privilege_access = true
  enable_just_in_time_access   = true
  jit_access_duration_hours    = 2

  # Cross-region and DR
  enable_cross_region_secrets = true
  enable_secret_dr           = true
  secret_dr_region          = "us-west-2"

  # Performance optimization
  enable_secret_batching   = true
  enable_secret_compression = true
  secret_cache_ttl_seconds = 300

  # Azure network security
  azure_public_access_enabled = false
  azure_allowed_subnets       = [var.azure_private_subnet_id]

  # Compliance monitoring
  enable_compliance_monitoring = true
  compliance_check_schedule    = "cron(0 6 * * ? *)"  # Daily at 6 AM
  enable_compliance_remediation = false  # Manual review required

  # Cost optimization
  enable_cost_optimization    = true
  secret_lifecycle_management = true
  unused_secret_threshold_days = 60
}
```

## Configuration Reference

### Required Variables

| Variable | Type | Description |
|----------|------|-------------|
| `name_prefix` | string | Prefix for all resource names |
| `environment` | string | Environment name (dev, staging, prod) |

### Core Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `compliance_frameworks` | list(string) | `[]` | Compliance frameworks (SOC2, PCI-DSS, HIPAA, NIST, FIPS) |
| `common_tags` | map(string) | `{}` | Common tags for all resources |

### Secret Definitions

#### Database Secrets (AWS)
```hcl
database_secrets = {
  "secret-name" = {
    description = "Human readable description"
    category    = "critical"  # critical, high, medium, low
    username    = "db_user"
    password    = "initial_password"
    engine      = "mysql"     # mysql, postgres, oracle, sqlserver, mariadb
    host        = "db.example.com"
    port        = 3306
    dbname      = "database_name"
  }
}
```

#### API Secrets (AWS)
```hcl
api_secrets = {
  "api-name" = {
    description = "API service description"
    category    = "high"
    api_key     = "public_api_key"
    secret_key  = "private_secret_key"
    endpoint    = "https://api.example.com"
  }
}
```

### Cloud Provider Configuration

#### AWS
| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `enable_aws_secrets` | bool | `true` | Enable AWS Secrets Manager |
| `enable_cross_region_secrets` | bool | `true` | Enable cross-region replication |
| `aws_replica_region` | string | `"us-west-2"` | AWS replica region |
| `secret_recovery_window_days` | number | `30` | Recovery window for deleted secrets |

#### Azure
| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `enable_azure_secrets` | bool | `false` | Enable Azure Key Vault |
| `azure_resource_group_name` | string | `""` | Resource group for Key Vault |
| `azure_location` | string | `"East US"` | Azure region |
| `enable_purge_protection` | bool | `true` | Enable purge protection |
| `azure_public_access_enabled` | bool | `false` | Allow public access |

#### GCP
| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `enable_gcp_secrets` | bool | `false` | Enable GCP Secret Manager |
| `gcp_project_id` | string | `""` | GCP project ID |

### Rotation Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `enable_automatic_rotation` | bool | `true` | Enable automatic rotation |
| `critical_rotation_days` | number | `30` | Critical secrets rotation interval |
| `high_rotation_days` | number | `60` | High priority secrets rotation |
| `default_rotation_days` | number | `90` | Default rotation interval |

### Security Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `enable_encryption_at_rest` | bool | `true` | Encrypt secrets at rest |
| `enable_encryption_in_transit` | bool | `true` | Encrypt secrets in transit |
| `kms_key_rotation_enabled` | bool | `true` | Enable KMS key rotation |
| `enable_least_privilege_access` | bool | `true` | Enforce least privilege |
| `enable_just_in_time_access` | bool | `false` | Enable JIT access |

## Secret Categories and Compliance

### Category Matrix

| Category | Rotation | Encryption | Audit Frequency | Cross-Region | Compliance Use Cases |
|----------|----------|------------|-----------------|--------------|---------------------|
| **Critical** | 30 days | AES-256 | Daily | ✅ Required | Payment data, authentication |
| **High** | 60 days | AES-256 | Weekly | ✅ Required | Database credentials, API keys |
| **Medium** | 90 days | AES-256 | Monthly | ⚠️ Optional | Application configs, certificates |
| **Low** | 180 days | AES-128 | Quarterly | ❌ Not required | Development credentials |

### Compliance Requirements

| Framework | Max Rotation | Access Review | Special Requirements |
|-----------|--------------|---------------|---------------------|
| **SOC 2** | 90 days | 30 days | Audit logging, encryption |
| **PCI-DSS** | 90 days | 15 days | Strong auth, network segmentation |
| **HIPAA** | 60 days | 30 days | Data integrity, DR capabilities |
| **NIST** | 60 days | 30 days | Incident response, risk assessment |
| **FIPS** | 30 days | 15 days | FIPS 140-2 Level 2, key rotation |

## Outputs

### Primary Outputs

| Output | Description |
|--------|-------------|
| `aws_secrets_kms_key_arn` | ARN of AWS secrets encryption key |
| `azure_key_vault_uri` | URI of Azure Key Vault |
| `database_secret_arns` | Map of database secret ARNs |
| `rotation_lambda_arn` | ARN of rotation Lambda function |

### Security Outputs

| Output | Description |
|--------|-------------|
| `secrets_security_score` | Calculated security score (0-100) |
| `compliance_requirements` | Active compliance requirements |
| `encryption_configuration` | Encryption settings summary |

### Monitoring Outputs

| Output | Description |
|--------|-------------|
| `rotation_failure_alarm_arn` | CloudWatch alarm for rotation failures |
| `compliance_monitor_function_arn` | Compliance monitoring Lambda ARN |
| `secrets_dashboard_url` | CloudWatch dashboard URL |

## Secret Rotation

### Supported Database Engines

| Engine | Port | Features |
|--------|------|----------|
| **MySQL** | 3306 | Password rotation, user management |
| **PostgreSQL** | 5432 | Password rotation, role management |
| **Oracle** | 1521 | Password rotation, profile management |
| **SQL Server** | 1433 | Password rotation, login management |
| **MariaDB** | 3306 | Password rotation, user management |

### Rotation Process

1. **Create Secret**: Generate new credentials with secure passwords
2. **Set Secret**: Update database/service with new credentials
3. **Test Secret**: Validate new credentials work correctly
4. **Finish Secret**: Promote new version to current, archive old

### Password Complexity by Category

| Category | Length | Uppercase | Lowercase | Digits | Special | Ambiguous |
|----------|--------|-----------|-----------|--------|---------|-----------|
| Critical | 32 | 8 | 8 | 8 | 8 | Excluded |
| High | 24 | 6 | 6 | 6 | 6 | Excluded |
| Medium | 16 | 4 | 4 | 4 | 4 | Allowed |
| Low | 12 | 3 | 3 | 3 | 3 | Allowed |

## Compliance Monitoring

### Automated Checks

- **Rotation Compliance**: Verify secrets rotated within required timeframes
- **Access Compliance**: Check IAM policies and access controls
- **Encryption Compliance**: Validate encryption at rest and in transit
- **Lifecycle Compliance**: Monitor secret versions and cleanup

### Violation Remediation

```bash
# Trigger compliance check
aws lambda invoke \
  --function-name enterprise-prod-compliance-monitor \
  --payload '{"check_type": "full_compliance_audit"}' \
  response.json

# Check specific compliance area
aws lambda invoke \
  --function-name enterprise-prod-compliance-monitor \
  --payload '{"check_type": "rotation_compliance"}' \
  response.json
```

## HashiCorp Vault Integration

### Supported Engines

- **Database**: Dynamic database credentials
- **KV v2**: Key-value secret storage
- **PKI**: Certificate management
- **Transit**: Encryption as a service
- **SSH**: Dynamic SSH keys
- **AWS/Azure/GCP**: Cloud provider credentials

### Example Vault Configuration

```hcl
# Enable Vault integration
enable_vault_integration = true

# Vault will be configured with:
# - AWS auth backend for EC2/Lambda authentication
# - Database secrets engine for dynamic credentials
# - Policy-based access control
# - Audit logging integration
```

## Cost Optimization

### Storage Optimization

- **Lifecycle Management**: Automatic cleanup of unused secrets
- **Compression**: Reduce storage costs for large secrets
- **Batching**: Efficient API operations

### Monitoring Costs

| Feature | Cost Impact | Optimization |
|---------|-------------|--------------|
| Cross-region replication | Medium | Enable only for critical/high |
| Automatic rotation | Low | Optimize rotation frequency |
| Compliance monitoring | Low | Adjust check frequency |
| Version retention | Medium | Implement cleanup policies |

## Security Best Practices

### Access Control
- Implement least privilege IAM policies
- Use service-specific roles
- Enable MFA for human access
- Regular access reviews

### Encryption
- Customer-managed KMS keys
- Automatic key rotation
- Transit encryption
- Field-level encryption for sensitive data

### Network Security
- VPC endpoints for AWS services
- Private endpoints for Azure Key Vault
- Network ACLs and security groups
- IP allowlists where appropriate

### Monitoring
- Real-time secret access logging
- Compliance drift detection
- Failed rotation alerting
- Unusual access pattern detection

## Troubleshooting

### Common Issues

1. **Rotation Failures**
   ```bash
   # Check rotation Lambda logs
   aws logs describe-log-streams --log-group-name /aws/lambda/rotation-function

   # View secret rotation history
   aws secretsmanager describe-secret --secret-id <secret-arn>
   ```

2. **Compliance Violations**
   ```bash
   # Run immediate compliance check
   aws lambda invoke --function-name compliance-monitor \
     --payload '{"check_type": "full_compliance_audit"}'

   # Check specific framework compliance
   aws lambda invoke --function-name compliance-monitor \
     --payload '{"check_type": "framework_compliance"}'
   ```

3. **Azure Key Vault Access Issues**
   ```bash
   # Check Key Vault access policies
   az keyvault show --name <vault-name> --query "properties.accessPolicies"

   # Test Key Vault connectivity
   az keyvault secret list --vault-name <vault-name>
   ```

4. **Cross-Region Replication Issues**
   ```bash
   # Check replica region secret status
   aws secretsmanager describe-secret --secret-id <secret-arn> --region <replica-region>

   # Verify KMS key permissions in replica region
   aws kms describe-key --key-id <key-id> --region <replica-region>
   ```

### Support

For enterprise support and custom implementations:
- 📧 Email: security-team@company.com
- 📖 Documentation: [Internal Security Wiki](https://wiki.company.com/secrets-management)
- 🔧 Issues: [GitHub Issues](https://github.com/company/secure-iac-templates/issues)

## License

This module is licensed under the MIT License. See [LICENSE](../../LICENSE) for details.

---

**⚠️ Security Notice**: This module handles sensitive credential information. Ensure proper access controls, monitoring, and compliance procedures are in place before deploying to production environments.