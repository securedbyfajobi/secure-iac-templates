# Enterprise Backup and Disaster Recovery Module

A comprehensive, enterprise-grade Terraform module for implementing multi-cloud backup and disaster recovery capabilities with automated orchestration, compliance validation, and cross-region replication.

## Features

### 🔒 **Enterprise Security**
- End-to-end encryption with customer-managed keys
- Cross-account and cross-region backup capabilities
- Immutable backup options for compliance
- Comprehensive access controls and audit logging

### 🌐 **Multi-Cloud Support**
- **AWS**: AWS Backup with cross-region replication
- **Azure**: Recovery Services with geo-redundant storage
- **GCP**: Cloud Storage with lifecycle management
- Unified orchestration across all cloud providers

### 📊 **Tier-Based Backup Policies**
- **Critical**: Hourly backups, 15-minute RTO, 5-minute RPO
- **High**: 6-hourly backups, 60-minute RTO, 30-minute RPO
- **Medium**: Daily backups, 4-hour RTO, 2-hour RPO
- **Low**: Weekly backups, 24-hour RTO, 12-hour RPO

### ⚖️ **Compliance Frameworks**
- SOC 2 Type II compliance
- PCI-DSS data protection requirements
- HIPAA healthcare data security
- NIST cybersecurity framework
- ISO 27001 information security

### 🤖 **Automation & Orchestration**
- Automated DR testing and validation
- Cross-cloud backup coordination
- Intelligent failure detection and recovery
- Comprehensive monitoring and alerting

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│      AWS        │    │      Azure      │    │      GCP        │
│                 │    │                 │    │                 │
│  ┌───────────┐  │    │  ┌───────────┐  │    │  ┌───────────┐  │
│  │  Backup   │  │    │  │ Recovery  │  │    │  │  Storage  │  │
│  │   Vault   │  │    │  │ Services  │  │    │  │  Bucket   │  │
│  └───────────┘  │    │  └───────────┘  │    │  └───────────┘  │
│                 │    │                 │    │                 │
│  ┌───────────┐  │    │  ┌───────────┐  │    │  ┌───────────┐  │
│  │    KMS    │  │    │  │ Key Vault │  │    │  │    KMS    │  │
│  └───────────┘  │    │  └───────────┘  │    │  └───────────┘  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    ┌─────────────────┐
                    │  DR Coordinator │
                    │    (Lambda)     │
                    └─────────────────┘
                                 │
                    ┌─────────────────┐
                    │   Monitoring    │
                    │ & Alerting      │
                    └─────────────────┘
```

## Quick Start

### Basic Configuration

```hcl
module "enterprise_backup_dr" {
  source = "./terraform/modules/enterprise-backup-disaster-recovery"

  name_prefix  = "mycompany"
  environment  = "prod"

  # Enable cloud providers
  enable_aws_dr   = true
  enable_azure_dr = true
  enable_gcp_dr   = true

  # Backup tiers
  backup_tiers = ["critical", "high", "medium"]

  # Compliance requirements
  compliance_frameworks = ["SOC2", "PCI-DSS"]

  # AWS configuration
  aws_backup_resources = {
    critical = [
      "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
      "arn:aws:rds:us-east-1:123456789012:db:prod-database"
    ]
    high = [
      "arn:aws:ec2:us-east-1:123456789012:instance/i-0987654321fedcba0"
    ]
    medium = [
      "arn:aws:s3:::my-application-data"
    ]
  }

  # Cross-region backup
  enable_cross_region_backup = true
  aws_dr_region             = "us-west-2"

  # Azure configuration
  azure_resource_group_name = "rg-backup-prod"
  azure_primary_location    = "East US"
  azure_dr_location        = "West US 2"

  # GCP configuration
  gcp_project_id      = "my-project-prod"
  gcp_primary_region  = "us-central1"
  gcp_dr_region      = "us-east1"

  # Automation
  enable_dr_automation     = true
  notification_topic_arn   = aws_sns_topic.backup_alerts.arn

  common_tags = {
    Project     = "MyProject"
    Owner       = "Platform Team"
    Environment = "production"
  }
}
```

### Advanced Configuration with Custom RTO/RPO

```hcl
module "enterprise_backup_dr" {
  source = "./terraform/modules/enterprise-backup-disaster-recovery"

  name_prefix = "enterprise"
  environment = "prod"

  # Custom RTO/RPO requirements
  critical_rto_minutes = 10
  critical_rpo_minutes = 2
  high_rto_minutes     = 30
  high_rpo_minutes     = 15

  # Advanced security features
  backup_encryption_enabled    = true
  enable_immutable_backups    = true
  backup_vault_lock_enabled   = true
  backup_vault_lock_days      = 2555  # 7 years

  # Cost optimization
  enable_backup_lifecycle       = true
  cold_storage_transition_days = 30
  archive_transition_days      = 90
  enable_backup_deduplication  = true
  enable_backup_compression    = true

  # Monitoring and alerting
  enable_backup_monitoring        = true
  backup_failure_alert_threshold  = 1
  backup_sla_threshold_hours      = 12

  # DR testing
  dr_test_schedule = "cron(0 6 ? * SUN *)"  # Every Sunday at 6 AM

  # Integration with existing infrastructure
  integrate_with_existing_backups = true
  existing_backup_vault_arn       = "arn:aws:backup:us-east-1:123456789012:backup-vault:existing-vault"
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
| `backup_tiers` | list(string) | `["critical", "high", "medium"]` | Backup tiers to enable |
| `compliance_frameworks` | list(string) | `[]` | Compliance frameworks to adhere to |
| `common_tags` | map(string) | `{}` | Common tags for all resources |

### Cloud Provider Configuration

#### AWS
| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `enable_aws_dr` | bool | `true` | Enable AWS disaster recovery |
| `aws_backup_resources` | map(list(string)) | `{}` | Resources to backup by tier |
| `enable_cross_region_backup` | bool | `true` | Enable cross-region replication |
| `aws_dr_region` | string | `"us-west-2"` | DR region for AWS |

#### Azure
| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `enable_azure_dr` | bool | `false` | Enable Azure disaster recovery |
| `azure_resource_group_name` | string | `""` | Resource group for backup resources |
| `azure_primary_location` | string | `"East US"` | Primary Azure region |
| `azure_encryption_key_id` | string | `""` | Key Vault key for encryption |

#### GCP
| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `enable_gcp_dr` | bool | `false` | Enable GCP disaster recovery |
| `gcp_project_id` | string | `""` | GCP project ID |
| `gcp_primary_region` | string | `"us-central1"` | Primary GCP region |
| `gcp_kms_key_name` | string | `""` | KMS key for encryption |

### RTO/RPO Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `critical_rto_minutes` | number | `15` | Critical tier RTO |
| `critical_rpo_minutes` | number | `5` | Critical tier RPO |
| `high_rto_minutes` | number | `60` | High tier RTO |
| `high_rpo_minutes` | number | `30` | High tier RPO |

## Outputs

### Primary Outputs

| Output | Description |
|--------|-------------|
| `aws_backup_vault_arn` | ARN of primary AWS backup vault |
| `azure_recovery_vault_id` | ID of Azure Recovery Services vault |
| `gcp_backup_bucket_name` | Name of GCP backup bucket |
| `dr_coordinator_function_arn` | ARN of DR coordinator Lambda |

### Security Outputs

| Output | Description |
|--------|-------------|
| `backup_security_score` | Calculated security score |
| `encryption_configuration` | Encryption settings summary |
| `compliance_retention_policies` | Applied retention policies |

### Monitoring Outputs

| Output | Description |
|--------|-------------|
| `backup_failure_alarm_arn` | CloudWatch alarm for failures |
| `dr_dashboard_url` | DR monitoring dashboard URL |

## Compliance Matrix

| Framework | Retention | Encryption | Immutability | Cross-Region |
|-----------|-----------|------------|--------------|--------------|
| **SOC 2** | 30 days | ✅ Required | ✅ Recommended | ✅ Required |
| **PCI-DSS** | 365 days | ✅ Required | ✅ Required | ✅ Required |
| **HIPAA** | 365 days | ✅ Required | ✅ Required | ✅ Required |
| **NIST** | 90 days | ✅ Required | ✅ Recommended | ✅ Recommended |
| **ISO 27001** | 90 days | ✅ Required | ✅ Recommended | ✅ Recommended |

## DR Testing

The module includes automated DR testing capabilities:

```bash
# Trigger manual DR test
aws lambda invoke \
  --function-name enterprise-prod-dr-coordinator \
  --payload '{"action": "test_dr", "tier": "critical"}' \
  response.json

# Validate backup health
aws lambda invoke \
  --function-name enterprise-prod-dr-coordinator \
  --payload '{"action": "validate_backups", "tier": "all"}' \
  response.json

# Check compliance status
aws lambda invoke \
  --function-name enterprise-prod-dr-coordinator \
  --payload '{"action": "compliance_check"}' \
  response.json
```

## Cost Optimization

The module implements several cost optimization strategies:

- **Lifecycle Policies**: Automatic transition to cheaper storage classes
- **Deduplication**: Reduces storage requirements by 30-50%
- **Compression**: Additional 20-30% storage savings
- **Cross-Region Intelligence**: Only replicates critical and high-tier backups

### Estimated Monthly Costs

| Tier | Storage (per TB) | Cross-Region | Total Estimated |
|------|------------------|--------------|-----------------|
| Critical | $23 | $46 | $69/TB/month |
| High | $23 | $23 | $46/TB/month |
| Medium | $15 | - | $15/TB/month |
| Low | $4 | - | $4/TB/month |

## Security Best Practices

### Encryption
- All backups encrypted with customer-managed keys
- Separate KMS keys per environment and region
- Automatic key rotation enabled

### Access Control
- Least privilege IAM policies
- Cross-account backup capabilities
- Service-specific roles with minimal permissions

### Network Security
- VPC endpoints for backup traffic
- Private subnet deployment
- Network ACLs and security groups

### Monitoring
- Real-time backup job monitoring
- Compliance drift detection
- Automated alerting for failures

## Integration Examples

### With Existing Database Modules

```hcl
# Use with existing database modules
module "aws_database" {
  source = "../aws-enterprise-database"
  # ... database configuration
}

module "backup_dr" {
  source = "../enterprise-backup-disaster-recovery"

  # Integrate with database backup policies
  integrate_with_existing_backups = true

  aws_backup_resources = {
    critical = [module.aws_database.database_arn]
    high     = [module.aws_database.read_replica_arn]
  }
}
```

### With Monitoring Stack

```hcl
# SNS topic for notifications
resource "aws_sns_topic" "backup_alerts" {
  name = "backup-dr-alerts"
}

# Integration with existing monitoring
module "backup_dr" {
  source = "../enterprise-backup-disaster-recovery"

  notification_topic_arn = aws_sns_topic.backup_alerts.arn

  # Send alerts to existing monitoring system
  enable_backup_monitoring = true
}
```

## Troubleshooting

### Common Issues

1. **Backup Job Failures**
   ```bash
   # Check backup job status
   aws backup list-backup-jobs --by-state FAILED

   # View detailed error messages
   aws backup describe-backup-job --backup-job-id <job-id>
   ```

2. **Cross-Region Replication Issues**
   ```bash
   # Verify cross-region vault permissions
   aws backup describe-backup-vault --backup-vault-name <vault-name>

   # Check KMS key permissions in DR region
   aws kms describe-key --key-id <key-id> --region <dr-region>
   ```

3. **DR Test Failures**
   ```bash
   # Check Lambda function logs
   aws logs describe-log-streams --log-group-name /aws/lambda/dr-coordinator

   # View recent executions
   aws lambda list-invocations --function-name dr-coordinator
   ```

### Support

For enterprise support and custom implementations:
- 📧 Email: platform-team@company.com
- 📖 Documentation: [Internal Wiki](https://wiki.company.com/backup-dr)
- 🔧 Issues: [GitHub Issues](https://github.com/company/secure-iac-templates/issues)

## License

This module is licensed under the MIT License. See [LICENSE](../../LICENSE) for details.

---

**⚠️ Important**: This module creates billable cloud resources. Review the cost optimization settings and compliance requirements before deployment in production environments.