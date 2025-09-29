# GCP Enterprise Database Security Module

Enterprise-grade database security module for Google Cloud Platform with Cloud SQL, Cloud Spanner, and Firestore support. Provides comprehensive security controls, compliance validation, and automated monitoring capabilities.

## Features

### 🛡️ Enterprise Security
- **Cloud SQL** with private IP, encryption at rest, and automated backups
- **Cloud Spanner** with global distribution and enterprise-grade security
- **Firestore** with point-in-time recovery and regional/multi-regional deployment
- **Customer-managed encryption keys** via Google Cloud KMS with HSM support
- **Private networking** with VPC peering and service networking
- **Advanced monitoring** with Cloud Monitoring and Security Command Center

### 🔐 Identity & Access Management
- **Custom IAM roles** for database administration and operations
- **Service account security** with minimal required permissions
- **Audit logging** for all database operations and administrative actions
- **Secure credential management** with automatic password generation
- **Network access controls** with authorized networks and private IP

### 📊 Monitoring & Compliance
- **Cloud Monitoring dashboards** with comprehensive database metrics
- **Alerting policies** for CPU, memory, connections, and security events
- **Security Command Center integration** for threat detection
- **Audit trail** with Cloud Audit Logs for compliance reporting
- **Multi-framework compliance** (SOC2, NIST, CIS, PCI-DSS, HIPAA, FedRAMP)

### 🔄 Backup & Disaster Recovery
- **Automated backups** with configurable retention periods
- **Point-in-time recovery** for Cloud SQL and Firestore
- **Cross-region replication** for high availability
- **Export bucket** for long-term backup storage
- **Encryption** for backups and exports

### ✅ Enterprise Validation
- **Comprehensive security validation** with severity-based recommendations
- **Compliance gap analysis** and remediation guidance
- **Security score calculation** with detailed breakdowns
- **Configuration drift detection** and best practice enforcement

## Usage

### Basic Implementation

```hcl
module "database_security" {
  source = "./modules/gcp-enterprise-database"

  name_prefix            = "myapp"
  environment           = "prod"
  region                = "us-central1"
  compliance_frameworks = ["SOC2", "NIST", "PCI-DSS"]

  # Network configuration
  vpc_network_id     = "projects/my-project/global/networks/vpc-network"
  enable_private_ip  = true

  # Cloud SQL configuration
  sql_instances = {
    "primary-db" = {
      database_version = "MYSQL_8_0"
      tier            = "db-n1-standard-2"
      availability_type = "REGIONAL"
      disk_size       = 100
      databases = {
        "app-db" = {
          name = "application"
        }
      }
    }
  }

  # Security configuration
  kms_protection_level = "HSM"
  deletion_protection  = true

  # Monitoring
  enable_monitoring_dashboard = true
  enable_alerting            = true
  notification_channels      = ["projects/my-project/notificationChannels/123"]

  common_labels = {
    environment = "prod"
    project     = "enterprise-app"
    owner       = "platform-team"
  }
}
```

### Advanced Multi-Database Configuration

```hcl
module "enterprise_databases" {
  source = "./modules/gcp-enterprise-database"

  name_prefix            = "enterprise"
  environment           = "prod"
  region                = "us-central1"
  data_classification   = "restricted"
  compliance_frameworks = ["SOC2", "NIST", "CIS", "PCI-DSS", "HIPAA", "FedRAMP"]

  # Network security
  vpc_network_id              = data.google_compute_network.main.id
  enable_private_ip          = true
  private_ip_prefix_length   = 20

  # KMS configuration
  kms_location         = "global"
  kms_protection_level = "HSM"
  kms_rotation_period  = "2592000s"  # 30 days

  # Cloud SQL instances
  sql_instances = {
    "customer-db" = {
      database_version               = "POSTGRES_14"
      tier                          = "db-custom-4-16384"
      availability_type             = "REGIONAL"
      disk_type                     = "PD_SSD"
      disk_size                     = 500
      disk_autoresize              = true
      disk_autoresize_limit        = 2000
      transaction_log_retention_days = 14
      database_flags = [
        {
          name  = "log_statement"
          value = "all"
        },
        {
          name  = "log_min_duration_statement"
          value = "1000"
        }
      ]
      databases = {
        "customers" = {
          name      = "customers"
          charset   = "UTF8"
          collation = "en_US.UTF8"
        },
        "orders" = {
          name      = "orders"
          charset   = "UTF8"
          collation = "en_US.UTF8"
        }
      }
    },
    "analytics-db" = {
      database_version  = "MYSQL_8_0"
      tier             = "db-n1-highmem-8"
      availability_type = "REGIONAL"
      disk_size        = 1000
      databases = {
        "analytics" = {
          name = "analytics"
        }
      }
    }
  }

  # Cloud Spanner for global applications
  create_spanner_instance = true
  spanner_config         = "regional-us-central1"
  spanner_processing_units = 2000
  spanner_databases = {
    "global-db" = {
      version_retention_period = "7d"
      ddl_statements = [
        "CREATE TABLE Users (UserId INT64 NOT NULL, Name STRING(100), Email STRING(255)) PRIMARY KEY (UserId)",
        "CREATE TABLE Orders (OrderId INT64 NOT NULL, UserId INT64, Amount NUMERIC) PRIMARY KEY (OrderId)"
      ]
    }
  }

  # Firestore for document storage
  create_firestore_database              = true
  firestore_database_id                 = "app-firestore"
  firestore_location_id                 = "nam5"
  firestore_type                        = "FIRESTORE_NATIVE"
  firestore_point_in_time_recovery      = true

  # Backup configuration
  backup_retention_days = 365  # 1 year for compliance
  backup_start_time     = "02:00"
  backup_location       = "us"
  create_export_bucket  = true
  export_lifecycle_days = 2555  # 7 years

  # Maintenance window
  maintenance_window_day   = 7  # Sunday
  maintenance_window_hour  = 3  # 3 AM
  maintenance_update_track = "stable"

  # Enhanced monitoring
  enable_monitoring_dashboard = true
  enable_alerting            = true
  cpu_alert_threshold        = 75
  memory_alert_threshold     = 80
  connections_alert_threshold = 100

  # Security features
  enable_security_center        = true
  organization_id              = "123456789012"
  security_notification_topic  = "projects/my-project/topics/security-alerts"
  create_custom_roles          = true
  deletion_protection          = true

  notification_channels = [
    "projects/my-project/notificationChannels/email-alerts",
    "projects/my-project/notificationChannels/slack-alerts"
  ]

  common_labels = {
    environment         = "prod"
    data-classification = "restricted"
    compliance-scope    = "SOC2,PCI-DSS,HIPAA"
    security-team       = "enterprise-security"
    cost-center         = "platform-services"
    backup-tier         = "tier1"
  }
}
```

### Development Environment Configuration

```hcl
module "dev_database" {
  source = "./modules/gcp-enterprise-database"

  name_prefix            = "myapp"
  environment           = "dev"
  region                = "us-central1"
  compliance_frameworks = ["SOC2"]

  # Simplified network configuration for dev
  enable_private_ip = false
  authorized_networks = [
    {
      name  = "office-network"
      value = "203.0.113.0/24"
    }
  ]

  # Basic Cloud SQL
  sql_instances = {
    "dev-db" = {
      database_version = "MYSQL_8_0"
      tier            = "db-f1-micro"
      disk_size       = 20
      databases = {
        "app-dev" = {
          name = "app_development"
        }
      }
    }
  }

  # Cost-optimized settings
  kms_protection_level   = "SOFTWARE"
  deletion_protection    = false
  backup_retention_days  = 7
  create_export_bucket   = false

  # Basic monitoring
  enable_monitoring_dashboard = true
  enable_alerting            = false

  common_labels = {
    environment = "dev"
    project     = "development"
  }
}
```

## Configuration Options

### Core Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `name_prefix` | string | - | Name prefix for all resources |
| `environment` | string | - | Environment (dev/staging/prod) |
| `region` | string | `"us-central1"` | GCP region |
| `data_classification` | string | `"confidential"` | Data classification level |
| `compliance_frameworks` | list(string) | `["SOC2", "NIST"]` | Compliance frameworks |

### Network Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `vpc_network_id` | string | `""` | VPC network ID for private IP |
| `enable_private_ip` | bool | `true` | Enable private IP for databases |
| `private_ip_prefix_length` | number | `16` | Prefix length for private IP range |
| `authorized_networks` | list(object) | `[]` | Authorized networks for database access |

### Encryption Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `kms_location` | string | `"global"` | Location for KMS key ring |
| `kms_protection_level` | string | `"SOFTWARE"` | KMS protection level (SOFTWARE/HSM) |
| `kms_rotation_period` | string | `"2592000s"` | KMS key rotation period |

### Cloud SQL Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `sql_instances` | map(object) | `{}` | Cloud SQL instances to create |
| `backup_start_time` | string | `"03:00"` | Backup start time (HH:MM) |
| `backup_retention_days` | number | `30` | Backup retention period |
| `maintenance_window_day` | number | `7` | Maintenance day (1-7) |
| `maintenance_window_hour` | number | `3` | Maintenance hour (0-23) |

### Monitoring Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `enable_monitoring_dashboard` | bool | `true` | Enable monitoring dashboard |
| `enable_alerting` | bool | `true` | Enable alerting policies |
| `cpu_alert_threshold` | number | `80` | CPU alert threshold (%) |
| `memory_alert_threshold` | number | `85` | Memory alert threshold (%) |
| `notification_channels` | list(string) | `[]` | Notification channel IDs |

## Outputs

### Resource Information
- `project_id` - GCP project ID
- `sql_instances` - Cloud SQL instance details
- `spanner_instance_name` - Cloud Spanner instance name
- `firestore_database_name` - Firestore database name
- `kms_crypto_key_id` - KMS encryption key ID

### Security Information
- `security_score` - Overall security score (0-100)
- `security_score_breakdown` - Detailed score breakdown
- `compliance_status` - Compliance status by framework
- `validation_report` - Comprehensive validation report

### Connection Information
- `sql_connection_strings` - Database connection details
- `sql_databases` - Database information
- `spanner_databases` - Spanner database details

## Security Features

### 🔒 Data Protection
- **Customer-managed encryption** with Google Cloud KMS
- **HSM-backed encryption** for highly sensitive data
- **Encryption in transit** with SSL/TLS connections
- **Point-in-time recovery** for data restoration
- **Automatic backup encryption** with customer keys

### 🌐 Network Security
- **Private IP** connectivity with VPC peering
- **Authorized networks** for IP-based access control
- **Service networking** for secure Google service access
- **Network isolation** with dedicated subnet ranges
- **SSL certificate management** for secure connections

### 👥 Identity & Access Management
- **Custom IAM roles** for database-specific permissions
- **Service account keys** with automatic rotation
- **Audit logging** for all administrative operations
- **Fine-grained permissions** following least privilege
- **Cross-project access controls** for multi-project setups

### 🔍 Monitoring & Alerting
- **Real-time metrics** for database performance
- **Security event detection** with Cloud Security Command Center
- **Custom alerting policies** for operational events
- **Dashboard visualization** for operational insights
- **Log export** for SIEM integration

## Compliance Support

### SOC2 Type II
- Access controls and monitoring
- Security incident management
- Change management processes
- Vendor management controls
- Data classification and handling

### NIST Cybersecurity Framework
- Identify, Protect, Detect, Respond, Recover functions
- Risk management and assessment
- Security awareness and training
- Incident response planning
- Supply chain risk management

### CIS Controls
- Inventory and control of database assets
- Secure configuration management
- Continuous vulnerability management
- Controlled use of administrative privileges
- Data recovery and backup procedures

### PCI-DSS
- Network segmentation and access control
- Strong cryptography and key management
- Regular monitoring and testing
- Incident response procedures
- Secure development practices

### HIPAA
- Administrative, physical, and technical safeguards
- Access control and audit controls
- Integrity and transmission security
- Business associate agreements
- Breach notification procedures

### FedRAMP
- Federal security requirements
- Continuous monitoring and assessment
- Supply chain risk management
- Incident response and recovery
- Security control implementation

## Best Practices

### 🏗️ Implementation
1. **Enable private IP** for all production workloads
2. **Use HSM protection** for highly sensitive data
3. **Configure regional deployment** for high availability
4. **Enable comprehensive monitoring** for operational visibility
5. **Implement proper backup strategies** based on RTO/RPO requirements

### 🔧 Configuration
1. **Use descriptive naming conventions** for consistent resource management
2. **Apply principle of least privilege** for database access
3. **Configure appropriate backup retention** based on compliance requirements
4. **Enable deletion protection** for production databases
5. **Set up proper alerting thresholds** for operational events

### 📊 Monitoring
1. **Monitor database performance metrics** regularly
2. **Set up alerting** for security and operational events
3. **Review audit logs** for suspicious activity
4. **Track compliance status** across frameworks
5. **Perform regular security assessments** and reviews

### 🔄 Maintenance
1. **Keep database versions updated** with latest security patches
2. **Rotate encryption keys** according to security policies
3. **Review and update access controls** regularly
4. **Test backup and recovery procedures** periodically
5. **Update compliance configurations** as requirements change

## Cost Optimization

### 💰 Cost Components
- **Cloud SQL**: Variable based on tier, storage, and network usage
- **Cloud Spanner**: Fixed cost based on processing units and storage
- **Firestore**: Variable based on operations, storage, and bandwidth
- **Cloud KMS**: ~$0.06 per key per month + operations
- **Cloud Monitoring**: Variable based on metrics and log volume
- **Cloud Storage**: Variable based on backup storage and operations

### 📉 Optimization Strategies
1. **Right-size database instances** based on actual usage patterns
2. **Use committed use discounts** for predictable workloads
3. **Optimize backup retention** based on compliance requirements
4. **Configure auto-scaling** for variable workloads
5. **Monitor and optimize storage usage** regularly

## Security Considerations

### ⚠️ Important Notes
- Private IP requires VPC peering configuration and proper network planning
- HSM protection increases costs but provides enhanced security
- Cross-region replication increases costs but improves availability
- Compliance frameworks may have conflicting requirements
- Backup and export costs scale with data volume

### 🔐 Security Recommendations
1. **Enable all security features** in production environments
2. **Use separate KMS keys** for different data classifications
3. **Implement proper network segmentation** for database tiers
4. **Configure security alerting** for all critical events
5. **Regular security assessments** and penetration testing

## Troubleshooting

### Common Issues
1. **VPC peering failures** - Check network configuration and permissions
2. **KMS key access denied** - Verify service account permissions
3. **Private IP connectivity issues** - Check firewall rules and routing
4. **Backup failures** - Verify storage bucket permissions
5. **Monitoring gaps** - Check metric collection and dashboard configuration

### Debugging
1. **Check Cloud Audit Logs** for API call failures
2. **Review Cloud Monitoring** for performance issues
3. **Validate network connectivity** with VPC flow logs
4. **Test database connections** from authorized networks
5. **Monitor security events** in Security Command Center

## Support

For issues, questions, or contributions:
- Review the validation report for configuration guidance
- Check Cloud Monitoring for operational issues
- Monitor security scores for compliance status
- Follow Google Cloud security best practices
- Implement regular security assessments and reviews