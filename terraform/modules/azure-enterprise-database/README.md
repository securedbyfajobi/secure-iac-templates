# Azure Enterprise Database Security Module

Enterprise-grade database security module for Azure SQL Database, Azure SQL Managed Instance, and Azure Cosmos DB with comprehensive security controls, compliance validation, and monitoring capabilities.

## Features

### 🛡️ Enterprise Security
- **Azure SQL Database** with transparent data encryption and advanced threat protection
- **Azure SQL Managed Instance** for enterprise workloads requiring instance-level features
- **Azure Cosmos DB** with multi-region replication and continuous backup
- **Private endpoints** for secure network isolation
- **Customer-managed encryption keys** via Azure Key Vault
- **Advanced threat detection** and vulnerability assessment

### 🔐 Identity & Access Management
- **Azure AD integration** for centralized identity management
- **Managed identity** support for seamless Azure service integration
- **Role-based access control** with principle of least privilege
- **Key Vault integration** for secure secrets management
- **Network access controls** with IP filtering and virtual network rules

### 📊 Monitoring & Compliance
- **Azure Monitor integration** with Log Analytics workspace
- **Security alert notifications** via email and Azure Monitor
- **Vulnerability assessment** with automated scanning and recommendations
- **Audit logging** with configurable retention periods
- **Multi-framework compliance** (SOC2, NIST, CIS, PCI-DSS, HIPAA, ISO27001)

### 🔄 Backup & Disaster Recovery
- **Automated backups** with configurable retention periods
- **Point-in-time recovery** for Azure SQL Database
- **Geo-redundant backup** options for enhanced durability
- **Cosmos DB continuous backup** with point-in-time restore
- **Cross-region replication** for high availability

### ✅ Enterprise Validation
- **Comprehensive security validation** rules with severity levels
- **Compliance gap analysis** and remediation guidance
- **Security score calculation** with detailed breakdowns
- **Configuration drift detection** and best practice enforcement

## Usage

### Basic Implementation

```hcl
module "database_security" {
  source = "./modules/azure-enterprise-database"

  name_prefix            = "myapp"
  environment           = "prod"
  location              = "East US"
  compliance_frameworks = ["SOC2", "NIST", "PCI-DSS"]

  # Network configuration
  virtual_network_id        = "/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet"
  private_endpoint_subnet_id = "/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/pe-subnet"
  enable_private_endpoint   = true

  # SQL Server configuration
  create_sql_server        = true
  sql_admin_username       = "sqladmin"
  azuread_admin_login      = "db-admins@company.com"
  azuread_admin_object_id  = "12345678-1234-1234-1234-123456789012"

  # Database configuration
  sql_databases = {
    "app-db" = {
      sku_name         = "S2"
      max_size_gb      = 100
      weekly_retention = "P4W"
    }
  }

  # Security configuration
  customer_managed_key_id      = "/subscriptions/sub-id/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv/keys/key"
  enable_vulnerability_assessment = true
  security_alert_email_addresses = ["security@company.com"]

  common_tags = {
    Environment = "prod"
    Project     = "enterprise-app"
    Owner       = "platform-team"
  }
}
```

### Advanced Multi-Database Configuration

```hcl
module "enterprise_databases" {
  source = "./modules/azure-enterprise-database"

  name_prefix            = "enterprise"
  environment           = "prod"
  location              = "East US"
  data_classification   = "restricted"
  compliance_frameworks = ["SOC2", "NIST", "CIS", "PCI-DSS", "HIPAA", "ISO27001"]

  # Network security
  virtual_network_id        = data.azurerm_virtual_network.main.id
  private_endpoint_subnet_id = data.azurerm_subnet.database.id
  enable_private_endpoint   = true
  allowed_subnet_ids        = [data.azurerm_subnet.app.id]

  # Key Vault configuration
  enable_purge_protection    = true
  soft_delete_retention_days = 90
  customer_managed_key_id    = azurerm_key_vault_key.database.id

  # SQL Server with multiple databases
  create_sql_server        = true
  sql_server_version       = "12.0"
  sql_admin_username       = "sqladmin"
  azuread_admin_login      = "enterprise-db-admins"
  azuread_admin_object_id  = data.azuread_group.db_admins.object_id

  sql_databases = {
    "customer-db" = {
      sku_name          = "P2"
      max_size_gb       = 500
      weekly_retention  = "P12W"
      monthly_retention = "P12M"
      yearly_retention  = "P7Y"
    }
    "analytics-db" = {
      sku_name          = "P4"
      max_size_gb       = 1000
      weekly_retention  = "P8W"
      monthly_retention = "P6M"
    }
    "audit-db" = {
      sku_name          = "S3"
      max_size_gb       = 250
      weekly_retention  = "P52W"
      yearly_retention  = "P10Y"
    }
  }

  # SQL Managed Instance for legacy applications
  create_managed_instance      = true
  managed_instance_sku_name    = "GP_Gen5"
  managed_instance_vcores      = 8
  managed_instance_storage_size = 256
  managed_instance_subnet_id   = data.azurerm_subnet.managed_instance.id

  # Cosmos DB for global applications
  create_cosmos_db                = true
  cosmos_db_kind                 = "GlobalDocumentDB"
  cosmos_consistency_level       = "Session"
  cosmos_enable_automatic_failover = true
  cosmos_enable_multi_master     = true
  cosmos_backup_type             = "Continuous"

  cosmos_geo_locations = [
    {
      location          = "East US"
      failover_priority = 0
      zone_redundant    = true
    },
    {
      location          = "West US"
      failover_priority = 1
      zone_redundant    = true
    },
    {
      location          = "West Europe"
      failover_priority = 2
      zone_redundant    = false
    }
  ]

  cosmos_databases = {
    "user-profiles" = {
      throughput = 1000
    }
    "product-catalog" = {
      autoscale_max_throughput = 4000
    }
  }

  # Enhanced monitoring
  enable_log_analytics         = true
  log_analytics_sku           = "PerGB2018"
  log_analytics_retention_days = 365

  # Security alerts and assessments
  enable_vulnerability_assessment = true
  security_alert_email_addresses = [
    "security@company.com",
    "dba@company.com"
  ]
  vulnerability_assessment_email_addresses = [
    "security@company.com"
  ]

  # Audit configuration
  audit_storage_account     = azurerm_storage_account.audit.name
  audit_storage_account_key = azurerm_storage_account.audit.primary_access_key
  audit_retention_days      = 2555  # 7 years

  # Threat detection
  threat_detection_email_addresses = ["security@company.com"]
  threat_detection_storage_account = azurerm_storage_account.security.name
  threat_detection_storage_account_key = azurerm_storage_account.security.primary_access_key

  common_tags = {
    Environment        = "prod"
    DataClassification = "restricted"
    ComplianceScope    = "SOC2,PCI-DSS,HIPAA"
    SecurityTeam       = "enterprise-security"
    CostCenter         = "platform-services"
    BackupTier         = "tier1"
  }
}
```

### Development Environment Configuration

```hcl
module "dev_database" {
  source = "./modules/azure-enterprise-database"

  name_prefix            = "myapp"
  environment           = "dev"
  location              = "East US"
  compliance_frameworks = ["SOC2"]

  # Simplified network configuration for dev
  enable_private_endpoint = false
  allowed_ip_ranges      = ["10.0.0.0/8", "172.16.0.0/12"]

  # Basic SQL Database
  create_sql_server = true
  sql_databases = {
    "app-dev-db" = {
      sku_name    = "S0"
      max_size_gb = 10
    }
  }

  # Cost-optimized settings
  enable_purge_protection    = false
  soft_delete_retention_days = 7
  backup_retention_days      = 7
  log_analytics_retention_days = 30

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
| `location` | string | `"East US"` | Azure region |
| `data_classification` | string | `"confidential"` | Data classification level |
| `compliance_frameworks` | list(string) | `["SOC2", "NIST"]` | Compliance frameworks |

### Network Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `virtual_network_id` | string | `""` | Virtual network ID for private endpoints |
| `private_endpoint_subnet_id` | string | `""` | Subnet ID for private endpoints |
| `enable_private_endpoint` | bool | `true` | Enable private endpoints |
| `allowed_ip_ranges` | list(string) | `[]` | Allowed IP ranges in CIDR notation |
| `allowed_subnet_ids` | list(string) | `[]` | Allowed subnet IDs |

### SQL Server Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `create_sql_server` | bool | `true` | Create Azure SQL Server |
| `sql_server_version` | string | `"12.0"` | SQL Server version |
| `sql_admin_username` | string | `"sqladmin"` | SQL admin username |
| `azuread_admin_login` | string | `""` | Azure AD admin login |
| `azuread_admin_object_id` | string | `""` | Azure AD admin object ID |

### Security Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `customer_managed_key_id` | string | `""` | Customer-managed encryption key ID |
| `enable_purge_protection` | bool | `true` | Enable Key Vault purge protection |
| `enable_vulnerability_assessment` | bool | `true` | Enable vulnerability assessment |
| `security_alert_email_addresses` | list(string) | `[]` | Security alert email addresses |

## Outputs

### Resource Information
- `resource_group_name` - Database resource group name
- `sql_server_name` - SQL Server name
- `sql_server_fqdn` - SQL Server FQDN
- `cosmos_db_account_name` - Cosmos DB account name
- `key_vault_name` - Key Vault name

### Security Information
- `security_score` - Overall security score (0-100)
- `security_score_breakdown` - Detailed score breakdown
- `compliance_status` - Compliance status by framework
- `validation_report` - Comprehensive validation report

### Connection Information
- `connection_strings` - Database connection information (sensitive)
- `sql_databases` - SQL database details
- `cosmos_databases` - Cosmos database details

## Security Features

### 🔒 Data Protection
- **Transparent Data Encryption (TDE)** with customer-managed keys
- **Always Encrypted** support for column-level encryption
- **Dynamic data masking** for sensitive data protection
- **Azure Key Vault integration** for secure key management
- **Soft delete and purge protection** for data recovery

### 🌐 Network Security
- **Private endpoints** for all database services
- **Virtual network integration** with subnet delegation
- **IP-based access control** with configurable allowlists
- **Azure Firewall integration** for advanced network filtering
- **Service endpoints** for secure Azure service communication

### 👥 Identity & Access Management
- **Azure AD authentication** with conditional access
- **Managed identity** for service-to-service authentication
- **Role-based access control (RBAC)** with custom roles
- **Multi-factor authentication** enforcement
- **Privileged access management** integration

### 🔍 Threat Detection
- **Advanced Threat Protection** with ML-based detection
- **Vulnerability Assessment** with automated scanning
- **Security alerts** with customizable notifications
- **Audit logging** with tamper-proof storage
- **Real-time monitoring** with Azure Sentinel integration

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

### ISO27001
- Information security management system (ISMS)
- Risk assessment and treatment
- Security controls implementation
- Continuous improvement processes
- Management review and audit

## Best Practices

### 🏗️ Implementation
1. **Enable private endpoints** for all production workloads
2. **Use customer-managed keys** for encryption in production
3. **Configure Azure AD authentication** for centralized identity management
4. **Enable comprehensive logging** for security monitoring
5. **Implement geo-redundancy** for critical databases

### 🔧 Configuration
1. **Use strong naming conventions** for consistent resource management
2. **Apply principle of least privilege** for database access
3. **Configure backup retention** based on compliance requirements
4. **Enable vulnerability assessment** for proactive security management
5. **Set up security alerting** for incident response

### 📊 Monitoring
1. **Monitor security metrics** regularly for anomaly detection
2. **Review vulnerability assessments** and remediate findings
3. **Audit access patterns** for suspicious activity
4. **Track compliance status** across frameworks
5. **Perform regular security assessments** and penetration testing

### 🔄 Maintenance
1. **Keep database engines updated** with latest security patches
2. **Rotate encryption keys** according to security policies
3. **Review and update access controls** regularly
4. **Test backup and recovery procedures** periodically
5. **Update compliance configurations** as requirements change

## Cost Optimization

### 💰 Cost Components
- **Azure SQL Database**: Variable based on DTU/vCore tier and storage
- **Azure SQL Managed Instance**: Fixed cost based on vCores and storage
- **Azure Cosmos DB**: Variable based on throughput and storage
- **Key Vault**: ~$0.03 per 10,000 operations
- **Private Endpoints**: ~$7.20 per endpoint per month
- **Log Analytics**: Variable based on data ingestion and retention

### 📉 Optimization Strategies
1. **Right-size database SKUs** based on actual usage patterns
2. **Use reserved capacity** for predictable workloads
3. **Optimize backup retention** based on compliance requirements
4. **Configure auto-pause** for development databases
5. **Monitor and optimize throughput** for Cosmos DB

## Security Considerations

### ⚠️ Important Notes
- Private endpoints require careful network planning and DNS configuration
- Customer-managed keys add complexity but provide enhanced security
- Vulnerability assessments may identify false positives requiring review
- Geo-replication increases costs but improves availability and disaster recovery
- Compliance frameworks may have conflicting requirements requiring careful configuration

### 🔐 Security Recommendations
1. **Enable all security features** in production environments
2. **Use separate Key Vaults** for different environments
3. **Implement proper RBAC** for database and Key Vault access
4. **Configure security alerting** for all critical events
5. **Regular security assessments** and compliance audits

## Troubleshooting

### Common Issues
1. **Private endpoint DNS resolution** - Ensure proper DNS zone configuration
2. **Key Vault access denied** - Check access policies and managed identity permissions
3. **Vulnerability assessment failures** - Verify storage account configuration
4. **Backup failures** - Check storage account permissions and network access
5. **Compliance gaps** - Review validation report for specific requirements

### Debugging
1. **Check Azure Activity Log** for resource deployment issues
2. **Review diagnostic settings** for proper log forwarding
3. **Validate network connectivity** for private endpoints
4. **Test authentication** with Azure AD integration
5. **Monitor security metrics** for operational issues

## Support

For issues, questions, or contributions:
- Review the validation report for configuration guidance
- Check Azure Monitor logs for operational issues
- Monitor security scores for compliance status
- Follow Azure security best practices documentation
- Implement regular security assessments and reviews