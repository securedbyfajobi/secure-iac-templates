# AWS WAF and API Security Module

Enterprise-grade Web Application Firewall (WAF) and API security module for AWS with advanced threat protection, compliance validation, and automated threat intelligence integration.

## Features

### 🛡️ Enterprise Security
- **Advanced Web Application Firewall** with AWS WAFv2
- **Multi-layer threat protection** (SQL injection, XSS, DDoS)
- **Geographic and IP-based access control**
- **Rate limiting and size restrictions**
- **AWS managed rule sets** integration
- **Custom security rules** support

### 🔍 Threat Intelligence
- **Automated threat intelligence** updates from multiple sources
- **Real-time IP reputation** integration
- **Configurable threat feeds** (Abuse.ch, Spamhaus, Emerging Threats)
- **Whitelist management** for false positive prevention
- **Scheduled updates** via Lambda and EventBridge

### 🏢 API Security
- **API Gateway resource policies** with fine-grained access control
- **VPC endpoint restrictions** for private API access
- **API key enforcement** for specific paths
- **CIDR-based access control** for APIs
- **Cross-service integration** (ALB, CloudFront, API Gateway)

### 📊 Monitoring & Compliance
- **CloudWatch integration** with custom alarms
- **WAF logging** to CloudWatch Logs with encryption
- **Real-time metrics** and dashboards
- **Security score calculation** and reporting
- **Multi-framework compliance** (SOC2, NIST, CIS, PCI-DSS, HIPAA, FedRAMP)

### ✅ Enterprise Validation
- **Comprehensive security validation** rules
- **Compliance gap analysis** and remediation guidance
- **Security posture assessment** with scoring
- **Configuration drift detection**
- **Best practice recommendations**

## Usage

### Basic Implementation

```hcl
module "waf_security" {
  source = "./modules/aws-waf-api-security"

  name_prefix            = "myapp"
  environment           = "prod"
  compliance_frameworks = ["SOC2", "NIST", "PCI-DSS"]

  # Basic WAF configuration
  waf_scope       = "REGIONAL"
  default_action  = "block"  # Zero-trust approach
  rate_limit      = 1000     # Requests per 5-minute period

  # Geographic restrictions
  blocked_countries = ["CN", "RU", "KP"]  # Block high-risk countries

  # Enable monitoring and logging
  enable_waf_logging        = true
  create_cloudwatch_alarms  = true
  log_retention_days        = 90
  kms_key_id               = "arn:aws:kms:region:account:key/key-id"

  # Associate with resources
  alb_arn              = "arn:aws:elasticloadbalancing:region:account:loadbalancer/app/my-alb/id"
  api_gateway_stage_arn = "arn:aws:apigateway:region::/restapis/api-id/stages/prod"

  common_tags = {
    Environment = "prod"
    Project     = "enterprise-security"
    Owner       = "security-team"
  }
}
```

### Advanced Configuration with Threat Intelligence

```hcl
module "advanced_waf" {
  source = "./modules/aws-waf-api-security"

  name_prefix            = "enterprise"
  environment           = "prod"
  data_classification   = "restricted"
  compliance_frameworks = ["SOC2", "NIST", "CIS", "PCI-DSS", "HIPAA", "FedRAMP"]

  # Strict WAF configuration
  waf_scope             = "REGIONAL"
  default_action        = "block"
  rate_limit           = 500
  max_request_size     = 4096

  # IP-based access control
  allowed_ip_addresses = [
    "10.0.0.0/8",      # Internal networks
    "203.0.113.0/24"   # Partner networks
  ]
  blocked_ip_addresses = [
    "198.51.100.0/24"  # Known malicious networks
  ]

  # Geographic restrictions
  allowed_countries = ["US", "CA", "GB"]  # Allow only specific countries

  # Managed rule sets
  managed_rule_sets = ["linux", "sql", "unix"]
  aws_managed_rules_exclusions = [
    "SizeRestrictions_BODY",  # Custom handling
    "GenericRFI_BODY"
  ]

  # Custom security rules
  custom_rules = [
    {
      name                  = "block-admin-paths"
      action               = "block"
      search_string        = "/admin"
      field_to_match       = "uri_path"
      text_transformation  = "LOWERCASE"
      positional_constraint = "STARTS_WITH"
    },
    {
      name                  = "monitor-api-calls"
      action               = "count"
      search_string        = "/api/v1"
      field_to_match       = "uri_path"
      text_transformation  = "LOWERCASE"
      positional_constraint = "STARTS_WITH"
    }
  ]

  # Threat intelligence
  enable_threat_intelligence    = true
  threat_intel_update_schedule = "rate(4 hours)"
  threat_intel_sources         = ["abuse.ch", "spamhaus", "emergingthreats"]

  # API Gateway security
  create_api_gateway_policy = true
  api_vpc_endpoint_only     = true
  api_vpc_endpoint_ids      = ["vpce-12345", "vpce-67890"]
  api_key_required_paths    = ["/api/admin/*", "/api/internal/*"]
  api_allowed_cidr_blocks   = ["10.0.0.0/8"]

  # Enhanced monitoring
  enable_waf_logging             = true
  create_cloudwatch_alarms       = true
  blocked_requests_threshold     = 50
  rate_limit_alarm_threshold     = 25
  log_retention_days            = 365
  kms_key_id                    = "arn:aws:kms:region:account:key/key-id"

  alarm_actions = [
    "arn:aws:sns:region:account:security-alerts"
  ]

  common_tags = {
    Environment        = "prod"
    DataClassification = "restricted"
    ComplianceScope    = "SOC2,PCI-DSS,HIPAA"
    SecurityTeam       = "enterprise-security"
    CostCenter         = "security-operations"
  }
}
```

### API-Only Security Configuration

```hcl
module "api_security" {
  source = "./modules/aws-waf-api-security"

  name_prefix  = "api"
  environment  = "prod"

  # Lightweight WAF for API-only protection
  waf_scope      = "REGIONAL"
  default_action = "allow"  # Less restrictive for APIs
  rate_limit     = 2000

  # API-specific protection
  managed_rule_sets = ["sql"]  # Focus on injection attacks

  # API Gateway integration
  api_gateway_stage_arn     = "arn:aws:apigateway:region::/restapis/api-id/stages/prod"
  create_api_gateway_policy = true
  api_key_required_paths    = ["/api/admin/*"]
  api_allowed_cidr_blocks   = ["10.0.0.0/8", "172.16.0.0/12"]

  # Basic monitoring
  enable_waf_logging       = true
  create_cloudwatch_alarms = true
}
```

## Configuration Options

### Core Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `name_prefix` | string | - | Name prefix for all resources |
| `environment` | string | - | Environment (dev/staging/prod) |
| `data_classification` | string | `"confidential"` | Data classification level |
| `compliance_frameworks` | list(string) | `["SOC2", "NIST"]` | Compliance frameworks |

### WAF Configuration

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `waf_scope` | string | `"REGIONAL"` | WAF scope (REGIONAL/CLOUDFRONT) |
| `default_action` | string | `"allow"` | Default WAF action |
| `rate_limit` | number | `2000` | Rate limit per 5-minute period |
| `max_request_size` | number | `8192` | Maximum request size in bytes |

### Security Controls

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `allowed_ip_addresses` | list(string) | `[]` | Allowed IP/CIDR blocks |
| `blocked_ip_addresses` | list(string) | `[]` | Blocked IP/CIDR blocks |
| `allowed_countries` | list(string) | `[]` | Allowed country codes |
| `blocked_countries` | list(string) | `[]` | Blocked country codes |
| `managed_rule_sets` | list(string) | `["linux", "sql"]` | AWS managed rule sets |

### API Security

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `create_api_gateway_policy` | bool | `false` | Create API Gateway resource policy |
| `api_vpc_endpoint_only` | bool | `false` | Restrict to VPC endpoints only |
| `api_key_required_paths` | list(string) | `[]` | Paths requiring API keys |
| `api_allowed_cidr_blocks` | list(string) | `[]` | Allowed CIDR blocks for API |

### Monitoring

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `enable_waf_logging` | bool | `true` | Enable WAF logging |
| `create_cloudwatch_alarms` | bool | `true` | Create CloudWatch alarms |
| `log_retention_days` | number | `30` | Log retention period |
| `kms_key_id` | string | `""` | KMS key for encryption |

## Outputs

### WAF Information
- `web_acl_id` - WAF Web ACL ID
- `web_acl_arn` - WAF Web ACL ARN
- `web_acl_name` - WAF Web ACL name
- `web_acl_capacity` - WAF capacity units used

### Security Assessment
- `security_score` - Overall security score (0-100)
- `security_score_breakdown` - Detailed score breakdown
- `compliance_status` - Compliance status by framework
- `validation_report` - Comprehensive validation report

### Monitoring
- `cloudwatch_log_group_name` - CloudWatch log group name
- `blocked_requests_alarm_arn` - Blocked requests alarm ARN
- `rate_limit_alarm_arn` - Rate limit alarm ARN

### Threat Intelligence
- `threat_intel_lambda_function_name` - Threat intelligence Lambda name
- `threat_intel_lambda_function_arn` - Threat intelligence Lambda ARN

## Security Features

### 🔒 Zero-Trust Security Model
- Default deny policies with explicit allow rules
- Principle of least privilege access
- Defense in depth with multiple security layers
- Continuous monitoring and validation

### 🌍 Geographic Protection
- Country-based blocking and allowing
- Regional threat intelligence integration
- Compliance with data sovereignty requirements
- Customizable geographic policies

### 🤖 Automated Threat Protection
- Real-time threat intelligence updates
- Automated IP reputation management
- Machine learning-based anomaly detection
- Incident response automation

### 📋 Compliance Automation
- Multi-framework compliance validation
- Automated compliance reporting
- Gap analysis and remediation guidance
- Audit trail and evidence collection

## Compliance Support

### SOC2 Type II
- Access controls and monitoring
- Security incident management
- Change management processes
- Vendor management controls

### NIST Cybersecurity Framework
- Identify, Protect, Detect, Respond, Recover
- Risk management and assessment
- Security awareness and training
- Incident response planning

### CIS Controls
- Inventory and control of assets
- Continuous vulnerability management
- Controlled use of administrative privileges
- Boundary defense mechanisms

### PCI-DSS
- Network segmentation and access control
- Strong cryptography and security protocols
- Regular monitoring and testing
- Incident response procedures

### HIPAA
- Administrative, physical, and technical safeguards
- Access control and audit controls
- Integrity and transmission security
- Business associate agreements

### FedRAMP
- Federal security requirements
- Continuous monitoring and assessment
- Supply chain risk management
- Incident response and recovery

## Best Practices

### 🏗️ Implementation
1. **Start with restrictive policies** and gradually open access
2. **Enable comprehensive logging** for security monitoring
3. **Use managed rule sets** for baseline protection
4. **Implement rate limiting** appropriate for your traffic
5. **Regular security assessment** and tuning

### 🔧 Configuration
1. **Use KMS encryption** for all log data
2. **Configure proper CIDR blocks** for network access
3. **Enable threat intelligence** for automated protection
4. **Set up CloudWatch alarms** for security monitoring
5. **Regular policy review** and updates

### 📊 Monitoring
1. **Monitor blocked request patterns** for threat analysis
2. **Set up alerting** for security incidents
3. **Regular compliance assessment** and reporting
4. **Performance impact analysis** of security rules
5. **Incident response planning** and testing

### 🔄 Maintenance
1. **Regular rule review** and optimization
2. **Threat intelligence updates** and tuning
3. **Compliance framework updates** as requirements change
4. **Security testing** and validation
5. **Documentation updates** and training

## Cost Optimization

### 💰 Cost Components
- **WAF Web ACL**: $1.00/month (fixed)
- **Rule evaluations**: $0.60 per million requests
- **Request charges**: $0.60 per million requests
- **Logging**: Variable based on log volume
- **Lambda execution**: Variable based on threat intel updates

### 📉 Optimization Strategies
1. **Right-size rule complexity** based on threat model
2. **Optimize logging verbosity** for cost vs. security balance
3. **Use managed rules efficiently** to reduce custom rule overhead
4. **Monitor and tune rate limits** to balance security and cost
5. **Regular cost analysis** and optimization

## Security Considerations

### ⚠️ Important Notes
- WAF rules are evaluated in order of priority
- Rate limiting is per IP address across all rules
- Geographic blocking may impact legitimate users
- Custom rules require careful testing to avoid false positives
- Threat intelligence sources may have different update frequencies

### 🔐 Security Recommendations
1. **Enable encryption** for all log data
2. **Use separate IP sets** for different security policies
3. **Implement proper RBAC** for WAF management
4. **Regular security testing** including penetration testing
5. **Incident response procedures** for security events

## Troubleshooting

### Common Issues
1. **False positives** - Review and tune security rules
2. **Performance impact** - Optimize rule complexity and order
3. **Blocked legitimate traffic** - Adjust geographic and IP restrictions
4. **High costs** - Optimize logging and rule efficiency
5. **Compliance gaps** - Review validation report and implement recommendations

### Debugging
1. **Check WAF logs** for blocked requests and patterns
2. **Monitor CloudWatch metrics** for performance impact
3. **Review security scores** and compliance status
4. **Test rule changes** in staging environment first
5. **Use AWS WAF sandbox** for rule testing

## Support

For issues, questions, or contributions:
- Review the validation report for configuration guidance
- Check CloudWatch logs for operational issues
- Monitor security scores for compliance status
- Follow AWS WAF best practices documentation
- Implement regular security assessments