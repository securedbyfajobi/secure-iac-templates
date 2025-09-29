# Variables for AWS WAF and API Security Module

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

variable "data_classification" {
  description = "Data classification level"
  type        = string
  default     = "confidential"
  validation {
    condition     = contains(["public", "internal", "confidential", "restricted"], var.data_classification)
    error_message = "Data classification must be one of: public, internal, confidential, restricted."
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
# WAF CONFIGURATION
# =============================================================================

variable "waf_scope" {
  description = "Scope of the WAF (CLOUDFRONT or REGIONAL)"
  type        = string
  default     = "REGIONAL"
  validation {
    condition     = contains(["CLOUDFRONT", "REGIONAL"], var.waf_scope)
    error_message = "WAF scope must be either CLOUDFRONT or REGIONAL."
  }
}

variable "default_action" {
  description = "Default action for the WAF (allow or block)"
  type        = string
  default     = "allow"
  validation {
    condition     = contains(["allow", "block"], var.default_action)
    error_message = "Default action must be either 'allow' or 'block'."
  }
}

variable "rate_limit" {
  description = "Rate limit for requests per 5-minute period from a single IP"
  type        = number
  default     = 2000
  validation {
    condition     = var.rate_limit >= 100 && var.rate_limit <= 2000000000
    error_message = "Rate limit must be between 100 and 2,000,000,000."
  }
}

variable "rate_limit_uri_path" {
  description = "URI path to apply rate limiting to (empty for all paths)"
  type        = string
  default     = ""
}

variable "max_request_size" {
  description = "Maximum request size in bytes"
  type        = number
  default     = 8192
  validation {
    condition     = var.max_request_size >= 1024 && var.max_request_size <= 104857600
    error_message = "Max request size must be between 1KB and 100MB."
  }
}

# =============================================================================
# IP AND GEOGRAPHIC RESTRICTIONS
# =============================================================================

variable "allowed_ip_addresses" {
  description = "List of IP addresses/CIDR blocks to allow"
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for ip in var.allowed_ip_addresses : can(cidrhost(ip, 0))
    ])
    error_message = "All IP addresses must be valid CIDR blocks."
  }
}

variable "blocked_ip_addresses" {
  description = "List of IP addresses/CIDR blocks to block"
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for ip in var.blocked_ip_addresses : can(cidrhost(ip, 0))
    ])
    error_message = "All IP addresses must be valid CIDR blocks."
  }
}

variable "allowed_countries" {
  description = "List of country codes to allow (ISO 3166-1 alpha-2)"
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for country in var.allowed_countries : length(country) == 2
    ])
    error_message = "Country codes must be 2-character ISO 3166-1 alpha-2 codes."
  }
}

variable "blocked_countries" {
  description = "List of country codes to block (ISO 3166-1 alpha-2)"
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for country in var.blocked_countries : length(country) == 2
    ])
    error_message = "Country codes must be 2-character ISO 3166-1 alpha-2 codes."
  }
}

# =============================================================================
# MANAGED RULE SETS
# =============================================================================

variable "managed_rule_sets" {
  description = "List of AWS managed rule sets to enable"
  type        = list(string)
  default     = ["linux", "sql"]
  validation {
    condition = alltrue([
      for rule_set in var.managed_rule_sets :
      contains(["linux", "windows", "php", "wordpress", "sql", "unix"], rule_set)
    ])
    error_message = "Managed rule sets must be from: linux, windows, php, wordpress, sql, unix."
  }
}

variable "aws_managed_rules_exclusions" {
  description = "List of AWS managed rules to exclude"
  type        = list(string)
  default     = []
}

# =============================================================================
# CUSTOM RULES
# =============================================================================

variable "custom_rules" {
  description = "List of custom WAF rules"
  type = list(object({
    name                  = string
    action               = string
    search_string        = string
    field_to_match       = string
    text_transformation  = string
    positional_constraint = string
  }))
  default = []
  validation {
    condition = alltrue([
      for rule in var.custom_rules :
      contains(["allow", "block", "count"], rule.action)
    ])
    error_message = "Custom rule actions must be 'allow', 'block', or 'count'."
  }
}

# =============================================================================
# RESOURCE ASSOCIATIONS
# =============================================================================

variable "alb_arn" {
  description = "ARN of the Application Load Balancer to associate with WAF"
  type        = string
  default     = ""
}

variable "api_gateway_stage_arn" {
  description = "ARN of the API Gateway stage to associate with WAF"
  type        = string
  default     = ""
}

variable "cloudfront_distribution_id" {
  description = "CloudFront distribution ID to associate with WAF"
  type        = string
  default     = ""
}

# =============================================================================
# API GATEWAY SECURITY
# =============================================================================

variable "create_api_gateway_policy" {
  description = "Create resource policy for API Gateway"
  type        = bool
  default     = false
}

variable "api_allowed_cidr_blocks" {
  description = "CIDR blocks allowed to access API Gateway"
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for cidr in var.api_allowed_cidr_blocks : can(cidrhost(cidr, 0))
    ])
    error_message = "All CIDR blocks must be valid IPv4 CIDR blocks."
  }
}

variable "api_blocked_cidr_blocks" {
  description = "CIDR blocks blocked from accessing API Gateway"
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for cidr in var.api_blocked_cidr_blocks : can(cidrhost(cidr, 0))
    ])
    error_message = "All CIDR blocks must be valid IPv4 CIDR blocks."
  }
}

variable "api_key_required_paths" {
  description = "API paths that require API key authentication"
  type        = list(string)
  default     = []
}

variable "api_vpc_endpoint_only" {
  description = "Restrict API Gateway access to VPC endpoints only"
  type        = bool
  default     = false
}

variable "api_vpc_endpoint_ids" {
  description = "List of VPC endpoint IDs allowed to access API Gateway"
  type        = list(string)
  default     = []
}

# =============================================================================
# LOGGING AND MONITORING
# =============================================================================

variable "enable_waf_logging" {
  description = "Enable WAF logging to CloudWatch"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "CloudWatch log retention period in days"
  type        = number
  default     = 30
  validation {
    condition = contains([
      1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653
    ], var.log_retention_days)
    error_message = "Log retention days must be a valid CloudWatch retention period."
  }
}

variable "kms_key_id" {
  description = "KMS key ID for encrypting logs"
  type        = string
  default     = ""
}

variable "create_cloudwatch_alarms" {
  description = "Create CloudWatch alarms for WAF monitoring"
  type        = bool
  default     = true
}

variable "blocked_requests_threshold" {
  description = "Threshold for blocked requests alarm"
  type        = number
  default     = 100
}

variable "rate_limit_alarm_threshold" {
  description = "Threshold for rate limit alarm"
  type        = number
  default     = 50
}

variable "alarm_actions" {
  description = "List of ARNs to notify when alarms trigger"
  type        = list(string)
  default     = []
}

# =============================================================================
# THREAT INTELLIGENCE
# =============================================================================

variable "enable_threat_intelligence" {
  description = "Enable automatic threat intelligence updates"
  type        = bool
  default     = false
}

variable "threat_intel_update_schedule" {
  description = "Schedule expression for threat intelligence updates"
  type        = string
  default     = "rate(6 hours)"
}

variable "threat_intel_sources" {
  description = "List of threat intelligence sources"
  type        = list(string)
  default     = ["abuse.ch", "spamhaus", "emergingthreats"]
}

# =============================================================================
# TAGGING
# =============================================================================

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Terraform   = "true"
    Module      = "aws-waf-api-security"
    Owner       = ""
    Project     = ""
    CostCenter  = ""
    Environment = ""
  }
}