# Variables for AWS Zero-Trust Network Architecture Module

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

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid IPv4 CIDR block."
  }
}

variable "max_azs" {
  description = "Maximum number of Availability Zones to use"
  type        = number
  default     = 3
  validation {
    condition     = var.max_azs >= 2 && var.max_azs <= 6
    error_message = "Max AZs must be between 2 and 6."
  }
}

variable "instance_tenancy" {
  description = "Instance tenancy for the VPC"
  type        = string
  default     = "default"
  validation {
    condition     = contains(["default", "dedicated"], var.instance_tenancy)
    error_message = "Instance tenancy must be either 'default' or 'dedicated'."
  }
}

# =============================================================================
# NETWORK FEATURES
# =============================================================================

variable "enable_nat_gateway" {
  description = "Enable NAT Gateway for private subnets"
  type        = bool
  default     = true
}

variable "enable_ipv6" {
  description = "Enable IPv6 support"
  type        = bool
  default     = false
}

variable "enable_management_subnets" {
  description = "Create dedicated management/admin subnets"
  type        = bool
  default     = true
}

variable "enable_vpc_endpoints" {
  description = "Enable VPC endpoints for AWS services"
  type        = bool
  default     = true
}

variable "enable_custom_dhcp_options" {
  description = "Enable custom DHCP options"
  type        = bool
  default     = false
}

# =============================================================================
# SECURITY AND MONITORING
# =============================================================================

variable "enable_flow_logs" {
  description = "Enable VPC Flow Logs"
  type        = bool
  default     = true
}

variable "flow_log_format" {
  description = "Flow log format"
  type        = string
  default     = "$${version} $${account-id} $${interface-id} $${srcaddr} $${dstaddr} $${srcport} $${dstport} $${protocol} $${packets} $${bytes} $${windowstart} $${windowend} $${action} $${flowlogstatus} $${vpc-id} $${subnet-id} $${instance-id} $${tcp-flags} $${type} $${pkt-srcaddr} $${pkt-dstaddr} $${region} $${az-id} $${sublocation-type} $${sublocation-id}"
}

variable "enable_cloudwatch_alarms" {
  description = "Enable CloudWatch alarms for network monitoring"
  type        = bool
  default     = true
}

variable "rejected_connections_threshold" {
  description = "Threshold for rejected connections alarm"
  type        = number
  default     = 100
}

variable "unusual_traffic_threshold" {
  description = "Threshold for unusual traffic pattern alarm (bytes)"
  type        = number
  default     = 1000000000 # 1GB
}

variable "alarm_actions" {
  description = "List of ARNs to notify when alarm triggers"
  type        = list(string)
  default     = []
}

# =============================================================================
# DHCP OPTIONS
# =============================================================================

variable "custom_dns_servers" {
  description = "List of custom DNS servers"
  type        = list(string)
  default     = ["AmazonProvidedDNS"]
  validation {
    condition = alltrue([
      for server in var.custom_dns_servers :
      server == "AmazonProvidedDNS" || can(regex("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$", server))
    ])
    error_message = "DNS servers must be valid IP addresses or 'AmazonProvidedDNS'."
  }
}

variable "domain_name" {
  description = "Domain name for DHCP options"
  type        = string
  default     = ""
}

variable "ntp_servers" {
  description = "List of NTP servers"
  type        = list(string)
  default     = []
}

# =============================================================================
# COMPLIANCE AND FRAMEWORKS
# =============================================================================

variable "compliance_frameworks" {
  description = "List of compliance frameworks to adhere to"
  type        = list(string)
  default     = ["SOC2", "NIST", "CIS"]
  validation {
    condition = alltrue([
      for framework in var.compliance_frameworks :
      contains(["SOC2", "NIST", "CIS", "PCI-DSS", "HIPAA", "FedRAMP", "ISO27001"], framework)
    ])
    error_message = "Compliance frameworks must be from: SOC2, NIST, CIS, PCI-DSS, HIPAA, FedRAMP, ISO27001."
  }
}

variable "data_classification" {
  description = "Data classification level for the VPC"
  type        = string
  default     = "internal"
  validation {
    condition     = contains(["public", "internal", "confidential", "restricted"], var.data_classification)
    error_message = "Data classification must be one of: public, internal, confidential, restricted."
  }
}

# =============================================================================
# COST OPTIMIZATION
# =============================================================================

variable "cost_optimization_level" {
  description = "Level of cost optimization (low, medium, high)"
  type        = string
  default     = "medium"
  validation {
    condition     = contains(["low", "medium", "high"], var.cost_optimization_level)
    error_message = "Cost optimization level must be: low, medium, or high."
  }
}

variable "enable_spot_instances" {
  description = "Allow use of spot instances for non-critical workloads"
  type        = bool
  default     = false
}

# =============================================================================
# DISASTER RECOVERY
# =============================================================================

variable "enable_cross_region_backup" {
  description = "Enable cross-region backup for critical resources"
  type        = bool
  default     = false
}

variable "backup_region" {
  description = "Secondary region for disaster recovery"
  type        = string
  default     = ""
}

variable "rpo_hours" {
  description = "Recovery Point Objective in hours"
  type        = number
  default     = 24
  validation {
    condition     = var.rpo_hours >= 1 && var.rpo_hours <= 168
    error_message = "RPO must be between 1 and 168 hours."
  }
}

variable "rto_hours" {
  description = "Recovery Time Objective in hours"
  type        = number
  default     = 4
  validation {
    condition     = var.rto_hours >= 1 && var.rto_hours <= 72
    error_message = "RTO must be between 1 and 72 hours."
  }
}

# =============================================================================
# TAGGING
# =============================================================================

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Terraform   = "true"
    Module      = "aws-zero-trust-network"
    Owner       = ""
    Project     = ""
    CostCenter  = ""
    Environment = ""
  }
}

# =============================================================================
# NETWORK SECURITY GROUPS
# =============================================================================

variable "enable_strict_security_groups" {
  description = "Enable strict security group rules (deny by default)"
  type        = bool
  default     = true
}

variable "allowed_ssh_cidrs" {
  description = "CIDR blocks allowed for SSH access"
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for cidr in var.allowed_ssh_cidrs : can(cidrhost(cidr, 0))
    ])
    error_message = "All SSH CIDRs must be valid IPv4 CIDR blocks."
  }
}

variable "allowed_rdp_cidrs" {
  description = "CIDR blocks allowed for RDP access"
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for cidr in var.allowed_rdp_cidrs : can(cidrhost(cidr, 0))
    ])
    error_message = "All RDP CIDRs must be valid IPv4 CIDR blocks."
  }
}

# =============================================================================
# ADVANCED NETWORKING
# =============================================================================

variable "enable_transit_gateway" {
  description = "Enable Transit Gateway for multi-VPC connectivity"
  type        = bool
  default     = false
}

variable "transit_gateway_id" {
  description = "Existing Transit Gateway ID to attach to"
  type        = string
  default     = ""
}

variable "enable_direct_connect" {
  description = "Enable AWS Direct Connect integration"
  type        = bool
  default     = false
}

variable "direct_connect_gateway_id" {
  description = "Direct Connect Gateway ID"
  type        = string
  default     = ""
}

variable "enable_vpn_gateway" {
  description = "Enable VPN Gateway for hybrid connectivity"
  type        = bool
  default     = false
}

# =============================================================================
# SECURITY MONITORING
# =============================================================================

variable "enable_security_hub" {
  description = "Enable AWS Security Hub integration"
  type        = bool
  default     = true
}

variable "enable_guard_duty" {
  description = "Enable AWS GuardDuty integration"
  type        = bool
  default     = true
}

variable "enable_config_rules" {
  description = "Enable AWS Config rules for compliance"
  type        = bool
  default     = true
}

variable "security_notification_topics" {
  description = "SNS topics for security notifications"
  type        = list(string)
  default     = []
}

# =============================================================================
# PERFORMANCE AND SCALING
# =============================================================================

variable "enable_enhanced_networking" {
  description = "Enable enhanced networking features"
  type        = bool
  default     = true
}

variable "enable_placement_groups" {
  description = "Create placement groups for high-performance workloads"
  type        = bool
  default     = false
}

variable "bandwidth_requirements" {
  description = "Bandwidth requirements for the network (Mbps)"
  type        = number
  default     = 1000
  validation {
    condition     = var.bandwidth_requirements >= 100 && var.bandwidth_requirements <= 100000
    error_message = "Bandwidth requirements must be between 100 and 100,000 Mbps."
  }
}

# =============================================================================
# ENCRYPTION
# =============================================================================

variable "enable_encryption_in_transit" {
  description = "Enable encryption in transit for all communications"
  type        = bool
  default     = true
}

variable "kms_key_rotation" {
  description = "Enable automatic KMS key rotation"
  type        = bool
  default     = true
}

variable "encryption_algorithm" {
  description = "Encryption algorithm for data at rest"
  type        = string
  default     = "AES256"
  validation {
    condition     = contains(["AES256", "aws:kms"], var.encryption_algorithm)
    error_message = "Encryption algorithm must be either 'AES256' or 'aws:kms'."
  }
}