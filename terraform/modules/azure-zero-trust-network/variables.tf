# Variables for Azure Zero-Trust Network Architecture Module

# =============================================================================
# BASIC CONFIGURATION
# =============================================================================

variable "name_prefix" {
  description = "Name prefix for all resources"
  type        = string
  validation {
    condition     = length(var.name_prefix) <= 15 && can(regex("^[a-zA-Z][a-zA-Z0-9-]*$", var.name_prefix))
    error_message = "Name prefix must be <= 15 characters and start with a letter."
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

variable "primary_location" {
  description = "Primary Azure region for resources"
  type        = string
  default     = "East US"
}

variable "vnet_address_space" {
  description = "Address space for the virtual network"
  type        = string
  default     = "10.0.0.0/16"
  validation {
    condition     = can(cidrhost(var.vnet_address_space, 0))
    error_message = "VNet address space must be a valid IPv4 CIDR block."
  }
}

# =============================================================================
# NETWORK FEATURES
# =============================================================================

variable "enable_ddos_protection" {
  description = "Enable DDoS Protection Standard"
  type        = bool
  default     = true
}

variable "enable_bastion" {
  description = "Enable Azure Bastion for secure remote access"
  type        = bool
  default     = true
}

variable "bastion_sku" {
  description = "SKU for Azure Bastion"
  type        = string
  default     = "Standard"
  validation {
    condition     = contains(["Basic", "Standard"], var.bastion_sku)
    error_message = "Bastion SKU must be either 'Basic' or 'Standard'."
  }
}

variable "enable_azure_firewall" {
  description = "Enable Azure Firewall for network security"
  type        = bool
  default     = true
}

variable "firewall_sku_tier" {
  description = "SKU tier for Azure Firewall"
  type        = string
  default     = "Standard"
  validation {
    condition     = contains(["Standard", "Premium"], var.firewall_sku_tier)
    error_message = "Firewall SKU tier must be either 'Standard' or 'Premium'."
  }
}

variable "enable_private_dns" {
  description = "Enable private DNS zone"
  type        = bool
  default     = true
}

variable "private_dns_zone_name" {
  description = "Name for the private DNS zone"
  type        = string
  default     = "internal.local"
}

variable "enable_sql_managed_instance" {
  description = "Enable SQL Managed Instance delegation on data subnet"
  type        = bool
  default     = false
}

# =============================================================================
# SECURITY AND MONITORING
# =============================================================================

variable "enable_network_watcher" {
  description = "Enable Network Watcher for monitoring"
  type        = bool
  default     = true
}

variable "enable_flow_logs" {
  description = "Enable NSG Flow Logs"
  type        = bool
  default     = true
}

variable "flow_log_retention_days" {
  description = "Retention period for NSG flow logs in days"
  type        = number
  default     = 30
  validation {
    condition     = var.flow_log_retention_days >= 1 && var.flow_log_retention_days <= 365
    error_message = "Flow log retention must be between 1 and 365 days."
  }
}

variable "enable_traffic_analytics" {
  description = "Enable Traffic Analytics for NSG flow logs"
  type        = bool
  default     = true
}

variable "enable_security_monitoring" {
  description = "Enable security monitoring with Log Analytics"
  type        = bool
  default     = true
}

variable "log_analytics_retention_days" {
  description = "Retention period for Log Analytics in days"
  type        = number
  default     = 90
  validation {
    condition     = var.log_analytics_retention_days >= 30 && var.log_analytics_retention_days <= 730
    error_message = "Log Analytics retention must be between 30 and 730 days."
  }
}

variable "management_allowed_ips" {
  description = "List of IP addresses allowed to access management subnet"
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for ip in var.management_allowed_ips : can(regex("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?$", ip))
    ])
    error_message = "All management IPs must be valid IPv4 addresses or CIDR blocks."
  }
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
  description = "Data classification level for the network"
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

# =============================================================================
# KEY VAULT
# =============================================================================

variable "enable_key_vault" {
  description = "Enable Azure Key Vault for secrets management"
  type        = bool
  default     = true
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
  default     = "West US"
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
    Module      = "azure-zero-trust-network"
    Owner       = ""
    Project     = ""
    CostCenter  = ""
    Environment = ""
  }
}

# =============================================================================
# ADVANCED NETWORKING
# =============================================================================

variable "enable_express_route" {
  description = "Enable ExpressRoute connectivity"
  type        = bool
  default     = false
}

variable "express_route_circuit_id" {
  description = "ExpressRoute circuit ID for hybrid connectivity"
  type        = string
  default     = ""
}

variable "enable_vpn_gateway" {
  description = "Enable VPN Gateway for site-to-site connectivity"
  type        = bool
  default     = false
}

variable "vpn_gateway_sku" {
  description = "SKU for VPN Gateway"
  type        = string
  default     = "VpnGw2"
  validation {
    condition     = contains(["VpnGw1", "VpnGw2", "VpnGw3", "VpnGw4", "VpnGw5"], var.vpn_gateway_sku)
    error_message = "VPN Gateway SKU must be one of: VpnGw1, VpnGw2, VpnGw3, VpnGw4, VpnGw5."
  }
}

# =============================================================================
# SECURITY FEATURES
# =============================================================================

variable "enable_microsoft_defender" {
  description = "Enable Microsoft Defender for Cloud"
  type        = bool
  default     = true
}

variable "enable_azure_policy" {
  description = "Enable Azure Policy for governance"
  type        = bool
  default     = true
}

variable "enable_sentinel" {
  description = "Enable Azure Sentinel for SIEM"
  type        = bool
  default     = false
}

variable "security_contact_email" {
  description = "Email address for security notifications"
  type        = string
  default     = ""
}

# =============================================================================
# PERFORMANCE AND SCALING
# =============================================================================

variable "enable_accelerated_networking" {
  description = "Enable accelerated networking for VMs"
  type        = bool
  default     = true
}

variable "enable_proximity_placement_groups" {
  description = "Create proximity placement groups for low latency"
  type        = bool
  default     = false
}

variable "bandwidth_requirements_gbps" {
  description = "Bandwidth requirements in Gbps"
  type        = number
  default     = 1
  validation {
    condition     = var.bandwidth_requirements_gbps >= 1 && var.bandwidth_requirements_gbps <= 100
    error_message = "Bandwidth requirements must be between 1 and 100 Gbps."
  }
}

# =============================================================================
# ENCRYPTION AND SECURITY
# =============================================================================

variable "enable_disk_encryption" {
  description = "Enable disk encryption for all VMs"
  type        = bool
  default     = true
}

variable "enable_double_encryption" {
  description = "Enable double encryption for highly sensitive data"
  type        = bool
  default     = false
}

variable "key_vault_key_size" {
  description = "Key size for Key Vault keys (2048, 3072, 4096)"
  type        = number
  default     = 2048
  validation {
    condition     = contains([2048, 3072, 4096], var.key_vault_key_size)
    error_message = "Key size must be 2048, 3072, or 4096."
  }
}

# =============================================================================
# NETWORK SECURITY
# =============================================================================

variable "enable_waf" {
  description = "Enable Web Application Firewall"
  type        = bool
  default     = true
}

variable "waf_mode" {
  description = "WAF mode (Detection or Prevention)"
  type        = string
  default     = "Prevention"
  validation {
    condition     = contains(["Detection", "Prevention"], var.waf_mode)
    error_message = "WAF mode must be either 'Detection' or 'Prevention'."
  }
}

variable "enable_custom_rules" {
  description = "Enable custom firewall rules"
  type        = bool
  default     = true
}

variable "allowed_source_ips" {
  description = "List of allowed source IP ranges for external access"
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for ip in var.allowed_source_ips : can(regex("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?$", ip))
    ])
    error_message = "All source IPs must be valid IPv4 addresses or CIDR blocks."
  }
}

# =============================================================================
# MONITORING AND ALERTING
# =============================================================================

variable "enable_application_insights" {
  description = "Enable Application Insights for application monitoring"
  type        = bool
  default     = true
}

variable "enable_service_map" {
  description = "Enable Service Map for dependency tracking"
  type        = bool
  default     = true
}

variable "alert_email_addresses" {
  description = "List of email addresses for alerts"
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for email in var.alert_email_addresses : can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", email))
    ])
    error_message = "All email addresses must be valid."
  }
}

variable "metric_alert_criteria" {
  description = "Criteria for metric alerts"
  type = object({
    cpu_threshold_percent    = number
    memory_threshold_percent = number
    disk_threshold_percent   = number
    network_threshold_mbps   = number
  })
  default = {
    cpu_threshold_percent    = 80
    memory_threshold_percent = 85
    disk_threshold_percent   = 90
    network_threshold_mbps   = 100
  }
}

# =============================================================================
# BACKUP AND RECOVERY
# =============================================================================

variable "enable_backup_vault" {
  description = "Enable Azure Backup vault"
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Backup retention period in days"
  type        = number
  default     = 30
  validation {
    condition     = var.backup_retention_days >= 7 && var.backup_retention_days <= 9999
    error_message = "Backup retention must be between 7 and 9999 days."
  }
}

variable "enable_geo_redundant_backup" {
  description = "Enable geo-redundant backup"
  type        = bool
  default     = true
}

# =============================================================================
# INTEGRATION AND APIS
# =============================================================================

variable "enable_api_management" {
  description = "Enable API Management for API gateway"
  type        = bool
  default     = false
}

variable "api_management_sku" {
  description = "SKU for API Management"
  type        = string
  default     = "Developer"
  validation {
    condition     = contains(["Consumption", "Developer", "Basic", "Standard", "Premium"], var.api_management_sku)
    error_message = "API Management SKU must be one of: Consumption, Developer, Basic, Standard, Premium."
  }
}

variable "enable_service_bus" {
  description = "Enable Azure Service Bus for messaging"
  type        = bool
  default     = false
}

variable "service_bus_sku" {
  description = "SKU for Service Bus"
  type        = string
  default     = "Standard"
  validation {
    condition     = contains(["Basic", "Standard", "Premium"], var.service_bus_sku)
    error_message = "Service Bus SKU must be one of: Basic, Standard, Premium."
  }
}