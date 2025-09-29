# Variables for Google Cloud Zero-Trust Network Architecture Module

# =============================================================================
# BASIC CONFIGURATION
# =============================================================================

variable "project_id" {
  description = "Google Cloud Project ID"
  type        = string
}

variable "name_prefix" {
  description = "Name prefix for all resources"
  type        = string
  validation {
    condition     = length(var.name_prefix) <= 20 && can(regex("^[a-z][a-z0-9-]*$", var.name_prefix))
    error_message = "Name prefix must be <= 20 characters, start with a letter, and contain only lowercase letters, numbers, and hyphens."
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

variable "region" {
  description = "Google Cloud region for resources"
  type        = string
  default     = "us-central1"
}

# =============================================================================
# NETWORK CONFIGURATION
# =============================================================================

variable "network_mtu" {
  description = "MTU size for the VPC network"
  type        = number
  default     = 1460
  validation {
    condition     = var.network_mtu >= 1460 && var.network_mtu <= 8896
    error_message = "Network MTU must be between 1460 and 8896."
  }
}

variable "enable_ipv6" {
  description = "Enable IPv6 support"
  type        = bool
  default     = false
}

# =============================================================================
# SUBNET CONFIGURATION
# =============================================================================

variable "dmz_subnet_cidr" {
  description = "CIDR block for DMZ subnet"
  type        = string
  default     = "10.0.1.0/24"
  validation {
    condition     = can(cidrhost(var.dmz_subnet_cidr, 0))
    error_message = "DMZ subnet CIDR must be a valid IPv4 CIDR block."
  }
}

variable "web_subnet_cidr" {
  description = "CIDR block for web tier subnet"
  type        = string
  default     = "10.0.2.0/24"
  validation {
    condition     = can(cidrhost(var.web_subnet_cidr, 0))
    error_message = "Web subnet CIDR must be a valid IPv4 CIDR block."
  }
}

variable "app_subnet_cidr" {
  description = "CIDR block for application tier subnet"
  type        = string
  default     = "10.0.3.0/24"
  validation {
    condition     = can(cidrhost(var.app_subnet_cidr, 0))
    error_message = "App subnet CIDR must be a valid IPv4 CIDR block."
  }
}

variable "data_subnet_cidr" {
  description = "CIDR block for data tier subnet"
  type        = string
  default     = "10.0.4.0/24"
  validation {
    condition     = can(cidrhost(var.data_subnet_cidr, 0))
    error_message = "Data subnet CIDR must be a valid IPv4 CIDR block."
  }
}

variable "management_subnet_cidr" {
  description = "CIDR block for management subnet"
  type        = string
  default     = "10.0.5.0/24"
  validation {
    condition     = can(cidrhost(var.management_subnet_cidr, 0))
    error_message = "Management subnet CIDR must be a valid IPv4 CIDR block."
  }
}

# =============================================================================
# GKE CONFIGURATION
# =============================================================================

variable "enable_gke" {
  description = "Enable GKE cluster support with secondary IP ranges"
  type        = bool
  default     = false
}

variable "gke_pod_cidr_web" {
  description = "CIDR block for GKE pods in web tier"
  type        = string
  default     = "172.16.0.0/16"
}

variable "gke_service_cidr_web" {
  description = "CIDR block for GKE services in web tier"
  type        = string
  default     = "172.20.0.0/16"
}

variable "gke_pod_cidr_app" {
  description = "CIDR block for GKE pods in app tier"
  type        = string
  default     = "172.17.0.0/16"
}

variable "gke_service_cidr_app" {
  description = "CIDR block for GKE services in app tier"
  type        = string
  default     = "172.21.0.0/16"
}

# =============================================================================
# CLOUD NAT
# =============================================================================

variable "enable_cloud_nat" {
  description = "Enable Cloud NAT for outbound internet access"
  type        = bool
  default     = true
}

variable "nat_ip_count" {
  description = "Number of static IP addresses for Cloud NAT"
  type        = number
  default     = 2
  validation {
    condition     = var.nat_ip_count >= 1 && var.nat_ip_count <= 16
    error_message = "NAT IP count must be between 1 and 16."
  }
}

# =============================================================================
# SECURITY FEATURES
# =============================================================================

variable "enable_cloud_armor" {
  description = "Enable Cloud Armor security policies"
  type        = bool
  default     = true
}

variable "allowed_countries" {
  description = "List of country codes allowed to access resources"
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for country in var.allowed_countries : length(country) == 2
    ])
    error_message = "Country codes must be 2-character ISO country codes."
  }
}

variable "blocked_ip_ranges" {
  description = "List of IP ranges to block"
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for ip in var.blocked_ip_ranges : can(cidrhost(ip, 0))
    ])
    error_message = "All blocked IP ranges must be valid IPv4 CIDR blocks."
  }
}

variable "rate_limit_threshold" {
  description = "Rate limit threshold (requests per minute)"
  type        = number
  default     = 100
  validation {
    condition     = var.rate_limit_threshold >= 10 && var.rate_limit_threshold <= 10000
    error_message = "Rate limit threshold must be between 10 and 10000."
  }
}

variable "enable_private_service_connect" {
  description = "Enable Private Service Connect for Google APIs"
  type        = bool
  default     = true
}

variable "enable_binary_authorization" {
  description = "Enable Binary Authorization for container security"
  type        = bool
  default     = false
}

variable "pgp_public_key" {
  description = "PGP public key for Binary Authorization attestor"
  type        = string
  default     = ""
}

# =============================================================================
# ENCRYPTION AND KMS
# =============================================================================

variable "enable_kms" {
  description = "Enable Cloud KMS for encryption"
  type        = bool
  default     = true
}

# =============================================================================
# MONITORING AND LOGGING
# =============================================================================

variable "enable_flow_logs_export" {
  description = "Enable export of VPC Flow Logs to Cloud Storage"
  type        = bool
  default     = true
}

variable "flow_logs_retention_days" {
  description = "Retention period for flow logs in days"
  type        = number
  default     = 30
  validation {
    condition     = var.flow_logs_retention_days >= 1 && var.flow_logs_retention_days <= 365
    error_message = "Flow logs retention must be between 1 and 365 days."
  }
}

variable "enable_monitoring_alerts" {
  description = "Enable monitoring and alerting"
  type        = bool
  default     = true
}

variable "notification_channels" {
  description = "List of notification channels for alerts"
  type        = list(string)
  default     = []
}

variable "denied_traffic_threshold" {
  description = "Threshold for denied traffic alerts"
  type        = number
  default     = 100
}

variable "suspicious_activity_threshold" {
  description = "Threshold for suspicious activity alerts"
  type        = number
  default     = 1000
}

# =============================================================================
# DNS CONFIGURATION
# =============================================================================

variable "enable_private_dns" {
  description = "Enable private DNS zone"
  type        = bool
  default     = true
}

variable "private_dns_name" {
  description = "Private DNS zone name"
  type        = string
  default     = "internal.local."
  validation {
    condition     = can(regex("^[a-z0-9.-]+\\.$", var.private_dns_name))
    error_message = "Private DNS name must be a valid domain name ending with a dot."
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
  default     = "us-east1"
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

variable "common_labels" {
  description = "Common labels to apply to all resources"
  type        = map(string)
  default = {
    terraform   = "true"
    module      = "gcp-zero-trust-network"
    owner       = ""
    project     = ""
    cost-center = ""
    environment = ""
  }
}

# =============================================================================
# ADVANCED SECURITY
# =============================================================================

variable "enable_vpc_service_controls" {
  description = "Enable VPC Service Controls for additional security"
  type        = bool
  default     = false
}

variable "enable_private_google_access" {
  description = "Enable Private Google Access on subnets"
  type        = bool
  default     = true
}

variable "enable_org_policies" {
  description = "Enable organization policies for governance"
  type        = bool
  default     = true
}

# =============================================================================
# NETWORK SECURITY
# =============================================================================

variable "enable_firewall_logging" {
  description = "Enable firewall rule logging"
  type        = bool
  default     = true
}

variable "firewall_log_metadata" {
  description = "Metadata to include in firewall logs"
  type        = string
  default     = "INCLUDE_ALL_METADATA"
  validation {
    condition     = contains(["EXCLUDE_ALL_METADATA", "INCLUDE_ALL_METADATA"], var.firewall_log_metadata)
    error_message = "Firewall log metadata must be either 'EXCLUDE_ALL_METADATA' or 'INCLUDE_ALL_METADATA'."
  }
}

variable "enable_packet_mirroring" {
  description = "Enable packet mirroring for network analysis"
  type        = bool
  default     = false
}

# =============================================================================
# PERFORMANCE AND SCALING
# =============================================================================

variable "enable_global_load_balancing" {
  description = "Enable global load balancing features"
  type        = bool
  default     = true
}

variable "enable_cdn" {
  description = "Enable Cloud CDN for content delivery"
  type        = bool
  default     = false
}

variable "bandwidth_tier" {
  description = "Network bandwidth tier (PREMIUM or STANDARD)"
  type        = string
  default     = "PREMIUM"
  validation {
    condition     = contains(["PREMIUM", "STANDARD"], var.bandwidth_tier)
    error_message = "Bandwidth tier must be either 'PREMIUM' or 'STANDARD'."
  }
}

# =============================================================================
# INTEGRATION
# =============================================================================

variable "enable_anthos_service_mesh" {
  description = "Enable Anthos Service Mesh integration"
  type        = bool
  default     = false
}

variable "enable_config_connector" {
  description = "Enable Config Connector for Kubernetes-native resource management"
  type        = bool
  default     = false
}

variable "enable_workload_identity" {
  description = "Enable Workload Identity for secure service account access"
  type        = bool
  default     = true
}

# =============================================================================
# BACKUP AND RECOVERY
# =============================================================================

variable "enable_persistent_disk_backup" {
  description = "Enable automated backup for persistent disks"
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Backup retention period in days"
  type        = number
  default     = 30
  validation {
    condition     = var.backup_retention_days >= 1 && var.backup_retention_days <= 365
    error_message = "Backup retention must be between 1 and 365 days."
  }
}

# =============================================================================
# SECRETS AND CONFIGURATION
# =============================================================================

variable "enable_secret_manager" {
  description = "Enable Secret Manager for secrets storage"
  type        = bool
  default     = true
}

variable "secret_replication_policy" {
  description = "Replication policy for secrets (automatic or user-managed)"
  type        = string
  default     = "automatic"
  validation {
    condition     = contains(["automatic", "user-managed"], var.secret_replication_policy)
    error_message = "Secret replication policy must be either 'automatic' or 'user-managed'."
  }
}