# Variables for AWS Enterprise Database Security Module

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
  description = "Data classification level for the database"
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
# NETWORK CONFIGURATION
# =============================================================================

variable "vpc_id" {
  description = "VPC ID where database will be deployed"
  type        = string
}

variable "vpc_cidr" {
  description = "VPC CIDR block for subnet creation"
  type        = string
  default     = "10.0.0.0/16"
  validation {
    condition     = can(cidrhost(var.vpc_cidr, 0))
    error_message = "VPC CIDR must be a valid IPv4 CIDR block."
  }
}

variable "subnet_ids" {
  description = "List of subnet IDs for database deployment (if null, will create new subnets)"
  type        = list(string)
  default     = null
}

variable "allowed_security_groups" {
  description = "List of security group IDs allowed to access the database"
  type        = list(string)
  default     = []
}

variable "allowed_cidr_blocks" {
  description = "List of CIDR blocks allowed to access the database"
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for cidr in var.allowed_cidr_blocks : can(cidrhost(cidr, 0))
    ])
    error_message = "All CIDR blocks must be valid IPv4 CIDR blocks."
  }
}

# =============================================================================
# RDS CONFIGURATION
# =============================================================================

variable "create_rds_instance" {
  description = "Whether to create an RDS instance"
  type        = bool
  default     = true
}

variable "db_instance_identifier" {
  description = "Identifier for the RDS instance"
  type        = string
  default     = ""
}

variable "engine" {
  description = "Database engine"
  type        = string
  default     = "mysql"
  validation {
    condition = contains([
      "mysql", "postgres", "aurora-mysql", "aurora-postgresql",
      "sqlserver-se", "sqlserver-ee", "sqlserver-ex", "sqlserver-web",
      "oracle-se2", "oracle-ee"
    ], var.engine)
    error_message = "Engine must be a supported RDS engine."
  }
}

variable "engine_version" {
  description = "Database engine version"
  type        = string
  default     = ""
}

variable "instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t3.medium"
}

variable "allocated_storage" {
  description = "Initial allocated storage in GB"
  type        = number
  default     = 20
  validation {
    condition     = var.allocated_storage >= 20 && var.allocated_storage <= 65536
    error_message = "Allocated storage must be between 20 and 65536 GB."
  }
}

variable "max_allocated_storage" {
  description = "Maximum allocated storage for autoscaling in GB"
  type        = number
  default     = 1000
  validation {
    condition     = var.max_allocated_storage >= 20 && var.max_allocated_storage <= 65536
    error_message = "Max allocated storage must be between 20 and 65536 GB."
  }
}

variable "storage_type" {
  description = "Storage type for RDS instance"
  type        = string
  default     = "gp3"
  validation {
    condition     = contains(["gp2", "gp3", "io1", "io2"], var.storage_type)
    error_message = "Storage type must be one of: gp2, gp3, io1, io2."
  }
}

variable "multi_az" {
  description = "Enable Multi-AZ deployment"
  type        = bool
  default     = true
}

variable "port" {
  description = "Database port"
  type        = number
  default     = null
}

# =============================================================================
# DATABASE CREDENTIALS
# =============================================================================

variable "database_name" {
  description = "Name of the database to create"
  type        = string
  default     = ""
}

variable "master_username" {
  description = "Master username for the database"
  type        = string
  default     = "admin"
}

variable "master_password" {
  description = "Master password for the database (if null, will generate random password)"
  type        = string
  default     = null
  sensitive   = true
}

variable "manage_master_user_password" {
  description = "Set to true to allow AWS to manage the master user password in Secrets Manager"
  type        = bool
  default     = true
}

variable "store_credentials_in_secrets_manager" {
  description = "Store database credentials in AWS Secrets Manager"
  type        = bool
  default     = true
}

# =============================================================================
# AURORA CLUSTER CONFIGURATION
# =============================================================================

variable "create_aurora_cluster" {
  description = "Whether to create an Aurora cluster"
  type        = bool
  default     = false
}

variable "cluster_identifier" {
  description = "Identifier for the Aurora cluster"
  type        = string
  default     = ""
}

variable "cluster_instance_count" {
  description = "Number of instances in the Aurora cluster"
  type        = number
  default     = 2
  validation {
    condition     = var.cluster_instance_count >= 1 && var.cluster_instance_count <= 15
    error_message = "Cluster instance count must be between 1 and 15."
  }
}

variable "engine_mode" {
  description = "Engine mode for Aurora cluster"
  type        = string
  default     = "provisioned"
  validation {
    condition     = contains(["provisioned", "serverless"], var.engine_mode)
    error_message = "Engine mode must be either 'provisioned' or 'serverless'."
  }
}

variable "backtrack_window" {
  description = "Target backtrack window in hours (Aurora MySQL only)"
  type        = number
  default     = 0
  validation {
    condition     = var.backtrack_window >= 0 && var.backtrack_window <= 72
    error_message = "Backtrack window must be between 0 and 72 hours."
  }
}

# =============================================================================
# BACKUP CONFIGURATION
# =============================================================================

variable "backup_window" {
  description = "Preferred backup window"
  type        = string
  default     = "03:00-04:00"
}

variable "maintenance_window" {
  description = "Preferred maintenance window"
  type        = string
  default     = "sun:04:00-sun:05:00"
}

variable "create_manual_snapshot" {
  description = "Create a manual snapshot"
  type        = bool
  default     = false
}

# =============================================================================
# MONITORING CONFIGURATION
# =============================================================================

variable "monitoring_interval" {
  description = "Enhanced monitoring interval in seconds"
  type        = number
  default     = 60
  validation {
    condition     = contains([0, 1, 5, 10, 15, 30, 60], var.monitoring_interval)
    error_message = "Monitoring interval must be one of: 0, 1, 5, 10, 15, 30, 60."
  }
}

variable "performance_insights_retention_period" {
  description = "Performance Insights retention period in days"
  type        = number
  default     = 7
  validation {
    condition     = contains([7, 731], var.performance_insights_retention_period)
    error_message = "Performance Insights retention period must be 7 or 731 days."
  }
}

variable "create_cloudwatch_alarms" {
  description = "Create CloudWatch alarms for database monitoring"
  type        = bool
  default     = true
}

variable "alarm_actions" {
  description = "List of ARNs to notify when alarm triggers"
  type        = list(string)
  default     = []
}

# =============================================================================
# PARAMETER GROUP CONFIGURATION
# =============================================================================

variable "create_parameter_group" {
  description = "Create a custom parameter group"
  type        = bool
  default     = true
}

variable "parameter_group_name" {
  description = "Name of existing parameter group to use (if create_parameter_group is false)"
  type        = string
  default     = null
}

variable "parameter_group_family" {
  description = "Parameter group family"
  type        = string
  default     = "mysql8.0"
}

# =============================================================================
# DYNAMODB CONFIGURATION
# =============================================================================

variable "dynamodb_tables" {
  description = "Map of DynamoDB tables to create"
  type = map(object({
    billing_mode   = string
    read_capacity  = optional(number)
    write_capacity = optional(number)
    hash_key       = string
    range_key      = optional(string)
    stream_enabled = optional(bool, false)
    stream_view_type = optional(string)
    ttl_attribute  = optional(string)
    attributes = list(object({
      name = string
      type = string
    }))
    global_secondary_indexes = optional(list(object({
      name            = string
      hash_key        = string
      range_key       = optional(string)
      write_capacity  = optional(number)
      read_capacity   = optional(number)
      projection_type = string
    })), [])
  }))
  default = {}
}

# =============================================================================
# COMPLIANCE AND SECURITY
# =============================================================================

variable "enable_config_compliance" {
  description = "Enable AWS Config rules for compliance monitoring"
  type        = bool
  default     = true
}

variable "config_s3_bucket" {
  description = "S3 bucket for AWS Config delivery channel"
  type        = string
  default     = ""
}

variable "enable_inspector_scanning" {
  description = "Enable Amazon Inspector for security scanning"
  type        = bool
  default     = true
}

# =============================================================================
# TAGGING
# =============================================================================

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default = {
    Terraform   = "true"
    Module      = "aws-enterprise-database"
    Owner       = ""
    Project     = ""
    CostCenter  = ""
    Environment = ""
  }
}