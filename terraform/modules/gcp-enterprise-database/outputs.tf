# Outputs for GCP Enterprise Database Security Module

# =============================================================================
# PROJECT AND LOCATION OUTPUTS
# =============================================================================

output "project_id" {
  description = "Project ID where resources are deployed"
  value       = data.google_project.current.project_id
}

output "region" {
  description = "GCP region where resources are deployed"
  value       = var.region
}

# =============================================================================
# KMS OUTPUTS
# =============================================================================

output "kms_key_ring_name" {
  description = "Name of the KMS key ring"
  value       = google_kms_key_ring.database.name
}

output "kms_key_ring_id" {
  description = "ID of the KMS key ring"
  value       = google_kms_key_ring.database.id
}

output "kms_crypto_key_name" {
  description = "Name of the KMS crypto key"
  value       = google_kms_crypto_key.database.name
}

output "kms_crypto_key_id" {
  description = "ID of the KMS crypto key"
  value       = google_kms_crypto_key.database.id
}

# =============================================================================
# NETWORK OUTPUTS
# =============================================================================

output "private_ip_range_name" {
  description = "Name of the private IP range"
  value       = var.enable_private_ip ? google_compute_global_address.private_ip_range[0].name : null
}

output "private_ip_range_address" {
  description = "Address of the private IP range"
  value       = var.enable_private_ip ? google_compute_global_address.private_ip_range[0].address : null
}

output "private_vpc_connection_id" {
  description = "ID of the private VPC connection"
  value       = var.enable_private_ip ? google_service_networking_connection.private_vpc_connection[0].id : null
}

# =============================================================================
# CLOUD SQL OUTPUTS
# =============================================================================

output "sql_instances" {
  description = "Map of Cloud SQL instance information"
  value = {
    for name, instance in google_sql_database_instance.main :
    name => {
      id                    = instance.id
      name                  = instance.name
      connection_name       = instance.connection_name
      self_link            = instance.self_link
      service_account_email = instance.service_account_email_address
      public_ip_address    = instance.public_ip_address
      private_ip_address   = instance.private_ip_address
      database_version     = instance.database_version
      settings = {
        tier              = instance.settings[0].tier
        availability_type = instance.settings[0].availability_type
        disk_type        = instance.settings[0].disk_type
        disk_size        = instance.settings[0].disk_size
        disk_autoresize  = instance.settings[0].disk_autoresize
      }
    }
  }
}

output "sql_users" {
  description = "Map of Cloud SQL user information"
  value = {
    for name, user in google_sql_user.admin :
    name => {
      id       = user.id
      name     = user.name
      instance = user.instance
      type     = user.type
    }
  }
  sensitive = true
}

output "sql_databases" {
  description = "Map of Cloud SQL database information"
  value = {
    for key, db in google_sql_database.databases :
    key => {
      id        = db.id
      name      = db.name
      instance  = db.instance
      charset   = db.charset
      collation = db.collation
    }
  }
}

output "sql_connection_strings" {
  description = "Connection strings for Cloud SQL instances"
  value = {
    for name, instance in google_sql_database_instance.main :
    name => {
      connection_name    = instance.connection_name
      public_ip_address  = instance.public_ip_address
      private_ip_address = instance.private_ip_address
    }
  }
}

# =============================================================================
# CLOUD SPANNER OUTPUTS
# =============================================================================

output "spanner_instance_name" {
  description = "Name of the Spanner instance"
  value       = var.create_spanner_instance ? google_spanner_instance.main[0].name : null
}

output "spanner_instance_id" {
  description = "ID of the Spanner instance"
  value       = var.create_spanner_instance ? google_spanner_instance.main[0].id : null
}

output "spanner_instance_state" {
  description = "State of the Spanner instance"
  value       = var.create_spanner_instance ? google_spanner_instance.main[0].state : null
}

output "spanner_databases" {
  description = "Map of Spanner database information"
  value = var.create_spanner_instance ? {
    for name, db in google_spanner_database.databases :
    name => {
      id       = db.id
      name     = db.name
      instance = db.instance
      state    = db.state
    }
  } : {}
}

# =============================================================================
# FIRESTORE OUTPUTS
# =============================================================================

output "firestore_database_name" {
  description = "Name of the Firestore database"
  value       = var.create_firestore_database ? google_firestore_database.main[0].name : null
}

output "firestore_database_id" {
  description = "ID of the Firestore database"
  value       = var.create_firestore_database ? google_firestore_database.main[0].id : null
}

output "firestore_database_location_id" {
  description = "Location ID of the Firestore database"
  value       = var.create_firestore_database ? google_firestore_database.main[0].location_id : null
}

output "firestore_database_type" {
  description = "Type of the Firestore database"
  value       = var.create_firestore_database ? google_firestore_database.main[0].type : null
}

# =============================================================================
# MONITORING OUTPUTS
# =============================================================================

output "monitoring_dashboard_id" {
  description = "ID of the monitoring dashboard"
  value       = var.enable_monitoring_dashboard ? google_monitoring_dashboard.database[0].id : null
}

output "cpu_alert_policy_id" {
  description = "ID of the CPU alert policy"
  value       = var.enable_alerting ? google_monitoring_alert_policy.database_cpu[0].id : null
}

output "memory_alert_policy_id" {
  description = "ID of the memory alert policy"
  value       = var.enable_alerting ? google_monitoring_alert_policy.database_memory[0].id : null
}

output "connections_alert_policy_id" {
  description = "ID of the connections alert policy"
  value       = var.enable_alerting ? google_monitoring_alert_policy.database_connections[0].id : null
}

# =============================================================================
# SECURITY OUTPUTS
# =============================================================================

output "security_notification_config_id" {
  description = "ID of the Security Command Center notification config"
  value       = var.enable_security_center ? google_scc_notification_config.database_security[0].id : null
}

output "database_admin_role_id" {
  description = "ID of the custom database admin role"
  value       = var.create_custom_roles ? google_project_iam_custom_role.database_admin[0].id : null
}

output "database_operator_role_id" {
  description = "ID of the custom database operator role"
  value       = var.create_custom_roles ? google_project_iam_custom_role.database_operator[0].id : null
}

# =============================================================================
# BACKUP OUTPUTS
# =============================================================================

output "export_bucket_name" {
  description = "Name of the database export bucket"
  value       = var.create_export_bucket ? google_storage_bucket.database_exports[0].name : null
}

output "export_bucket_url" {
  description = "URL of the database export bucket"
  value       = var.create_export_bucket ? google_storage_bucket.database_exports[0].url : null
}

output "export_bucket_self_link" {
  description = "Self link of the database export bucket"
  value       = var.create_export_bucket ? google_storage_bucket.database_exports[0].self_link : null
}

# =============================================================================
# SECURITY ASSESSMENT OUTPUTS
# =============================================================================

output "security_score" {
  description = "Overall security score (0-100)"
  value       = local.total_security_score
}

output "security_score_breakdown" {
  description = "Breakdown of security score by category"
  value = {
    encryption        = local.encryption_score
    access_control   = local.access_control_score
    monitoring       = local.monitoring_score
    compliance       = local.compliance_score
    backup_recovery  = local.backup_recovery_score
    network_security = local.network_security_score
    total           = local.total_security_score
  }
}

output "compliance_status" {
  description = "Compliance status for each framework"
  value = {
    for framework in var.compliance_frameworks :
    framework => {
      enabled = contains(var.compliance_frameworks, framework)
      config  = local.compliance_configs[framework]
    }
  }
}

# =============================================================================
# CONFIGURATION SUMMARY
# =============================================================================

output "database_configuration_summary" {
  description = "Summary of database configuration"
  value = {
    sql_instances_count      = length(var.sql_instances)
    spanner_instance_enabled = var.create_spanner_instance
    firestore_enabled        = var.create_firestore_database
    private_ip_enabled       = var.enable_private_ip
    monitoring_enabled       = var.enable_monitoring_dashboard
    alerting_enabled         = var.enable_alerting
    security_center_enabled  = var.enable_security_center
    backup_retention_days    = local.max_backup_retention
    compliance_frameworks    = var.compliance_frameworks
    data_classification      = var.data_classification
    deletion_protection      = var.deletion_protection
  }
}

output "network_security_summary" {
  description = "Summary of network security configuration"
  value = {
    private_ip_enabled     = var.enable_private_ip
    authorized_networks    = length(var.authorized_networks)
    vpc_network_id        = var.vpc_network_id
    private_ip_prefix     = var.private_ip_prefix_length
  }
}

output "encryption_summary" {
  description = "Summary of encryption configuration"
  value = {
    kms_key_ring_id       = google_kms_key_ring.database.id
    kms_crypto_key_id     = google_kms_crypto_key.database.id
    protection_level      = var.kms_protection_level
    rotation_period       = var.kms_rotation_period
    encryption_at_rest    = true
    encryption_in_transit = var.enable_private_ip
  }
}

# =============================================================================
# COST OPTIMIZATION OUTPUTS
# =============================================================================

output "estimated_monthly_cost" {
  description = "Estimated monthly cost in USD (approximate)"
  value = {
    sql_instances_cost = "Variable based on tier, storage, and usage"
    spanner_cost      = var.create_spanner_instance ? "Variable based on processing units and storage" : 0
    firestore_cost    = var.create_firestore_database ? "Variable based on operations and storage" : 0
    kms_cost          = "~$0.06 per key per month + operations"
    monitoring_cost   = "Variable based on metrics and logs volume"
    storage_cost      = var.create_export_bucket ? "Variable based on backup storage" : 0
    network_cost      = var.enable_private_ip ? "~$0.01 per GB for VPC peering" : 0
    total_fixed_monthly = "~$0.06 (KMS) + variable costs"
    note = "Actual costs depend on usage patterns, data volume, and operational activity"
  }
}

# =============================================================================
# RECOMMENDATIONS
# =============================================================================

output "security_recommendations" {
  description = "Security improvement recommendations"
  value = {
    high_priority = compact([
      local.total_security_score < 80 ? "Security score below enterprise threshold (80). Review and enhance security configurations." : "",
      !var.enable_private_ip ? "Enable private IP for enhanced network security." : "",
      var.kms_protection_level != "HSM" && var.data_classification == "restricted" ? "Consider HSM protection level for restricted data." : "",
      !var.enable_monitoring_dashboard ? "Enable monitoring dashboard for operational visibility." : ""
    ])
    medium_priority = compact([
      !var.enable_alerting ? "Enable alerting policies for proactive monitoring." : "",
      !var.enable_security_center ? "Enable Security Command Center for threat detection." : "",
      !var.create_custom_roles ? "Create custom IAM roles for principle of least privilege." : "",
      local.max_backup_retention < 90 && contains(var.compliance_frameworks, "PCI-DSS") ? "Extend backup retention for PCI-DSS compliance." : ""
    ])
    low_priority = compact([
      !var.create_export_bucket ? "Create export bucket for disaster recovery capabilities." : "",
      var.maintenance_update_track != "stable" ? "Use stable update track for production environments." : "",
      length(var.authorized_networks) > 0 && var.enable_private_ip ? "Remove authorized networks when using private IP." : "",
      !var.firestore_point_in_time_recovery && var.create_firestore_database ? "Enable point-in-time recovery for Firestore." : ""
    ])
  }
}

output "compliance_gaps" {
  description = "Identified compliance gaps and remediation steps"
  value = {
    for framework in ["SOC2", "NIST", "CIS", "PCI-DSS", "HIPAA", "FedRAMP"] :
    framework => {
      required     = contains(var.compliance_frameworks, framework)
      configured   = contains(var.compliance_frameworks, framework)
      requirements = local.compliance_configs[framework]
      gap_analysis = !contains(var.compliance_frameworks, framework) ? "Framework not configured" : "Compliant"
      remediation  = !contains(var.compliance_frameworks, framework) ? "Add ${framework} to compliance_frameworks variable" : "No action required"
    }
  }
}

# =============================================================================
# DISASTER RECOVERY INFORMATION
# =============================================================================

output "disaster_recovery_summary" {
  description = "Disaster recovery configuration summary"
  value = {
    automated_backups     = true
    backup_retention_days = local.max_backup_retention
    point_in_time_recovery = true
    export_bucket_enabled = var.create_export_bucket
    multi_region_setup   = var.create_spanner_instance ? contains(var.spanner_config, "multi-region") : false
    encryption_protected = true
    deletion_protection  = var.deletion_protection
  }
}

# =============================================================================
# OPERATIONAL INFORMATION
# =============================================================================

output "operational_summary" {
  description = "Operational configuration summary"
  value = {
    maintenance_window = {
      day  = var.maintenance_window_day
      hour = var.maintenance_window_hour
      track = var.maintenance_update_track
    }
    backup_schedule = {
      start_time = var.backup_start_time
      location   = var.backup_location
      retention  = local.max_backup_retention
    }
    monitoring = {
      dashboard_enabled = var.enable_monitoring_dashboard
      alerts_enabled    = var.enable_alerting
      thresholds = {
        cpu_percent    = var.cpu_alert_threshold
        memory_percent = var.memory_alert_threshold
        connections    = var.connections_alert_threshold
      }
    }
  }
}