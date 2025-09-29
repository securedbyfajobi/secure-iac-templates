# GCP Enterprise Database Security Module
# Enterprise-grade database security for Google Cloud SQL, Cloud Spanner, and Firestore

terraform {
  required_version = ">= 1.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 4.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0"
    }
  }
}

# =============================================================================
# LOCALS AND DATA SOURCES
# =============================================================================

locals {
  name_prefix = "${var.name_prefix}-${var.environment}"

  # Common labels for all resources
  common_labels = merge(var.common_labels, {
    environment         = var.environment
    module             = "gcp-enterprise-database"
    data-classification = var.data_classification
    compliance         = join(",", var.compliance_frameworks)
    created-by         = "terraform"
    last-modified      = formatdate("YYYY-MM-DD", timestamp())
  })

  # Security score weights
  security_weights = {
    encryption          = 20
    access_control     = 20
    monitoring         = 15
    compliance         = 15
    backup_recovery    = 15
    network_security   = 15
  }

  # Compliance mapping
  compliance_configs = {
    "SOC2" = {
      audit_enabled              = true
      private_ip_required        = true
      encryption_at_rest        = true
      backup_retention_days     = 35
      point_in_time_recovery    = true
      automated_backups         = true
    }
    "NIST" = {
      audit_enabled              = true
      private_ip_required        = true
      encryption_at_rest        = true
      backup_retention_days     = 90
      point_in_time_recovery    = true
      automated_backups         = true
    }
    "CIS" = {
      audit_enabled              = true
      private_ip_required        = true
      encryption_at_rest        = true
      backup_retention_days     = 30
      point_in_time_recovery    = true
      automated_backups         = true
    }
    "PCI-DSS" = {
      audit_enabled              = true
      private_ip_required        = true
      encryption_at_rest        = true
      backup_retention_days     = 365
      point_in_time_recovery    = true
      automated_backups         = true
    }
    "HIPAA" = {
      audit_enabled              = true
      private_ip_required        = true
      encryption_at_rest        = true
      backup_retention_days     = 365
      point_in_time_recovery    = true
      automated_backups         = true
    }
    "FedRAMP" = {
      audit_enabled              = true
      private_ip_required        = true
      encryption_at_rest        = true
      backup_retention_days     = 90
      point_in_time_recovery    = true
      automated_backups         = true
    }
  }

  # Get the most restrictive compliance requirements
  max_backup_retention = length(var.compliance_frameworks) > 0 ? max([
    for framework in var.compliance_frameworks :
    local.compliance_configs[framework].backup_retention_days
  ]...) : var.backup_retention_days
}

data "google_client_config" "current" {}
data "google_project" "current" {}

# =============================================================================
# KMS ENCRYPTION KEY
# =============================================================================

resource "google_kms_key_ring" "database" {
  name     = "${local.name_prefix}-database-keyring"
  location = var.kms_location
  project  = data.google_project.current.project_id
}

resource "google_kms_crypto_key" "database" {
  name     = "${local.name_prefix}-database-key"
  key_ring = google_kms_key_ring.database.id
  purpose  = "ENCRYPT_DECRYPT"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = var.kms_protection_level
  }

  rotation_period = var.kms_rotation_period
  labels          = local.common_labels

  lifecycle {
    prevent_destroy = true
  }
}

# IAM binding for Cloud SQL service account
resource "google_kms_crypto_key_iam_binding" "sql_service_account" {
  crypto_key_id = google_kms_crypto_key.database.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"

  members = [
    "serviceAccount:service-${data.google_project.current.number}@gcp-sa-cloud-sql.iam.gserviceaccount.com"
  ]
}

# =============================================================================
# VPC AND NETWORKING
# =============================================================================

# Private service connection for Cloud SQL
resource "google_compute_global_address" "private_ip_range" {
  count         = var.enable_private_ip ? 1 : 0
  name          = "${local.name_prefix}-private-ip-range"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = var.private_ip_prefix_length
  network       = var.vpc_network_id
  project       = data.google_project.current.project_id
}

resource "google_service_networking_connection" "private_vpc_connection" {
  count                   = var.enable_private_ip ? 1 : 0
  network                 = var.vpc_network_id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_range[0].name]
}

# =============================================================================
# CLOUD SQL INSTANCES
# =============================================================================

# Generate random password for Cloud SQL instances
resource "random_password" "sql_password" {
  for_each = var.sql_instances
  length   = 32
  special  = true
}

# Cloud SQL instances
resource "google_sql_database_instance" "main" {
  for_each            = var.sql_instances
  name                = "${local.name_prefix}-${each.key}"
  database_version    = each.value.database_version
  region              = var.region
  deletion_protection = var.deletion_protection
  project             = data.google_project.current.project_id

  settings {
    tier                        = each.value.tier
    availability_type          = each.value.availability_type
    disk_type                  = each.value.disk_type
    disk_size                  = each.value.disk_size
    disk_autoresize            = each.value.disk_autoresize
    disk_autoresize_limit      = each.value.disk_autoresize_limit
    deletion_protection_enabled = var.deletion_protection

    # Backup configuration
    backup_configuration {
      enabled                        = true
      start_time                     = var.backup_start_time
      point_in_time_recovery_enabled = true
      location                       = var.backup_location
      transaction_log_retention_days = each.value.transaction_log_retention_days
      backup_retention_settings {
        retained_backups = local.max_backup_retention
        retention_unit   = "COUNT"
      }
    }

    # IP configuration
    ip_configuration {
      ipv4_enabled                                  = !var.enable_private_ip
      private_network                              = var.enable_private_ip ? var.vpc_network_id : null
      enable_private_path_for_google_cloud_services = var.enable_private_ip
      require_ssl                                  = true

      dynamic "authorized_networks" {
        for_each = var.enable_private_ip ? [] : var.authorized_networks
        content {
          name  = authorized_networks.value.name
          value = authorized_networks.value.value
        }
      }
    }

    # Database flags for security
    dynamic "database_flags" {
      for_each = each.value.database_flags
      content {
        name  = database_flags.value.name
        value = database_flags.value.value
      }
    }

    # Maintenance window
    maintenance_window {
      day          = var.maintenance_window_day
      hour         = var.maintenance_window_hour
      update_track = var.maintenance_update_track
    }

    # User labels
    user_labels = local.common_labels
  }

  # Encryption configuration
  encryption_key_name = google_kms_crypto_key.database.id

  depends_on = [
    google_service_networking_connection.private_vpc_connection,
    google_kms_crypto_key_iam_binding.sql_service_account
  ]

  lifecycle {
    ignore_changes = [
      settings[0].disk_size,
    ]
  }
}

# Database users
resource "google_sql_user" "admin" {
  for_each = var.sql_instances
  name     = each.value.admin_username
  instance = google_sql_database_instance.main[each.key].name
  password = random_password.sql_password[each.key].result
  project  = data.google_project.current.project_id

  # For PostgreSQL, specify the type
  type = contains(["POSTGRES_11", "POSTGRES_12", "POSTGRES_13", "POSTGRES_14"], each.value.database_version) ? "CLOUD_IAM_USER" : null
}

# Databases
resource "google_sql_database" "databases" {
  for_each = merge([
    for instance_key, instance in var.sql_instances : {
      for db_key, db in instance.databases :
      "${instance_key}-${db_key}" => {
        instance_name = google_sql_database_instance.main[instance_key].name
        name          = db.name
        charset       = db.charset
        collation     = db.collation
      }
    }
  ]...)

  name      = each.value.name
  instance  = each.value.instance_name
  charset   = each.value.charset
  collation = each.value.collation
  project   = data.google_project.current.project_id
}

# =============================================================================
# CLOUD SPANNER
# =============================================================================

resource "google_spanner_instance" "main" {
  count            = var.create_spanner_instance ? 1 : 0
  config           = var.spanner_config
  display_name     = "${local.name_prefix}-spanner"
  name             = "${local.name_prefix}-spanner"
  num_nodes        = var.spanner_num_nodes
  processing_units = var.spanner_processing_units
  project          = data.google_project.current.project_id
  labels           = local.common_labels
}

resource "google_spanner_database" "databases" {
  for_each                 = var.create_spanner_instance ? var.spanner_databases : {}
  instance                 = google_spanner_instance.main[0].name
  name                     = each.key
  version_retention_period = each.value.version_retention_period
  ddl                      = each.value.ddl_statements
  deletion_protection      = var.deletion_protection
  project                  = data.google_project.current.project_id

  encryption_config {
    kms_key_name = google_kms_crypto_key.database.id
  }
}

# =============================================================================
# FIRESTORE
# =============================================================================

resource "google_firestore_database" "main" {
  count                           = var.create_firestore_database ? 1 : 0
  project                         = data.google_project.current.project_id
  name                           = var.firestore_database_id
  location_id                    = var.firestore_location_id
  type                           = var.firestore_type
  concurrency_mode               = var.firestore_concurrency_mode
  app_engine_integration_mode    = var.firestore_app_engine_integration_mode
  point_in_time_recovery_enablement = var.firestore_point_in_time_recovery ? "POINT_IN_TIME_RECOVERY_ENABLED" : "POINT_IN_TIME_RECOVERY_DISABLED"
  delete_protection_state        = var.deletion_protection ? "DELETE_PROTECTION_ENABLED" : "DELETE_PROTECTION_DISABLED"
}

# =============================================================================
# SECURITY AND MONITORING
# =============================================================================

# Cloud Security Command Center notifications
resource "google_scc_notification_config" "database_security" {
  count           = var.enable_security_center ? 1 : 0
  config_id       = "${local.name_prefix}-database-security"
  organization    = var.organization_id
  description     = "Database security notifications for ${var.environment}"
  pubsub_topic    = var.security_notification_topic
  streaming_config {
    filter = "category=\"MEDIUM\" OR category=\"HIGH\" OR category=\"CRITICAL\""
  }
}

# Cloud Audit Logs
resource "google_project_iam_audit_config" "database_audit" {
  project = data.google_project.current.project_id
  service = "sqladmin.googleapis.com"

  audit_log_config {
    log_type = "ADMIN_READ"
  }
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}

# Cloud Monitoring dashboards and alerts
resource "google_monitoring_dashboard" "database" {
  count          = var.enable_monitoring_dashboard ? 1 : 0
  dashboard_json = templatefile("${path.module}/templates/database_dashboard.json", {
    project_id    = data.google_project.current.project_id
    environment   = var.environment
    name_prefix   = local.name_prefix
  })
}

# Alerting policies
resource "google_monitoring_alert_policy" "database_cpu" {
  count        = var.enable_alerting ? 1 : 0
  display_name = "${local.name_prefix} Database High CPU"
  combiner     = "OR"
  enabled      = true
  project      = data.google_project.current.project_id

  conditions {
    display_name = "Database CPU utilization"
    condition_threshold {
      filter          = "resource.type=\"gce_instance\""
      duration        = "300s"
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = var.cpu_alert_threshold

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }

  alert_strategy {
    auto_close = "1800s"
  }

  notification_channels = var.notification_channels

  documentation {
    content   = "Database CPU utilization is above ${var.cpu_alert_threshold}%"
    mime_type = "text/markdown"
  }
}

resource "google_monitoring_alert_policy" "database_memory" {
  count        = var.enable_alerting ? 1 : 0
  display_name = "${local.name_prefix} Database High Memory"
  combiner     = "OR"
  enabled      = true
  project      = data.google_project.current.project_id

  conditions {
    display_name = "Database memory utilization"
    condition_threshold {
      filter          = "resource.type=\"gce_instance\""
      duration        = "300s"
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = var.memory_alert_threshold

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }

  notification_channels = var.notification_channels

  documentation {
    content   = "Database memory utilization is above ${var.memory_alert_threshold}%"
    mime_type = "text/markdown"
  }
}

resource "google_monitoring_alert_policy" "database_connections" {
  count        = var.enable_alerting ? 1 : 0
  display_name = "${local.name_prefix} Database High Connections"
  combiner     = "OR"
  enabled      = true
  project      = data.google_project.current.project_id

  conditions {
    display_name = "Database active connections"
    condition_threshold {
      filter          = "resource.type=\"cloudsql_database\""
      duration        = "300s"
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = var.connections_alert_threshold

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_MEAN"
      }
    }
  }

  notification_channels = var.notification_channels

  documentation {
    content   = "Database active connections exceed ${var.connections_alert_threshold}"
    mime_type = "text/markdown"
  }
}

# =============================================================================
# IAM AND ACCESS CONTROL
# =============================================================================

# Database admin group
resource "google_project_iam_custom_role" "database_admin" {
  count       = var.create_custom_roles ? 1 : 0
  role_id     = "${replace(local.name_prefix, "-", "_")}_database_admin"
  title       = "${local.name_prefix} Database Administrator"
  description = "Custom role for database administration"
  project     = data.google_project.current.project_id
  stage       = "GA"

  permissions = [
    "cloudsql.instances.create",
    "cloudsql.instances.delete",
    "cloudsql.instances.get",
    "cloudsql.instances.list",
    "cloudsql.instances.update",
    "cloudsql.instances.restart",
    "cloudsql.instances.resetSslConfig",
    "cloudsql.databases.create",
    "cloudsql.databases.delete",
    "cloudsql.databases.get",
    "cloudsql.databases.list",
    "cloudsql.databases.update",
    "cloudsql.users.create",
    "cloudsql.users.delete",
    "cloudsql.users.get",
    "cloudsql.users.list",
    "cloudsql.users.update",
    "cloudsql.backupRuns.create",
    "cloudsql.backupRuns.get",
    "cloudsql.backupRuns.list",
    "spanner.instances.get",
    "spanner.instances.list",
    "spanner.databases.get",
    "spanner.databases.list",
    "spanner.databases.create",
    "spanner.databases.update",
    "spanner.databases.drop",
    "datastore.entities.get",
    "datastore.entities.list",
    "datastore.entities.create",
    "datastore.entities.update",
    "datastore.entities.delete"
  ]
}

# Database operator role
resource "google_project_iam_custom_role" "database_operator" {
  count       = var.create_custom_roles ? 1 : 0
  role_id     = "${replace(local.name_prefix, "-", "_")}_database_operator"
  title       = "${local.name_prefix} Database Operator"
  description = "Custom role for database operations"
  project     = data.google_project.current.project_id
  stage       = "GA"

  permissions = [
    "cloudsql.instances.get",
    "cloudsql.instances.list",
    "cloudsql.databases.get",
    "cloudsql.databases.list",
    "cloudsql.users.get",
    "cloudsql.users.list",
    "cloudsql.backupRuns.get",
    "cloudsql.backupRuns.list",
    "spanner.instances.get",
    "spanner.instances.list",
    "spanner.databases.get",
    "spanner.databases.list",
    "datastore.entities.get",
    "datastore.entities.list"
  ]
}

# =============================================================================
# BACKUP AND DISASTER RECOVERY
# =============================================================================

# Cloud Storage bucket for database exports
resource "google_storage_bucket" "database_exports" {
  count                       = var.create_export_bucket ? 1 : 0
  name                        = "${local.name_prefix}-database-exports"
  location                    = var.backup_location
  project                     = data.google_project.current.project_id
  uniform_bucket_level_access = true
  force_destroy               = !var.deletion_protection

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      age = var.export_lifecycle_days
    }
    action {
      type = "Delete"
    }
  }

  encryption {
    default_kms_key_name = google_kms_crypto_key.database.id
  }

  labels = local.common_labels
}

# IAM binding for Cloud SQL service account to access export bucket
resource "google_storage_bucket_iam_binding" "sql_export_bucket" {
  count  = var.create_export_bucket ? 1 : 0
  bucket = google_storage_bucket.database_exports[0].name
  role   = "roles/storage.objectCreator"

  members = [
    "serviceAccount:service-${data.google_project.current.number}@gcp-sa-cloud-sql.iam.gserviceaccount.com"
  ]
}

# =============================================================================
# SECURITY ASSESSMENT
# =============================================================================

locals {
  # Encryption score (0-20)
  encryption_score = (
    (var.kms_protection_level == "HSM" ? 10 : 5) +
    (var.kms_rotation_period != "" ? 5 : 0) +
    (var.enable_private_ip ? 5 : 0)
  )

  # Access control score (0-20)
  access_control_score = (
    (var.enable_private_ip ? 10 : 0) +
    (var.create_custom_roles ? 5 : 0) +
    (length(var.authorized_networks) == 0 || var.enable_private_ip ? 5 : 0)
  )

  # Monitoring score (0-15)
  monitoring_score = (
    (var.enable_monitoring_dashboard ? 5 : 0) +
    (var.enable_alerting ? 5 : 0) +
    (var.enable_security_center ? 5 : 0)
  )

  # Compliance score (0-15)
  compliance_score = (
    (contains(var.compliance_frameworks, "SOC2") ? 3 : 0) +
    (contains(var.compliance_frameworks, "NIST") ? 3 : 0) +
    (contains(var.compliance_frameworks, "CIS") ? 3 : 0) +
    (contains(var.compliance_frameworks, "PCI-DSS") ? 3 : 0) +
    (contains(var.compliance_frameworks, "HIPAA") ? 3 : 0)
  )

  # Backup and recovery score (0-15)
  backup_recovery_score = (
    (local.max_backup_retention >= 30 ? 5 : 0) +
    (var.create_export_bucket ? 5 : 0) +
    (var.firestore_point_in_time_recovery ? 3 : 0) +
    (var.deletion_protection ? 2 : 0)
  )

  # Network security score (0-15)
  network_security_score = (
    (var.enable_private_ip ? 10 : 0) +
    (length(var.authorized_networks) == 0 || var.enable_private_ip ? 5 : 0)
  )

  # Total security score
  total_security_score = (
    local.encryption_score +
    local.access_control_score +
    local.monitoring_score +
    local.compliance_score +
    local.backup_recovery_score +
    local.network_security_score
  )
}