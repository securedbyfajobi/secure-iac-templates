# Google Cloud Zero-Trust Network Architecture Module
# Enterprise-grade network security following Google's BeyondCorp model

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.4"
    }
  }
}

# =============================================================================
# DATA SOURCES
# =============================================================================

data "google_client_config" "current" {}

data "google_project" "current" {}

data "google_compute_zones" "available" {
  project = var.project_id
  region  = var.region
}

# =============================================================================
# LOCALS AND COMPUTED VALUES
# =============================================================================

locals {
  # Common labels for all resources
  common_labels = merge(var.common_labels, {
    environment          = var.environment
    module              = "gcp-zero-trust-network"
    created-by          = "terraform"
    security-framework  = "zero-trust"
    compliance-required = "true"
    data-classification = var.data_classification
  })

  # Network configuration
  vpc_name = "${var.name_prefix}-vpc"

  # Subnet configurations with zero-trust segmentation
  subnets = {
    dmz = {
      name          = "${var.name_prefix}-dmz-subnet"
      ip_cidr_range = var.dmz_subnet_cidr
      region        = var.region
      purpose       = "REGIONAL_MANAGED_PROXY"
    }
    web = {
      name          = "${var.name_prefix}-web-subnet"
      ip_cidr_range = var.web_subnet_cidr
      region        = var.region
      purpose       = "PRIVATE"
    }
    app = {
      name          = "${var.name_prefix}-app-subnet"
      ip_cidr_range = var.app_subnet_cidr
      region        = var.region
      purpose       = "PRIVATE"
    }
    data = {
      name          = "${var.name_prefix}-data-subnet"
      ip_cidr_range = var.data_subnet_cidr
      region        = var.region
      purpose       = "PRIVATE"
    }
    management = {
      name          = "${var.name_prefix}-mgmt-subnet"
      ip_cidr_range = var.management_subnet_cidr
      region        = var.region
      purpose       = "PRIVATE"
    }
  }

  # Secondary ranges for GKE clusters
  secondary_ranges = var.enable_gke ? {
    pods     = "${var.name_prefix}-pods"
    services = "${var.name_prefix}-services"
  } : {}

  # Zero-trust firewall rules
  zero_trust_rules = {
    # Deny all ingress by default
    deny_all_ingress = {
      name        = "${var.name_prefix}-deny-all-ingress"
      direction   = "INGRESS"
      priority    = 65534
      action      = "deny"
      ranges      = ["0.0.0.0/0"]
      protocols   = ["all"]
      description = "Zero-trust: Deny all ingress traffic by default"
    }
    # Deny all egress by default (except essential services)
    deny_all_egress = {
      name        = "${var.name_prefix}-deny-all-egress"
      direction   = "EGRESS"
      priority    = 65534
      action      = "deny"
      ranges      = ["0.0.0.0/0"]
      protocols   = ["all"]
      description = "Zero-trust: Deny all egress traffic by default"
    }
  }

  # Compliance requirements
  compliance_features = {
    for framework in var.compliance_frameworks : framework => {
      network_segmentation = true
      encryption_required  = true
      monitoring_required  = true
      audit_logging       = true
      access_controls     = true
    }
  }
}

# =============================================================================
# VPC NETWORK
# =============================================================================

resource "google_compute_network" "vpc" {
  name                    = local.vpc_name
  auto_create_subnetworks = false
  routing_mode           = "REGIONAL"
  mtu                    = var.network_mtu

  # Enable VPC Flow Logs
  enable_ula_internal_ipv6 = var.enable_ipv6

  project = var.project_id

  depends_on = [google_project_service.compute]
}

# Enable required APIs
resource "google_project_service" "compute" {
  project = var.project_id
  service = "compute.googleapis.com"

  disable_dependent_services = false
  disable_on_destroy        = false
}

resource "google_project_service" "container" {
  count   = var.enable_gke ? 1 : 0
  project = var.project_id
  service = "container.googleapis.com"

  disable_dependent_services = false
  disable_on_destroy        = false
}

resource "google_project_service" "cloudkms" {
  count   = var.enable_kms ? 1 : 0
  project = var.project_id
  service = "cloudkms.googleapis.com"

  disable_dependent_services = false
  disable_on_destroy        = false
}

resource "google_project_service" "logging" {
  project = var.project_id
  service = "logging.googleapis.com"

  disable_dependent_services = false
  disable_on_destroy        = false
}

resource "google_project_service" "monitoring" {
  project = var.project_id
  service = "monitoring.googleapis.com"

  disable_dependent_services = false
  disable_on_destroy        = false
}

# =============================================================================
# SUBNETS - ZERO TRUST SEGMENTATION
# =============================================================================

# DMZ Subnet (for load balancers and proxies)
resource "google_compute_subnetwork" "dmz" {
  name          = local.subnets.dmz.name
  ip_cidr_range = local.subnets.dmz.ip_cidr_range
  network       = google_compute_network.vpc.self_link
  region        = var.region
  purpose       = "REGIONAL_MANAGED_PROXY"
  role          = "ACTIVE"

  # Enable VPC Flow Logs
  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }

  project = var.project_id
}

# Web Tier Subnet
resource "google_compute_subnetwork" "web" {
  name                     = local.subnets.web.name
  ip_cidr_range           = local.subnets.web.ip_cidr_range
  network                 = google_compute_network.vpc.self_link
  region                  = var.region
  private_ip_google_access = true

  # Secondary ranges for GKE if enabled
  dynamic "secondary_ip_range" {
    for_each = var.enable_gke ? [1] : []
    content {
      range_name    = "${local.secondary_ranges.pods}-web"
      ip_cidr_range = var.gke_pod_cidr_web
    }
  }

  dynamic "secondary_ip_range" {
    for_each = var.enable_gke ? [1] : []
    content {
      range_name    = "${local.secondary_ranges.services}-web"
      ip_cidr_range = var.gke_service_cidr_web
    }
  }

  # Enable VPC Flow Logs
  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }

  project = var.project_id
}

# Application Tier Subnet
resource "google_compute_subnetwork" "app" {
  name                     = local.subnets.app.name
  ip_cidr_range           = local.subnets.app.ip_cidr_range
  network                 = google_compute_network.vpc.self_link
  region                  = var.region
  private_ip_google_access = true

  # Secondary ranges for GKE if enabled
  dynamic "secondary_ip_range" {
    for_each = var.enable_gke ? [1] : []
    content {
      range_name    = "${local.secondary_ranges.pods}-app"
      ip_cidr_range = var.gke_pod_cidr_app
    }
  }

  dynamic "secondary_ip_range" {
    for_each = var.enable_gke ? [1] : []
    content {
      range_name    = "${local.secondary_ranges.services}-app"
      ip_cidr_range = var.gke_service_cidr_app
    }
  }

  # Enable VPC Flow Logs
  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }

  project = var.project_id
}

# Data Tier Subnet
resource "google_compute_subnetwork" "data" {
  name                     = local.subnets.data.name
  ip_cidr_range           = local.subnets.data.ip_cidr_range
  network                 = google_compute_network.vpc.self_link
  region                  = var.region
  private_ip_google_access = true

  # Enable VPC Flow Logs
  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }

  project = var.project_id
}

# Management Subnet
resource "google_compute_subnetwork" "management" {
  name                     = local.subnets.management.name
  ip_cidr_range           = local.subnets.management.ip_cidr_range
  network                 = google_compute_network.vpc.self_link
  region                  = var.region
  private_ip_google_access = true

  # Enable VPC Flow Logs
  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }

  project = var.project_id
}

# =============================================================================
# FIREWALL RULES - ZERO TRUST
# =============================================================================

# Default deny all ingress (highest priority)
resource "google_compute_firewall" "deny_all_ingress" {
  name    = "${var.name_prefix}-deny-all-ingress"
  network = google_compute_network.vpc.name

  deny {
    protocol = "all"
  }

  direction          = "INGRESS"
  priority           = 65534
  source_ranges      = ["0.0.0.0/0"]
  target_tags        = ["zero-trust"]
  description        = "Zero-trust: Deny all ingress traffic by default"

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }

  project = var.project_id
}

# Allow IAP for SSH and RDP to management instances
resource "google_compute_firewall" "allow_iap" {
  name    = "${var.name_prefix}-allow-iap"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["22", "3389"]
  }

  direction     = "INGRESS"
  priority      = 1000
  source_ranges = ["35.235.240.0/20"] # Cloud IAP range
  target_tags   = ["iap-ssh"]
  description   = "Allow SSH and RDP from Cloud IAP"

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }

  project = var.project_id
}

# Allow HTTPS from internet to DMZ (load balancers)
resource "google_compute_firewall" "allow_lb_ingress" {
  name    = "${var.name_prefix}-allow-lb-ingress"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }

  direction     = "INGRESS"
  priority      = 1000
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["load-balancer"]
  description   = "Allow HTTP/HTTPS from internet to load balancers"

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }

  project = var.project_id
}

# Allow Google health checks
resource "google_compute_firewall" "allow_health_checks" {
  name    = "${var.name_prefix}-allow-health-checks"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
  }

  direction     = "INGRESS"
  priority      = 1000
  source_ranges = ["35.191.0.0/16", "130.211.0.0/22"] # Google health check ranges
  target_tags   = ["health-check"]
  description   = "Allow Google health checks"

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }

  project = var.project_id
}

# Web tier to app tier communication
resource "google_compute_firewall" "web_to_app" {
  name    = "${var.name_prefix}-web-to-app"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["8080", "8443"]
  }

  direction   = "INGRESS"
  priority    = 1000
  source_tags = ["web-tier"]
  target_tags = ["app-tier"]
  description = "Allow web tier to communicate with app tier"

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }

  project = var.project_id
}

# App tier to data tier communication
resource "google_compute_firewall" "app_to_data" {
  name    = "${var.name_prefix}-app-to-data"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["3306", "5432", "1433", "27017"]
  }

  direction   = "INGRESS"
  priority    = 1000
  source_tags = ["app-tier"]
  target_tags = ["data-tier"]
  description = "Allow app tier to communicate with data tier"

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }

  project = var.project_id
}

# Management access to all tiers
resource "google_compute_firewall" "management_access" {
  name    = "${var.name_prefix}-management-access"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["22", "3389", "80", "443", "8080", "8443"]
  }

  direction   = "INGRESS"
  priority    = 1000
  source_tags = ["management"]
  target_tags = ["web-tier", "app-tier", "data-tier"]
  description = "Allow management access to all tiers"

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }

  project = var.project_id
}

# Allow essential egress (DNS, NTP, package updates)
resource "google_compute_firewall" "allow_essential_egress" {
  name    = "${var.name_prefix}-allow-essential-egress"
  network = google_compute_network.vpc.name

  allow {
    protocol = "tcp"
    ports    = ["53", "80", "443"]
  }

  allow {
    protocol = "udp"
    ports    = ["53", "123"]
  }

  direction        = "EGRESS"
  priority         = 1000
  destination_ranges = ["0.0.0.0/0"]
  target_tags      = ["allow-internet"]
  description      = "Allow essential egress traffic (DNS, HTTP/HTTPS, NTP)"

  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }

  project = var.project_id
}

# =============================================================================
# CLOUD NAT
# =============================================================================

resource "google_compute_router" "nat_router" {
  count   = var.enable_cloud_nat ? 1 : 0
  name    = "${var.name_prefix}-nat-router"
  region  = var.region
  network = google_compute_network.vpc.id

  bgp {
    asn = 64514
  }

  project = var.project_id
}

resource "google_compute_router_nat" "nat_gateway" {
  count  = var.enable_cloud_nat ? 1 : 0
  name   = "${var.name_prefix}-nat-gateway"
  router = google_compute_router.nat_router[0].name
  region = var.region

  nat_ip_allocate_option             = "MANUAL_ONLY"
  nat_ips                           = google_compute_address.nat_ip[*].self_link
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"

  subnetwork {
    name                    = google_compute_subnetwork.web.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }

  subnetwork {
    name                    = google_compute_subnetwork.app.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }

  subnetwork {
    name                    = google_compute_subnetwork.data.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }

  subnetwork {
    name                    = google_compute_subnetwork.management.id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }

  project = var.project_id
}

# Static IP addresses for NAT
resource "google_compute_address" "nat_ip" {
  count  = var.enable_cloud_nat ? var.nat_ip_count : 0
  name   = "${var.name_prefix}-nat-ip-${count.index + 1}"
  region = var.region

  project = var.project_id
}

# =============================================================================
# CLOUD ARMOR SECURITY POLICY
# =============================================================================

resource "google_compute_security_policy" "main" {
  count = var.enable_cloud_armor ? 1 : 0
  name  = "${var.name_prefix}-security-policy"

  # Default rule - deny all
  rule {
    action   = "deny(403)"
    priority = "2147483647"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Default deny rule"
  }

  # Allow traffic from specific countries if configured
  dynamic "rule" {
    for_each = length(var.allowed_countries) > 0 ? [1] : []
    content {
      action   = "allow"
      priority = "1000"
      match {
        expr {
          expression = "origin.region_code in ${jsonencode(var.allowed_countries)}"
        }
      }
      description = "Allow traffic from allowed countries"
    }
  }

  # Rate limiting rule
  rule {
    action   = "rate_based_ban"
    priority = "1001"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    rate_limit_options {
      conform_action = "allow"
      exceed_action  = "deny(429)"
      enforce_on_key = "IP"
      rate_limit_threshold {
        count        = var.rate_limit_threshold
        interval_sec = 60
      }
      ban_duration_sec = 300
    }
    description = "Rate limiting rule"
  }

  # Block known bad IPs
  rule {
    action   = "deny(403)"
    priority = "1002"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = var.blocked_ip_ranges
      }
    }
    description = "Block known bad IP ranges"
  }

  adaptive_protection_config {
    layer_7_ddos_defense_config {
      enable = true
    }
  }

  project = var.project_id
}

# =============================================================================
# PRIVATE SERVICE CONNECT
# =============================================================================

# Private Service Connect for Google APIs
resource "google_compute_global_address" "private_service_connect" {
  count        = var.enable_private_service_connect ? 1 : 0
  name         = "${var.name_prefix}-psc-address"
  purpose      = "PRIVATE_SERVICE_CONNECT"
  network      = google_compute_network.vpc.id
  address_type = "INTERNAL"

  project = var.project_id
}

resource "google_compute_global_forwarding_rule" "private_service_connect" {
  count                 = var.enable_private_service_connect ? 1 : 0
  name                  = "${var.name_prefix}-psc-forwarding-rule"
  target                = "all-apis"
  network               = google_compute_network.vpc.id
  ip_address            = google_compute_global_address.private_service_connect[0].id
  load_balancing_scheme = ""

  project = var.project_id
}

# =============================================================================
# KMS FOR ENCRYPTION
# =============================================================================

resource "google_kms_key_ring" "main" {
  count    = var.enable_kms ? 1 : 0
  name     = "${var.name_prefix}-keyring"
  location = var.region

  project = var.project_id

  depends_on = [google_project_service.cloudkms]
}

resource "google_kms_crypto_key" "network_key" {
  count           = var.enable_kms ? 1 : 0
  name            = "${var.name_prefix}-network-key"
  key_ring        = google_kms_key_ring.main[0].id
  rotation_period = "2592000s" # 30 days

  lifecycle {
    prevent_destroy = true
  }

  project = var.project_id
}

# =============================================================================
# MONITORING AND ALERTING
# =============================================================================

# Log sink for VPC Flow Logs
resource "google_logging_project_sink" "vpc_flow_logs" {
  count                  = var.enable_flow_logs_export ? 1 : 0
  name                   = "${var.name_prefix}-vpc-flow-logs-sink"
  destination            = "storage.googleapis.com/${google_storage_bucket.flow_logs[0].name}"
  filter                 = "resource.type=\"gce_subnetwork\" AND log_name=\"projects/${var.project_id}/logs/compute.googleapis.com%2Fvpc_flows\""
  unique_writer_identity = true

  project = var.project_id
}

# Storage bucket for flow logs
resource "google_storage_bucket" "flow_logs" {
  count    = var.enable_flow_logs_export ? 1 : 0
  name     = "${var.project_id}-${var.name_prefix}-flow-logs"
  location = var.region

  uniform_bucket_level_access = true

  # Encryption
  encryption {
    default_kms_key_name = var.enable_kms ? google_kms_crypto_key.network_key[0].id : null
  }

  # Lifecycle management
  lifecycle_rule {
    condition {
      age = var.flow_logs_retention_days
    }
    action {
      type = "Delete"
    }
  }

  # Versioning
  versioning {
    enabled = false
  }

  project = var.project_id
}

# Grant log writer permission to storage bucket
resource "google_storage_bucket_iam_member" "flow_logs_writer" {
  count  = var.enable_flow_logs_export ? 1 : 0
  bucket = google_storage_bucket.flow_logs[0].name
  role   = "roles/storage.objectCreator"
  member = google_logging_project_sink.vpc_flow_logs[0].writer_identity

  project = var.project_id
}

# Monitoring alerts
resource "google_monitoring_alert_policy" "high_denied_traffic" {
  count        = var.enable_monitoring_alerts ? 1 : 0
  display_name = "${var.name_prefix} High Denied Traffic"
  combiner     = "OR"

  conditions {
    display_name = "VPC Firewall denied connections"
    condition_threshold {
      filter          = "resource.type=\"gce_instance\""
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = var.denied_traffic_threshold
      duration        = "300s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = var.notification_channels

  alert_strategy {
    auto_close = "1800s"
  }

  project = var.project_id

  depends_on = [google_project_service.monitoring]
}

# Security monitoring alert
resource "google_monitoring_alert_policy" "suspicious_activity" {
  count        = var.enable_monitoring_alerts ? 1 : 0
  display_name = "${var.name_prefix} Suspicious Network Activity"
  combiner     = "OR"

  conditions {
    display_name = "Unusual network patterns"
    condition_threshold {
      filter          = "resource.type=\"gce_subnetwork\""
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = var.suspicious_activity_threshold
      duration        = "600s"

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }

  notification_channels = var.notification_channels

  alert_strategy {
    auto_close = "3600s"
  }

  project = var.project_id

  depends_on = [google_project_service.monitoring]
}

# =============================================================================
# PRIVATE DNS
# =============================================================================

resource "google_dns_managed_zone" "private_zone" {
  count       = var.enable_private_dns ? 1 : 0
  name        = "${replace(var.name_prefix, "-", "")}privatezone"
  dns_name    = var.private_dns_name
  description = "Private DNS zone for ${var.name_prefix}"
  visibility  = "private"

  private_visibility_config {
    networks {
      network_url = google_compute_network.vpc.id
    }
  }

  dnssec_config {
    state = "on"
  }

  project = var.project_id
}

# =============================================================================
# BINARY AUTHORIZATION (if enabled)
# =============================================================================

resource "google_binary_authorization_policy" "main" {
  count = var.enable_binary_authorization ? 1 : 0

  default_admission_rule {
    evaluation_mode  = "REQUIRE_ATTESTATION"
    enforcement_mode = "ENFORCED_BLOCK_AND_AUDIT_LOG"
    require_attestations_by = [
      google_binary_authorization_attestor.attestor[0].name
    ]
  }

  project = var.project_id
}

resource "google_binary_authorization_attestor" "attestor" {
  count = var.enable_binary_authorization ? 1 : 0
  name  = "${var.name_prefix}-attestor"

  attestation_authority_note {
    note_reference = google_container_analysis_note.note[0].name
    public_keys {
      ascii_armored_pgp_public_key = var.pgp_public_key
    }
  }

  project = var.project_id
}

resource "google_container_analysis_note" "note" {
  count = var.enable_binary_authorization ? 1 : 0
  name  = "${var.name_prefix}-attestor-note"

  attestation_authority {
    hint {
      human_readable_name = "${var.name_prefix} Attestor"
    }
  }

  project = var.project_id
}