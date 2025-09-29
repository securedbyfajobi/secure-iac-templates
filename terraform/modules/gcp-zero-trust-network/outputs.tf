# Outputs for Google Cloud Zero-Trust Network Architecture Module

# =============================================================================
# NETWORK OUTPUTS
# =============================================================================

output "vpc_network_id" {
  description = "ID of the VPC network"
  value       = google_compute_network.vpc.id
}

output "vpc_network_name" {
  description = "Name of the VPC network"
  value       = google_compute_network.vpc.name
}

output "vpc_network_self_link" {
  description = "Self link of the VPC network"
  value       = google_compute_network.vpc.self_link
}

output "vpc_network_gateway_ipv4" {
  description = "Gateway IPv4 address of the VPC network"
  value       = google_compute_network.vpc.gateway_ipv4
}

# =============================================================================
# SUBNET OUTPUTS
# =============================================================================

output "dmz_subnet_id" {
  description = "ID of the DMZ subnet"
  value       = google_compute_subnetwork.dmz.id
}

output "dmz_subnet_self_link" {
  description = "Self link of the DMZ subnet"
  value       = google_compute_subnetwork.dmz.self_link
}

output "dmz_subnet_cidr" {
  description = "CIDR block of the DMZ subnet"
  value       = google_compute_subnetwork.dmz.ip_cidr_range
}

output "web_subnet_id" {
  description = "ID of the web tier subnet"
  value       = google_compute_subnetwork.web.id
}

output "web_subnet_self_link" {
  description = "Self link of the web tier subnet"
  value       = google_compute_subnetwork.web.self_link
}

output "web_subnet_cidr" {
  description = "CIDR block of the web tier subnet"
  value       = google_compute_subnetwork.web.ip_cidr_range
}

output "app_subnet_id" {
  description = "ID of the application tier subnet"
  value       = google_compute_subnetwork.app.id
}

output "app_subnet_self_link" {
  description = "Self link of the application tier subnet"
  value       = google_compute_subnetwork.app.self_link
}

output "app_subnet_cidr" {
  description = "CIDR block of the application tier subnet"
  value       = google_compute_subnetwork.app.ip_cidr_range
}

output "data_subnet_id" {
  description = "ID of the data tier subnet"
  value       = google_compute_subnetwork.data.id
}

output "data_subnet_self_link" {
  description = "Self link of the data tier subnet"
  value       = google_compute_subnetwork.data.self_link
}

output "data_subnet_cidr" {
  description = "CIDR block of the data tier subnet"
  value       = google_compute_subnetwork.data.ip_cidr_range
}

output "management_subnet_id" {
  description = "ID of the management subnet"
  value       = google_compute_subnetwork.management.id
}

output "management_subnet_self_link" {
  description = "Self link of the management subnet"
  value       = google_compute_subnetwork.management.self_link
}

output "management_subnet_cidr" {
  description = "CIDR block of the management subnet"
  value       = google_compute_subnetwork.management.ip_cidr_range
}

# =============================================================================
# GKE SECONDARY RANGES
# =============================================================================

output "gke_pod_ranges" {
  description = "Secondary IP ranges for GKE pods"
  value = var.enable_gke ? {
    web = "${local.secondary_ranges.pods}-web"
    app = "${local.secondary_ranges.pods}-app"
  } : {}
}

output "gke_service_ranges" {
  description = "Secondary IP ranges for GKE services"
  value = var.enable_gke ? {
    web = "${local.secondary_ranges.services}-web"
    app = "${local.secondary_ranges.services}-app"
  } : {}
}

# =============================================================================
# FIREWALL OUTPUTS
# =============================================================================

output "firewall_rule_names" {
  description = "Names of created firewall rules"
  value = [
    google_compute_firewall.deny_all_ingress.name,
    google_compute_firewall.allow_iap.name,
    google_compute_firewall.allow_lb_ingress.name,
    google_compute_firewall.allow_health_checks.name,
    google_compute_firewall.web_to_app.name,
    google_compute_firewall.app_to_data.name,
    google_compute_firewall.management_access.name,
    google_compute_firewall.allow_essential_egress.name
  ]
}

output "zero_trust_tags" {
  description = "Network tags for zero-trust architecture"
  value = {
    deny_all       = "zero-trust"
    iap_ssh        = "iap-ssh"
    load_balancer  = "load-balancer"
    health_check   = "health-check"
    web_tier       = "web-tier"
    app_tier       = "app-tier"
    data_tier      = "data-tier"
    management     = "management"
    allow_internet = "allow-internet"
  }
}

# =============================================================================
# CLOUD NAT OUTPUTS
# =============================================================================

output "cloud_nat_router_id" {
  description = "ID of the Cloud NAT router"
  value       = var.enable_cloud_nat ? google_compute_router.nat_router[0].id : null
}

output "cloud_nat_gateway_name" {
  description = "Name of the Cloud NAT gateway"
  value       = var.enable_cloud_nat ? google_compute_router_nat.nat_gateway[0].name : null
}

output "nat_ip_addresses" {
  description = "Static IP addresses allocated for Cloud NAT"
  value       = var.enable_cloud_nat ? google_compute_address.nat_ip[*].address : []
}

# =============================================================================
# CLOUD ARMOR OUTPUTS
# =============================================================================

output "cloud_armor_policy_id" {
  description = "ID of the Cloud Armor security policy"
  value       = var.enable_cloud_armor ? google_compute_security_policy.main[0].id : null
}

output "cloud_armor_policy_self_link" {
  description = "Self link of the Cloud Armor security policy"
  value       = var.enable_cloud_armor ? google_compute_security_policy.main[0].self_link : null
}

# =============================================================================
# PRIVATE SERVICE CONNECT OUTPUTS
# =============================================================================

output "private_service_connect_address" {
  description = "IP address for Private Service Connect"
  value       = var.enable_private_service_connect ? google_compute_global_address.private_service_connect[0].address : null
}

output "private_service_connect_forwarding_rule" {
  description = "Self link of the Private Service Connect forwarding rule"
  value       = var.enable_private_service_connect ? google_compute_global_forwarding_rule.private_service_connect[0].self_link : null
}

# =============================================================================
# KMS OUTPUTS
# =============================================================================

output "kms_key_ring_id" {
  description = "ID of the KMS key ring"
  value       = var.enable_kms ? google_kms_key_ring.main[0].id : null
}

output "kms_crypto_key_id" {
  description = "ID of the KMS crypto key"
  value       = var.enable_kms ? google_kms_crypto_key.network_key[0].id : null
}

output "kms_crypto_key_name" {
  description = "Name of the KMS crypto key"
  value       = var.enable_kms ? google_kms_crypto_key.network_key[0].name : null
}

# =============================================================================
# MONITORING OUTPUTS
# =============================================================================

output "flow_logs_bucket_name" {
  description = "Name of the Cloud Storage bucket for VPC Flow Logs"
  value       = var.enable_flow_logs_export ? google_storage_bucket.flow_logs[0].name : null
}

output "flow_logs_bucket_url" {
  description = "URL of the Cloud Storage bucket for VPC Flow Logs"
  value       = var.enable_flow_logs_export ? google_storage_bucket.flow_logs[0].url : null
}

output "log_sink_writer_identity" {
  description = "Writer identity of the VPC Flow Logs sink"
  value       = var.enable_flow_logs_export ? google_logging_project_sink.vpc_flow_logs[0].writer_identity : null
}

output "monitoring_alert_policy_names" {
  description = "Names of created monitoring alert policies"
  value = var.enable_monitoring_alerts ? [
    google_monitoring_alert_policy.high_denied_traffic[0].display_name,
    google_monitoring_alert_policy.suspicious_activity[0].display_name
  ] : []
}

# =============================================================================
# DNS OUTPUTS
# =============================================================================

output "private_dns_zone_id" {
  description = "ID of the private DNS zone"
  value       = var.enable_private_dns ? google_dns_managed_zone.private_zone[0].id : null
}

output "private_dns_zone_name" {
  description = "Name of the private DNS zone"
  value       = var.enable_private_dns ? google_dns_managed_zone.private_zone[0].dns_name : null
}

output "private_dns_zone_name_servers" {
  description = "Name servers of the private DNS zone"
  value       = var.enable_private_dns ? google_dns_managed_zone.private_zone[0].name_servers : []
}

# =============================================================================
# BINARY AUTHORIZATION OUTPUTS
# =============================================================================

output "binary_authorization_policy_id" {
  description = "ID of the Binary Authorization policy"
  value       = var.enable_binary_authorization ? google_binary_authorization_policy.main[0].id : null
}

output "binary_authorization_attestor_name" {
  description = "Name of the Binary Authorization attestor"
  value       = var.enable_binary_authorization ? google_binary_authorization_attestor.attestor[0].name : null
}

# =============================================================================
# SECURITY SUMMARY OUTPUTS
# =============================================================================

output "security_summary" {
  description = "Summary of security configurations"
  value = {
    zero_trust_architecture       = true
    network_segmentation         = true
    cloud_armor_enabled          = var.enable_cloud_armor
    private_service_connect      = var.enable_private_service_connect
    kms_encryption_enabled       = var.enable_kms
    vpc_flow_logs_enabled        = true
    monitoring_alerts_enabled    = var.enable_monitoring_alerts
    private_dns_enabled          = var.enable_private_dns
    binary_authorization_enabled = var.enable_binary_authorization
    compliance_frameworks        = var.compliance_frameworks
    data_classification          = var.data_classification
  }
}

# =============================================================================
# NETWORK CONFIGURATION SUMMARY
# =============================================================================

output "network_configuration_summary" {
  description = "Summary of network configuration"
  value = {
    vpc_network_id        = google_compute_network.vpc.id
    vpc_network_name      = google_compute_network.vpc.name
    region               = var.region
    project_id           = var.project_id
    subnet_count         = 5
    firewall_rules_count = 8
    cloud_nat_enabled    = var.enable_cloud_nat
    gke_ready           = var.enable_gke
    mtu_size            = var.network_mtu
    ipv6_enabled        = var.enable_ipv6
  }
}

# =============================================================================
# COST ESTIMATION OUTPUTS
# =============================================================================

output "estimated_monthly_cost_usd" {
  description = "Estimated monthly cost in USD (approximate)"
  value = (
    # Cloud NAT (~$45/month per gateway)
    (var.enable_cloud_nat ? 45 + (var.nat_ip_count * 4.50) : 0) +
    # Cloud Armor (~$1/month per policy + $0.75 per million requests)
    (var.enable_cloud_armor ? 1 : 0) +
    # KMS (~$1/month per key + usage)
    (var.enable_kms ? 1 : 0) +
    # Storage for flow logs (~$10/month)
    (var.enable_flow_logs_export ? 10 : 0) +
    # Monitoring (~$2/month for basic alerts)
    (var.enable_monitoring_alerts ? 2 : 0) +
    # Private DNS (~$0.20/month per zone)
    (var.enable_private_dns ? 0.20 : 0) +
    # Private Service Connect (~$0.01/hour per endpoint)
    (var.enable_private_service_connect ? 7.30 : 0)
  )
}

output "cost_breakdown" {
  description = "Detailed cost breakdown by service"
  value = {
    cloud_nat                = var.enable_cloud_nat ? 45 + (var.nat_ip_count * 4.50) : 0
    cloud_armor             = var.enable_cloud_armor ? 1 : 0
    kms                     = var.enable_kms ? 1 : 0
    storage_flow_logs       = var.enable_flow_logs_export ? 10 : 0
    monitoring              = var.enable_monitoring_alerts ? 2 : 0
    private_dns             = var.enable_private_dns ? 0.20 : 0
    private_service_connect = var.enable_private_service_connect ? 7.30 : 0
  }
}

# =============================================================================
# COMPLIANCE OUTPUTS
# =============================================================================

output "compliance_status" {
  description = "Compliance framework status"
  value = {
    frameworks_enabled   = var.compliance_frameworks
    zero_trust_compliant = true
    network_segmentation = true
    encryption_enabled   = var.enable_kms
    monitoring_enabled   = var.enable_monitoring_alerts
    access_controls     = true
    audit_logging       = var.enable_flow_logs_export
    private_access      = var.enable_private_service_connect
  }
}

# =============================================================================
# INTEGRATION ENDPOINTS
# =============================================================================

output "integration_endpoints" {
  description = "Endpoints for integration with other services"
  value = {
    vpc_network_self_link       = google_compute_network.vpc.self_link
    kms_crypto_key_id          = var.enable_kms ? google_kms_crypto_key.network_key[0].id : null
    flow_logs_bucket_name      = var.enable_flow_logs_export ? google_storage_bucket.flow_logs[0].name : null
    private_dns_zone_name      = var.enable_private_dns ? google_dns_managed_zone.private_zone[0].dns_name : null
    cloud_armor_policy_self_link = var.enable_cloud_armor ? google_compute_security_policy.main[0].self_link : null
  }
}

# =============================================================================
# TAGS AND LABELS OUTPUTS
# =============================================================================

output "common_labels" {
  description = "Common labels applied to all resources"
  value       = local.common_labels
}

output "resource_naming_convention" {
  description = "Resource naming convention used"
  value = {
    prefix      = var.name_prefix
    environment = var.environment
    pattern     = "${var.name_prefix}-{resource-type}"
  }
}

# =============================================================================
# DISASTER RECOVERY SUMMARY
# =============================================================================

output "disaster_recovery_summary" {
  description = "Disaster recovery configuration summary"
  value = {
    cross_region_backup_enabled = var.enable_cross_region_backup
    primary_region             = var.region
    backup_region             = var.backup_region
    rpo_hours                 = var.rpo_hours
    rto_hours                 = var.rto_hours
    backup_retention_days     = var.backup_retention_days
  }
}

# =============================================================================
# SECURITY RECOMMENDATIONS
# =============================================================================

output "security_recommendations" {
  description = "Security enhancement recommendations"
  value = [
    var.enable_cloud_armor ? null : "Enable Cloud Armor for web application firewall protection",
    var.enable_kms ? null : "Enable Cloud KMS for encryption key management",
    var.enable_private_service_connect ? null : "Enable Private Service Connect for secure API access",
    var.enable_binary_authorization ? null : "Enable Binary Authorization for container image verification",
    length(var.notification_channels) > 0 ? null : "Configure notification channels for monitoring alerts",
    var.enable_monitoring_alerts ? null : "Enable monitoring alerts for security events",
    length(var.allowed_countries) > 0 ? null : "Configure allowed countries for geo-blocking"
  ]
}

# =============================================================================
# PROJECT CONFIGURATION
# =============================================================================

output "project_configuration" {
  description = "Project-level configuration summary"
  value = {
    project_id              = var.project_id
    enabled_apis           = [
      "compute.googleapis.com",
      var.enable_gke ? "container.googleapis.com" : null,
      var.enable_kms ? "cloudkms.googleapis.com" : null,
      "logging.googleapis.com",
      "monitoring.googleapis.com"
    ]
    org_policies_enabled   = var.enable_org_policies
    vpc_service_controls   = var.enable_vpc_service_controls
    workload_identity      = var.enable_workload_identity
  }
}