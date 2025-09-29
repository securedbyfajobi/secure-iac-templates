# Outputs for Azure Zero-Trust Network Architecture Module

# =============================================================================
# RESOURCE GROUP OUTPUTS
# =============================================================================

output "resource_group_name" {
  description = "Name of the resource group"
  value       = azurerm_resource_group.main.name
}

output "resource_group_id" {
  description = "ID of the resource group"
  value       = azurerm_resource_group.main.id
}

output "location" {
  description = "Azure region where resources are deployed"
  value       = azurerm_resource_group.main.location
}

# =============================================================================
# VIRTUAL NETWORK OUTPUTS
# =============================================================================

output "virtual_network_id" {
  description = "ID of the virtual network"
  value       = azurerm_virtual_network.main.id
}

output "virtual_network_name" {
  description = "Name of the virtual network"
  value       = azurerm_virtual_network.main.name
}

output "virtual_network_address_space" {
  description = "Address space of the virtual network"
  value       = azurerm_virtual_network.main.address_space
}

output "virtual_network_guid" {
  description = "GUID of the virtual network"
  value       = azurerm_virtual_network.main.guid
}

# =============================================================================
# SUBNET OUTPUTS
# =============================================================================

output "gateway_subnet_id" {
  description = "ID of the gateway subnet"
  value       = azurerm_subnet.gateway.id
}

output "dmz_subnet_id" {
  description = "ID of the DMZ subnet"
  value       = azurerm_subnet.dmz.id
}

output "dmz_subnet_address_prefixes" {
  description = "Address prefixes of the DMZ subnet"
  value       = azurerm_subnet.dmz.address_prefixes
}

output "web_subnet_id" {
  description = "ID of the web tier subnet"
  value       = azurerm_subnet.web.id
}

output "web_subnet_address_prefixes" {
  description = "Address prefixes of the web tier subnet"
  value       = azurerm_subnet.web.address_prefixes
}

output "app_subnet_id" {
  description = "ID of the application tier subnet"
  value       = azurerm_subnet.app.id
}

output "app_subnet_address_prefixes" {
  description = "Address prefixes of the application tier subnet"
  value       = azurerm_subnet.app.address_prefixes
}

output "data_subnet_id" {
  description = "ID of the data tier subnet"
  value       = azurerm_subnet.data.id
}

output "data_subnet_address_prefixes" {
  description = "Address prefixes of the data tier subnet"
  value       = azurerm_subnet.data.address_prefixes
}

output "management_subnet_id" {
  description = "ID of the management subnet"
  value       = azurerm_subnet.management.id
}

output "management_subnet_address_prefixes" {
  description = "Address prefixes of the management subnet"
  value       = azurerm_subnet.management.address_prefixes
}

output "bastion_subnet_id" {
  description = "ID of the Azure Bastion subnet"
  value       = var.enable_bastion ? azurerm_subnet.bastion[0].id : null
}

output "firewall_subnet_id" {
  description = "ID of the Azure Firewall subnet"
  value       = var.enable_azure_firewall ? azurerm_subnet.firewall[0].id : null
}

# =============================================================================
# NETWORK SECURITY GROUP OUTPUTS
# =============================================================================

output "dmz_nsg_id" {
  description = "ID of the DMZ network security group"
  value       = azurerm_network_security_group.dmz.id
}

output "web_nsg_id" {
  description = "ID of the web tier network security group"
  value       = azurerm_network_security_group.web.id
}

output "app_nsg_id" {
  description = "ID of the application tier network security group"
  value       = azurerm_network_security_group.app.id
}

output "data_nsg_id" {
  description = "ID of the data tier network security group"
  value       = azurerm_network_security_group.data.id
}

output "management_nsg_id" {
  description = "ID of the management network security group"
  value       = azurerm_network_security_group.management.id
}

# =============================================================================
# AZURE BASTION OUTPUTS
# =============================================================================

output "bastion_host_id" {
  description = "ID of the Azure Bastion host"
  value       = var.enable_bastion ? azurerm_bastion_host.main[0].id : null
}

output "bastion_host_fqdn" {
  description = "FQDN of the Azure Bastion host"
  value       = var.enable_bastion ? azurerm_bastion_host.main[0].dns_name : null
}

output "bastion_public_ip" {
  description = "Public IP address of Azure Bastion"
  value       = var.enable_bastion ? azurerm_public_ip.bastion[0].ip_address : null
}

# =============================================================================
# AZURE FIREWALL OUTPUTS
# =============================================================================

output "firewall_id" {
  description = "ID of the Azure Firewall"
  value       = var.enable_azure_firewall ? azurerm_firewall.main[0].id : null
}

output "firewall_private_ip" {
  description = "Private IP address of the Azure Firewall"
  value       = var.enable_azure_firewall ? azurerm_firewall.main[0].ip_configuration[0].private_ip_address : null
}

output "firewall_public_ip" {
  description = "Public IP address of the Azure Firewall"
  value       = var.enable_azure_firewall ? azurerm_public_ip.firewall[0].ip_address : null
}

# =============================================================================
# ROUTE TABLE OUTPUTS
# =============================================================================

output "firewall_route_table_id" {
  description = "ID of the firewall route table"
  value       = var.enable_azure_firewall ? azurerm_route_table.firewall[0].id : null
}

# =============================================================================
# PRIVATE DNS OUTPUTS
# =============================================================================

output "private_dns_zone_id" {
  description = "ID of the private DNS zone"
  value       = var.enable_private_dns ? azurerm_private_dns_zone.internal[0].id : null
}

output "private_dns_zone_name" {
  description = "Name of the private DNS zone"
  value       = var.enable_private_dns ? azurerm_private_dns_zone.internal[0].name : null
}

# =============================================================================
# MONITORING OUTPUTS
# =============================================================================

output "network_watcher_id" {
  description = "ID of the Network Watcher"
  value       = var.enable_network_watcher ? azurerm_network_watcher.main[0].id : null
}

output "log_analytics_workspace_id" {
  description = "ID of the Log Analytics workspace"
  value       = var.enable_traffic_analytics || var.enable_security_monitoring ? azurerm_log_analytics_workspace.main[0].id : null
}

output "log_analytics_workspace_workspace_id" {
  description = "Workspace ID of the Log Analytics workspace"
  value       = var.enable_traffic_analytics || var.enable_security_monitoring ? azurerm_log_analytics_workspace.main[0].workspace_id : null
}

output "flow_logs_storage_account_id" {
  description = "ID of the storage account for flow logs"
  value       = var.enable_flow_logs ? azurerm_storage_account.flow_logs[0].id : null
}

output "flow_logs_storage_account_name" {
  description = "Name of the storage account for flow logs"
  value       = var.enable_flow_logs ? azurerm_storage_account.flow_logs[0].name : null
}

# =============================================================================
# KEY VAULT OUTPUTS
# =============================================================================

output "key_vault_id" {
  description = "ID of the Azure Key Vault"
  value       = var.enable_key_vault ? azurerm_key_vault.main[0].id : null
}

output "key_vault_uri" {
  description = "URI of the Azure Key Vault"
  value       = var.enable_key_vault ? azurerm_key_vault.main[0].vault_uri : null
}

output "key_vault_name" {
  description = "Name of the Azure Key Vault"
  value       = var.enable_key_vault ? azurerm_key_vault.main[0].name : null
}

# =============================================================================
# SECURITY SUMMARY OUTPUTS
# =============================================================================

output "security_summary" {
  description = "Summary of security configurations"
  value = {
    zero_trust_architecture    = true
    network_segmentation      = true
    ddos_protection_enabled   = var.enable_ddos_protection
    azure_firewall_enabled    = var.enable_azure_firewall
    bastion_enabled           = var.enable_bastion
    flow_logs_enabled         = var.enable_flow_logs
    traffic_analytics_enabled = var.enable_traffic_analytics
    network_watcher_enabled   = var.enable_network_watcher
    key_vault_enabled         = var.enable_key_vault
    compliance_frameworks     = var.compliance_frameworks
    data_classification       = var.data_classification
  }
}

# =============================================================================
# NETWORK CONFIGURATION SUMMARY
# =============================================================================

output "network_configuration_summary" {
  description = "Summary of network configuration"
  value = {
    virtual_network_id    = azurerm_virtual_network.main.id
    address_space        = azurerm_virtual_network.main.address_space
    location             = azurerm_resource_group.main.location
    resource_group_name  = azurerm_resource_group.main.name
    subnet_count         = 7 + (var.enable_bastion ? 1 : 0) + (var.enable_azure_firewall ? 1 : 0)
    nsg_count           = 5
    ddos_protection     = var.enable_ddos_protection
    azure_firewall      = var.enable_azure_firewall
    bastion_host        = var.enable_bastion
    private_dns         = var.enable_private_dns
  }
}

# =============================================================================
# COST ESTIMATION OUTPUTS
# =============================================================================

output "estimated_monthly_cost_usd" {
  description = "Estimated monthly cost in USD (approximate)"
  value = (
    # DDoS Protection Standard ($2,944/month)
    (var.enable_ddos_protection ? 2944 : 0) +
    # Azure Firewall Standard (~$1,256/month)
    (var.enable_azure_firewall && var.firewall_sku_tier == "Standard" ? 1256 : 0) +
    # Azure Firewall Premium (~$1,600/month)
    (var.enable_azure_firewall && var.firewall_sku_tier == "Premium" ? 1600 : 0) +
    # Azure Bastion Standard (~$87/month)
    (var.enable_bastion && var.bastion_sku == "Standard" ? 87 : 0) +
    # Azure Bastion Basic (~$44/month)
    (var.enable_bastion && var.bastion_sku == "Basic" ? 44 : 0) +
    # Storage for flow logs (~$10/month)
    (var.enable_flow_logs ? 10 : 0) +
    # Log Analytics workspace (~$2.30/GB)
    (var.enable_traffic_analytics || var.enable_security_monitoring ? 50 : 0) +
    # Key Vault (~$1.50/month base)
    (var.enable_key_vault ? 2 : 0) +
    # Network Watcher (~$1/month)
    (var.enable_network_watcher ? 1 : 0)
  )
}

output "cost_breakdown" {
  description = "Detailed cost breakdown by service"
  value = {
    ddos_protection = var.enable_ddos_protection ? 2944 : 0
    azure_firewall  = var.enable_azure_firewall ? (var.firewall_sku_tier == "Premium" ? 1600 : 1256) : 0
    bastion_host    = var.enable_bastion ? (var.bastion_sku == "Standard" ? 87 : 44) : 0
    storage_logs    = var.enable_flow_logs ? 10 : 0
    log_analytics   = var.enable_traffic_analytics || var.enable_security_monitoring ? 50 : 0
    key_vault       = var.enable_key_vault ? 2 : 0
    network_watcher = var.enable_network_watcher ? 1 : 0
  }
}

# =============================================================================
# COMPLIANCE OUTPUTS
# =============================================================================

output "compliance_status" {
  description = "Compliance framework status"
  value = {
    frameworks_enabled = var.compliance_frameworks
    zero_trust_compliant = true
    network_segmentation = true
    encryption_enabled   = var.enable_key_vault
    monitoring_enabled   = var.enable_flow_logs && var.enable_traffic_analytics
    access_controls     = var.enable_bastion
    audit_logging       = var.enable_flow_logs
  }
}

# =============================================================================
# TAGS OUTPUT
# =============================================================================

output "common_tags" {
  description = "Common tags applied to all resources"
  value       = local.common_tags
}

# =============================================================================
# RESOURCE NAMING CONVENTION
# =============================================================================

output "resource_naming_convention" {
  description = "Resource naming convention used"
  value = {
    prefix      = var.name_prefix
    environment = var.environment
    pattern     = "${var.name_prefix}-{resource-type}-{environment}"
  }
}

# =============================================================================
# AVAILABILITY AND DISASTER RECOVERY
# =============================================================================

output "disaster_recovery_summary" {
  description = "Disaster recovery configuration summary"
  value = {
    cross_region_backup_enabled = var.enable_cross_region_backup
    primary_region             = var.primary_location
    backup_region             = var.backup_region
    rpo_hours                 = var.rpo_hours
    rto_hours                 = var.rto_hours
    geo_redundant_backup      = var.enable_geo_redundant_backup
  }
}

# =============================================================================
# SECURITY RECOMMENDATIONS
# =============================================================================

output "security_recommendations" {
  description = "Security enhancement recommendations"
  value = [
    var.enable_ddos_protection ? null : "Enable DDoS Protection Standard for production workloads",
    var.enable_azure_firewall ? null : "Enable Azure Firewall for centralized network security",
    var.enable_bastion ? null : "Enable Azure Bastion for secure remote access",
    var.enable_flow_logs ? null : "Enable NSG Flow Logs for security monitoring",
    var.enable_key_vault ? null : "Enable Key Vault for centralized secrets management",
    length(var.management_allowed_ips) > 0 ? null : "Configure allowed IP ranges for management access",
    var.enable_traffic_analytics ? null : "Enable Traffic Analytics for network insights"
  ]
}

# =============================================================================
# INTEGRATION ENDPOINTS
# =============================================================================

output "integration_endpoints" {
  description = "Endpoints for integration with other services"
  value = {
    key_vault_uri             = var.enable_key_vault ? azurerm_key_vault.main[0].vault_uri : null
    log_analytics_workspace_id = var.enable_traffic_analytics || var.enable_security_monitoring ? azurerm_log_analytics_workspace.main[0].workspace_id : null
    storage_account_endpoint  = var.enable_flow_logs ? azurerm_storage_account.flow_logs[0].primary_blob_endpoint : null
    private_dns_zone_name     = var.enable_private_dns ? azurerm_private_dns_zone.internal[0].name : null
  }
}