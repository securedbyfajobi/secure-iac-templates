# Azure Zero-Trust Network Architecture Module
# Enterprise-grade network security following Microsoft's Zero Trust model

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.0"
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

data "azurerm_client_config" "current" {}

data "azurerm_subscription" "current" {}

# Get available locations for multi-region deployment
data "azurerm_locations" "available" {
  location = var.primary_location
}

# =============================================================================
# LOCALS AND COMPUTED VALUES
# =============================================================================

locals {
  # Common tags for all resources
  common_tags = merge(var.common_tags, {
    Environment          = var.environment
    Module              = "azure-zero-trust-network"
    CreatedBy           = "terraform"
    LastModified        = timestamp()
    SecurityFramework   = "zero-trust"
    ComplianceRequired  = "true"
    DataClassification  = var.data_classification
  })

  # Network configuration
  vnet_address_space = [var.vnet_address_space]

  # Subnet calculations
  subnet_cidrs = {
    gateway     = cidrsubnet(var.vnet_address_space, 8, 0)   # First /24
    dmz         = cidrsubnet(var.vnet_address_space, 8, 1)   # Second /24
    web         = cidrsubnet(var.vnet_address_space, 8, 2)   # Third /24
    app         = cidrsubnet(var.vnet_address_space, 8, 3)   # Fourth /24
    data        = cidrsubnet(var.vnet_address_space, 8, 4)   # Fifth /24
    management  = cidrsubnet(var.vnet_address_space, 8, 5)   # Sixth /24
    bastion     = cidrsubnet(var.vnet_address_space, 8, 6)   # Seventh /24
  }

  # Security rules for zero-trust
  zero_trust_rules = {
    deny_all_inbound = {
      name                       = "DenyAllInbound"
      priority                   = 4096
      direction                  = "Inbound"
      access                     = "Deny"
      protocol                   = "*"
      source_port_range          = "*"
      destination_port_range     = "*"
      source_address_prefix      = "*"
      destination_address_prefix = "*"
    }
    deny_all_outbound = {
      name                       = "DenyAllOutbound"
      priority                   = 4096
      direction                  = "Outbound"
      access                     = "Deny"
      protocol                   = "*"
      source_port_range          = "*"
      destination_port_range     = "*"
      source_address_prefix      = "*"
      destination_address_prefix = "*"
    }
  }

  # Compliance requirements mapping
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
# RESOURCE GROUP
# =============================================================================

resource "azurerm_resource_group" "main" {
  name     = "${var.name_prefix}-network-rg"
  location = var.primary_location
  tags     = local.common_tags
}

# =============================================================================
# VIRTUAL NETWORK
# =============================================================================

resource "azurerm_virtual_network" "main" {
  name                = "${var.name_prefix}-vnet"
  address_space       = local.vnet_address_space
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  # DDoS protection
  ddos_protection_plan {
    id     = var.enable_ddos_protection ? azurerm_network_ddos_protection_plan.main[0].id : null
    enable = var.enable_ddos_protection
  }

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-vnet"
    Type = "virtual-network"
  })
}

# DDoS Protection Plan
resource "azurerm_network_ddos_protection_plan" "main" {
  count               = var.enable_ddos_protection ? 1 : 0
  name                = "${var.name_prefix}-ddos-protection"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.common_tags
}

# =============================================================================
# SUBNETS - ZERO TRUST SEGMENTATION
# =============================================================================

# Gateway Subnet (for VPN/ExpressRoute gateways)
resource "azurerm_subnet" "gateway" {
  name                 = "GatewaySubnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [local.subnet_cidrs.gateway]
}

# DMZ Subnet (External-facing resources)
resource "azurerm_subnet" "dmz" {
  name                 = "${var.name_prefix}-dmz-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [local.subnet_cidrs.dmz]

  # Disable private endpoint network policies for security services
  private_endpoint_network_policies_enabled = false
}

# Web Tier Subnet
resource "azurerm_subnet" "web" {
  name                 = "${var.name_prefix}-web-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [local.subnet_cidrs.web]

  # Service endpoints for storage and key vault
  service_endpoints = ["Microsoft.Storage", "Microsoft.KeyVault", "Microsoft.Sql"]
}

# Application Tier Subnet
resource "azurerm_subnet" "app" {
  name                 = "${var.name_prefix}-app-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [local.subnet_cidrs.app]

  service_endpoints = ["Microsoft.Storage", "Microsoft.KeyVault", "Microsoft.Sql"]
}

# Data Tier Subnet
resource "azurerm_subnet" "data" {
  name                 = "${var.name_prefix}-data-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [local.subnet_cidrs.data]

  service_endpoints = ["Microsoft.Storage", "Microsoft.KeyVault", "Microsoft.Sql"]

  # Delegate to SQL managed instances if enabled
  dynamic "delegation" {
    for_each = var.enable_sql_managed_instance ? [1] : []
    content {
      name = "Microsoft.Sql.managedInstances"
      service_delegation {
        name    = "Microsoft.Sql/managedInstances"
        actions = ["Microsoft.Network/virtualNetworks/subnets/join/action"]
      }
    }
  }
}

# Management Subnet
resource "azurerm_subnet" "management" {
  name                 = "${var.name_prefix}-mgmt-subnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [local.subnet_cidrs.management]

  service_endpoints = ["Microsoft.Storage", "Microsoft.KeyVault"]
}

# Azure Bastion Subnet
resource "azurerm_subnet" "bastion" {
  count                = var.enable_bastion ? 1 : 0
  name                 = "AzureBastionSubnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [local.subnet_cidrs.bastion]
}

# =============================================================================
# NETWORK SECURITY GROUPS - ZERO TRUST
# =============================================================================

# DMZ NSG - External traffic
resource "azurerm_network_security_group" "dmz" {
  name                = "${var.name_prefix}-dmz-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  # Allow HTTPS inbound from internet
  security_rule {
    name                       = "AllowHTTPS"
    priority                   = 1000
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }

  # Allow HTTP inbound (redirect to HTTPS)
  security_rule {
    name                       = "AllowHTTP"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }

  # Deny all other inbound
  security_rule {
    name                       = "DenyAllInbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = local.common_tags
}

# Web Tier NSG
resource "azurerm_network_security_group" "web" {
  name                = "${var.name_prefix}-web-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  # Allow traffic from DMZ
  security_rule {
    name                       = "AllowFromDMZ"
    priority                   = 1000
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = ["80", "443"]
    source_address_prefix      = local.subnet_cidrs.dmz
    destination_address_prefix = "*"
  }

  # Allow Azure Load Balancer health probes
  security_rule {
    name                       = "AllowLoadBalancerProbes"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "AzureLoadBalancer"
    destination_address_prefix = "*"
  }

  # Deny all other inbound
  security_rule {
    name                       = "DenyAllInbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = local.common_tags
}

# Application Tier NSG
resource "azurerm_network_security_group" "app" {
  name                = "${var.name_prefix}-app-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  # Allow traffic from web tier
  security_rule {
    name                       = "AllowFromWeb"
    priority                   = 1000
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = ["8080", "8443"]
    source_address_prefix      = local.subnet_cidrs.web
    destination_address_prefix = "*"
  }

  # Allow management access from management subnet
  security_rule {
    name                       = "AllowFromManagement"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = ["22", "3389"]
    source_address_prefix      = local.subnet_cidrs.management
    destination_address_prefix = "*"
  }

  # Deny all other inbound
  security_rule {
    name                       = "DenyAllInbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = local.common_tags
}

# Data Tier NSG
resource "azurerm_network_security_group" "data" {
  name                = "${var.name_prefix}-data-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  # Allow database access from app tier
  security_rule {
    name                       = "AllowFromApp"
    priority                   = 1000
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = ["1433", "3306", "5432"]
    source_address_prefix      = local.subnet_cidrs.app
    destination_address_prefix = "*"
  }

  # Allow management access
  security_rule {
    name                       = "AllowFromManagement"
    priority                   = 1001
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = ["22", "3389", "1433", "3306", "5432"]
    source_address_prefix      = local.subnet_cidrs.management
    destination_address_prefix = "*"
  }

  # Deny all other inbound
  security_rule {
    name                       = "DenyAllInbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = local.common_tags
}

# Management NSG
resource "azurerm_network_security_group" "management" {
  name                = "${var.name_prefix}-mgmt-nsg"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name

  # Allow SSH/RDP from specific IPs only
  dynamic "security_rule" {
    for_each = var.management_allowed_ips
    content {
      name                       = "AllowManagement${security_rule.key}"
      priority                   = 1000 + security_rule.key
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = "Tcp"
      source_port_range          = "*"
      destination_port_ranges    = ["22", "3389"]
      source_address_prefix      = security_rule.value
      destination_address_prefix = "*"
    }
  }

  # Deny all other inbound
  security_rule {
    name                       = "DenyAllInbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = local.common_tags
}

# =============================================================================
# NSG ASSOCIATIONS
# =============================================================================

resource "azurerm_subnet_network_security_group_association" "dmz" {
  subnet_id                 = azurerm_subnet.dmz.id
  network_security_group_id = azurerm_network_security_group.dmz.id
}

resource "azurerm_subnet_network_security_group_association" "web" {
  subnet_id                 = azurerm_subnet.web.id
  network_security_group_id = azurerm_network_security_group.web.id
}

resource "azurerm_subnet_network_security_group_association" "app" {
  subnet_id                 = azurerm_subnet.app.id
  network_security_group_id = azurerm_network_security_group.app.id
}

resource "azurerm_subnet_network_security_group_association" "data" {
  subnet_id                 = azurerm_subnet.data.id
  network_security_group_id = azurerm_network_security_group.data.id
}

resource "azurerm_subnet_network_security_group_association" "management" {
  subnet_id                 = azurerm_subnet.management.id
  network_security_group_id = azurerm_network_security_group.management.id
}

# =============================================================================
# AZURE BASTION
# =============================================================================

resource "azurerm_public_ip" "bastion" {
  count               = var.enable_bastion ? 1 : 0
  name                = "${var.name_prefix}-bastion-pip"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.common_tags
}

resource "azurerm_bastion_host" "main" {
  count               = var.enable_bastion ? 1 : 0
  name                = "${var.name_prefix}-bastion"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = var.bastion_sku

  ip_configuration {
    name                 = "configuration"
    subnet_id            = azurerm_subnet.bastion[0].id
    public_ip_address_id = azurerm_public_ip.bastion[0].id
  }

  # Enterprise features
  copy_paste_enabled     = var.bastion_sku == "Standard" ? true : false
  file_copy_enabled      = var.bastion_sku == "Standard" ? true : false
  ip_connect_enabled     = var.bastion_sku == "Standard" ? true : false
  shareable_link_enabled = var.bastion_sku == "Standard" ? false : false
  tunneling_enabled      = var.bastion_sku == "Standard" ? true : false

  tags = local.common_tags
}

# =============================================================================
# AZURE FIREWALL (Optional)
# =============================================================================

resource "azurerm_public_ip" "firewall" {
  count               = var.enable_azure_firewall ? 1 : 0
  name                = "${var.name_prefix}-fw-pip"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.common_tags
}

resource "azurerm_subnet" "firewall" {
  count                = var.enable_azure_firewall ? 1 : 0
  name                 = "AzureFirewallSubnet"
  resource_group_name  = azurerm_resource_group.main.name
  virtual_network_name = azurerm_virtual_network.main.name
  address_prefixes     = [cidrsubnet(var.vnet_address_space, 8, 7)]
}

resource "azurerm_firewall" "main" {
  count               = var.enable_azure_firewall ? 1 : 0
  name                = "${var.name_prefix}-firewall"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku_name            = "AZFW_VNet"
  sku_tier            = var.firewall_sku_tier

  ip_configuration {
    name                 = "configuration"
    subnet_id            = azurerm_subnet.firewall[0].id
    public_ip_address_id = azurerm_public_ip.firewall[0].id
  }

  # Threat intelligence
  threat_intel_mode = "Alert"

  tags = local.common_tags
}

# =============================================================================
# ROUTE TABLES
# =============================================================================

# Route table for forcing traffic through firewall
resource "azurerm_route_table" "firewall" {
  count                         = var.enable_azure_firewall ? 1 : 0
  name                          = "${var.name_prefix}-fw-rt"
  location                      = azurerm_resource_group.main.location
  resource_group_name           = azurerm_resource_group.main.name
  disable_bgp_route_propagation = false

  route {
    name           = "DefaultRoute"
    address_prefix = "0.0.0.0/0"
    next_hop_type  = "VirtualAppliance"
    next_hop_in_ip_address = azurerm_firewall.main[0].ip_configuration[0].private_ip_address
  }

  tags = local.common_tags
}

# Associate route table with subnets
resource "azurerm_subnet_route_table_association" "web" {
  count          = var.enable_azure_firewall ? 1 : 0
  subnet_id      = azurerm_subnet.web.id
  route_table_id = azurerm_route_table.firewall[0].id
}

resource "azurerm_subnet_route_table_association" "app" {
  count          = var.enable_azure_firewall ? 1 : 0
  subnet_id      = azurerm_subnet.app.id
  route_table_id = azurerm_route_table.firewall[0].id
}

# =============================================================================
# PRIVATE DNS ZONES
# =============================================================================

resource "azurerm_private_dns_zone" "internal" {
  count               = var.enable_private_dns ? 1 : 0
  name                = var.private_dns_zone_name
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.common_tags
}

resource "azurerm_private_dns_zone_virtual_network_link" "internal" {
  count                 = var.enable_private_dns ? 1 : 0
  name                  = "${var.name_prefix}-dns-link"
  resource_group_name   = azurerm_resource_group.main.name
  private_dns_zone_name = azurerm_private_dns_zone.internal[0].name
  virtual_network_id    = azurerm_virtual_network.main.id
  registration_enabled  = true
  tags                  = local.common_tags
}

# =============================================================================
# NETWORK WATCHER AND MONITORING
# =============================================================================

resource "azurerm_network_watcher" "main" {
  count               = var.enable_network_watcher ? 1 : 0
  name                = "${var.name_prefix}-netwatcher"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tags                = local.common_tags
}

# Flow logs storage account
resource "azurerm_storage_account" "flow_logs" {
  count                    = var.enable_flow_logs ? 1 : 0
  name                     = "${replace(var.name_prefix, "-", "")}flowlogs${random_string.storage_suffix.result}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  # Security features
  enable_https_traffic_only      = true
  min_tls_version                = "TLS1_2"
  allow_nested_items_to_be_public = false

  # Encryption
  infrastructure_encryption_enabled = true

  tags = local.common_tags
}

resource "random_string" "storage_suffix" {
  length  = 6
  special = false
  upper   = false
}

# NSG Flow Logs
resource "azurerm_network_watcher_flow_log" "nsg_flow_logs" {
  for_each = var.enable_flow_logs ? {
    dmz        = azurerm_network_security_group.dmz.id
    web        = azurerm_network_security_group.web.id
    app        = azurerm_network_security_group.app.id
    data       = azurerm_network_security_group.data.id
    management = azurerm_network_security_group.management.id
  } : {}

  network_watcher_name = azurerm_network_watcher.main[0].name
  resource_group_name  = azurerm_resource_group.main.name
  name                 = "${var.name_prefix}-${each.key}-flow-log"

  network_security_group_id = each.value
  storage_account_id        = azurerm_storage_account.flow_logs[0].id
  enabled                   = true

  retention_policy {
    enabled = true
    days    = var.flow_log_retention_days
  }

  traffic_analytics {
    enabled               = var.enable_traffic_analytics
    workspace_id          = var.enable_traffic_analytics ? azurerm_log_analytics_workspace.main[0].workspace_id : null
    workspace_region      = var.enable_traffic_analytics ? azurerm_log_analytics_workspace.main[0].location : null
    workspace_resource_id = var.enable_traffic_analytics ? azurerm_log_analytics_workspace.main[0].id : null
    interval_in_minutes   = 10
  }

  tags = local.common_tags
}

# =============================================================================
# LOG ANALYTICS AND MONITORING
# =============================================================================

resource "azurerm_log_analytics_workspace" "main" {
  count               = var.enable_traffic_analytics || var.enable_security_monitoring ? 1 : 0
  name                = "${var.name_prefix}-law"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_analytics_retention_days

  tags = local.common_tags
}

# Security monitoring solutions
resource "azurerm_log_analytics_solution" "security" {
  count                 = var.enable_security_monitoring ? 1 : 0
  solution_name         = "Security"
  location              = azurerm_resource_group.main.location
  resource_group_name   = azurerm_resource_group.main.name
  workspace_resource_id = azurerm_log_analytics_workspace.main[0].id
  workspace_name        = azurerm_log_analytics_workspace.main[0].name

  plan {
    publisher = "Microsoft"
    product   = "OMSGallery/Security"
  }

  tags = local.common_tags
}

# =============================================================================
# KEY VAULT FOR SECRETS MANAGEMENT
# =============================================================================

resource "azurerm_key_vault" "main" {
  count                       = var.enable_key_vault ? 1 : 0
  name                        = "${var.name_prefix}-kv-${random_string.kv_suffix.result}"
  location                    = azurerm_resource_group.main.location
  resource_group_name         = azurerm_resource_group.main.name
  enabled_for_disk_encryption = true
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  soft_delete_retention_days  = 7
  purge_protection_enabled    = var.environment == "prod"
  sku_name                    = "standard"

  # Network access restrictions
  public_network_access_enabled = false

  network_acls {
    bypass         = "AzureServices"
    default_action = "Deny"
    virtual_network_subnet_ids = [
      azurerm_subnet.management.id,
      azurerm_subnet.app.id
    ]
  }

  tags = local.common_tags
}

resource "random_string" "kv_suffix" {
  length  = 6
  special = false
  upper   = false
}

# Key Vault access policy for current user
resource "azurerm_key_vault_access_policy" "current_user" {
  count        = var.enable_key_vault ? 1 : 0
  key_vault_id = azurerm_key_vault.main[0].id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = data.azurerm_client_config.current.object_id

  key_permissions = [
    "Get", "List", "Create", "Delete", "Update", "Recover", "Purge", "GetRotationPolicy", "SetRotationPolicy"
  ]

  secret_permissions = [
    "Get", "List", "Set", "Delete", "Recover", "Backup", "Restore", "Purge"
  ]

  certificate_permissions = [
    "Get", "List", "Create", "Delete", "Update", "ManageContacts", "GetIssuers", "ListIssuers", "SetIssuers", "DeleteIssuers", "ManageIssuers", "Recover", "Purge"
  ]
}