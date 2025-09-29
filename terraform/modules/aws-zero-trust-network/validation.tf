# Enterprise-grade validation and compliance checking for Zero-Trust Network Architecture

# =============================================================================
# INPUT VALIDATION RULES
# =============================================================================

# Validate VPC CIDR doesn't overlap with common enterprise ranges
locals {
  # Common enterprise CIDR ranges to avoid conflicts
  forbidden_cidrs = [
    "192.168.0.0/16",   # Common home networks
    "172.16.0.0/12",    # Common corporate networks
    "10.1.0.0/16",      # Common cloud provider defaults
    "10.10.0.0/16",     # Common corporate networks
  ]

  # Check for CIDR overlap
  cidr_overlaps = [
    for forbidden in local.forbidden_cidrs :
    cidr_overlap(var.vpc_cidr, forbidden)
  ]

  # Validate subnet distribution
  min_subnets_per_tier = 2
  max_subnets_per_tier = 6

  # Security validation flags
  has_proper_segmentation = length(aws_subnet.public) >= 2 && length(aws_subnet.private) >= 2 && length(aws_subnet.database) >= 2
  has_monitoring_enabled  = var.enable_flow_logs && var.enable_cloudwatch_alarms
  has_encryption_enabled  = var.enable_flow_logs # Flow logs use KMS encryption

  # Compliance validation
  compliance_requirements = {
    SOC2 = {
      flow_logs_required        = true
      encryption_required       = true
      network_segmentation      = true
      monitoring_required       = true
      access_logging_required   = true
    }
    NIST = {
      multi_az_required         = true
      network_isolation         = true
      encryption_in_transit     = true
      audit_logging_required    = true
      incident_response_ready   = true
    }
    CIS = {
      default_sg_restrictive    = true
      flow_logs_enabled         = true
      unused_security_groups    = false
      nacl_restrictions         = true
      vpc_endpoints_preferred   = true
    }
    "PCI-DSS" = {
      network_segmentation      = true
      encryption_required       = true
      access_controls           = true
      logging_monitoring        = true
      secure_transmission       = true
    }
    HIPAA = {
      encryption_at_rest        = true
      encryption_in_transit     = true
      access_controls           = true
      audit_logging             = true
      data_integrity            = true
    }
    FedRAMP = {
      high_availability         = true
      continuous_monitoring     = true
      incident_response         = true
      configuration_management  = true
      system_protection         = true
    }
  }
}

# =============================================================================
# VALIDATION CHECKS
# =============================================================================

# Check 1: VPC CIDR validation
check "vpc_cidr_not_forbidden" {
  assert {
    condition     = !contains(local.cidr_overlaps, true)
    error_message = "VPC CIDR ${var.vpc_cidr} overlaps with forbidden enterprise ranges: ${join(", ", local.forbidden_cidrs)}"
  }
}

# Check 2: Multi-AZ requirement for enterprise
check "multi_az_deployment" {
  assert {
    condition     = local.az_count >= 2
    error_message = "Enterprise deployments require at least 2 Availability Zones for high availability"
  }
}

# Check 3: Proper network segmentation
check "network_segmentation" {
  assert {
    condition     = local.has_proper_segmentation
    error_message = "Enterprise zero-trust requires at least 2 subnets per tier (public, private, database)"
  }
}

# Check 4: Security monitoring enabled
check "security_monitoring" {
  assert {
    condition     = local.has_monitoring_enabled
    error_message = "Enterprise security requires VPC Flow Logs and CloudWatch alarms to be enabled"
  }
}

# Check 5: Encryption requirements
check "encryption_enabled" {
  assert {
    condition     = local.has_encryption_enabled || !var.enable_flow_logs
    error_message = "Enterprise compliance requires encryption for all data at rest and in transit"
  }
}

# Check 6: Restrictive default security group
check "default_sg_restrictive" {
  assert {
    condition     = length(aws_default_security_group.default.ingress) == 0 && length(aws_default_security_group.default.egress) == 0
    error_message = "Default security group must be restrictive (no ingress/egress rules) for zero-trust architecture"
  }
}

# Check 7: NAT Gateway high availability
check "nat_gateway_ha" {
  assert {
    condition     = !var.enable_nat_gateway || length(aws_nat_gateway.main) >= 2
    error_message = "Enterprise deployments require NAT Gateways in multiple AZs for high availability"
  }
}

# Check 8: VPC Endpoints for AWS services
check "vpc_endpoints_security" {
  assert {
    condition     = var.enable_vpc_endpoints || var.cost_optimization_level == "high"
    error_message = "Enterprise security recommends VPC endpoints to avoid internet routing for AWS services"
  }
}

# Check 9: Compliance framework validation
check "compliance_frameworks_valid" {
  assert {
    condition = alltrue([
      for framework in var.compliance_frameworks :
      contains(keys(local.compliance_requirements), framework)
    ])
    error_message = "All compliance frameworks must be supported: ${join(", ", keys(local.compliance_requirements))}"
  }
}

# Check 10: Environment-specific validations
check "production_security_requirements" {
  assert {
    condition = var.environment != "prod" && var.environment != "production" || (
      var.enable_flow_logs &&
      var.enable_cloudwatch_alarms &&
      var.enable_vpc_endpoints &&
      length(var.compliance_frameworks) > 0
    )
    error_message = "Production environments must have flow logs, CloudWatch alarms, VPC endpoints, and compliance frameworks enabled"
  }
}

# =============================================================================
# COMPLIANCE-SPECIFIC VALIDATIONS
# =============================================================================

# SOC 2 Compliance Validation
check "soc2_compliance" {
  assert {
    condition = !contains(var.compliance_frameworks, "SOC2") || (
      var.enable_flow_logs &&
      var.enable_cloudwatch_alarms &&
      local.has_proper_segmentation &&
      var.enable_vpc_endpoints
    )
    error_message = "SOC 2 compliance requires flow logs, monitoring, network segmentation, and VPC endpoints"
  }
}

# NIST Compliance Validation
check "nist_compliance" {
  assert {
    condition = !contains(var.compliance_frameworks, "NIST") || (
      local.az_count >= 2 &&
      var.enable_flow_logs &&
      var.enable_encryption_in_transit &&
      var.enable_cloudwatch_alarms
    )
    error_message = "NIST compliance requires multi-AZ deployment, encryption, and comprehensive monitoring"
  }
}

# CIS Compliance Validation
check "cis_compliance" {
  assert {
    condition = !contains(var.compliance_frameworks, "CIS") || (
      var.enable_flow_logs &&
      var.enable_vpc_endpoints &&
      length(aws_default_security_group.default.ingress) == 0 &&
      length(aws_default_security_group.default.egress) == 0
    )
    error_message = "CIS compliance requires flow logs, VPC endpoints, and restrictive default security groups"
  }
}

# PCI-DSS Compliance Validation
check "pci_dss_compliance" {
  assert {
    condition = !contains(var.compliance_frameworks, "PCI-DSS") || (
      local.has_proper_segmentation &&
      var.enable_flow_logs &&
      var.enable_encryption_in_transit &&
      var.enable_cloudwatch_alarms &&
      length(aws_subnet.database) >= 2
    )
    error_message = "PCI-DSS compliance requires network segmentation, encryption, monitoring, and isolated database tier"
  }
}

# =============================================================================
# POSTCONDITION VALIDATIONS
# =============================================================================

# Validate resource creation success
data "aws_vpc" "validation" {
  id = aws_vpc.main.id

  lifecycle {
    postcondition {
      condition     = self.enable_dns_hostnames == true
      error_message = "VPC must have DNS hostnames enabled for proper service resolution"
    }

    postcondition {
      condition     = self.enable_dns_support == true
      error_message = "VPC must have DNS support enabled for proper service resolution"
    }

    postcondition {
      condition     = self.instance_tenancy == var.instance_tenancy
      error_message = "VPC instance tenancy must match the specified configuration"
    }
  }
}

# Validate subnet distribution across AZs
data "aws_subnets" "validation_private" {
  filter {
    name   = "vpc-id"
    values = [aws_vpc.main.id]
  }

  filter {
    name   = "tag:Tier"
    values = ["private"]
  }

  lifecycle {
    postcondition {
      condition     = length(self.ids) >= 2
      error_message = "Must have at least 2 private subnets for high availability"
    }
  }
}

# Validate security group rules
data "aws_security_group" "validation_default" {
  id = aws_default_security_group.default.id

  lifecycle {
    postcondition {
      condition     = length(self.ingress) == 0 && length(self.egress) == 0
      error_message = "Default security group must have no ingress or egress rules (zero-trust principle)"
    }
  }
}

# =============================================================================
# CUSTOM VALIDATION FUNCTIONS
# =============================================================================

# Function to check CIDR overlap
function "cidr_overlap" {
  params = [cidr1, cidr2]
  result = can(cidrhost(cidr1, 0)) && can(cidrhost(cidr2, 0)) && (
    can(cidrsubnet(cidr1, 0, 0)) && can(cidrsubnet(cidr2, 0, 0)) &&
    cidrsubnet(cidr1, 0, 0) == cidrsubnet(cidr2, 0, 0)
  )
}

# =============================================================================
# SECURITY POSTURE VALIDATION
# =============================================================================

# Calculate security score based on enabled features
locals {
  security_features = {
    flow_logs_enabled      = var.enable_flow_logs ? 15 : 0
    vpc_endpoints_enabled  = var.enable_vpc_endpoints ? 10 : 0
    cloudwatch_alarms      = var.enable_cloudwatch_alarms ? 10 : 0
    multi_az_deployment    = local.az_count >= 2 ? 15 : 0
    network_segmentation   = local.has_proper_segmentation ? 20 : 0
    encryption_enabled     = var.enable_encryption_in_transit ? 10 : 0
    restrictive_default_sg = length(aws_default_security_group.default.ingress) == 0 ? 10 : 0
    compliance_frameworks  = length(var.compliance_frameworks) > 0 ? 10 : 0
  }

  security_score = sum(values(local.security_features))
  max_security_score = 100

  # Security grade calculation
  security_grade = local.security_score >= 90 ? "A" : (
    local.security_score >= 80 ? "B" : (
      local.security_score >= 70 ? "C" : (
        local.security_score >= 60 ? "D" : "F"
      )
    )
  )
}

# Validate minimum security score for enterprise deployments
check "enterprise_security_score" {
  assert {
    condition     = local.security_score >= 80
    error_message = "Enterprise deployments require a minimum security score of 80/100. Current score: ${local.security_score}. Missing features: ${jsonencode([for k, v in local.security_features : k if v == 0])}"
  }
}

# =============================================================================
# COST VALIDATION
# =============================================================================

# Calculate and validate estimated costs
locals {
  estimated_costs = {
    nat_gateways    = var.enable_nat_gateway ? local.az_count * 45 : 0
    vpc_endpoints   = var.enable_vpc_endpoints ? 22 : 0
    cloudwatch      = var.enable_cloudwatch_alarms ? 0.20 : 0
    flow_logs       = var.enable_flow_logs ? 5 : 0
  }

  total_estimated_monthly_cost = sum(values(local.estimated_costs))
}

# Validate cost thresholds based on optimization level
check "cost_optimization_compliance" {
  assert {
    condition = (
      var.cost_optimization_level == "low" ||
      (var.cost_optimization_level == "medium" && local.total_estimated_monthly_cost <= 500) ||
      (var.cost_optimization_level == "high" && local.total_estimated_monthly_cost <= 200)
    )
    error_message = "Estimated monthly cost ($${local.total_estimated_monthly_cost}) exceeds budget for optimization level '${var.cost_optimization_level}'"
  }
}

# =============================================================================
# OUTPUT VALIDATION RESULTS
# =============================================================================

output "validation_results" {
  description = "Comprehensive validation results for the zero-trust network"
  value = {
    security_score         = local.security_score
    security_grade         = local.security_grade
    compliance_frameworks  = var.compliance_frameworks
    validation_passed      = local.security_score >= 80
    cost_estimate_usd      = local.total_estimated_monthly_cost
    recommendations = [
      for feature, score in local.security_features :
      "Enable ${replace(feature, "_", " ")}" if score == 0
    ]
  }
}