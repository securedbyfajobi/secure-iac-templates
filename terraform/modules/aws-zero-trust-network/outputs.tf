# Outputs for AWS Zero-Trust Network Architecture Module

# =============================================================================
# VPC OUTPUTS
# =============================================================================

output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "vpc_arn" {
  description = "ARN of the VPC"
  value       = aws_vpc.main.arn
}

output "vpc_cidr_block" {
  description = "CIDR block of the VPC"
  value       = aws_vpc.main.cidr_block
}

output "vpc_ipv6_cidr_block" {
  description = "IPv6 CIDR block of the VPC"
  value       = aws_vpc.main.ipv6_cidr_block
}

output "vpc_main_route_table_id" {
  description = "ID of the main route table"
  value       = aws_vpc.main.main_route_table_id
}

output "vpc_default_security_group_id" {
  description = "ID of the default security group"
  value       = aws_vpc.main.default_security_group_id
}

output "vpc_default_network_acl_id" {
  description = "ID of the default network ACL"
  value       = aws_vpc.main.default_network_acl_id
}

# =============================================================================
# SUBNET OUTPUTS
# =============================================================================

output "public_subnet_ids" {
  description = "IDs of the public subnets"
  value       = aws_subnet.public[*].id
}

output "public_subnet_arns" {
  description = "ARNs of the public subnets"
  value       = aws_subnet.public[*].arn
}

output "public_subnet_cidrs" {
  description = "CIDR blocks of the public subnets"
  value       = aws_subnet.public[*].cidr_block
}

output "private_subnet_ids" {
  description = "IDs of the private subnets"
  value       = aws_subnet.private[*].id
}

output "private_subnet_arns" {
  description = "ARNs of the private subnets"
  value       = aws_subnet.private[*].arn
}

output "private_subnet_cidrs" {
  description = "CIDR blocks of the private subnets"
  value       = aws_subnet.private[*].cidr_block
}

output "database_subnet_ids" {
  description = "IDs of the database subnets"
  value       = aws_subnet.database[*].id
}

output "database_subnet_arns" {
  description = "ARNs of the database subnets"
  value       = aws_subnet.database[*].arn
}

output "database_subnet_cidrs" {
  description = "CIDR blocks of the database subnets"
  value       = aws_subnet.database[*].cidr_block
}

output "management_subnet_ids" {
  description = "IDs of the management subnets"
  value       = var.enable_management_subnets ? aws_subnet.management[*].id : []
}

output "management_subnet_arns" {
  description = "ARNs of the management subnets"
  value       = var.enable_management_subnets ? aws_subnet.management[*].arn : []
}

output "management_subnet_cidrs" {
  description = "CIDR blocks of the management subnets"
  value       = var.enable_management_subnets ? aws_subnet.management[*].cidr_block : []
}

# =============================================================================
# GATEWAY OUTPUTS
# =============================================================================

output "internet_gateway_id" {
  description = "ID of the Internet Gateway"
  value       = aws_internet_gateway.main.id
}

output "internet_gateway_arn" {
  description = "ARN of the Internet Gateway"
  value       = aws_internet_gateway.main.arn
}

output "nat_gateway_ids" {
  description = "IDs of the NAT Gateways"
  value       = var.enable_nat_gateway ? aws_nat_gateway.main[*].id : []
}

output "nat_gateway_public_ips" {
  description = "Public IPs of the NAT Gateways"
  value       = var.enable_nat_gateway ? aws_eip.nat[*].public_ip : []
}

output "nat_gateway_private_ips" {
  description = "Private IPs of the NAT Gateways"
  value       = var.enable_nat_gateway ? aws_nat_gateway.main[*].private_ip : []
}

# =============================================================================
# ROUTE TABLE OUTPUTS
# =============================================================================

output "public_route_table_id" {
  description = "ID of the public route table"
  value       = aws_route_table.public.id
}

output "private_route_table_ids" {
  description = "IDs of the private route tables"
  value       = aws_route_table.private[*].id
}

output "database_route_table_ids" {
  description = "IDs of the database route tables"
  value       = aws_route_table.database[*].id
}

output "management_route_table_ids" {
  description = "IDs of the management route tables"
  value       = var.enable_management_subnets ? aws_route_table.management[*].id : []
}

# =============================================================================
# SECURITY GROUP OUTPUTS
# =============================================================================

output "default_security_group_id" {
  description = "ID of the default security group (restrictive)"
  value       = aws_default_security_group.default.id
}

output "web_tier_security_group_id" {
  description = "ID of the web tier security group"
  value       = aws_security_group.web_tier.id
}

output "app_tier_security_group_id" {
  description = "ID of the application tier security group"
  value       = aws_security_group.app_tier.id
}

output "database_tier_security_group_id" {
  description = "ID of the database tier security group"
  value       = aws_security_group.database_tier.id
}

output "vpc_endpoints_security_group_id" {
  description = "ID of the VPC endpoints security group"
  value       = var.enable_vpc_endpoints ? aws_security_group.vpc_endpoints[0].id : null
}

# =============================================================================
# NETWORK ACL OUTPUTS
# =============================================================================

output "public_network_acl_id" {
  description = "ID of the public network ACL"
  value       = aws_network_acl.public.id
}

output "private_network_acl_id" {
  description = "ID of the private network ACL"
  value       = aws_network_acl.private.id
}

output "database_network_acl_id" {
  description = "ID of the database network ACL"
  value       = aws_network_acl.database.id
}

# =============================================================================
# VPC ENDPOINT OUTPUTS
# =============================================================================

output "s3_vpc_endpoint_id" {
  description = "ID of the S3 VPC endpoint"
  value       = var.enable_vpc_endpoints ? aws_vpc_endpoint.s3[0].id : null
}

output "dynamodb_vpc_endpoint_id" {
  description = "ID of the DynamoDB VPC endpoint"
  value       = var.enable_vpc_endpoints ? aws_vpc_endpoint.dynamodb[0].id : null
}

output "ec2_vpc_endpoint_id" {
  description = "ID of the EC2 VPC endpoint"
  value       = var.enable_vpc_endpoints ? aws_vpc_endpoint.ec2[0].id : null
}

output "vpc_endpoint_dns_names" {
  description = "DNS names of the VPC endpoints"
  value = var.enable_vpc_endpoints ? {
    s3       = aws_vpc_endpoint.s3[0].dns_entry[0]["dns_name"]
    dynamodb = aws_vpc_endpoint.dynamodb[0].dns_entry[0]["dns_name"]
    ec2      = aws_vpc_endpoint.ec2[0].dns_entry[0]["dns_name"]
  } : {}
}

# =============================================================================
# MONITORING AND LOGGING OUTPUTS
# =============================================================================

output "flow_logs_id" {
  description = "ID of the VPC Flow Logs"
  value       = var.enable_flow_logs ? aws_flow_log.vpc_flow_log[0].id : null
}

output "flow_logs_s3_bucket" {
  description = "S3 bucket for VPC Flow Logs"
  value       = var.enable_flow_logs ? aws_s3_bucket.flow_logs[0].id : null
}

output "flow_logs_kms_key_id" {
  description = "KMS key ID for VPC Flow Logs encryption"
  value       = var.enable_flow_logs ? aws_kms_key.vpc_logs[0].id : null
}

output "flow_logs_kms_key_arn" {
  description = "KMS key ARN for VPC Flow Logs encryption"
  value       = var.enable_flow_logs ? aws_kms_key.vpc_logs[0].arn : null
}

# =============================================================================
# CLOUDWATCH ALARMS OUTPUTS
# =============================================================================

output "high_rejected_connections_alarm_arn" {
  description = "ARN of the high rejected connections alarm"
  value       = var.enable_flow_logs && var.enable_cloudwatch_alarms ? aws_cloudwatch_metric_alarm.high_rejected_connections[0].arn : null
}

output "unusual_traffic_pattern_alarm_arn" {
  description = "ARN of the unusual traffic pattern alarm"
  value       = var.enable_flow_logs && var.enable_cloudwatch_alarms ? aws_cloudwatch_metric_alarm.unusual_traffic_pattern[0].arn : null
}

# =============================================================================
# DHCP OPTIONS OUTPUTS
# =============================================================================

output "dhcp_options_id" {
  description = "ID of the DHCP options"
  value       = var.enable_custom_dhcp_options ? aws_vpc_dhcp_options.main[0].id : null
}

# =============================================================================
# AVAILABILITY ZONE OUTPUTS
# =============================================================================

output "availability_zones" {
  description = "List of availability zones used"
  value       = slice(data.aws_availability_zones.available.names, 0, local.az_count)
}

output "az_count" {
  description = "Number of availability zones used"
  value       = local.az_count
}

# =============================================================================
# SUBNET GROUP OUTPUTS (FOR RDS, ElastiCache, etc.)
# =============================================================================

output "database_subnet_group_name" {
  description = "Name for database subnet group (use database_subnet_ids)"
  value       = "${var.name_prefix}-database-subnet-group"
}

output "cache_subnet_group_name" {
  description = "Name for cache subnet group (use private_subnet_ids)"
  value       = "${var.name_prefix}-cache-subnet-group"
}

# =============================================================================
# COMPUTED VALUES
# =============================================================================

output "vpc_cidr_prefix" {
  description = "CIDR prefix of the VPC"
  value       = split("/", var.vpc_cidr)[1]
}

output "total_subnet_count" {
  description = "Total number of subnets created"
  value = (
    length(aws_subnet.public) +
    length(aws_subnet.private) +
    length(aws_subnet.database) +
    (var.enable_management_subnets ? length(aws_subnet.management) : 0)
  )
}

output "network_configuration_summary" {
  description = "Summary of network configuration"
  value = {
    vpc_id                = aws_vpc.main.id
    vpc_cidr             = aws_vpc.main.cidr_block
    availability_zones   = slice(data.aws_availability_zones.available.names, 0, local.az_count)
    public_subnets       = length(aws_subnet.public)
    private_subnets      = length(aws_subnet.private)
    database_subnets     = length(aws_subnet.database)
    management_subnets   = var.enable_management_subnets ? length(aws_subnet.management) : 0
    nat_gateways         = var.enable_nat_gateway ? length(aws_nat_gateway.main) : 0
    vpc_endpoints        = var.enable_vpc_endpoints ? 3 : 0
    flow_logs_enabled    = var.enable_flow_logs
    ipv6_enabled         = var.enable_ipv6
    instance_tenancy     = var.instance_tenancy
    compliance_frameworks = var.compliance_frameworks
  }
}

# =============================================================================
# SECURITY OUTPUTS
# =============================================================================

output "security_summary" {
  description = "Summary of security configurations"
  value = {
    default_sg_restrictive   = true
    network_acls_enabled     = true
    flow_logs_enabled        = var.enable_flow_logs
    vpc_endpoints_enabled    = var.enable_vpc_endpoints
    encryption_enabled       = var.enable_flow_logs
    cloudwatch_alarms        = var.enable_cloudwatch_alarms
    compliance_frameworks    = var.compliance_frameworks
    data_classification      = var.data_classification
    zero_trust_architecture  = true
  }
}

# =============================================================================
# COST OUTPUTS
# =============================================================================

output "estimated_monthly_cost_usd" {
  description = "Estimated monthly cost in USD (approximate)"
  value = (
    # NAT Gateway costs (approximately $45/month per gateway)
    (var.enable_nat_gateway ? local.az_count * 45 : 0) +
    # VPC Endpoint costs (approximately $7.20/month per interface endpoint)
    (var.enable_vpc_endpoints ? 22 : 0) +
    # CloudWatch alarms (approximately $0.10/month per alarm)
    (var.enable_cloudwatch_alarms ? 0.20 : 0) +
    # S3 storage for flow logs (estimated $5/month)
    (var.enable_flow_logs ? 5 : 0)
  )
}

# =============================================================================
# TAGS OUTPUTS
# =============================================================================

output "common_tags" {
  description = "Common tags applied to all resources"
  value       = local.common_tags
}

output "resource_naming_convention" {
  description = "Resource naming convention used"
  value = {
    prefix      = var.name_prefix
    environment = var.environment
    pattern     = "${var.name_prefix}-{resource-type}-{environment}"
  }
}