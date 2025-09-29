# AWS Zero-Trust Network Architecture Module
# Enterprise-grade security with micro-segmentation, private connectivity, and comprehensive monitoring
# Implements NIST Zero Trust Architecture principles and AWS Well-Architected Security Pillar

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

# Local values for consistent naming and tagging
locals {
  common_tags = merge(var.common_tags, {
    Module      = "aws-zero-trust-network"
    Environment = var.environment
    Security    = "zero-trust"
    Compliance  = join(",", var.compliance_frameworks)
  })

  # Calculate subnet CIDRs automatically
  az_count           = min(length(data.aws_availability_zones.available.names), var.max_azs)
  public_cidr_blocks = [for i in range(local.az_count) : cidrsubnet(var.vpc_cidr, 8, i)]
  private_cidr_blocks = [for i in range(local.az_count) : cidrsubnet(var.vpc_cidr, 8, i + 10)]
  database_cidr_blocks = [for i in range(local.az_count) : cidrsubnet(var.vpc_cidr, 8, i + 20)]
  management_cidr_blocks = [for i in range(local.az_count) : cidrsubnet(var.vpc_cidr, 8, i + 30)]
}

# Data sources
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

# =============================================================================
# VPC AND CORE NETWORKING
# =============================================================================

# Main VPC with enhanced security configuration
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  instance_tenancy     = var.instance_tenancy

  # Enhanced security features
  assign_generated_ipv6_cidr_block = var.enable_ipv6

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-zero-trust-vpc"
    Type = "zero-trust-network"
  })
}

# Internet Gateway
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-igw"
  })
}

# =============================================================================
# MULTI-TIER SUBNET ARCHITECTURE
# =============================================================================

# Public Subnets (DMZ) - Minimal exposure
resource "aws_subnet" "public" {
  count = local.az_count

  vpc_id                          = aws_vpc.main.id
  cidr_block                      = local.public_cidr_blocks[count.index]
  availability_zone               = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch         = false # Zero Trust: Never auto-assign public IPs
  assign_ipv6_address_on_creation = false

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-public-subnet-${count.index + 1}"
    Tier = "public"
    Zone = "dmz"
    kubernetes.io/role/elb = "1" # For ALB/ELB
  })
}

# Private Subnets (Application Tier)
resource "aws_subnet" "private" {
  count = local.az_count

  vpc_id            = aws_vpc.main.id
  cidr_block        = local.private_cidr_blocks[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-private-subnet-${count.index + 1}"
    Tier = "private"
    Zone = "application"
    kubernetes.io/role/internal-elb = "1" # For internal ALB/ELB
  })
}

# Database Subnets (Data Tier) - Maximum isolation
resource "aws_subnet" "database" {
  count = local.az_count

  vpc_id            = aws_vpc.main.id
  cidr_block        = local.database_cidr_blocks[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-database-subnet-${count.index + 1}"
    Tier = "database"
    Zone = "data"
  })
}

# Management Subnets (Admin/Operations)
resource "aws_subnet" "management" {
  count = var.enable_management_subnets ? local.az_count : 0

  vpc_id            = aws_vpc.main.id
  cidr_block        = local.management_cidr_blocks[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-management-subnet-${count.index + 1}"
    Tier = "management"
    Zone = "admin"
  })
}

# =============================================================================
# NAT GATEWAYS WITH HIGH AVAILABILITY
# =============================================================================

# Elastic IPs for NAT Gateways
resource "aws_eip" "nat" {
  count = var.enable_nat_gateway ? local.az_count : 0

  domain     = "vpc"
  depends_on = [aws_internet_gateway.main]

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-nat-eip-${count.index + 1}"
  })

  lifecycle {
    prevent_destroy = true
  }
}

# NAT Gateways for outbound internet access
resource "aws_nat_gateway" "main" {
  count = var.enable_nat_gateway ? local.az_count : 0

  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-nat-gateway-${count.index + 1}"
  })

  depends_on = [aws_internet_gateway.main]
}

# =============================================================================
# ROUTE TABLES WITH MICRO-SEGMENTATION
# =============================================================================

# Public Route Table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  # Conditional IPv6 route
  dynamic "route" {
    for_each = var.enable_ipv6 ? [1] : []
    content {
      ipv6_cidr_block = "::/0"
      gateway_id      = aws_internet_gateway.main.id
    }
  }

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-public-rt"
    Tier = "public"
  })
}

# Private Route Tables (One per AZ for isolation)
resource "aws_route_table" "private" {
  count = local.az_count

  vpc_id = aws_vpc.main.id

  dynamic "route" {
    for_each = var.enable_nat_gateway ? [1] : []
    content {
      cidr_block     = "0.0.0.0/0"
      nat_gateway_id = aws_nat_gateway.main[count.index].id
    }
  }

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-private-rt-${count.index + 1}"
    Tier = "private"
  })
}

# Database Route Tables (Highly restricted)
resource "aws_route_table" "database" {
  count = local.az_count

  vpc_id = aws_vpc.main.id

  # No default route - database tier is isolated
  # Only VPC-internal routing

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-database-rt-${count.index + 1}"
    Tier = "database"
  })
}

# Management Route Tables
resource "aws_route_table" "management" {
  count = var.enable_management_subnets ? local.az_count : 0

  vpc_id = aws_vpc.main.id

  dynamic "route" {
    for_each = var.enable_nat_gateway ? [1] : []
    content {
      cidr_block     = "0.0.0.0/0"
      nat_gateway_id = aws_nat_gateway.main[count.index].id
    }
  }

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-management-rt-${count.index + 1}"
    Tier = "management"
  })
}

# =============================================================================
# ROUTE TABLE ASSOCIATIONS
# =============================================================================

resource "aws_route_table_association" "public" {
  count = local.az_count

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count = local.az_count

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

resource "aws_route_table_association" "database" {
  count = local.az_count

  subnet_id      = aws_subnet.database[count.index].id
  route_table_id = aws_route_table.database[count.index].id
}

resource "aws_route_table_association" "management" {
  count = var.enable_management_subnets ? local.az_count : 0

  subnet_id      = aws_subnet.management[count.index].id
  route_table_id = aws_route_table.management[count.index].id
}

# =============================================================================
# VPC FLOW LOGS WITH COMPREHENSIVE MONITORING
# =============================================================================

# S3 Bucket for Flow Logs
resource "aws_s3_bucket" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0

  bucket = "${var.name_prefix}-vpc-flow-logs-${random_id.bucket_suffix.hex}"

  tags = local.common_tags
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket_versioning" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0

  bucket = aws_s3_bucket.flow_logs[0].id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0

  bucket = aws_s3_bucket.flow_logs[0].id

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.vpc_logs[0].arn
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

resource "aws_s3_bucket_public_access_block" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0

  bucket = aws_s3_bucket.flow_logs[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# KMS Key for encryption
resource "aws_kms_key" "vpc_logs" {
  count = var.enable_flow_logs ? 1 : 0

  description             = "KMS key for VPC Flow Logs encryption"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow VPC Flow Logs"
        Effect = "Allow"
        Principal = {
          Service = "delivery.logs.amazonaws.com"
        }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_kms_alias" "vpc_logs" {
  count = var.enable_flow_logs ? 1 : 0

  name          = "alias/${var.name_prefix}-vpc-flow-logs"
  target_key_id = aws_kms_key.vpc_logs[0].key_id
}

# IAM Role for Flow Logs
resource "aws_iam_role" "flow_log" {
  count = var.enable_flow_logs ? 1 : 0

  name = "${var.name_prefix}-vpc-flow-log-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy" "flow_log" {
  count = var.enable_flow_logs ? 1 : 0

  name = "${var.name_prefix}-vpc-flow-log-policy"
  role = aws_iam_role.flow_log[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:GetBucketAcl",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.flow_logs[0].arn,
          "${aws_s3_bucket.flow_logs[0].arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.vpc_logs[0].arn
      }
    ]
  })
}

# VPC Flow Logs
resource "aws_flow_log" "vpc_flow_log" {
  count = var.enable_flow_logs ? 1 : 0

  iam_role_arn         = aws_iam_role.flow_log[0].arn
  log_destination      = aws_s3_bucket.flow_logs[0].arn
  log_destination_type = "s3"
  traffic_type         = "ALL"
  vpc_id               = aws_vpc.main.id
  log_format           = var.flow_log_format

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-vpc-flow-log"
  })
}

# =============================================================================
# NETWORK ACLS FOR DEFENSE IN DEPTH
# =============================================================================

# Public Subnet Network ACL
resource "aws_network_acl" "public" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.public[*].id

  # Inbound rules
  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 80
    to_port    = 80
  }

  ingress {
    protocol   = "tcp"
    rule_no    = 110
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }

  ingress {
    protocol   = "tcp"
    rule_no    = 120
    action     = "allow"
    cidr_block = aws_vpc.main.cidr_block
    from_port  = 22
    to_port    = 22
  }

  # Ephemeral ports for return traffic
  ingress {
    protocol   = "tcp"
    rule_no    = 200
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  # Outbound rules
  egress {
    protocol   = -1
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-public-nacl"
    Tier = "public"
  })
}

# Private Subnet Network ACL
resource "aws_network_acl" "private" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.private[*].id

  # Allow all traffic from VPC
  ingress {
    protocol   = -1
    rule_no    = 100
    action     = "allow"
    cidr_block = aws_vpc.main.cidr_block
    from_port  = 0
    to_port    = 0
  }

  # Allow return traffic from internet
  ingress {
    protocol   = "tcp"
    rule_no    = 200
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  # Allow all outbound traffic
  egress {
    protocol   = -1
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-private-nacl"
    Tier = "private"
  })
}

# Database Subnet Network ACL (Most restrictive)
resource "aws_network_acl" "database" {
  vpc_id     = aws_vpc.main.id
  subnet_ids = aws_subnet.database[*].id

  # Only allow traffic from private subnets
  ingress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = aws_subnet.private[0].cidr_block
    from_port  = 3306
    to_port    = 3306
  }

  ingress {
    protocol   = "tcp"
    rule_no    = 110
    action     = "allow"
    cidr_block = aws_subnet.private[0].cidr_block
    from_port  = 5432
    to_port    = 5432
  }

  # Allow management access
  dynamic "ingress" {
    for_each = var.enable_management_subnets ? aws_subnet.management : []
    content {
      protocol   = "tcp"
      rule_no    = 120 + ingress.key
      action     = "allow"
      cidr_block = ingress.value.cidr_block
      from_port  = 22
      to_port    = 22
    }
  }

  # Limited outbound (for updates only)
  egress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = aws_vpc.main.cidr_block
    from_port  = 1024
    to_port    = 65535
  }

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-database-nacl"
    Tier = "database"
  })
}

# =============================================================================
# VPC ENDPOINTS FOR PRIVATE CONNECTIVITY
# =============================================================================

# S3 VPC Endpoint (Gateway)
resource "aws_vpc_endpoint" "s3" {
  count = var.enable_vpc_endpoints ? 1 : 0

  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = concat(aws_route_table.private[*].id, aws_route_table.database[*].id)

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = "*"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket"
        ]
        Resource = [
          "arn:aws:s3:::${var.name_prefix}-*",
          "arn:aws:s3:::${var.name_prefix}-*/*"
        ]
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-s3-endpoint"
  })
}

# DynamoDB VPC Endpoint (Gateway)
resource "aws_vpc_endpoint" "dynamodb" {
  count = var.enable_vpc_endpoints ? 1 : 0

  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${data.aws_region.current.name}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = concat(aws_route_table.private[*].id, aws_route_table.database[*].id)

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-dynamodb-endpoint"
  })
}

# EC2 VPC Endpoint (Interface)
resource "aws_vpc_endpoint" "ec2" {
  count = var.enable_vpc_endpoints ? 1 : 0

  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${data.aws_region.current.name}.ec2"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints[0].id]
  private_dns_enabled = true

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-ec2-endpoint"
  })
}

# Security Group for VPC Endpoints
resource "aws_security_group" "vpc_endpoints" {
  count = var.enable_vpc_endpoints ? 1 : 0

  name_prefix = "${var.name_prefix}-vpc-endpoints-"
  vpc_id      = aws_vpc.main.id
  description = "Security group for VPC endpoints"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.main.cidr_block]
    description = "HTTPS from VPC"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "All outbound traffic"
  }

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-vpc-endpoints-sg"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# =============================================================================
# SECURITY GROUPS WITH ZERO TRUST PRINCIPLES
# =============================================================================

# Restrictive Default Security Group
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id

  # Explicit deny all - no rules
  ingress = []
  egress  = []

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-default-sg-deny-all"
    Type = "restrictive-default"
  })
}

# Web Tier Security Group
resource "aws_security_group" "web_tier" {
  name_prefix = "${var.name_prefix}-web-tier-"
  vpc_id      = aws_vpc.main.id
  description = "Security group for web tier (ALB/ELB)"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP from anywhere"
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS from anywhere"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [aws_vpc.main.cidr_block]
    description = "All traffic within VPC"
  }

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-web-tier-sg"
    Tier = "web"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Application Tier Security Group
resource "aws_security_group" "app_tier" {
  name_prefix = "${var.name_prefix}-app-tier-"
  vpc_id      = aws_vpc.main.id
  description = "Security group for application tier"

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.web_tier.id]
    description     = "HTTP from web tier"
  }

  ingress {
    from_port       = 8443
    to_port         = 8443
    protocol        = "tcp"
    security_groups = [aws_security_group.web_tier.id]
    description     = "HTTPS from web tier"
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS to internet"
  }

  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP to internet"
  }

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-app-tier-sg"
    Tier = "application"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Database Tier Security Group
resource "aws_security_group" "database_tier" {
  name_prefix = "${var.name_prefix}-database-tier-"
  vpc_id      = aws_vpc.main.id
  description = "Security group for database tier"

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.app_tier.id]
    description     = "MySQL from app tier"
  }

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app_tier.id]
    description     = "PostgreSQL from app tier"
  }

  # No egress rules - database should not initiate outbound connections

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-database-tier-sg"
    Tier = "database"
  })

  lifecycle {
    create_before_destroy = true
  }
}

# =============================================================================
# DHCP OPTIONS FOR ENHANCED SECURITY
# =============================================================================

resource "aws_vpc_dhcp_options" "main" {
  count = var.enable_custom_dhcp_options ? 1 : 0

  domain_name_servers = var.custom_dns_servers
  domain_name         = var.domain_name
  ntp_servers         = var.ntp_servers

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-dhcp-options"
  })
}

resource "aws_vpc_dhcp_options_association" "main" {
  count = var.enable_custom_dhcp_options ? 1 : 0

  vpc_id          = aws_vpc.main.id
  dhcp_options_id = aws_vpc_dhcp_options.main[0].id
}

# =============================================================================
# CLOUDWATCH ALARMS FOR MONITORING
# =============================================================================

# VPC Flow Logs CloudWatch Alarms
resource "aws_cloudwatch_metric_alarm" "high_rejected_connections" {
  count = var.enable_flow_logs && var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.name_prefix}-high-rejected-connections"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "PacketsDropCount"
  namespace           = "AWS/VPC"
  period              = "300"
  statistic           = "Sum"
  threshold           = var.rejected_connections_threshold
  alarm_description   = "This metric monitors high number of rejected connections"
  alarm_actions       = var.alarm_actions

  dimensions = {
    VpcId = aws_vpc.main.id
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "unusual_traffic_pattern" {
  count = var.enable_flow_logs && var.enable_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${var.name_prefix}-unusual-traffic-pattern"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "3"
  metric_name         = "BytesTransferred"
  namespace           = "AWS/VPC"
  period              = "300"
  statistic           = "Sum"
  threshold           = var.unusual_traffic_threshold
  alarm_description   = "This metric monitors unusual traffic patterns"
  alarm_actions       = var.alarm_actions

  dimensions = {
    VpcId = aws_vpc.main.id
  }

  tags = local.common_tags
}