# AWS Enterprise Compute Security Module
# Enterprise-grade compute security with EC2, Lambda, ECS, and EKS hardening

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.4"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    cloudinit = {
      source  = "hashicorp/cloudinit"
      version = "~> 2.0"
    }
  }
}

# =============================================================================
# DATA SOURCES AND LOCALS
# =============================================================================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

# Get latest Amazon Linux 2 AMI
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Get latest Ubuntu AMI
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

locals {
  # Common tags for all resources
  common_tags = merge(var.common_tags, {
    Module             = "aws-enterprise-compute"
    Environment        = var.environment
    DataClassification = var.data_classification
    ComplianceFramework = join(",", var.compliance_frameworks)
    CreatedBy          = "terraform"
    LastModified       = timestamp()
  })

  # Security configurations based on compliance frameworks
  compliance_configs = {
    SOC2 = {
      enable_detailed_monitoring     = true
      enable_instance_metadata_v2    = true
      disable_instance_metadata_v1   = true
      enable_nitro_enclaves         = true
      require_imdsv2                = true
      enable_ebs_encryption         = true
      enable_cloudtrail_logging     = true
    }
    NIST = {
      enable_detailed_monitoring     = true
      enable_instance_metadata_v2    = true
      disable_instance_metadata_v1   = true
      enable_nitro_enclaves         = true
      require_imdsv2                = true
      enable_ebs_encryption         = true
      enable_cloudtrail_logging     = true
    }
    PCI-DSS = {
      enable_detailed_monitoring     = true
      enable_instance_metadata_v2    = true
      disable_instance_metadata_v1   = true
      enable_nitro_enclaves         = true
      require_imdsv2                = true
      enable_ebs_encryption         = true
      enable_cloudtrail_logging     = true
    }
    HIPAA = {
      enable_detailed_monitoring     = true
      enable_instance_metadata_v2    = true
      disable_instance_metadata_v1   = true
      enable_nitro_enclaves         = true
      require_imdsv2                = true
      enable_ebs_encryption         = true
      enable_cloudtrail_logging     = true
    }
  }

  # Select the strictest compliance requirements
  active_compliance = var.compliance_frameworks[0]
  compute_config = local.compliance_configs[local.active_compliance]

  # AMI selection based on OS preference
  selected_ami = var.operating_system == "ubuntu" ? data.aws_ami.ubuntu.id : data.aws_ami.amazon_linux.id
}

# =============================================================================
# KMS ENCRYPTION
# =============================================================================

resource "aws_kms_key" "compute" {
  description             = "KMS key for compute encryption - ${var.name_prefix}"
  deletion_window_in_days = var.environment == "prod" ? 30 : 7
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
        Sid    = "Allow EC2 Service"
        Effect = "Allow"
        Principal = {
          Service = ["ec2.amazonaws.com", "lambda.amazonaws.com", "ecs.amazonaws.com"]
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

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-compute-kms-key"
    Type = "compute-encryption"
  })
}

resource "aws_kms_alias" "compute" {
  name          = "alias/${var.name_prefix}-compute-key"
  target_key_id = aws_kms_key.compute.key_id
}

# =============================================================================
# SECURITY GROUPS
# =============================================================================

# Web tier security group
resource "aws_security_group" "web_tier" {
  count = var.create_web_tier ? 1 : 0

  name        = "${var.name_prefix}-web-tier-sg"
  description = "Security group for web tier instances"
  vpc_id      = var.vpc_id

  # HTTPS from internet
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.web_tier_allowed_cidrs
  }

  # HTTP (redirect to HTTPS)
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = var.web_tier_allowed_cidrs
  }

  # SSH from bastion only
  dynamic "ingress" {
    for_each = var.bastion_security_group_id != null ? [1] : []
    content {
      from_port       = 22
      to_port         = 22
      protocol        = "tcp"
      security_groups = [var.bastion_security_group_id]
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-web-tier-sg"
    Tier = "web"
  })
}

# Application tier security group
resource "aws_security_group" "app_tier" {
  count = var.create_app_tier ? 1 : 0

  name        = "${var.name_prefix}-app-tier-sg"
  description = "Security group for application tier instances"
  vpc_id      = var.vpc_id

  # Application ports from web tier
  dynamic "ingress" {
    for_each = var.create_web_tier ? [1] : []
    content {
      from_port       = var.app_port
      to_port         = var.app_port
      protocol        = "tcp"
      security_groups = [aws_security_group.web_tier[0].id]
    }
  }

  # SSH from bastion only
  dynamic "ingress" {
    for_each = var.bastion_security_group_id != null ? [1] : []
    content {
      from_port       = 22
      to_port         = 22
      protocol        = "tcp"
      security_groups = [var.bastion_security_group_id]
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-app-tier-sg"
    Tier = "application"
  })
}

# =============================================================================
# IAM ROLES AND POLICIES
# =============================================================================

# EC2 Instance Role
resource "aws_iam_role" "ec2_instance_role" {
  name = "${var.name_prefix}-ec2-instance-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

# Basic EC2 permissions
resource "aws_iam_role_policy" "ec2_basic_policy" {
  name = "${var.name_prefix}-ec2-basic-policy"
  role = aws_iam_role.ec2_instance_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeTags"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:GetParameters",
          "ssm:GetParametersByPath"
        ]
        Resource = "arn:aws:ssm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:parameter/${var.name_prefix}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:log-group:/aws/ec2/${var.name_prefix}*"
      }
    ]
  })
}

# Attach AWS managed policies for SSM
resource "aws_iam_role_policy_attachment" "ec2_ssm_managed_instance" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  role       = aws_iam_role.ec2_instance_role.name
}

resource "aws_iam_role_policy_attachment" "ec2_cloudwatch_agent" {
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
  role       = aws_iam_role.ec2_instance_role.name
}

# Instance profile
resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "${var.name_prefix}-ec2-instance-profile"
  role = aws_iam_role.ec2_instance_role.name

  tags = local.common_tags
}

# =============================================================================
# USER DATA SCRIPTS
# =============================================================================

# Generate secure user data
data "cloudinit_config" "user_data" {
  gzip          = true
  base64_encode = true

  part {
    content_type = "text/x-shellscript"
    content = templatefile("${path.module}/templates/user_data.sh", {
      environment        = var.environment
      compliance_frameworks = var.compliance_frameworks
      enable_cloudwatch_agent = var.enable_cloudwatch_monitoring
      log_group_name     = "/aws/ec2/${var.name_prefix}"
      region            = data.aws_region.current.name
    })
  }

  part {
    content_type = "text/cloud-config"
    content = yamlencode({
      package_update = true
      package_upgrade = true
      packages = [
        "htop",
        "tmux",
        "fail2ban",
        "aide",
        "rkhunter",
        "chkrootkit"
      ]
      runcmd = [
        "systemctl enable fail2ban",
        "systemctl start fail2ban",
        "aide --init",
        "mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz"
      ]
    })
  }
}

# =============================================================================
# LAUNCH TEMPLATES
# =============================================================================

resource "aws_launch_template" "web_tier" {
  count = var.create_web_tier ? 1 : 0

  name_prefix   = "${var.name_prefix}-web-"
  image_id      = local.selected_ami
  instance_type = var.web_tier_instance_type
  key_name      = var.key_pair_name

  vpc_security_group_ids = [aws_security_group.web_tier[0].id]

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_instance_profile.name
  }

  user_data = data.cloudinit_config.user_data.rendered

  # Enable detailed monitoring
  monitoring {
    enabled = local.compute_config.enable_detailed_monitoring
  }

  # Metadata options for security
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = local.compute_config.require_imdsv2 ? "required" : "optional"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  # EBS encryption
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_type           = var.ebs_volume_type
      volume_size           = var.web_tier_root_volume_size
      encrypted             = true
      kms_key_id           = aws_kms_key.compute.arn
      delete_on_termination = true
    }
  }

  # Nitro Enclaves
  enclave_options {
    enabled = local.compute_config.enable_nitro_enclaves
  }

  tag_specifications {
    resource_type = "instance"
    tags = merge(local.common_tags, {
      Name = "${var.name_prefix}-web-instance"
      Tier = "web"
    })
  }

  tag_specifications {
    resource_type = "volume"
    tags = merge(local.common_tags, {
      Name = "${var.name_prefix}-web-volume"
      Tier = "web"
    })
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = local.common_tags
}

resource "aws_launch_template" "app_tier" {
  count = var.create_app_tier ? 1 : 0

  name_prefix   = "${var.name_prefix}-app-"
  image_id      = local.selected_ami
  instance_type = var.app_tier_instance_type
  key_name      = var.key_pair_name

  vpc_security_group_ids = [aws_security_group.app_tier[0].id]

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_instance_profile.name
  }

  user_data = data.cloudinit_config.user_data.rendered

  # Enable detailed monitoring
  monitoring {
    enabled = local.compute_config.enable_detailed_monitoring
  }

  # Metadata options for security
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = local.compute_config.require_imdsv2 ? "required" : "optional"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "enabled"
  }

  # EBS encryption
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_type           = var.ebs_volume_type
      volume_size           = var.app_tier_root_volume_size
      encrypted             = true
      kms_key_id           = aws_kms_key.compute.arn
      delete_on_termination = true
    }
  }

  # Nitro Enclaves
  enclave_options {
    enabled = local.compute_config.enable_nitro_enclaves
  }

  tag_specifications {
    resource_type = "instance"
    tags = merge(local.common_tags, {
      Name = "${var.name_prefix}-app-instance"
      Tier = "application"
    })
  }

  tag_specifications {
    resource_type = "volume"
    tags = merge(local.common_tags, {
      Name = "${var.name_prefix}-app-volume"
      Tier = "application"
    })
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = local.common_tags
}

# =============================================================================
# AUTO SCALING GROUPS
# =============================================================================

resource "aws_autoscaling_group" "web_tier" {
  count = var.create_web_tier && var.enable_auto_scaling ? 1 : 0

  name                = "${var.name_prefix}-web-asg"
  vpc_zone_identifier = var.public_subnet_ids
  target_group_arns   = var.web_tier_target_group_arns
  health_check_type   = "ELB"
  health_check_grace_period = 300

  min_size         = var.web_tier_min_size
  max_size         = var.web_tier_max_size
  desired_capacity = var.web_tier_desired_capacity

  launch_template {
    id      = aws_launch_template.web_tier[0].id
    version = "$Latest"
  }

  # Instance refresh for rolling updates
  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
    }
  }

  tag {
    key                 = "Name"
    value               = "${var.name_prefix}-web-asg"
    propagate_at_launch = false
  }

  dynamic "tag" {
    for_each = local.common_tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "app_tier" {
  count = var.create_app_tier && var.enable_auto_scaling ? 1 : 0

  name                = "${var.name_prefix}-app-asg"
  vpc_zone_identifier = var.private_subnet_ids
  target_group_arns   = var.app_tier_target_group_arns
  health_check_type   = "ELB"
  health_check_grace_period = 300

  min_size         = var.app_tier_min_size
  max_size         = var.app_tier_max_size
  desired_capacity = var.app_tier_desired_capacity

  launch_template {
    id      = aws_launch_template.app_tier[0].id
    version = "$Latest"
  }

  # Instance refresh for rolling updates
  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
    }
  }

  tag {
    key                 = "Name"
    value               = "${var.name_prefix}-app-asg"
    propagate_at_launch = false
  }

  dynamic "tag" {
    for_each = local.common_tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

# =============================================================================
# LAMBDA FUNCTIONS
# =============================================================================

# Lambda execution role
resource "aws_iam_role" "lambda_execution_role" {
  count = var.create_lambda_functions ? 1 : 0

  name = "${var.name_prefix}-lambda-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "lambda_basic_execution" {
  count = var.create_lambda_functions ? 1 : 0

  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  role       = aws_iam_role.lambda_execution_role[0].name
}

resource "aws_iam_role_policy_attachment" "lambda_vpc_execution" {
  count = var.create_lambda_functions && var.lambda_vpc_config != null ? 1 : 0

  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
  role       = aws_iam_role.lambda_execution_role[0].name
}

# Lambda function
resource "aws_lambda_function" "main" {
  for_each = var.lambda_functions

  function_name = "${var.name_prefix}-${each.key}"
  role         = aws_iam_role.lambda_execution_role[0].arn
  handler      = each.value.handler
  runtime      = each.value.runtime
  timeout      = each.value.timeout
  memory_size  = each.value.memory_size

  filename         = each.value.filename
  source_code_hash = each.value.source_code_hash

  # VPC configuration
  dynamic "vpc_config" {
    for_each = var.lambda_vpc_config != null ? [var.lambda_vpc_config] : []
    content {
      subnet_ids         = vpc_config.value.subnet_ids
      security_group_ids = vpc_config.value.security_group_ids
    }
  }

  # Environment variables
  dynamic "environment" {
    for_each = each.value.environment_variables != null ? [each.value.environment_variables] : []
    content {
      variables = environment.value
    }
  }

  # KMS encryption
  kms_key_arn = aws_kms_key.compute.arn

  # Reserved concurrency
  reserved_concurrent_executions = each.value.reserved_concurrency

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-${each.key}"
    Type = "lambda-function"
  })

  depends_on = [aws_iam_role_policy_attachment.lambda_basic_execution]
}

# =============================================================================
# ECS CLUSTER
# =============================================================================

resource "aws_ecs_cluster" "main" {
  count = var.create_ecs_cluster ? 1 : 0

  name = "${var.name_prefix}-ecs-cluster"

  configuration {
    execute_command_configuration {
      kms_key_id = aws_kms_key.compute.arn
      logging    = "OVERRIDE"

      log_configuration {
        cloud_watch_encryption_enabled = true
        cloud_watch_log_group_name     = aws_cloudwatch_log_group.ecs_exec[0].name
      }
    }
  }

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-ecs-cluster"
  })
}

resource "aws_ecs_cluster_capacity_providers" "main" {
  count = var.create_ecs_cluster ? 1 : 0

  cluster_name = aws_ecs_cluster.main[0].name

  capacity_providers = ["FARGATE", "FARGATE_SPOT"]

  default_capacity_provider_strategy {
    base              = 1
    weight            = 100
    capacity_provider = "FARGATE"
  }
}

# CloudWatch log group for ECS Exec
resource "aws_cloudwatch_log_group" "ecs_exec" {
  count = var.create_ecs_cluster ? 1 : 0

  name              = "/aws/ecs/${var.name_prefix}/exec"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.compute.arn

  tags = local.common_tags
}

# =============================================================================
# CLOUDWATCH MONITORING
# =============================================================================

# CloudWatch log groups
resource "aws_cloudwatch_log_group" "ec2_logs" {
  name              = "/aws/ec2/${var.name_prefix}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.compute.arn

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-ec2-logs"
  })
}

resource "aws_cloudwatch_log_group" "lambda_logs" {
  for_each = var.lambda_functions

  name              = "/aws/lambda/${var.name_prefix}-${each.key}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.compute.arn

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-${each.key}-logs"
  })
}

# CloudWatch alarms for EC2 instances
resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  count = var.enable_cloudwatch_alarms && var.create_web_tier ? 1 : 0

  alarm_name          = "${var.name_prefix}-web-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors ec2 cpu utilization"
  alarm_actions       = var.alarm_actions

  dimensions = {
    AutoScalingGroupName = var.enable_auto_scaling ? aws_autoscaling_group.web_tier[0].name : ""
  }

  tags = local.common_tags
}

# =============================================================================
# SYSTEMS MANAGER (SSM)
# =============================================================================

# SSM parameters for application configuration
resource "aws_ssm_parameter" "app_config" {
  for_each = var.ssm_parameters

  name  = "/${var.name_prefix}/${each.key}"
  type  = each.value.type
  value = each.value.value
  tier  = each.value.tier

  # Encryption for SecureString parameters
  key_id = each.value.type == "SecureString" ? aws_kms_key.compute.arn : null

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-${each.key}"
  })
}

# =============================================================================
# SECURITY SCANNING
# =============================================================================

resource "aws_inspector2_enabler" "compute" {
  count = var.enable_inspector_scanning ? 1 : 0

  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = ["EC2", "ECR", "LAMBDA"]
}