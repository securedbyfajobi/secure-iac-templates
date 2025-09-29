# AWS Enterprise Database Security Module
# Enterprise-grade database security with encryption, monitoring, and compliance

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
    time = {
      source  = "hashicorp/time"
      version = "~> 0.9"
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

locals {
  # Common tags for all resources
  common_tags = merge(var.common_tags, {
    Module             = "aws-enterprise-database"
    Environment        = var.environment
    DataClassification = var.data_classification
    ComplianceFramework = join(",", var.compliance_frameworks)
    CreatedBy          = "terraform"
    LastModified       = timestamp()
  })

  # Database configurations for different compliance frameworks
  compliance_configs = {
    SOC2 = {
      backup_retention_period = 35
      monitoring_interval     = 60
      performance_insights    = true
      deletion_protection     = true
      log_exports            = ["error", "general", "slow-query"]
    }
    NIST = {
      backup_retention_period = 30
      monitoring_interval     = 60
      performance_insights    = true
      deletion_protection     = true
      log_exports            = ["error", "general", "slow-query", "audit"]
    }
    PCI-DSS = {
      backup_retention_period = 90
      monitoring_interval     = 15
      performance_insights    = true
      deletion_protection     = true
      log_exports            = ["error", "general", "slow-query", "audit"]
    }
    HIPAA = {
      backup_retention_period = 180
      monitoring_interval     = 15
      performance_insights    = true
      deletion_protection     = true
      log_exports            = ["error", "general", "slow-query", "audit"]
    }
  }

  # Select the strictest compliance requirements
  active_compliance = var.compliance_frameworks[0]
  db_config = local.compliance_configs[local.active_compliance]

  # Subnet configuration
  db_subnet_cidrs = [
    for i, az in slice(data.aws_availability_zones.available.names, 0, var.multi_az ? 3 : 2) :
    cidrsubnet(var.vpc_cidr, 8, 10 + i)
  ]
}

# =============================================================================
# KMS ENCRYPTION
# =============================================================================

resource "aws_kms_key" "database" {
  description             = "KMS key for database encryption - ${var.name_prefix}"
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
        Sid    = "Allow RDS Service"
        Effect = "Allow"
        Principal = {
          Service = "rds.amazonaws.com"
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
    Name = "${var.name_prefix}-database-kms-key"
    Type = "database-encryption"
  })
}

resource "aws_kms_alias" "database" {
  name          = "alias/${var.name_prefix}-database-key"
  target_key_id = aws_kms_key.database.key_id
}

# =============================================================================
# DATABASE SUBNET GROUP
# =============================================================================

resource "aws_db_subnet_group" "main" {
  name       = "${var.name_prefix}-db-subnet-group"
  subnet_ids = var.subnet_ids != null ? var.subnet_ids : aws_subnet.database[*].id

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-db-subnet-group"
  })
}

# Create database subnets if not provided
resource "aws_subnet" "database" {
  count = var.subnet_ids == null ? length(local.db_subnet_cidrs) : 0

  vpc_id            = var.vpc_id
  cidr_block        = local.db_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-db-subnet-${count.index + 1}"
    Tier = "database"
  })
}

# =============================================================================
# SECURITY GROUPS
# =============================================================================

resource "aws_security_group" "database" {
  name        = "${var.name_prefix}-database-sg"
  description = "Security group for enterprise database"
  vpc_id      = var.vpc_id

  # MySQL/Aurora MySQL
  dynamic "ingress" {
    for_each = var.engine == "mysql" || var.engine == "aurora-mysql" ? [1] : []
    content {
      from_port       = 3306
      to_port         = 3306
      protocol        = "tcp"
      security_groups = var.allowed_security_groups
      cidr_blocks     = var.allowed_cidr_blocks
    }
  }

  # PostgreSQL/Aurora PostgreSQL
  dynamic "ingress" {
    for_each = var.engine == "postgres" || var.engine == "aurora-postgresql" ? [1] : []
    content {
      from_port       = 5432
      to_port         = 5432
      protocol        = "tcp"
      security_groups = var.allowed_security_groups
      cidr_blocks     = var.allowed_cidr_blocks
    }
  }

  # SQL Server
  dynamic "ingress" {
    for_each = contains(["sqlserver-se", "sqlserver-ee", "sqlserver-ex", "sqlserver-web"], var.engine) ? [1] : []
    content {
      from_port       = 1433
      to_port         = 1433
      protocol        = "tcp"
      security_groups = var.allowed_security_groups
      cidr_blocks     = var.allowed_cidr_blocks
    }
  }

  # Oracle
  dynamic "ingress" {
    for_each = contains(["oracle-se2", "oracle-ee"], var.engine) ? [1] : []
    content {
      from_port       = 1521
      to_port         = 1521
      protocol        = "tcp"
      security_groups = var.allowed_security_groups
      cidr_blocks     = var.allowed_cidr_blocks
    }
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-database-sg"
  })
}

# =============================================================================
# DB PARAMETER GROUP
# =============================================================================

resource "aws_db_parameter_group" "main" {
  count = var.create_parameter_group ? 1 : 0

  family = var.parameter_group_family
  name   = "${var.name_prefix}-db-params"

  # Security-focused parameters for MySQL
  dynamic "parameter" {
    for_each = var.engine == "mysql" || var.engine == "aurora-mysql" ? [1] : []
    content {
      name  = "general_log"
      value = "1"
    }
  }

  dynamic "parameter" {
    for_each = var.engine == "mysql" || var.engine == "aurora-mysql" ? [1] : []
    content {
      name  = "slow_query_log"
      value = "1"
    }
  }

  dynamic "parameter" {
    for_each = var.engine == "mysql" || var.engine == "aurora-mysql" ? [1] : []
    content {
      name  = "long_query_time"
      value = "2"
    }
  }

  dynamic "parameter" {
    for_each = var.engine == "mysql" || var.engine == "aurora-mysql" ? [1] : []
    content {
      name  = "log_queries_not_using_indexes"
      value = "1"
    }
  }

  # Security-focused parameters for PostgreSQL
  dynamic "parameter" {
    for_each = var.engine == "postgres" || var.engine == "aurora-postgresql" ? [1] : []
    content {
      name  = "log_statement"
      value = "all"
    }
  }

  dynamic "parameter" {
    for_each = var.engine == "postgres" || var.engine == "aurora-postgresql" ? [1] : []
    content {
      name  = "log_min_duration_statement"
      value = "1000"
    }
  }

  dynamic "parameter" {
    for_each = var.engine == "postgres" || var.engine == "aurora-postgresql" ? [1] : []
    content {
      name  = "shared_preload_libraries"
      value = "pg_stat_statements"
    }
  }

  tags = local.common_tags
}

# =============================================================================
# RDS INSTANCE
# =============================================================================

resource "random_password" "master_password" {
  count   = var.manage_master_user_password ? 0 : 1
  length  = 32
  special = true
}

resource "aws_db_instance" "main" {
  count = var.create_rds_instance ? 1 : 0

  # Basic Configuration
  identifier     = var.db_instance_identifier
  engine         = var.engine
  engine_version = var.engine_version
  instance_class = var.instance_class
  allocated_storage     = var.allocated_storage
  max_allocated_storage = var.max_allocated_storage
  storage_type          = var.storage_type
  storage_encrypted     = true
  kms_key_id           = aws_kms_key.database.arn

  # Database Configuration
  db_name  = var.database_name
  username = var.master_username
  password = var.manage_master_user_password ? null : (var.master_password != null ? var.master_password : random_password.master_password[0].result)

  # AWS Managed Master User Password
  manage_master_user_password = var.manage_master_user_password
  master_user_secret_kms_key_id = var.manage_master_user_password ? aws_kms_key.database.arn : null

  # Network Configuration
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.database.id]
  publicly_accessible    = false
  multi_az              = var.multi_az
  availability_zone     = var.multi_az ? null : data.aws_availability_zones.available.names[0]

  # Backup Configuration
  backup_retention_period = local.db_config.backup_retention_period
  backup_window          = var.backup_window
  maintenance_window     = var.maintenance_window
  copy_tags_to_snapshot  = true
  delete_automated_backups = false

  # Monitoring Configuration
  monitoring_interval = local.db_config.monitoring_interval
  monitoring_role_arn = var.monitoring_interval > 0 ? aws_iam_role.rds_enhanced_monitoring[0].arn : null
  performance_insights_enabled = local.db_config.performance_insights
  performance_insights_kms_key_id = local.db_config.performance_insights ? aws_kms_key.database.arn : null
  performance_insights_retention_period = local.db_config.performance_insights ? var.performance_insights_retention_period : null

  # Logging Configuration
  enabled_cloudwatch_logs_exports = local.db_config.log_exports

  # Security Configuration
  deletion_protection = local.db_config.deletion_protection
  skip_final_snapshot = var.environment != "prod"
  final_snapshot_identifier = var.environment == "prod" ? "${var.db_instance_identifier}-final-snapshot-${formatdate("YYYY-MM-DD-hhmm", timestamp())}" : null

  # Parameter Group
  parameter_group_name = var.create_parameter_group ? aws_db_parameter_group.main[0].name : var.parameter_group_name

  # Apply changes immediately in non-prod environments
  apply_immediately = var.environment != "prod"

  # Auto minor version upgrades
  auto_minor_version_upgrade = true

  # Network port
  port = var.port

  tags = merge(local.common_tags, {
    Name = var.db_instance_identifier
    Type = "rds-instance"
  })

  depends_on = [aws_db_subnet_group.main]
}

# =============================================================================
# RDS CLUSTER (Aurora)
# =============================================================================

resource "aws_rds_cluster" "main" {
  count = var.create_aurora_cluster ? 1 : 0

  cluster_identifier = var.cluster_identifier
  engine             = var.engine
  engine_version     = var.engine_version
  engine_mode        = var.engine_mode
  database_name      = var.database_name
  master_username    = var.master_username
  master_password    = var.manage_master_user_password ? null : (var.master_password != null ? var.master_password : random_password.master_password[0].result)

  # AWS Managed Master User Password
  manage_master_user_password = var.manage_master_user_password
  master_user_secret_kms_key_id = var.manage_master_user_password ? aws_kms_key.database.arn : null

  # Network Configuration
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.database.id]
  availability_zones     = slice(data.aws_availability_zones.available.names, 0, 3)
  port                   = var.port

  # Encryption
  storage_encrypted = true
  kms_key_id       = aws_kms_key.database.arn

  # Backup Configuration
  backup_retention_period = local.db_config.backup_retention_period
  preferred_backup_window = var.backup_window
  preferred_maintenance_window = var.maintenance_window
  copy_tags_to_snapshot = true

  # Logging Configuration
  enabled_cloudwatch_logs_exports = local.db_config.log_exports

  # Security Configuration
  deletion_protection = local.db_config.deletion_protection
  skip_final_snapshot = var.environment != "prod"
  final_snapshot_identifier = var.environment == "prod" ? "${var.cluster_identifier}-final-snapshot-${formatdate("YYYY-MM-DD-hhmm", timestamp())}" : null

  # Apply changes immediately in non-prod environments
  apply_immediately = var.environment != "prod"

  # Backtrack (MySQL only)
  backtrack_window = contains(["aurora-mysql"], var.engine) ? var.backtrack_window : null

  tags = merge(local.common_tags, {
    Name = var.cluster_identifier
    Type = "aurora-cluster"
  })

  depends_on = [aws_db_subnet_group.main]
}

resource "aws_rds_cluster_instance" "cluster_instances" {
  count = var.create_aurora_cluster ? var.cluster_instance_count : 0

  identifier         = "${var.cluster_identifier}-${count.index + 1}"
  cluster_identifier = aws_rds_cluster.main[0].id
  instance_class     = var.instance_class
  engine             = aws_rds_cluster.main[0].engine
  engine_version     = aws_rds_cluster.main[0].engine_version

  # Monitoring
  monitoring_interval = local.db_config.monitoring_interval
  monitoring_role_arn = var.monitoring_interval > 0 ? aws_iam_role.rds_enhanced_monitoring[0].arn : null
  performance_insights_enabled = local.db_config.performance_insights
  performance_insights_kms_key_id = local.db_config.performance_insights ? aws_kms_key.database.arn : null

  # Auto minor version upgrades
  auto_minor_version_upgrade = true

  # Apply changes immediately in non-prod environments
  apply_immediately = var.environment != "prod"

  tags = merge(local.common_tags, {
    Name = "${var.cluster_identifier}-${count.index + 1}"
    Type = "aurora-instance"
  })
}

# =============================================================================
# DYNAMODB TABLES
# =============================================================================

resource "aws_dynamodb_table" "tables" {
  for_each = var.dynamodb_tables

  name           = each.key
  billing_mode   = each.value.billing_mode
  read_capacity  = each.value.billing_mode == "PROVISIONED" ? each.value.read_capacity : null
  write_capacity = each.value.billing_mode == "PROVISIONED" ? each.value.write_capacity : null
  hash_key       = each.value.hash_key
  range_key      = each.value.range_key

  # Attributes
  dynamic "attribute" {
    for_each = each.value.attributes
    content {
      name = attribute.value.name
      type = attribute.value.type
    }
  }

  # Global Secondary Indexes
  dynamic "global_secondary_index" {
    for_each = each.value.global_secondary_indexes
    content {
      name            = global_secondary_index.value.name
      hash_key        = global_secondary_index.value.hash_key
      range_key       = global_secondary_index.value.range_key
      write_capacity  = each.value.billing_mode == "PROVISIONED" ? global_secondary_index.value.write_capacity : null
      read_capacity   = each.value.billing_mode == "PROVISIONED" ? global_secondary_index.value.read_capacity : null
      projection_type = global_secondary_index.value.projection_type
    }
  }

  # Encryption
  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.database.arn
  }

  # Point-in-time recovery
  point_in_time_recovery {
    enabled = true
  }

  # TTL
  dynamic "ttl" {
    for_each = each.value.ttl_attribute != null ? [1] : []
    content {
      attribute_name = each.value.ttl_attribute
      enabled        = true
    }
  }

  # Stream
  stream_enabled   = each.value.stream_enabled
  stream_view_type = each.value.stream_enabled ? each.value.stream_view_type : null

  tags = merge(local.common_tags, {
    Name = each.key
    Type = "dynamodb-table"
  })

  lifecycle {
    prevent_destroy = true
  }
}

# =============================================================================
# IAM ROLE FOR ENHANCED MONITORING
# =============================================================================

resource "aws_iam_role" "rds_enhanced_monitoring" {
  count = var.monitoring_interval > 0 ? 1 : 0

  name = "${var.name_prefix}-rds-monitoring-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "monitoring.rds.amazonaws.com"
        }
      }
    ]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "rds_enhanced_monitoring" {
  count = var.monitoring_interval > 0 ? 1 : 0

  role       = aws_iam_role.rds_enhanced_monitoring[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

# =============================================================================
# CLOUDWATCH ALARMS
# =============================================================================

resource "aws_cloudwatch_metric_alarm" "database_cpu" {
  count = var.create_cloudwatch_alarms && var.create_rds_instance ? 1 : 0

  alarm_name          = "${var.db_instance_identifier}-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = "120"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors RDS instance CPU utilization"
  alarm_actions       = var.alarm_actions

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main[0].id
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "database_connections" {
  count = var.create_cloudwatch_alarms && var.create_rds_instance ? 1 : 0

  alarm_name          = "${var.db_instance_identifier}-high-connections"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "DatabaseConnections"
  namespace           = "AWS/RDS"
  period              = "120"
  statistic           = "Average"
  threshold           = "40"
  alarm_description   = "This metric monitors RDS database connections"
  alarm_actions       = var.alarm_actions

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main[0].id
  }

  tags = local.common_tags
}

# =============================================================================
# SECRETS MANAGER INTEGRATION
# =============================================================================

resource "aws_secretsmanager_secret" "db_credentials" {
  count = var.store_credentials_in_secrets_manager && !var.manage_master_user_password ? 1 : 0

  name                    = "${var.name_prefix}-db-credentials"
  description             = "Database credentials for ${var.name_prefix}"
  recovery_window_in_days = var.environment == "prod" ? 30 : 0
  kms_key_id             = aws_kms_key.database.arn

  tags = merge(local.common_tags, {
    Name = "${var.name_prefix}-db-credentials"
    Type = "database-credentials"
  })
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  count = var.store_credentials_in_secrets_manager && !var.manage_master_user_password ? 1 : 0

  secret_id = aws_secretsmanager_secret.db_credentials[0].id
  secret_string = jsonencode({
    username = var.master_username
    password = var.master_password != null ? var.master_password : random_password.master_password[0].result
    engine   = var.engine
    host     = var.create_rds_instance ? aws_db_instance.main[0].endpoint : aws_rds_cluster.main[0].endpoint
    port     = var.port
    dbname   = var.database_name
  })
}

# =============================================================================
# DATABASE SECURITY SCANNING
# =============================================================================

resource "aws_inspector2_enabler" "database" {
  count = var.enable_inspector_scanning ? 1 : 0

  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = ["ECR"]
}

# =============================================================================
# BACKUP AND RECOVERY
# =============================================================================

resource "aws_db_snapshot" "manual_snapshot" {
  count = var.create_manual_snapshot && var.create_rds_instance ? 1 : 0

  db_instance_identifier = aws_db_instance.main[0].id
  db_snapshot_identifier = "${var.db_instance_identifier}-manual-snapshot-${formatdate("YYYY-MM-DD-hhmm", timestamp())}"

  tags = merge(local.common_tags, {
    Name = "${var.db_instance_identifier}-manual-snapshot"
    Type = "manual-snapshot"
  })
}

# =============================================================================
# COMPLIANCE MONITORING
# =============================================================================

resource "aws_config_configuration_recorder_status" "database" {
  count                  = var.enable_config_compliance ? 1 : 0
  name                   = "${var.name_prefix}-config-recorder"
  is_enabled             = true
  depends_on             = [aws_config_delivery_channel.database]
}

resource "aws_config_delivery_channel" "database" {
  count           = var.enable_config_compliance ? 1 : 0
  name            = "${var.name_prefix}-config-delivery-channel"
  s3_bucket_name  = var.config_s3_bucket
}

# Config rules for database compliance
resource "aws_config_config_rule" "rds_encrypted" {
  count = var.enable_config_compliance ? 1 : 0

  name = "${var.name_prefix}-rds-storage-encrypted"

  source {
    owner             = "AWS"
    source_identifier = "RDS_STORAGE_ENCRYPTED"
  }

  depends_on = [aws_config_configuration_recorder_status.database]

  tags = local.common_tags
}