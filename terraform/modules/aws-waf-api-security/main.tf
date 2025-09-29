# AWS WAF and API Security Module
# Enterprise-grade web application firewall and API security with advanced threat protection

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

# =============================================================================
# LOCALS AND DATA SOURCES
# =============================================================================

locals {
  name_prefix = "${var.name_prefix}-${var.environment}"

  # Common tags for all resources
  common_tags = merge(var.common_tags, {
    Environment     = var.environment
    Module          = "aws-waf-api-security"
    DataClassification = var.data_classification
    Compliance      = join(",", var.compliance_frameworks)
    CreatedBy       = "terraform"
    LastModified    = timestamp()
  })

  # WAF rules priority mapping
  waf_rule_priorities = {
    geo_restriction    = 10
    ip_whitelist      = 20
    ip_blacklist      = 30
    rate_limiting     = 40
    sql_injection     = 50
    xss_protection    = 60
    size_restrictions = 70
    known_bad_inputs  = 80
    admin_protection  = 90
    aws_managed_core  = 100
    aws_managed_known = 110
    aws_managed_linux = 120
    aws_managed_sql   = 130
    custom_rules      = 140
  }

  # Security score weights
  security_weights = {
    encryption        = 15
    access_control   = 20
    monitoring       = 15
    compliance       = 20
    threat_protection = 20
    api_security     = 10
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# =============================================================================
# WAF WEB ACL
# =============================================================================

resource "aws_wafv2_web_acl" "main" {
  name        = "${local.name_prefix}-web-acl"
  description = "Enterprise WAF for ${var.environment} environment"
  scope       = var.waf_scope

  default_action {
    dynamic "allow" {
      for_each = var.default_action == "allow" ? [1] : []
      content {}
    }

    dynamic "block" {
      for_each = var.default_action == "block" ? [1] : []
      content {}
    }
  }

  # Geographic restrictions
  dynamic "rule" {
    for_each = length(var.allowed_countries) > 0 || length(var.blocked_countries) > 0 ? [1] : []
    content {
      name     = "geo-restriction"
      priority = local.waf_rule_priorities.geo_restriction

      action {
        dynamic "allow" {
          for_each = length(var.allowed_countries) > 0 ? [1] : []
          content {}
        }

        dynamic "block" {
          for_each = length(var.blocked_countries) > 0 ? [1] : []
          content {}
        }
      }

      statement {
        geo_match_statement {
          country_codes = length(var.allowed_countries) > 0 ? var.allowed_countries : var.blocked_countries
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name_prefix}-geo-restriction"
        sampled_requests_enabled   = true
      }
    }
  }

  # IP whitelist
  dynamic "rule" {
    for_each = length(var.allowed_ip_addresses) > 0 ? [1] : []
    content {
      name     = "ip-whitelist"
      priority = local.waf_rule_priorities.ip_whitelist

      action {
        allow {}
      }

      statement {
        ip_set_reference_statement {
          arn = aws_wafv2_ip_set.allowed_ips[0].arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name_prefix}-ip-whitelist"
        sampled_requests_enabled   = true
      }
    }
  }

  # IP blacklist
  dynamic "rule" {
    for_each = length(var.blocked_ip_addresses) > 0 ? [1] : []
    content {
      name     = "ip-blacklist"
      priority = local.waf_rule_priorities.ip_blacklist

      action {
        block {}
      }

      statement {
        ip_set_reference_statement {
          arn = aws_wafv2_ip_set.blocked_ips[0].arn
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name_prefix}-ip-blacklist"
        sampled_requests_enabled   = true
      }
    }
  }

  # Rate limiting
  rule {
    name     = "rate-limiting"
    priority = local.waf_rule_priorities.rate_limiting

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.rate_limit
        aggregate_key_type = "IP"

        dynamic "scope_down_statement" {
          for_each = var.rate_limit_uri_path != "" ? [1] : []
          content {
            byte_match_statement {
              search_string = var.rate_limit_uri_path
              field_to_match {
                uri_path {}
              }
              text_transformation {
                priority = 0
                type     = "LOWERCASE"
              }
              positional_constraint = "STARTS_WITH"
            }
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-rate-limiting"
      sampled_requests_enabled   = true
    }
  }

  # SQL injection protection
  rule {
    name     = "sql-injection-protection"
    priority = local.waf_rule_priorities.sql_injection

    action {
      block {}
    }

    statement {
      sqli_match_statement {
        field_to_match {
          all_query_arguments {}
        }
        text_transformation {
          priority = 1
          type     = "URL_DECODE"
        }
        text_transformation {
          priority = 2
          type     = "HTML_ENTITY_DECODE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-sqli-protection"
      sampled_requests_enabled   = true
    }
  }

  # XSS protection
  rule {
    name     = "xss-protection"
    priority = local.waf_rule_priorities.xss_protection

    action {
      block {}
    }

    statement {
      xss_match_statement {
        field_to_match {
          all_query_arguments {}
        }
        text_transformation {
          priority = 1
          type     = "URL_DECODE"
        }
        text_transformation {
          priority = 2
          type     = "HTML_ENTITY_DECODE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-xss-protection"
      sampled_requests_enabled   = true
    }
  }

  # Size restrictions
  rule {
    name     = "size-restrictions"
    priority = local.waf_rule_priorities.size_restrictions

    action {
      block {}
    }

    statement {
      size_constraint_statement {
        field_to_match {
          body {}
        }
        comparison_operator = "GT"
        size                = var.max_request_size
        text_transformation {
          priority = 0
          type     = "NONE"
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-size-restrictions"
      sampled_requests_enabled   = true
    }
  }

  # AWS Managed Rules - Core Rule Set
  rule {
    name     = "aws-managed-core-rules"
    priority = local.waf_rule_priorities.aws_managed_core

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"

        dynamic "excluded_rule" {
          for_each = var.aws_managed_rules_exclusions
          content {
            name = excluded_rule.value
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-aws-core-rules"
      sampled_requests_enabled   = true
    }
  }

  # AWS Managed Rules - Known Bad Inputs
  rule {
    name     = "aws-managed-known-bad-inputs"
    priority = local.waf_rule_priorities.aws_managed_known

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${local.name_prefix}-known-bad-inputs"
      sampled_requests_enabled   = true
    }
  }

  # AWS Managed Rules - Linux Operating System
  dynamic "rule" {
    for_each = contains(var.managed_rule_sets, "linux") ? [1] : []
    content {
      name     = "aws-managed-linux-rules"
      priority = local.waf_rule_priorities.aws_managed_linux

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesLinuxRuleSet"
          vendor_name = "AWS"
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name_prefix}-linux-rules"
        sampled_requests_enabled   = true
      }
    }
  }

  # AWS Managed Rules - SQL Database
  dynamic "rule" {
    for_each = contains(var.managed_rule_sets, "sql") ? [1] : []
    content {
      name     = "aws-managed-sql-rules"
      priority = local.waf_rule_priorities.aws_managed_sql

      override_action {
        none {}
      }

      statement {
        managed_rule_group_statement {
          name        = "AWSManagedRulesSQLiRuleSet"
          vendor_name = "AWS"
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name_prefix}-sql-rules"
        sampled_requests_enabled   = true
      }
    }
  }

  # Custom rules
  dynamic "rule" {
    for_each = var.custom_rules
    content {
      name     = rule.value.name
      priority = local.waf_rule_priorities.custom_rules + rule.key

      action {
        dynamic "allow" {
          for_each = rule.value.action == "allow" ? [1] : []
          content {}
        }

        dynamic "block" {
          for_each = rule.value.action == "block" ? [1] : []
          content {}
        }

        dynamic "count" {
          for_each = rule.value.action == "count" ? [1] : []
          content {}
        }
      }

      statement {
        byte_match_statement {
          search_string = rule.value.search_string
          field_to_match {
            dynamic "uri_path" {
              for_each = rule.value.field_to_match == "uri_path" ? [1] : []
              content {}
            }
            dynamic "query_string" {
              for_each = rule.value.field_to_match == "query_string" ? [1] : []
              content {}
            }
            dynamic "body" {
              for_each = rule.value.field_to_match == "body" ? [1] : []
              content {}
            }
          }
          text_transformation {
            priority = 0
            type     = rule.value.text_transformation
          }
          positional_constraint = rule.value.positional_constraint
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "${local.name_prefix}-${rule.value.name}"
        sampled_requests_enabled   = true
      }
    }
  }

  tags = local.common_tags

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${local.name_prefix}-web-acl"
    sampled_requests_enabled   = true
  }
}

# =============================================================================
# IP SETS
# =============================================================================

resource "aws_wafv2_ip_set" "allowed_ips" {
  count = length(var.allowed_ip_addresses) > 0 ? 1 : 0

  name               = "${local.name_prefix}-allowed-ips"
  description        = "Allowed IP addresses for ${var.environment}"
  scope              = var.waf_scope
  ip_address_version = "IPV4"
  addresses          = var.allowed_ip_addresses

  tags = local.common_tags
}

resource "aws_wafv2_ip_set" "blocked_ips" {
  count = length(var.blocked_ip_addresses) > 0 ? 1 : 0

  name               = "${local.name_prefix}-blocked-ips"
  description        = "Blocked IP addresses for ${var.environment}"
  scope              = var.waf_scope
  ip_address_version = "IPV4"
  addresses          = var.blocked_ip_addresses

  tags = local.common_tags
}

# =============================================================================
# API GATEWAY SECURITY
# =============================================================================

# WAF Association for API Gateway
resource "aws_wafv2_web_acl_association" "api_gateway" {
  count        = var.api_gateway_stage_arn != "" ? 1 : 0
  resource_arn = var.api_gateway_stage_arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}

# API Gateway Resource Policy
data "aws_iam_policy_document" "api_gateway_resource_policy" {
  count = var.create_api_gateway_policy ? 1 : 0

  # Allow access from specified CIDR blocks
  dynamic "statement" {
    for_each = length(var.api_allowed_cidr_blocks) > 0 ? [1] : []
    content {
      effect = "Allow"
      principals {
        type        = "*"
        identifiers = ["*"]
      }
      actions   = ["execute-api:Invoke"]
      resources = ["*"]
      condition {
        test     = "IpAddress"
        variable = "aws:SourceIp"
        values   = var.api_allowed_cidr_blocks
      }
    }
  }

  # Deny access from blocked CIDR blocks
  dynamic "statement" {
    for_each = length(var.api_blocked_cidr_blocks) > 0 ? [1] : []
    content {
      effect = "Deny"
      principals {
        type        = "*"
        identifiers = ["*"]
      }
      actions   = ["execute-api:Invoke"]
      resources = ["*"]
      condition {
        test     = "IpAddress"
        variable = "aws:SourceIp"
        values   = var.api_blocked_cidr_blocks
      }
    }
  }

  # Require API key for certain paths
  dynamic "statement" {
    for_each = length(var.api_key_required_paths) > 0 ? [1] : []
    content {
      effect = "Deny"
      principals {
        type        = "*"
        identifiers = ["*"]
      }
      actions   = ["execute-api:Invoke"]
      resources = [for path in var.api_key_required_paths : "arn:aws:execute-api:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*/${path}"]
      condition {
        test     = "Null"
        variable = "aws:RequestTag/x-api-key"
        values   = ["true"]
      }
    }
  }

  # VPC endpoint only access
  dynamic "statement" {
    for_each = var.api_vpc_endpoint_only ? [1] : []
    content {
      effect = "Deny"
      principals {
        type        = "*"
        identifiers = ["*"]
      }
      actions   = ["execute-api:Invoke"]
      resources = ["*"]
      condition {
        test     = "StringNotEquals"
        variable = "aws:SourceVpce"
        values   = var.api_vpc_endpoint_ids
      }
    }
  }
}

# =============================================================================
# APPLICATION LOAD BALANCER SECURITY
# =============================================================================

# WAF Association for ALB
resource "aws_wafv2_web_acl_association" "alb" {
  count        = var.alb_arn != "" ? 1 : 0
  resource_arn = var.alb_arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}

# =============================================================================
# CLOUDFRONT SECURITY
# =============================================================================

# WAF Association for CloudFront (handled in CloudFront module)
# Note: CloudFront requires WAF in us-east-1 region

# =============================================================================
# LOGGING AND MONITORING
# =============================================================================

# CloudWatch Log Group for WAF
resource "aws_cloudwatch_log_group" "waf" {
  count             = var.enable_waf_logging ? 1 : 0
  name              = "/aws/waf/${local.name_prefix}"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.kms_key_id

  tags = local.common_tags
}

# WAF Logging Configuration
resource "aws_wafv2_web_acl_logging_configuration" "main" {
  count                   = var.enable_waf_logging ? 1 : 0
  resource_arn           = aws_wafv2_web_acl.main.arn
  log_destination_configs = [aws_cloudwatch_log_group.waf[0].arn]

  redacted_fields {
    single_header {
      name = "authorization"
    }
  }

  redacted_fields {
    single_header {
      name = "cookie"
    }
  }

  redacted_fields {
    single_header {
      name = "x-api-key"
    }
  }
}

# CloudWatch Alarms for WAF
resource "aws_cloudwatch_metric_alarm" "blocked_requests" {
  count = var.create_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${local.name_prefix}-waf-blocked-requests"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = "300"
  statistic           = "Sum"
  threshold           = var.blocked_requests_threshold
  alarm_description   = "This metric monitors blocked requests in WAF"
  alarm_actions       = var.alarm_actions

  dimensions = {
    WebACL = aws_wafv2_web_acl.main.name
    Rule   = "ALL"
    Region = data.aws_region.current.name
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "rate_limit_triggered" {
  count = var.create_cloudwatch_alarms ? 1 : 0

  alarm_name          = "${local.name_prefix}-waf-rate-limit"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = "300"
  statistic           = "Sum"
  threshold           = var.rate_limit_alarm_threshold
  alarm_description   = "This metric monitors rate limiting triggers"
  alarm_actions       = var.alarm_actions

  dimensions = {
    WebACL = aws_wafv2_web_acl.main.name
    Rule   = "rate-limiting"
    Region = data.aws_region.current.name
  }

  tags = local.common_tags
}

# =============================================================================
# THREAT INTELLIGENCE INTEGRATION
# =============================================================================

# Lambda function for threat intelligence updates
resource "aws_lambda_function" "threat_intel_updater" {
  count = var.enable_threat_intelligence ? 1 : 0

  filename         = data.archive_file.threat_intel_lambda[0].output_path
  function_name    = "${local.name_prefix}-threat-intel-updater"
  role            = aws_iam_role.threat_intel_lambda[0].arn
  handler         = "index.handler"
  source_code_hash = data.archive_file.threat_intel_lambda[0].output_base64sha256
  runtime         = "python3.9"
  timeout         = 300

  environment {
    variables = {
      IP_SET_ID = aws_wafv2_ip_set.blocked_ips[0].id
      REGION    = data.aws_region.current.name
    }
  }

  tags = local.common_tags
}

data "archive_file" "threat_intel_lambda" {
  count = var.enable_threat_intelligence ? 1 : 0

  type        = "zip"
  output_path = "/tmp/threat_intel_lambda.zip"
  source {
    content = templatefile("${path.module}/templates/threat_intel_updater.py", {
      ip_set_id = aws_wafv2_ip_set.blocked_ips[0].id
    })
    filename = "index.py"
  }
}

# IAM role for threat intelligence Lambda
resource "aws_iam_role" "threat_intel_lambda" {
  count = var.enable_threat_intelligence ? 1 : 0

  name = "${local.name_prefix}-threat-intel-lambda-role"

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

resource "aws_iam_role_policy" "threat_intel_lambda" {
  count = var.enable_threat_intelligence ? 1 : 0

  name = "${local.name_prefix}-threat-intel-lambda-policy"
  role = aws_iam_role.threat_intel_lambda[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
        Effect = "Allow"
        Action = [
          "wafv2:UpdateIPSet",
          "wafv2:GetIPSet"
        ]
        Resource = aws_wafv2_ip_set.blocked_ips[0].arn
      }
    ]
  })
}

# EventBridge rule to trigger threat intelligence updates
resource "aws_cloudwatch_event_rule" "threat_intel_schedule" {
  count = var.enable_threat_intelligence ? 1 : 0

  name                = "${local.name_prefix}-threat-intel-schedule"
  description         = "Trigger threat intelligence updates"
  schedule_expression = var.threat_intel_update_schedule

  tags = local.common_tags
}

resource "aws_cloudwatch_event_target" "threat_intel_lambda" {
  count = var.enable_threat_intelligence ? 1 : 0

  rule      = aws_cloudwatch_event_rule.threat_intel_schedule[0].name
  target_id = "ThreatIntelLambdaTarget"
  arn       = aws_lambda_function.threat_intel_updater[0].arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  count = var.enable_threat_intelligence ? 1 : 0

  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.threat_intel_updater[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.threat_intel_schedule[0].arn
}

# =============================================================================
# SECURITY ASSESSMENT
# =============================================================================

# Security score calculation
locals {
  # Encryption score (0-15)
  encryption_score = var.kms_key_id != "" ? 15 : 0

  # Access control score (0-20)
  access_control_score = (
    (length(var.allowed_ip_addresses) > 0 ? 5 : 0) +
    (length(var.blocked_ip_addresses) > 0 ? 5 : 0) +
    (length(var.allowed_countries) > 0 || length(var.blocked_countries) > 0 ? 5 : 0) +
    (var.rate_limit < 2000 ? 5 : 0)
  )

  # Monitoring score (0-15)
  monitoring_score = (
    (var.enable_waf_logging ? 8 : 0) +
    (var.create_cloudwatch_alarms ? 7 : 0)
  )

  # Compliance score (0-20)
  compliance_score = (
    (contains(var.compliance_frameworks, "SOC2") ? 5 : 0) +
    (contains(var.compliance_frameworks, "NIST") ? 5 : 0) +
    (contains(var.compliance_frameworks, "CIS") ? 5 : 0) +
    (contains(var.compliance_frameworks, "PCI-DSS") ? 5 : 0)
  )

  # Threat protection score (0-20)
  threat_protection_score = (
    (var.default_action == "block" ? 5 : 0) +
    (length(var.managed_rule_sets) * 3) +
    (var.enable_threat_intelligence ? 8 : 0)
  )

  # API security score (0-10)
  api_security_score = (
    (var.create_api_gateway_policy ? 5 : 0) +
    (var.api_vpc_endpoint_only ? 3 : 0) +
    (length(var.api_key_required_paths) > 0 ? 2 : 0)
  )

  # Total security score
  total_security_score = (
    local.encryption_score +
    local.access_control_score +
    local.monitoring_score +
    local.compliance_score +
    local.threat_protection_score +
    local.api_security_score
  )
}