# Outputs for AWS WAF and API Security Module

# =============================================================================
# WAF OUTPUTS
# =============================================================================

output "web_acl_id" {
  description = "ID of the WAF Web ACL"
  value       = aws_wafv2_web_acl.main.id
}

output "web_acl_arn" {
  description = "ARN of the WAF Web ACL"
  value       = aws_wafv2_web_acl.main.arn
}

output "web_acl_name" {
  description = "Name of the WAF Web ACL"
  value       = aws_wafv2_web_acl.main.name
}

output "web_acl_capacity" {
  description = "Capacity units used by the WAF Web ACL"
  value       = aws_wafv2_web_acl.main.capacity
}

# =============================================================================
# IP SET OUTPUTS
# =============================================================================

output "allowed_ip_set_id" {
  description = "ID of the allowed IP set"
  value       = length(aws_wafv2_ip_set.allowed_ips) > 0 ? aws_wafv2_ip_set.allowed_ips[0].id : null
}

output "allowed_ip_set_arn" {
  description = "ARN of the allowed IP set"
  value       = length(aws_wafv2_ip_set.allowed_ips) > 0 ? aws_wafv2_ip_set.allowed_ips[0].arn : null
}

output "blocked_ip_set_id" {
  description = "ID of the blocked IP set"
  value       = length(aws_wafv2_ip_set.blocked_ips) > 0 ? aws_wafv2_ip_set.blocked_ips[0].id : null
}

output "blocked_ip_set_arn" {
  description = "ARN of the blocked IP set"
  value       = length(aws_wafv2_ip_set.blocked_ips) > 0 ? aws_wafv2_ip_set.blocked_ips[0].arn : null
}

# =============================================================================
# ASSOCIATION OUTPUTS
# =============================================================================

output "alb_association_id" {
  description = "ID of the ALB WAF association"
  value       = length(aws_wafv2_web_acl_association.alb) > 0 ? aws_wafv2_web_acl_association.alb[0].id : null
}

output "api_gateway_association_id" {
  description = "ID of the API Gateway WAF association"
  value       = length(aws_wafv2_web_acl_association.api_gateway) > 0 ? aws_wafv2_web_acl_association.api_gateway[0].id : null
}

# =============================================================================
# API GATEWAY POLICY OUTPUTS
# =============================================================================

output "api_gateway_policy_json" {
  description = "JSON policy document for API Gateway resource policy"
  value       = length(data.aws_iam_policy_document.api_gateway_resource_policy) > 0 ? data.aws_iam_policy_document.api_gateway_resource_policy[0].json : null
}

# =============================================================================
# MONITORING OUTPUTS
# =============================================================================

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group for WAF logs"
  value       = length(aws_cloudwatch_log_group.waf) > 0 ? aws_cloudwatch_log_group.waf[0].name : null
}

output "cloudwatch_log_group_arn" {
  description = "ARN of the CloudWatch log group for WAF logs"
  value       = length(aws_cloudwatch_log_group.waf) > 0 ? aws_cloudwatch_log_group.waf[0].arn : null
}

output "blocked_requests_alarm_arn" {
  description = "ARN of the blocked requests CloudWatch alarm"
  value       = length(aws_cloudwatch_metric_alarm.blocked_requests) > 0 ? aws_cloudwatch_metric_alarm.blocked_requests[0].arn : null
}

output "rate_limit_alarm_arn" {
  description = "ARN of the rate limit CloudWatch alarm"
  value       = length(aws_cloudwatch_metric_alarm.rate_limit_triggered) > 0 ? aws_cloudwatch_metric_alarm.rate_limit_triggered[0].arn : null
}

# =============================================================================
# THREAT INTELLIGENCE OUTPUTS
# =============================================================================

output "threat_intel_lambda_function_name" {
  description = "Name of the threat intelligence Lambda function"
  value       = length(aws_lambda_function.threat_intel_updater) > 0 ? aws_lambda_function.threat_intel_updater[0].function_name : null
}

output "threat_intel_lambda_function_arn" {
  description = "ARN of the threat intelligence Lambda function"
  value       = length(aws_lambda_function.threat_intel_updater) > 0 ? aws_lambda_function.threat_intel_updater[0].arn : null
}

output "threat_intel_schedule_rule_name" {
  description = "Name of the threat intelligence EventBridge rule"
  value       = length(aws_cloudwatch_event_rule.threat_intel_schedule) > 0 ? aws_cloudwatch_event_rule.threat_intel_schedule[0].name : null
}

# =============================================================================
# SECURITY ASSESSMENT OUTPUTS
# =============================================================================

output "security_score" {
  description = "Overall security score (0-100)"
  value       = local.total_security_score
}

output "security_score_breakdown" {
  description = "Breakdown of security score by category"
  value = {
    encryption        = local.encryption_score
    access_control   = local.access_control_score
    monitoring       = local.monitoring_score
    compliance       = local.compliance_score
    threat_protection = local.threat_protection_score
    api_security     = local.api_security_score
    total            = local.total_security_score
  }
}

output "compliance_status" {
  description = "Compliance status for each framework"
  value = {
    for framework in var.compliance_frameworks :
    framework => {
      enabled = contains(var.compliance_frameworks, framework)
      score   = contains(var.compliance_frameworks, framework) ? 5 : 0
    }
  }
}

# =============================================================================
# CONFIGURATION SUMMARY
# =============================================================================

output "waf_configuration_summary" {
  description = "Summary of WAF configuration"
  value = {
    scope                    = var.waf_scope
    default_action          = var.default_action
    rate_limit              = var.rate_limit
    max_request_size        = var.max_request_size
    allowed_countries_count = length(var.allowed_countries)
    blocked_countries_count = length(var.blocked_countries)
    allowed_ips_count       = length(var.allowed_ip_addresses)
    blocked_ips_count       = length(var.blocked_ip_addresses)
    managed_rule_sets       = var.managed_rule_sets
    custom_rules_count      = length(var.custom_rules)
    logging_enabled         = var.enable_waf_logging
    threat_intel_enabled    = var.enable_threat_intelligence
  }
}

output "api_security_configuration" {
  description = "Summary of API security configuration"
  value = {
    api_gateway_policy_enabled = var.create_api_gateway_policy
    vpc_endpoint_only         = var.api_vpc_endpoint_only
    api_key_required_paths    = var.api_key_required_paths
    allowed_cidr_blocks       = var.api_allowed_cidr_blocks
    blocked_cidr_blocks       = var.api_blocked_cidr_blocks
    vpc_endpoint_ids          = var.api_vpc_endpoint_ids
  }
}

# =============================================================================
# COST OPTIMIZATION OUTPUTS
# =============================================================================

output "estimated_monthly_cost" {
  description = "Estimated monthly cost in USD (approximate)"
  value = {
    web_acl_base          = 1.00
    request_charges       = "Variable based on traffic"
    rule_evaluations      = "Variable based on rules and traffic"
    logging_charges       = var.enable_waf_logging ? "Variable based on log volume" : 0
    lambda_charges        = var.enable_threat_intelligence ? "Variable based on executions" : 0
    total_fixed_monthly   = 1.00
    note                  = "Actual costs depend on traffic volume and usage patterns"
  }
}

# =============================================================================
# RECOMMENDATIONS
# =============================================================================

output "security_recommendations" {
  description = "Security improvement recommendations"
  value = {
    high_priority = compact([
      local.total_security_score < 80 ? "Security score below enterprise threshold (80). Review and enhance security configurations." : "",
      var.default_action == "allow" ? "Consider changing default action to 'block' for zero-trust security model." : "",
      !var.enable_waf_logging ? "Enable WAF logging for security monitoring and compliance." : "",
      length(var.blocked_ip_addresses) == 0 ? "Configure threat intelligence and IP blocking for enhanced protection." : ""
    ])
    medium_priority = compact([
      !var.create_cloudwatch_alarms ? "Enable CloudWatch alarms for proactive monitoring." : "",
      var.kms_key_id == "" ? "Configure KMS encryption for log data protection." : "",
      !var.enable_threat_intelligence ? "Enable automatic threat intelligence updates." : "",
      length(var.managed_rule_sets) < 2 ? "Consider enabling additional AWS managed rule sets." : ""
    ])
    low_priority = compact([
      length(var.custom_rules) == 0 ? "Consider adding custom rules for application-specific protection." : "",
      var.api_vpc_endpoint_only == false && var.create_api_gateway_policy ? "Consider restricting API access to VPC endpoints only." : "",
      var.rate_limit > 1000 ? "Consider lowering rate limit for stricter protection." : ""
    ])
  }
}

output "compliance_gaps" {
  description = "Identified compliance gaps and remediation steps"
  value = {
    for framework in ["SOC2", "NIST", "CIS", "PCI-DSS", "HIPAA", "FedRAMP"] :
    framework => {
      required     = contains(var.compliance_frameworks, framework)
      configured   = contains(var.compliance_frameworks, framework)
      gap_analysis = !contains(var.compliance_frameworks, framework) ? "Framework not configured" : "Compliant"
      remediation  = !contains(var.compliance_frameworks, framework) ? "Add ${framework} to compliance_frameworks variable" : "No action required"
    }
  }
}