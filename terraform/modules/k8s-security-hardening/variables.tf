# Variables for Kubernetes Security Hardening Module

# =============================================================================
# BASIC CONFIGURATION
# =============================================================================

variable "cluster_name" {
  description = "Name of the Kubernetes cluster"
  type        = string
  validation {
    condition     = length(var.cluster_name) <= 63 && can(regex("^[a-z][a-z0-9-]*[a-z0-9]$", var.cluster_name))
    error_message = "Cluster name must be a valid DNS label (lowercase, start/end with alphanumeric, max 63 chars)."
  }
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod", "development", "production"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod, development, production."
  }
}

variable "cloud_provider" {
  description = "Cloud provider (aws, azure, gcp)"
  type        = string
  validation {
    condition     = contains(["aws", "azure", "gcp"], var.cloud_provider)
    error_message = "Cloud provider must be one of: aws, azure, gcp."
  }
}

variable "data_classification" {
  description = "Data classification level for the cluster"
  type        = string
  default     = "internal"
  validation {
    condition     = contains(["public", "internal", "confidential", "restricted"], var.data_classification)
    error_message = "Data classification must be one of: public, internal, confidential, restricted."
  }
}

# =============================================================================
# COMPLIANCE FRAMEWORKS
# =============================================================================

variable "compliance_frameworks" {
  description = "List of compliance frameworks to implement"
  type        = list(string)
  default     = ["CIS", "NIST", "SOC2"]
  validation {
    condition = alltrue([
      for framework in var.compliance_frameworks :
      contains(["CIS", "NIST", "SOC2", "PCI-DSS", "HIPAA", "FedRAMP"], framework)
    ])
    error_message = "Compliance frameworks must be from: CIS, NIST, SOC2, PCI-DSS, HIPAA, FedRAMP."
  }
}

variable "pod_security_standard" {
  description = "Pod Security Standard level (privileged, baseline, restricted)"
  type        = string
  default     = "restricted"
  validation {
    condition     = contains(["privileged", "baseline", "restricted"], var.pod_security_standard)
    error_message = "Pod Security Standard must be: privileged, baseline, or restricted."
  }
}

# =============================================================================
# NAMESPACE CONFIGURATION
# =============================================================================

variable "security_namespaces" {
  description = "List of security-hardened namespaces to create"
  type        = list(string)
  default = [
    "security-system",
    "monitoring",
    "backup",
    "web",
    "app",
    "data"
  ]
  validation {
    condition = alltrue([
      for ns in var.security_namespaces : can(regex("^[a-z][a-z0-9-]*[a-z0-9]$", ns))
    ])
    error_message = "All namespace names must be valid DNS labels."
  }
}

variable "enable_node_isolation" {
  description = "Enable node isolation with taints and tolerations"
  type        = bool
  default     = true
}

# =============================================================================
# RBAC CONFIGURATION
# =============================================================================

variable "enable_rbac_hardening" {
  description = "Enable RBAC hardening policies"
  type        = bool
  default     = true
}

variable "scanner_role_arn" {
  description = "IAM role ARN for security scanner (AWS only)"
  type        = string
  default     = ""
}

# =============================================================================
# SECURITY POLICIES
# =============================================================================

variable "enable_pod_security_policies" {
  description = "Enable Pod Security Policies (deprecated in K8s 1.25+)"
  type        = bool
  default     = false
}

variable "enable_network_policies" {
  description = "Enable Kubernetes Network Policies"
  type        = bool
  default     = true
}

variable "enable_admission_controllers" {
  description = "Enable additional admission controllers"
  type        = bool
  default     = true
}

# =============================================================================
# SECURITY SCANNING
# =============================================================================

variable "enable_security_scanning" {
  description = "Enable security vulnerability scanning"
  type        = bool
  default     = true
}

variable "enable_trivy_operator" {
  description = "Enable Trivy Operator for vulnerability scanning"
  type        = bool
  default     = true
}

variable "trivy_operator_version" {
  description = "Version of Trivy Operator to deploy"
  type        = string
  default     = "0.16.4"
}

variable "compliance_scan_schedule" {
  description = "Cron schedule for compliance scans"
  type        = string
  default     = "0 2 * * *" # Daily at 2 AM
}

# =============================================================================
# RUNTIME SECURITY
# =============================================================================

variable "enable_falco" {
  description = "Enable Falco for runtime security monitoring"
  type        = bool
  default     = true
}

variable "falco_version" {
  description = "Version of Falco to deploy"
  type        = string
  default     = "3.8.4"
}

variable "enable_ebpf" {
  description = "Enable eBPF driver for Falco"
  type        = bool
  default     = true
}

variable "enable_falco_grpc" {
  description = "Enable Falco gRPC API"
  type        = bool
  default     = false
}

# =============================================================================
# ADMISSION CONTROLLERS
# =============================================================================

variable "enable_opa_gatekeeper" {
  description = "Enable OPA Gatekeeper for policy enforcement"
  type        = bool
  default     = true
}

variable "gatekeeper_version" {
  description = "Version of OPA Gatekeeper to deploy"
  type        = string
  default     = "3.14.0"
}

# =============================================================================
# IMAGE SECURITY
# =============================================================================

variable "enable_image_signing" {
  description = "Enable image signing and verification"
  type        = bool
  default     = false
}

variable "enable_image_scanning" {
  description = "Enable container image vulnerability scanning"
  type        = bool
  default     = true
}

variable "harbor_version" {
  description = "Version of Harbor registry to deploy"
  type        = string
  default     = "1.13.0"
}

variable "allowed_registries" {
  description = "List of allowed container registries"
  type        = list(string)
  default = [
    "docker.io",
    "gcr.io",
    "quay.io",
    "registry.k8s.io"
  ]
}

# =============================================================================
# SERVICE MESH SECURITY
# =============================================================================

variable "enable_istio" {
  description = "Enable Istio service mesh for mTLS and traffic policies"
  type        = bool
  default     = false
}

variable "istio_version" {
  description = "Version of Istio to deploy"
  type        = string
  default     = "1.19.3"
}

variable "trust_domain" {
  description = "Trust domain for service mesh"
  type        = string
  default     = "cluster.local"
}

variable "enable_ambient_mesh" {
  description = "Enable Istio ambient mesh mode"
  type        = bool
  default     = false
}

variable "ingress_hosts" {
  description = "List of hostnames for ingress gateway"
  type        = list(string)
  default     = ["*"]
}

# =============================================================================
# SECRETS MANAGEMENT
# =============================================================================

variable "enable_external_secrets" {
  description = "Enable External Secrets Operator"
  type        = bool
  default     = true
}

variable "external_secrets_version" {
  description = "Version of External Secrets Operator"
  type        = string
  default     = "0.9.9"
}

variable "secrets_backend" {
  description = "Secrets backend (aws-secrets-manager, azure-keyvault, gcp-secret-manager, vault)"
  type        = string
  default     = "aws-secrets-manager"
  validation {
    condition     = contains(["aws-secrets-manager", "azure-keyvault", "gcp-secret-manager", "vault"], var.secrets_backend)
    error_message = "Secrets backend must be one of: aws-secrets-manager, azure-keyvault, gcp-secret-manager, vault."
  }
}

# =============================================================================
# MONITORING AND OBSERVABILITY
# =============================================================================

variable "enable_prometheus" {
  description = "Enable Prometheus for security metrics monitoring"
  type        = bool
  default     = true
}

variable "prometheus_version" {
  description = "Version of Prometheus stack to deploy"
  type        = string
  default     = "54.2.2"
}

variable "enable_grafana" {
  description = "Enable Grafana for security dashboards"
  type        = bool
  default     = true
}

variable "enable_alerting" {
  description = "Enable security alerting"
  type        = bool
  default     = true
}

variable "alert_webhook_url" {
  description = "Webhook URL for security alerts"
  type        = string
  default     = ""
  sensitive   = true
}

# =============================================================================
# BACKUP AND DISASTER RECOVERY
# =============================================================================

variable "enable_velero_backup" {
  description = "Enable Velero for cluster backup"
  type        = bool
  default     = true
}

variable "velero_version" {
  description = "Version of Velero to deploy"
  type        = string
  default     = "5.1.4"
}

variable "backup_schedule" {
  description = "Cron schedule for cluster backups"
  type        = string
  default     = "0 3 * * *" # Daily at 3 AM
}

variable "backup_bucket_name" {
  description = "Name of the backup storage bucket"
  type        = string
  default     = ""
}

variable "backup_retention_days" {
  description = "Number of days to retain backups"
  type        = number
  default     = 30
  validation {
    condition     = var.backup_retention_days >= 7 && var.backup_retention_days <= 365
    error_message = "Backup retention must be between 7 and 365 days."
  }
}

# =============================================================================
# CLOUD-SPECIFIC CONFIGURATION
# =============================================================================

# AWS Configuration
variable "aws_region" {
  description = "AWS region for resources"
  type        = string
  default     = "us-east-1"
}

variable "backup_kms_key_id" {
  description = "KMS key ID for backup encryption (AWS)"
  type        = string
  default     = ""
}

variable "velero_role_arn" {
  description = "IAM role ARN for Velero (AWS)"
  type        = string
  default     = ""
}

# Azure Configuration
variable "azure_resource_group" {
  description = "Azure resource group name"
  type        = string
  default     = ""
}

variable "azure_storage_account" {
  description = "Azure storage account for backups"
  type        = string
  default     = ""
}

variable "azure_subscription_id" {
  description = "Azure subscription ID"
  type        = string
  default     = ""
}

variable "azure_tenant_id" {
  description = "Azure tenant ID"
  type        = string
  default     = ""
}

variable "azure_client_id" {
  description = "Azure client ID"
  type        = string
  default     = ""
  sensitive   = true
}

variable "azure_client_secret" {
  description = "Azure client secret"
  type        = string
  default     = ""
  sensitive   = true
}

# GCP Configuration
variable "gcp_project_id" {
  description = "Google Cloud project ID"
  type        = string
  default     = ""
}

variable "gcp_service_account_key" {
  description = "Path to GCP service account key file"
  type        = string
  default     = ""
}

# =============================================================================
# STORAGE CONFIGURATION
# =============================================================================

variable "storage_class" {
  description = "Storage class for persistent volumes"
  type        = string
  default     = "gp3"
}

variable "enable_encryption_at_rest" {
  description = "Enable encryption at rest for persistent volumes"
  type        = bool
  default     = true
}

# =============================================================================
# RESOURCE LIMITS
# =============================================================================

variable "default_cpu_limit" {
  description = "Default CPU limit for containers"
  type        = string
  default     = "500m"
}

variable "default_memory_limit" {
  description = "Default memory limit for containers"
  type        = string
  default     = "1Gi"
}

variable "default_cpu_request" {
  description = "Default CPU request for containers"
  type        = string
  default     = "100m"
}

variable "default_memory_request" {
  description = "Default memory request for containers"
  type        = string
  default     = "128Mi"
}

# =============================================================================
# NETWORK SECURITY
# =============================================================================

variable "enable_network_segmentation" {
  description = "Enable network segmentation between tiers"
  type        = bool
  default     = true
}

variable "allowed_ingress_cidrs" {
  description = "List of CIDR blocks allowed for ingress"
  type        = list(string)
  default     = []
  validation {
    condition = alltrue([
      for cidr in var.allowed_ingress_cidrs : can(cidrhost(cidr, 0))
    ])
    error_message = "All ingress CIDRs must be valid IPv4 CIDR blocks."
  }
}

variable "deny_egress_to_metadata" {
  description = "Deny egress to cloud metadata services"
  type        = bool
  default     = true
}

# =============================================================================
# SECURITY POLICIES
# =============================================================================

variable "enable_psp_migration" {
  description = "Enable migration from PSP to Pod Security Standards"
  type        = bool
  default     = true
}

variable "require_non_root_containers" {
  description = "Require containers to run as non-root"
  type        = bool
  default     = true
}

variable "require_readonly_root_filesystem" {
  description = "Require containers to have read-only root filesystem"
  type        = bool
  default     = true
}

variable "disallow_privilege_escalation" {
  description = "Disallow privilege escalation in containers"
  type        = bool
  default     = true
}

variable "drop_all_capabilities" {
  description = "Drop all Linux capabilities by default"
  type        = bool
  default     = true
}

# =============================================================================
# COST OPTIMIZATION
# =============================================================================

variable "cost_optimization_level" {
  description = "Level of cost optimization (low, medium, high)"
  type        = string
  default     = "medium"
  validation {
    condition     = contains(["low", "medium", "high"], var.cost_optimization_level)
    error_message = "Cost optimization level must be: low, medium, or high."
  }
}

variable "enable_spot_instances" {
  description = "Allow scheduling on spot/preemptible instances"
  type        = bool
  default     = false
}

# =============================================================================
# TAGGING
# =============================================================================

variable "common_labels" {
  description = "Common labels to apply to all Kubernetes resources"
  type        = map(string)
  default = {
    "terraform"   = "true"
    "module"      = "k8s-security-hardening"
    "owner"       = ""
    "project"     = ""
    "cost-center" = ""
    "environment" = ""
  }
}

# =============================================================================
# ADVANCED FEATURES
# =============================================================================

variable "enable_chaos_engineering" {
  description = "Enable chaos engineering for resilience testing"
  type        = bool
  default     = false
}

variable "enable_policy_as_code" {
  description = "Enable policy-as-code with OPA/Gatekeeper"
  type        = bool
  default     = true
}

variable "enable_audit_logging" {
  description = "Enable Kubernetes audit logging"
  type        = bool
  default     = true
}

variable "audit_log_retention_days" {
  description = "Number of days to retain audit logs"
  type        = number
  default     = 90
  validation {
    condition     = var.audit_log_retention_days >= 30 && var.audit_log_retention_days <= 2557
    error_message = "Audit log retention must be between 30 and 2557 days."
  }
}

# =============================================================================
# INTEGRATION
# =============================================================================

variable "enable_service_mesh_integration" {
  description = "Enable integration with service mesh"
  type        = bool
  default     = false
}

variable "enable_ci_cd_integration" {
  description = "Enable CI/CD security integration"
  type        = bool
  default     = true
}

variable "enable_siem_integration" {
  description = "Enable SIEM integration for security events"
  type        = bool
  default     = false
}

variable "siem_endpoint" {
  description = "SIEM endpoint for security event forwarding"
  type        = string
  default     = ""
  sensitive   = true
}

# =============================================================================
# VULNERABILITY MANAGEMENT
# =============================================================================

variable "vulnerability_scan_schedule" {
  description = "Cron schedule for vulnerability scans"
  type        = string
  default     = "0 4 * * *" # Daily at 4 AM
}

variable "critical_vulnerability_threshold" {
  description = "CVSS threshold for critical vulnerabilities"
  type        = number
  default     = 9.0
  validation {
    condition     = var.critical_vulnerability_threshold >= 0.0 && var.critical_vulnerability_threshold <= 10.0
    error_message = "Critical vulnerability threshold must be between 0.0 and 10.0."
  }
}

variable "enable_vulnerability_alerts" {
  description = "Enable alerts for vulnerability findings"
  type        = bool
  default     = true
}

# =============================================================================
# PERFORMANCE AND SCALING
# =============================================================================

variable "enable_hpa" {
  description = "Enable Horizontal Pod Autoscaler for security components"
  type        = bool
  default     = true
}

variable "enable_vpa" {
  description = "Enable Vertical Pod Autoscaler for resource optimization"
  type        = bool
  default     = false
}

variable "max_surge_percentage" {
  description = "Maximum surge percentage for rolling updates"
  type        = number
  default     = 25
  validation {
    condition     = var.max_surge_percentage >= 0 && var.max_surge_percentage <= 100
    error_message = "Max surge percentage must be between 0 and 100."
  }
}

variable "max_unavailable_percentage" {
  description = "Maximum unavailable percentage for rolling updates"
  type        = number
  default     = 25
  validation {
    condition     = var.max_unavailable_percentage >= 0 && var.max_unavailable_percentage <= 100
    error_message = "Max unavailable percentage must be between 0 and 100."
  }
}