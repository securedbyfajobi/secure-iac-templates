# Kubernetes Security Hardening Module
# Enterprise-grade container and Kubernetes security infrastructure

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.0"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    kubectl = {
      source  = "gavinbunney/kubectl"
      version = "~> 1.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.4"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

# =============================================================================
# LOCALS AND DATA SOURCES
# =============================================================================

locals {
  # Common labels for all Kubernetes resources
  common_labels = merge(var.common_labels, {
    "app.kubernetes.io/managed-by" = "terraform"
    "security.framework"           = "hardened"
    "compliance.required"          = "true"
    "environment"                  = var.environment
    "data.classification"          = var.data_classification
  })

  # Security policies mapping
  security_policies = {
    CIS = {
      name = "cis-kubernetes-benchmark"
      controls = [
        "1.1.1", "1.1.2", "1.1.3", "1.1.4", "1.1.5", "1.1.6", "1.1.7", "1.1.8",
        "1.2.1", "1.2.2", "1.2.3", "1.2.4", "1.2.5", "1.2.6", "1.2.7", "1.2.8",
        "2.1", "2.2", "2.3", "2.4", "2.5", "2.6", "2.7",
        "3.1.1", "3.2.1", "3.2.2", "4.1.1", "4.1.2", "4.1.3", "4.1.4",
        "4.2.1", "4.2.2", "4.2.3", "4.2.4", "4.2.5", "4.2.6", "4.2.7",
        "5.1.1", "5.1.2", "5.1.3", "5.1.4", "5.1.5", "5.1.6",
        "5.2.1", "5.2.2", "5.2.3", "5.2.4", "5.2.5",
        "5.3.1", "5.3.2", "5.7.1", "5.7.2", "5.7.3", "5.7.4"
      ]
    }
    NIST = {
      name = "nist-sp-800-190"
      controls = [
        "AC-1", "AC-2", "AC-3", "AC-4", "AC-5", "AC-6", "AC-7",
        "AU-2", "AU-3", "AU-6", "AU-8", "AU-9", "AU-12",
        "CA-2", "CA-7", "CM-2", "CM-3", "CM-6", "CM-7", "CM-8",
        "CP-2", "CP-4", "CP-9", "CP-10", "IA-2", "IA-3", "IA-5",
        "IR-4", "IR-6", "RA-5", "SA-10", "SC-2", "SC-4", "SC-7",
        "SC-8", "SC-28", "SI-2", "SI-3", "SI-4", "SI-7"
      ]
    }
    SOC2 = {
      name = "soc2-kubernetes"
      controls = [
        "CC1.1", "CC1.2", "CC1.3", "CC2.1", "CC2.2", "CC2.3",
        "CC3.1", "CC3.2", "CC3.3", "CC3.4", "CC4.1", "CC4.2",
        "CC5.1", "CC5.2", "CC5.3", "CC6.1", "CC6.2", "CC6.3",
        "CC6.4", "CC6.5", "CC6.6", "CC6.7", "CC6.8", "CC7.1",
        "CC7.2", "CC7.3", "CC7.4", "CC7.5", "CC8.1", "CC8.2"
      ]
    }
  }

  # Resource quotas and limits
  resource_quotas = {
    compute = {
      "requests.cpu"    = var.environment == "prod" ? "100" : "50"
      "requests.memory" = var.environment == "prod" ? "200Gi" : "100Gi"
      "limits.cpu"      = var.environment == "prod" ? "200" : "100"
      "limits.memory"   = var.environment == "prod" ? "400Gi" : "200Gi"
    }
    storage = {
      "requests.storage"                           = "1Ti"
      "persistentvolumeclaims"                    = "100"
      "requests.ephemeral-storage"                = "100Gi"
      "limits.ephemeral-storage"                  = "200Gi"
    }
    objects = {
      "pods"                    = "1000"
      "replicationcontrollers"  = "20"
      "resourcequotas"          = "4"
      "secrets"                 = "100"
      "configmaps"             = "100"
      "services"               = "50"
      "services.loadbalancers" = "10"
      "services.nodeports"     = "5"
    }
  }
}

# =============================================================================
# NAMESPACE CONFIGURATION
# =============================================================================

# Security-hardened namespaces
resource "kubernetes_namespace" "security_namespaces" {
  for_each = toset(var.security_namespaces)

  metadata {
    name = each.value
    labels = merge(local.common_labels, {
      "name"                          = each.value
      "pod-security.kubernetes.io/enforce" = var.pod_security_standard
      "pod-security.kubernetes.io/audit"   = var.pod_security_standard
      "pod-security.kubernetes.io/warn"    = var.pod_security_standard
    })
    annotations = {
      "security.hardened"                    = "true"
      "compliance.frameworks"                = join(",", var.compliance_frameworks)
      "scheduler.alpha.kubernetes.io/node-selector" = var.enable_node_isolation ? "security-tier=hardened" : ""
    }
  }
}

# =============================================================================
# RBAC CONFIGURATION
# =============================================================================

# Security admin cluster role
resource "kubernetes_cluster_role" "security_admin" {
  metadata {
    name = "${var.cluster_name}-security-admin"
    labels = local.common_labels
  }

  rule {
    api_groups = [""]
    resources  = ["pods", "pods/log", "pods/exec", "pods/portforward"]
    verbs      = ["get", "list", "watch"]
  }

  rule {
    api_groups = [""]
    resources  = ["secrets", "configmaps"]
    verbs      = ["get", "list", "watch", "create", "update", "patch", "delete"]
  }

  rule {
    api_groups = ["apps"]
    resources  = ["deployments", "replicasets", "daemonsets", "statefulsets"]
    verbs      = ["get", "list", "watch", "create", "update", "patch", "delete"]
  }

  rule {
    api_groups = ["networking.k8s.io"]
    resources  = ["networkpolicies"]
    verbs      = ["get", "list", "watch", "create", "update", "patch", "delete"]
  }

  rule {
    api_groups = ["policy"]
    resources  = ["podsecuritypolicies"]
    verbs      = ["get", "list", "watch", "create", "update", "patch", "delete"]
  }

  rule {
    api_groups = ["security.istio.io"]
    resources  = ["*"]
    verbs      = ["*"]
  }
}

# Security readonly role
resource "kubernetes_cluster_role" "security_readonly" {
  metadata {
    name = "${var.cluster_name}-security-readonly"
    labels = local.common_labels
  }

  rule {
    api_groups = [""]
    resources  = ["pods", "pods/log", "services", "endpoints", "configmaps"]
    verbs      = ["get", "list", "watch"]
  }

  rule {
    api_groups = ["apps"]
    resources  = ["deployments", "replicasets", "daemonsets", "statefulsets"]
    verbs      = ["get", "list", "watch"]
  }

  rule {
    api_groups = ["networking.k8s.io"]
    resources  = ["networkpolicies", "ingresses"]
    verbs      = ["get", "list", "watch"]
  }
}

# Service accounts for security services
resource "kubernetes_service_account" "security_scanner" {
  count = var.enable_security_scanning ? 1 : 0

  metadata {
    name      = "security-scanner"
    namespace = kubernetes_namespace.security_namespaces["security-system"].metadata[0].name
    labels    = local.common_labels
    annotations = {
      "eks.amazonaws.com/role-arn" = var.cloud_provider == "aws" ? var.scanner_role_arn : ""
    }
  }

  automount_service_account_token = false
}

resource "kubernetes_service_account" "falco" {
  count = var.enable_falco ? 1 : 0

  metadata {
    name      = "falco"
    namespace = kubernetes_namespace.security_namespaces["security-system"].metadata[0].name
    labels    = local.common_labels
  }

  automount_service_account_token = true
}

# =============================================================================
# POD SECURITY POLICIES
# =============================================================================

resource "kubernetes_manifest" "restricted_psp" {
  count = var.enable_pod_security_policies ? 1 : 0

  manifest = {
    apiVersion = "policy/v1beta1"
    kind       = "PodSecurityPolicy"
    metadata = {
      name   = "${var.cluster_name}-restricted"
      labels = local.common_labels
    }
    spec = {
      privileged                = false
      allowPrivilegeEscalation = false
      requiredDropCapabilities = ["ALL"]
      volumes = [
        "configMap",
        "emptyDir",
        "projected",
        "secret",
        "downwardAPI",
        "persistentVolumeClaim"
      ]
      runAsUser = {
        rule = "MustRunAsNonRoot"
      }
      runAsGroup = {
        rule = "MustRunAs"
        ranges = [
          {
            min = 1
            max = 65535
          }
        ]
      }
      seLinux = {
        rule = "RunAsAny"
      }
      supplementalGroups = {
        rule = "MustRunAs"
        ranges = [
          {
            min = 1
            max = 65535
          }
        ]
      }
      fsGroup = {
        rule = "RunAsAny"
      }
      readOnlyRootFilesystem = true
      securityContext = {
        runAsNonRoot = true
        runAsUser    = 65534
        fsGroup      = 65534
      }
    }
  }
}

# =============================================================================
# NETWORK POLICIES
# =============================================================================

# Default deny-all network policy
resource "kubernetes_network_policy" "default_deny_all" {
  for_each = var.enable_network_policies ? kubernetes_namespace.security_namespaces : {}

  metadata {
    name      = "default-deny-all"
    namespace = each.value.metadata[0].name
    labels    = local.common_labels
  }

  spec {
    pod_selector {}
    policy_types = ["Ingress", "Egress"]
  }
}

# Allow DNS network policy
resource "kubernetes_network_policy" "allow_dns" {
  for_each = var.enable_network_policies ? kubernetes_namespace.security_namespaces : {}

  metadata {
    name      = "allow-dns"
    namespace = each.value.metadata[0].name
    labels    = local.common_labels
  }

  spec {
    pod_selector {}

    policy_types = ["Egress"]

    egress {
      to {
        namespace_selector {
          match_labels = {
            name = "kube-system"
          }
        }
      }
      ports {
        protocol = "UDP"
        port     = "53"
      }
      ports {
        protocol = "TCP"
        port     = "53"
      }
    }
  }
}

# Web tier network policies
resource "kubernetes_network_policy" "web_tier" {
  count = var.enable_network_policies && contains(var.security_namespaces, "web") ? 1 : 0

  metadata {
    name      = "web-tier-policy"
    namespace = "web"
    labels    = local.common_labels
  }

  spec {
    pod_selector {
      match_labels = {
        tier = "web"
      }
    }

    policy_types = ["Ingress", "Egress"]

    ingress {
      from {
        namespace_selector {
          match_labels = {
            name = "ingress-system"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "8080"
      }
      ports {
        protocol = "TCP"
        port     = "8443"
      }
    }

    egress {
      to {
        namespace_selector {
          match_labels = {
            name = "app"
          }
        }
      }
      ports {
        protocol = "TCP"
        port     = "8080"
      }
    }
  }
}

# =============================================================================
# RESOURCE QUOTAS AND LIMITS
# =============================================================================

resource "kubernetes_resource_quota" "compute_quota" {
  for_each = kubernetes_namespace.security_namespaces

  metadata {
    name      = "compute-quota"
    namespace = each.value.metadata[0].name
    labels    = local.common_labels
  }

  spec {
    hard = local.resource_quotas.compute
  }
}

resource "kubernetes_resource_quota" "storage_quota" {
  for_each = kubernetes_namespace.security_namespaces

  metadata {
    name      = "storage-quota"
    namespace = each.value.metadata[0].name
    labels    = local.common_labels
  }

  spec {
    hard = local.resource_quotas.storage
  }
}

resource "kubernetes_resource_quota" "object_quota" {
  for_each = kubernetes_namespace.security_namespaces

  metadata {
    name      = "object-quota"
    namespace = each.value.metadata[0].name
    labels    = local.common_labels
  }

  spec {
    hard = local.resource_quotas.objects
  }
}

# Limit ranges for pods
resource "kubernetes_limit_range" "pod_limits" {
  for_each = kubernetes_namespace.security_namespaces

  metadata {
    name      = "pod-limits"
    namespace = each.value.metadata[0].name
    labels    = local.common_labels
  }

  spec {
    limit {
      type = "Pod"
      max = {
        cpu    = "2"
        memory = "4Gi"
      }
      min = {
        cpu    = "100m"
        memory = "128Mi"
      }
    }

    limit {
      type = "Container"
      default = {
        cpu    = "500m"
        memory = "1Gi"
      }
      default_request = {
        cpu    = "100m"
        memory = "128Mi"
      }
      max = {
        cpu    = "1"
        memory = "2Gi"
      }
      min = {
        cpu    = "50m"
        memory = "64Mi"
      }
    }

    limit {
      type = "PersistentVolumeClaim"
      min = {
        storage = "1Gi"
      }
      max = {
        storage = "100Gi"
      }
    }
  }
}

# =============================================================================
# SECURITY SCANNING
# =============================================================================

# Trivy security scanner
resource "helm_release" "trivy_operator" {
  count = var.enable_trivy_operator ? 1 : 0

  name       = "trivy-operator"
  repository = "https://aquasecurity.github.io/helm-charts"
  chart      = "trivy-operator"
  version    = var.trivy_operator_version
  namespace  = kubernetes_namespace.security_namespaces["security-system"].metadata[0].name

  values = [
    yamlencode({
      serviceAccount = {
        create = false
        name   = kubernetes_service_account.security_scanner[0].metadata[0].name
      }

      trivy = {
        ignoreUnfixed = false
        severity      = "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL"
        mode          = "Standalone"

        resources = {
          requests = {
            cpu    = "100m"
            memory = "100M"
          }
          limits = {
            cpu    = "500m"
            memory = "500M"
          }
        }
      }

      operator = {
        scanJobTimeout = "5m"
        configAuditScannerEnabled = true
        rbacAssessmentScannerEnabled = true
        infraAssessmentScannerEnabled = true
        clusterComplianceEnabled = true

        resources = {
          requests = {
            cpu    = "100m"
            memory = "120M"
          }
          limits = {
            cpu    = "500m"
            memory = "500M"
          }
        }
      }

      compliance = {
        cron = var.compliance_scan_schedule
      }

      nodeCollector = {
        volumeMounts = [
          {
            name      = "var-lib-etcd"
            mountPath = "/var/lib/etcd"
            readOnly  = true
          },
          {
            name      = "var-lib-kubelet"
            mountPath = "/var/lib/kubelet"
            readOnly  = true
          },
          {
            name      = "etc-systemd"
            mountPath = "/etc/systemd"
            readOnly  = true
          }
        ]
      }
    })
  ]

  depends_on = [kubernetes_service_account.security_scanner]
}

# =============================================================================
# RUNTIME SECURITY (FALCO)
# =============================================================================

resource "helm_release" "falco" {
  count = var.enable_falco ? 1 : 0

  name       = "falco"
  repository = "https://falcosecurity.github.io/charts"
  chart      = "falco"
  version    = var.falco_version
  namespace  = kubernetes_namespace.security_namespaces["security-system"].metadata[0].name

  values = [
    yamlencode({
      serviceAccount = {
        create = false
        name   = kubernetes_service_account.falco[0].metadata[0].name
      }

      ebpf = {
        enabled = var.enable_ebpf
      }

      falco = {
        rules_file = [
          "/etc/falco/falco_rules.yaml",
          "/etc/falco/falco_rules.local.yaml",
          "/etc/falco/k8s_audit_rules.yaml"
        ]

        json_output = true
        json_include_output_property = true
        json_include_tags_property = true

        log_stderr = true
        log_syslog = false
        log_level = "info"

        priority = "debug"

        syscall_event_drops = {
          actions             = ["log", "alert"]
          rate                = 0.03333
          max_burst           = 10
        }

        outputs = {
          rate    = 1
          max_burst = 1000
        }

        webserver = {
          enabled            = true
          listen_port        = 8765
          k8s_healthz_endpoint = "/healthz"
          ssl_enabled        = false
          ssl_certificate    = "/etc/ssl/falco/falco.pem"
        }

        grpc = {
          enabled       = var.enable_falco_grpc
          bind_address  = "0.0.0.0:5060"
          threadiness   = 8
        }

        grpc_output = {
          enabled = var.enable_falco_grpc
        }
      }

      customRules = {
        "security_rules.yaml" = yamlencode({
          customRules = [
            {
              rule = "Detect crypto miners"
              desc = "Detect cryptocurrency mining"
              condition = "spawned_process and ((proc.name in (xmrig, minergate)) or (proc.cmdline contains \"-t \" and proc.cmdline contains \"stratum+tcp://\"))"
              output = "Cryptocurrency mining detected (user=%user.name command=%proc.cmdline container=%container.info image=%container.image)"
              priority = "CRITICAL"
            },
            {
              rule = "Detect privilege escalation"
              desc = "Detect attempts to escalate privileges"
              condition = "(spawned_process and proc.name in (su, sudo, doas)) or (spawned_process and proc.cmdline contains \"chmod +s\")"
              output = "Privilege escalation detected (user=%user.name command=%proc.cmdline container=%container.info)"
              priority = "HIGH"
            },
            {
              rule = "Detect suspicious network connections"
              desc = "Detect connections to suspicious domains"
              condition = "outbound and fd.sport_name exists and (fd.sport_name contains \".onion\" or fd.sport_name contains \"bit.ly\" or fd.sport_name contains \"tinyurl\")"
              output = "Suspicious network connection (connection=%fd.name container=%container.info)"
              priority = "MEDIUM"
            }
          ]
        })
      }

      resources = {
        requests = {
          cpu    = "100m"
          memory = "512Mi"
        }
        limits = {
          cpu    = "1000m"
          memory = "1024Mi"
        }
      }

      tolerations = [
        {
          effect   = "NoSchedule"
          key      = "node-role.kubernetes.io/master"
          operator = "Exists"
        },
        {
          effect   = "NoSchedule"
          key      = "node-role.kubernetes.io/control-plane"
          operator = "Exists"
        }
      ]

      extra = {
        env = [
          {
            name  = "FALCO_K8S_NODE_NAME"
            valueFrom = {
              fieldRef = {
                fieldPath = "spec.nodeName"
              }
            }
          }
        ]
      }
    })
  ]

  depends_on = [kubernetes_service_account.falco]
}

# =============================================================================
# ADMISSION CONTROLLERS
# =============================================================================

# OPA Gatekeeper for policy enforcement
resource "helm_release" "gatekeeper" {
  count = var.enable_opa_gatekeeper ? 1 : 0

  name       = "gatekeeper"
  repository = "https://open-policy-agent.github.io/gatekeeper/charts"
  chart      = "gatekeeper"
  version    = var.gatekeeper_version
  namespace  = "gatekeeper-system"

  create_namespace = true

  values = [
    yamlencode({
      replicas = var.environment == "prod" ? 3 : 2

      auditInterval = 60
      constraintViolationsLimit = 20
      auditFromCache = false

      image = {
        repository = "openpolicyagent/gatekeeper"
        pullPolicy = "Always"
      }

      nodeSelector = {
        "kubernetes.io/os" = "linux"
      }

      resources = {
        limits = {
          cpu    = "1000m"
          memory = "512Mi"
        }
        requests = {
          cpu    = "100m"
          memory = "256Mi"
        }
      }

      securityContext = {
        runAsGroup      = 999
        runAsNonRoot    = true
        runAsUser       = 1000
        fsGroup         = 999
        seccompProfile = {
          type = "RuntimeDefault"
        }
      }

      podSecurityContext = {
        runAsNonRoot = true
        runAsUser    = 1000
        fsGroup      = 999
      }

      controllerManager = {
        exemptNamespaces = ["gatekeeper-system", "kube-system", "kube-public"]
      }

      audit = {
        resources = {
          limits = {
            cpu    = "1000m"
            memory = "512Mi"
          }
          requests = {
            cpu    = "100m"
            memory = "256Mi"
          }
        }
      }

      webhook = {
        failurePolicy = "Fail"
        namespaceSelector = {
          matchExpressions = [
            {
              key      = "name"
              operator = "NotIn"
              values   = ["gatekeeper-system", "kube-system", "kube-public"]
            }
          ]
        }
      }
    })
  ]
}

# Gatekeeper constraint templates
resource "kubectl_manifest" "require_security_context" {
  count = var.enable_opa_gatekeeper ? 1 : 0

  yaml_body = yamlencode({
    apiVersion = "templates.gatekeeper.sh/v1beta1"
    kind       = "ConstraintTemplate"
    metadata = {
      name = "k8srequiresecuritycontext"
    }
    spec = {
      crd = {
        spec = {
          names = {
            kind = "K8sRequireSecurityContext"
          }
          validation = {
            openAPIV3Schema = {
              type = "object"
              properties = {
                runAsNonRoot = {
                  type = "boolean"
                }
                readOnlyRootFilesystem = {
                  type = "boolean"
                }
                allowPrivilegeEscalation = {
                  type = "boolean"
                }
              }
            }
          }
        }
      }
      targets = [
        {
          target = "admission.k8s.gatekeeper.sh"
          rego = <<-REGO
            package k8srequiresecuritycontext

            violation[{"msg": msg}] {
              container := input.review.object.spec.containers[_]
              not container.securityContext.runAsNonRoot
              msg := "Container must run as non-root user"
            }

            violation[{"msg": msg}] {
              container := input.review.object.spec.containers[_]
              not container.securityContext.readOnlyRootFilesystem
              msg := "Container must have read-only root filesystem"
            }

            violation[{"msg": msg}] {
              container := input.review.object.spec.containers[_]
              container.securityContext.allowPrivilegeEscalation != false
              msg := "Container must not allow privilege escalation"
            }
          REGO
        }
      ]
    }
  })

  depends_on = [helm_release.gatekeeper]
}

# Security context constraint
resource "kubectl_manifest" "security_context_constraint" {
  count = var.enable_opa_gatekeeper ? 1 : 0

  yaml_body = yamlencode({
    apiVersion = "config.gatekeeper.sh/v1alpha1"
    kind       = "K8sRequireSecurityContext"
    metadata = {
      name = "must-have-security-context"
    }
    spec = {
      match = {
        kinds = [
          {
            apiGroups = [""]
            kinds     = ["Pod"]
          }
        ]
        excludedNamespaces = ["kube-system", "gatekeeper-system", "kube-public"]
      }
      parameters = {
        runAsNonRoot             = true
        readOnlyRootFilesystem   = true
        allowPrivilegeEscalation = false
      }
    }
  })

  depends_on = [kubectl_manifest.require_security_context]
}

# =============================================================================
# IMAGE SECURITY
# =============================================================================

# Notary for image signing
resource "helm_release" "notary" {
  count = var.enable_image_signing ? 1 : 0

  name       = "notary"
  repository = "https://charts.bitnami.com/bitnami"
  chart      = "harbor"
  version    = var.harbor_version
  namespace  = kubernetes_namespace.security_namespaces["security-system"].metadata[0].name

  values = [
    yamlencode({
      expose = {
        type = "clusterIP"
        tls = {
          enabled = true
          certSource = "auto"
        }
      }

      chartmuseum = {
        enabled = false
      }

      clair = {
        enabled = true
        updatersInterval = 12
      }

      notary = {
        enabled = true
      }

      database = {
        type = "internal"
        internal = {
          password = "changeit"
        }
      }

      redis = {
        type = "internal"
        internal = {
          password = "changeit"
        }
      }

      harborAdminPassword = "Harbor12345"

      secretKey = "not-a-secure-key"

      persistence = {
        enabled = true
        persistentVolumeClaim = {
          registry = {
            size = "200Gi"
          }
          chartmuseum = {
            size = "5Gi"
          }
          jobservice = {
            size = "1Gi"
          }
          database = {
            size = "1Gi"
          }
          redis = {
            size = "1Gi"
          }
        }
      }

      logLevel = "info"
    })
  ]
}

# =============================================================================
# SERVICE MESH SECURITY (ISTIO)
# =============================================================================

resource "helm_release" "istio_base" {
  count = var.enable_istio ? 1 : 0

  name       = "istio-base"
  repository = "https://istio-release.storage.googleapis.com/charts"
  chart      = "base"
  version    = var.istio_version
  namespace  = "istio-system"

  create_namespace = true

  set {
    name  = "global.meshID"
    value = var.cluster_name
  }

  set {
    name  = "global.meshConfig.trustDomain"
    value = var.trust_domain
  }

  set {
    name  = "global.meshConfig.enableAutoMtls"
    value = "true"
  }
}

resource "helm_release" "istio_discovery" {
  count = var.enable_istio ? 1 : 0

  name       = "istiod"
  repository = "https://istio-release.storage.googleapis.com/charts"
  chart      = "istiod"
  version    = var.istio_version
  namespace  = "istio-system"

  values = [
    yamlencode({
      global = {
        meshID = var.cluster_name
        meshConfig = {
          trustDomain      = var.trust_domain
          enableAutoMtls   = true
          defaultConfig = {
            gatewayTopology = {
              numTrustedProxies = 2
            }
          }
        }
      }

      pilot = {
        resources = {
          requests = {
            cpu    = "100m"
            memory = "128Mi"
          }
          limits = {
            cpu    = "500m"
            memory = "2048Mi"
          }
        }

        env = {
          PILOT_ENABLE_WORKLOAD_ENTRY_AUTOREGISTRATION = true
          PILOT_ENABLE_CROSS_CLUSTER_WORKLOAD_ENTRY    = true
          PILOT_ENABLE_AMBIENT                         = var.enable_ambient_mesh
        }

        securityContext = {
          runAsUser       = 1337
          runAsGroup      = 1337
          runAsNonRoot    = true
          readOnlyRootFilesystem = true
        }
      }
    })
  ]

  depends_on = [helm_release.istio_base]
}

# Istio gateway for secure ingress
resource "kubectl_manifest" "istio_gateway" {
  count = var.enable_istio ? 1 : 0

  yaml_body = yamlencode({
    apiVersion = "networking.istio.io/v1beta1"
    kind       = "Gateway"
    metadata = {
      name      = "${var.cluster_name}-gateway"
      namespace = "istio-system"
      labels    = local.common_labels
    }
    spec = {
      selector = {
        istio = "ingressgateway"
      }
      servers = [
        {
          port = {
            number   = 443
            name     = "https"
            protocol = "HTTPS"
          }
          tls = {
            mode = "SIMPLE"
            credentialName = "${var.cluster_name}-tls-secret"
          }
          hosts = var.ingress_hosts
        },
        {
          port = {
            number   = 80
            name     = "http"
            protocol = "HTTP"
          }
          hosts = var.ingress_hosts
          tls = {
            httpsRedirect = true
          }
        }
      ]
    }
  })

  depends_on = [helm_release.istio_discovery]
}

# =============================================================================
# SECRETS MANAGEMENT
# =============================================================================

# External Secrets Operator
resource "helm_release" "external_secrets" {
  count = var.enable_external_secrets ? 1 : 0

  name       = "external-secrets"
  repository = "https://charts.external-secrets.io"
  chart      = "external-secrets"
  version    = var.external_secrets_version
  namespace  = kubernetes_namespace.security_namespaces["security-system"].metadata[0].name

  values = [
    yamlencode({
      installCRDs = true

      replicaCount = var.environment == "prod" ? 2 : 1

      leaderElect = true

      resources = {
        limits = {
          cpu    = "100m"
          memory = "128Mi"
        }
        requests = {
          cpu    = "10m"
          memory = "32Mi"
        }
      }

      securityContext = {
        allowPrivilegeEscalation = false
        capabilities = {
          drop = ["ALL"]
        }
        readOnlyRootFilesystem = true
        runAsNonRoot = true
        runAsUser    = 65532
        seccompProfile = {
          type = "RuntimeDefault"
        }
      }

      webhook = {
        create = true
        port   = 9443

        resources = {
          limits = {
            cpu    = "100m"
            memory = "128Mi"
          }
          requests = {
            cpu    = "10m"
            memory = "32Mi"
          }
        }
      }

      certController = {
        create = true

        resources = {
          limits = {
            cpu    = "100m"
            memory = "128Mi"
          }
          requests = {
            cpu    = "10m"
            memory = "32Mi"
          }
        }
      }
    })
  ]
}

# =============================================================================
# MONITORING AND OBSERVABILITY
# =============================================================================

# Prometheus for security metrics
resource "helm_release" "prometheus" {
  count = var.enable_prometheus ? 1 : 0

  name       = "prometheus"
  repository = "https://prometheus-community.github.io/helm-charts"
  chart      = "kube-prometheus-stack"
  version    = var.prometheus_version
  namespace  = kubernetes_namespace.security_namespaces["monitoring"].metadata[0].name

  values = [
    yamlencode({
      prometheus = {
        prometheusSpec = {
          retention = "30d"
          retentionSize = "50GiB"

          storageSpec = {
            volumeClaimTemplate = {
              spec = {
                storageClassName = var.storage_class
                accessModes      = ["ReadWriteOnce"]
                resources = {
                  requests = {
                    storage = "100Gi"
                  }
                }
              }
            }
          }

          securityContext = {
            runAsGroup   = 2000
            runAsNonRoot = true
            runAsUser    = 1000
            fsGroup      = 2000
          }

          resources = {
            limits = {
              cpu    = "2000m"
              memory = "8Gi"
            }
            requests = {
              cpu    = "100m"
              memory = "512Mi"
            }
          }

          additionalScrapeConfigs = [
            {
              job_name = "falco-metrics"
              static_configs = [
                {
                  targets = ["falco.security-system.svc.cluster.local:8765"]
                }
              ]
            }
          ]
        }
      }

      grafana = {
        enabled = true

        securityContext = {
          runAsGroup   = 472
          runAsUser    = 472
          runAsNonRoot = true
          fsGroup      = 472
        }

        resources = {
          limits = {
            cpu    = "200m"
            memory = "200Mi"
          }
          requests = {
            cpu    = "100m"
            memory = "128Mi"
          }
        }

        persistence = {
          enabled      = true
          size         = "10Gi"
          storageClassName = var.storage_class
        }

        dashboardProviders = {
          "dashboardproviders.yaml" = {
            apiVersion = 1
            providers = [
              {
                name            = "security"
                orgId           = 1
                folder          = "Security"
                type            = "file"
                disableDeletion = false
                editable        = true
                options = {
                  path = "/var/lib/grafana/dashboards/security"
                }
              }
            ]
          }
        }

        dashboards = {
          security = {
            falco-dashboard = {
              gnetId     = 11914
              revision   = 1
              datasource = "Prometheus"
            }
            kubernetes-security = {
              gnetId     = 12146
              revision   = 1
              datasource = "Prometheus"
            }
          }
        }
      }

      alertmanager = {
        alertmanagerSpec = {
          resources = {
            limits = {
              cpu    = "100m"
              memory = "128Mi"
            }
            requests = {
              cpu    = "4m"
              memory = "32Mi"
            }
          }

          securityContext = {
            runAsGroup   = 2000
            runAsNonRoot = true
            runAsUser    = 1000
            fsGroup      = 2000
          }
        }
      }
    })
  ]
}

# =============================================================================
# BACKUP AND DISASTER RECOVERY
# =============================================================================

resource "helm_release" "velero" {
  count = var.enable_velero_backup ? 1 : 0

  name       = "velero"
  repository = "https://vmware-tanzu.github.io/helm-charts"
  chart      = "velero"
  version    = var.velero_version
  namespace  = kubernetes_namespace.security_namespaces["backup"].metadata[0].name

  values = [
    yamlencode({
      configuration = {
        provider = var.cloud_provider

        backupStorageLocation = {
          name   = "primary"
          provider = var.cloud_provider
          bucket = var.backup_bucket_name
          config = var.cloud_provider == "aws" ? {
            region = var.aws_region
            kmsKeyId = var.backup_kms_key_id
          } : var.cloud_provider == "azure" ? {
            resourceGroup     = var.azure_resource_group
            storageAccount    = var.azure_storage_account
            subscriptionId    = var.azure_subscription_id
          } : {
            project = var.gcp_project_id
          }
        }

        volumeSnapshotLocation = {
          name     = "primary"
          provider = var.cloud_provider
          config = var.cloud_provider == "aws" ? {
            region = var.aws_region
          } : var.cloud_provider == "azure" ? {
            resourceGroup  = var.azure_resource_group
            subscriptionId = var.azure_subscription_id
          } : {
            project = var.gcp_project_id
          }
        }

        defaultBackupStorageLocation = "primary"
        defaultVolumeSnapshotLocations = "primary"
      }

      schedules = {
        daily = {
          schedule = var.backup_schedule
          template = {
            includedNamespaces = var.security_namespaces
            storageLocation    = "primary"
            volumeSnapshotLocations = ["primary"]
            ttl = "720h0m0s" # 30 days
          }
        }
      }

      serviceAccount = {
        server = {
          annotations = var.cloud_provider == "aws" ? {
            "eks.amazonaws.com/role-arn" = var.velero_role_arn
          } : {}
        }
      }

      credentials = {
        useSecret = var.cloud_provider != "aws"
        secretContents = var.cloud_provider == "azure" ? {
          cloud = base64encode(templatefile("${path.module}/templates/azure-credentials", {
            subscription_id = var.azure_subscription_id
            tenant_id       = var.azure_tenant_id
            client_id       = var.azure_client_id
            client_secret   = var.azure_client_secret
          }))
        } : var.cloud_provider == "gcp" ? {
          cloud = base64encode(file(var.gcp_service_account_key))
        } : {}
      }

      resources = {
        limits = {
          cpu    = "1000m"
          memory = "512Mi"
        }
        requests = {
          cpu    = "500m"
          memory = "128Mi"
        }
      }

      securityContext = {
        runAsGroup   = 65534
        runAsNonRoot = true
        runAsUser    = 65534
        fsGroup      = 65534
      }

      initContainers = var.cloud_provider == "aws" ? [
        {
          name  = "velero-plugin-for-aws"
          image = "velero/velero-plugin-for-aws:v1.8.0"
          volumeMounts = [
            {
              mountPath = "/target"
              name      = "plugins"
            }
          ]
        }
      ] : var.cloud_provider == "azure" ? [
        {
          name  = "velero-plugin-for-microsoft-azure"
          image = "velero/velero-plugin-for-microsoft-azure:v1.8.0"
          volumeMounts = [
            {
              mountPath = "/target"
              name      = "plugins"
            }
          ]
        }
      ] : [
        {
          name  = "velero-plugin-for-gcp"
          image = "velero/velero-plugin-for-gcp:v1.8.0"
          volumeMounts = [
            {
              mountPath = "/target"
              name      = "plugins"
            }
          ]
        }
      ]
    })
  ]
}