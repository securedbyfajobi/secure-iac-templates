# GitOps and Policy-as-Code Automation Module
# Enterprise-grade GitOps workflows and policy automation

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
    github = {
      source  = "integrations/github"
      version = "~> 5.0"
    }
    gitlab = {
      source  = "gitlabhq/gitlab"
      version = "~> 16.0"
    }
    flux = {
      source  = "fluxcd/flux"
      version = "~> 1.0"
    }
    kubectl = {
      source  = "gavinbunney/kubectl"
      version = "~> 1.0"
    }
    opa = {
      source  = "StyraInc/opa"
      version = "~> 0.9"
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
  # Common labels for all resources
  common_labels = merge(var.common_labels, {
    "app.kubernetes.io/managed-by" = "terraform"
    "gitops.enabled"               = "true"
    "policy.enforcement"           = "enabled"
    "compliance.frameworks"        = join(",", var.compliance_frameworks)
    "environment"                  = var.environment
  })

  # GitOps configuration
  gitops_config = {
    flux = {
      namespace     = "flux-system"
      version      = var.flux_version
      sync_interval = var.sync_interval
    }
    argocd = {
      namespace     = "argocd"
      version      = var.argocd_version
      sync_interval = var.sync_interval
    }
  }

  # Policy frameworks configuration
  policy_frameworks = {
    opa = {
      namespace = "opa-system"
      policies = [
        "security-policies",
        "compliance-policies",
        "resource-policies",
        "network-policies"
      ]
    }
    kyverno = {
      namespace = "kyverno"
      policies = [
        "security-baseline",
        "compliance-validation",
        "resource-quotas",
        "mutation-policies"
      ]
    }
    polaris = {
      namespace = "polaris"
      checks = [
        "security",
        "efficiency",
        "reliability"
      ]
    }
  }

  # Compliance policy mappings
  compliance_policies = {
    CIS = {
      policies = [
        "cis-k8s-1.2.1-api-server-anonymous-auth",
        "cis-k8s-1.2.2-api-server-basic-auth",
        "cis-k8s-1.2.3-api-server-token-auth",
        "cis-k8s-1.2.4-api-server-kubelet-https",
        "cis-k8s-1.2.5-api-server-kubelet-client-cert",
        "cis-k8s-1.2.6-api-server-kubelet-client-key",
        "cis-k8s-1.2.7-api-server-etcd-ca",
        "cis-k8s-1.2.8-api-server-etcd-cert",
        "cis-k8s-1.2.9-api-server-etcd-key",
        "cis-k8s-5.1.1-pod-security-context",
        "cis-k8s-5.1.2-pod-service-account",
        "cis-k8s-5.1.3-pod-security-context-runasnonroot",
        "cis-k8s-5.1.4-pod-security-context-runasuser",
        "cis-k8s-5.2.1-pod-security-context-fsgroup",
        "cis-k8s-5.7.1-network-policy-default-deny"
      ]
    }
    NIST = {
      policies = [
        "nist-ac-2-account-management",
        "nist-ac-3-access-enforcement",
        "nist-ac-4-information-flow",
        "nist-au-2-audit-events",
        "nist-au-3-audit-content",
        "nist-ca-7-continuous-monitoring",
        "nist-cm-2-baseline-configuration",
        "nist-cm-6-configuration-settings",
        "nist-cm-7-least-functionality",
        "nist-ia-2-identification-authentication",
        "nist-ra-5-vulnerability-scanning",
        "nist-sc-7-boundary-protection",
        "nist-si-4-information-monitoring"
      ]
    }
    SOC2 = {
      policies = [
        "soc2-cc1-control-environment",
        "soc2-cc2-communication-information",
        "soc2-cc3-risk-assessment",
        "soc2-cc4-monitoring-activities",
        "soc2-cc5-control-activities",
        "soc2-cc6-logical-physical-access",
        "soc2-cc7-system-operations",
        "soc2-cc8-change-management"
      ]
    }
    "PCI-DSS" = {
      policies = [
        "pci-dss-1-firewall-configuration",
        "pci-dss-2-default-passwords",
        "pci-dss-3-cardholder-data-protection",
        "pci-dss-4-encryption-transmission",
        "pci-dss-5-antivirus-software",
        "pci-dss-6-secure-systems",
        "pci-dss-7-access-control",
        "pci-dss-8-unique-ids",
        "pci-dss-9-physical-access",
        "pci-dss-10-network-monitoring",
        "pci-dss-11-security-testing",
        "pci-dss-12-information-security"
      ]
    }
  }

  # Git repository configuration
  git_config = {
    infrastructure_repo = {
      name        = var.infrastructure_repo_name
      description = "Infrastructure as Code repository"
      visibility  = "private"
      topics      = ["infrastructure", "terraform", "kubernetes", "security"]
    }
    policies_repo = {
      name        = var.policies_repo_name
      description = "Policy as Code repository"
      visibility  = "private"
      topics      = ["policies", "opa", "gatekeeper", "compliance"]
    }
    applications_repo = {
      name        = var.applications_repo_name
      description = "Applications configuration repository"
      visibility  = "private"
      topics      = ["applications", "gitops", "kubernetes", "deployments"]
    }
  }
}

# =============================================================================
# GITOPS OPERATOR INSTALLATION
# =============================================================================

# Create GitOps namespace
resource "kubernetes_namespace" "gitops" {
  metadata {
    name = var.gitops_operator == "flux" ? local.gitops_config.flux.namespace : local.gitops_config.argocd.namespace
    labels = merge(local.common_labels, {
      "name" = var.gitops_operator == "flux" ? local.gitops_config.flux.namespace : local.gitops_config.argocd.namespace
      "gitops.operator" = var.gitops_operator
    })
    annotations = {
      "gitops.toolkit.fluxcd.io/prune" = "disabled"
    }
  }
}

# Flux CD Installation
resource "helm_release" "flux" {
  count = var.gitops_operator == "flux" ? 1 : 0

  name       = "flux2"
  repository = "https://fluxcd-community.github.io/helm-charts"
  chart      = "flux2"
  version    = var.flux_version
  namespace  = kubernetes_namespace.gitops.metadata[0].name

  values = [
    yamlencode({
      installCRDs = true

      sourceController = {
        create = true
        resources = {
          limits = {
            cpu    = "1000m"
            memory = "1Gi"
          }
          requests = {
            cpu    = "50m"
            memory = "64Mi"
          }
        }
        serviceAccount = {
          annotations = var.cloud_provider == "aws" ? {
            "eks.amazonaws.com/role-arn" = var.flux_role_arn
          } : {}
        }
      }

      helmController = {
        create = true
        resources = {
          limits = {
            cpu    = "1000m"
            memory = "1Gi"
          }
          requests = {
            cpu    = "100m"
            memory = "64Mi"
          }
        }
      }

      kustomizeController = {
        create = true
        resources = {
          limits = {
            cpu    = "1000m"
            memory = "1Gi"
          }
          requests = {
            cpu    = "100m"
            memory = "64Mi"
          }
        }
      }

      notificationController = {
        create = true
        resources = {
          limits = {
            cpu    = "1000m"
            memory = "1Gi"
          }
          requests = {
            cpu    = "100m"
            memory = "64Mi"
          }
        }
      }

      imageReflectionController = {
        create = var.enable_image_automation
        resources = {
          limits = {
            cpu    = "1000m"
            memory = "1Gi"
          }
          requests = {
            cpu    = "100m"
            memory = "64Mi"
          }
        }
      }

      imageAutomationController = {
        create = var.enable_image_automation
        resources = {
          limits = {
            cpu    = "1000m"
            memory = "1Gi"
          }
          requests = {
            cpu    = "100m"
            memory = "64Mi"
          }
        }
      }

      policies = {
        create = true
      }

      rbac = {
        create                = true
        createAggregation     = true
        impersonationEnabled  = false
      }

      logLevel = "info"
      watchAllNamespaces = true

      multitenancy = {
        enabled = var.enable_multitenancy
        defaultServiceAccount = "default"
      }

      prometheus = {
        podMonitor = {
          create = var.enable_prometheus_monitoring
        }
      }
    })
  ]
}

# ArgoCD Installation
resource "helm_release" "argocd" {
  count = var.gitops_operator == "argocd" ? 1 : 0

  name       = "argocd"
  repository = "https://argoproj.github.io/argo-helm"
  chart      = "argo-cd"
  version    = var.argocd_version
  namespace  = kubernetes_namespace.gitops.metadata[0].name

  values = [
    yamlencode({
      installCRDs = true

      global = {
        image = {
          repository = "quay.io/argoproj/argocd"
        }
        securityContext = {
          runAsNonRoot = true
          runAsUser    = 999
          fsGroup      = 999
        }
        networkPolicy = {
          create    = true
          defaultDenyIngress = true
        }
      }

      controller = {
        replicas = var.environment == "prod" ? 2 : 1
        resources = {
          limits = {
            cpu    = "2000m"
            memory = "2Gi"
          }
          requests = {
            cpu    = "250m"
            memory = "1Gi"
          }
        }
        serviceAccount = {
          annotations = var.cloud_provider == "aws" ? {
            "eks.amazonaws.com/role-arn" = var.argocd_role_arn
          } : {}
        }
        metrics = {
          enabled = var.enable_prometheus_monitoring
          service = {
            servicePort = 8082
          }
        }
      }

      server = {
        replicas = var.environment == "prod" ? 2 : 1
        resources = {
          limits = {
            cpu    = "500m"
            memory = "256Mi"
          }
          requests = {
            cpu    = "50m"
            memory = "64Mi"
          }
        }
        config = {
          "application.instanceLabelKey" = "argocd.argoproj.io/instance"
          "server.rbac.log.enforce.enable" = "true"
          "policy.default" = "role:readonly"
          "policy.csv" = <<-CSV
            p, role:admin, applications, *, */*, allow
            p, role:admin, clusters, *, *, allow
            p, role:admin, repositories, *, *, allow
            p, role:readonly, applications, get, */*, allow
            p, role:readonly, clusters, get, *, allow
            p, role:readonly, repositories, get, *, allow
            g, argocd-admins, role:admin
          CSV
        }
        ingress = {
          enabled = var.enable_ingress
          ingressClassName = var.ingress_class_name
          annotations = {
            "nginx.ingress.kubernetes.io/ssl-redirect" = "true"
            "nginx.ingress.kubernetes.io/backend-protocol" = "GRPC"
          }
          hosts = var.argocd_hostname != "" ? [var.argocd_hostname] : []
          tls = var.argocd_hostname != "" ? [
            {
              secretName = "argocd-server-tls"
              hosts      = [var.argocd_hostname]
            }
          ] : []
        }
        metrics = {
          enabled = var.enable_prometheus_monitoring
          service = {
            servicePort = 8083
          }
        }
      }

      repoServer = {
        replicas = var.environment == "prod" ? 2 : 1
        resources = {
          limits = {
            cpu    = "1000m"
            memory = "1Gi"
          }
          requests = {
            cpu    = "10m"
            memory = "64Mi"
          }
        }
        metrics = {
          enabled = var.enable_prometheus_monitoring
          service = {
            servicePort = 8084
          }
        }
      }

      applicationSet = {
        enabled = var.enable_applicationset
        replicas = 1
        resources = {
          limits = {
            cpu    = "500m"
            memory = "512Mi"
          }
          requests = {
            cpu    = "250m"
            memory = "256Mi"
          }
        }
        metrics = {
          enabled = var.enable_prometheus_monitoring
          service = {
            servicePort = 8080
          }
        }
      }

      notifications = {
        enabled = var.enable_notifications
        argocdUrl = var.argocd_hostname != "" ? "https://${var.argocd_hostname}" : ""
        secret = {
          create = true
          items = {
            slack-token = var.slack_webhook_url
          }
        }
        cm = {
          create = true
        }
        templates = {
          "template.app-deployed" = {
            message = "Application {{.app.metadata.name}} is now running new version."
            slack = {
              attachments = jsonencode([
                {
                  title = "{{.app.metadata.name}}"
                  title_link = "{{.context.argocdUrl}}/applications/{{.app.metadata.name}}"
                  color = "#18be52"
                  fields = [
                    {
                      title = "Sync Status"
                      value = "{{.app.status.sync.status}}"
                      short = true
                    },
                    {
                      title = "Repository"
                      value = "{{.app.spec.source.repoURL}}"
                      short = true
                    }
                  ]
                }
              ])
            }
          }
        }
        triggers = {
          "trigger.on-deployed" = [
            {
              oncePer = "app.status.sync.revision"
              send = ["app-deployed"]
              when = "app.status.operationState.phase in ['Succeeded'] and app.status.health.status == 'Healthy'"
            }
          ]
        }
        subscriptions = [
          {
            recipients = ["slack:general"]
            triggers   = ["on-deployed"]
          }
        ]
      }

      dex = {
        enabled = var.enable_sso
      }

      redis = {
        enabled = true
        resources = {
          limits = {
            cpu    = "200m"
            memory = "128Mi"
          }
          requests = {
            cpu    = "100m"
            memory = "64Mi"
          }
        }
      }
    })
  ]
}

# =============================================================================
# POLICY ENGINE INSTALLATION
# =============================================================================

# OPA Gatekeeper for policy enforcement
resource "helm_release" "gatekeeper" {
  count = contains(var.policy_engines, "gatekeeper") ? 1 : 0

  name       = "gatekeeper"
  repository = "https://open-policy-agent.github.io/gatekeeper/charts"
  chart      = "gatekeeper"
  version    = var.gatekeeper_version
  namespace  = "gatekeeper-system"

  create_namespace = true

  values = [
    yamlencode({
      replicas = var.environment == "prod" ? 3 : 2

      image = {
        repository = "openpolicyagent/gatekeeper"
        pullPolicy = "Always"
      }

      auditInterval = 60
      constraintViolationsLimit = 20
      auditFromCache = false

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

      nodeSelector = {
        "kubernetes.io/os" = "linux"
      }

      controllerManager = {
        exemptNamespaces = ["gatekeeper-system", "kube-system", "kube-public", kubernetes_namespace.gitops.metadata[0].name]
        logLevel = "INFO"
        auditChunkSize = 500
        logDenies = false
        emitAdmissionEvents = true
        emitAuditEvents = true
        auditMatchKindOnly = false
        disableValidatingAdmissionWebhook = false
        validatingAdmissionWebhook = {
          exemptNamespacesLabels = ["admission.gatekeeper.sh/ignore"]
          skipValidationForNamespaces = ["gatekeeper-system", "kube-system"]
        }
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
        writeToRAMDisk = false
        auditChunkSize = 500
      }

      violations = {
        allowedUsers = []
      }

      webhook = {
        failurePolicy = "Fail"
        namespaceSelector = {
          matchExpressions = [
            {
              key      = "admission.gatekeeper.sh/ignore"
              operator = "DoesNotExist"
            }
          ]
        }
      }

      disableValidatingAdmissionWebhook = false
      logLevel = "INFO"

      enableDeleteOperations = false
      enableExternalData = false
      enableGeneratorResourceExpansion = true
      maxServingThreads = -1

      mutatingWebhook = {
        enabled = false
      }
    })
  ]
}

# Kyverno for policy management
resource "helm_release" "kyverno" {
  count = contains(var.policy_engines, "kyverno") ? 1 : 0

  name       = "kyverno"
  repository = "https://kyverno.github.io/kyverno"
  chart      = "kyverno"
  version    = var.kyverno_version
  namespace  = "kyverno"

  create_namespace = true

  values = [
    yamlencode({
      installCRDs = true

      replicaCount = var.environment == "prod" ? 3 : 2

      image = {
        repository = "ghcr.io/kyverno/kyverno"
        pullPolicy = "Always"
      }

      initImage = {
        repository = "ghcr.io/kyverno/kyvernopre"
      }

      resources = {
        limits = {
          memory = "384Mi"
          cpu    = "100m"
        }
        requests = {
          memory = "128Mi"
          cpu    = "100m"
        }
      }

      securityContext = {
        runAsNonRoot = true
        runAsUser    = 10001
        fsGroup      = 10001
        seccompProfile = {
          type = "RuntimeDefault"
        }
      }

      rbac = {
        create = true
        serviceAccount = {
          create = true
          name   = "kyverno"
        }
      }

      config = {
        excludeGroups = [
          "system:nodes"
        ]
        excludeRoles = [
          "system:node-proxier"
        ]
        excludeUsers = [
          "system:node"
        ]
        excludeNamespaces = [
          "kube-system",
          "kube-public",
          "kube-node-lease",
          "kyverno",
          kubernetes_namespace.gitops.metadata[0].name
        ]
        resourceFilters = [
          "[Event,*,*]",
          "[*,kube-system,*]",
          "[*,kube-public,*]",
          "[*,kube-node-lease,*]",
          "[Node,*,*]",
          "[APIService,*,*]",
          "[TokenReview,*,*]",
          "[SubjectAccessReview,*,*]",
          "[SelfSubjectAccessReview,*,*]",
          "[Binding,*,*]",
          "[ReplicaSet,*,*]",
          "[AdmissionReport,*,*]",
          "[ClusterAdmissionReport,*,*]",
          "[BackgroundScanReport,*,*]",
          "[ClusterBackgroundScanReport,*,*]"
        ]
        webhooks = [
          {
            namespaceSelector = {
              matchExpressions = [
                {
                  key      = "name"
                  operator = "NotIn"
                  values   = ["kyverno", "kube-system", "kube-public"]
                }
              ]
            }
          }
        ]
      }

      metrics = {
        enabled = var.enable_prometheus_monitoring
      }

      backgroundController = {
        enabled = true
        resources = {
          limits = {
            memory = "128Mi"
            cpu    = "100m"
          }
          requests = {
            memory = "64Mi"
            cpu    = "100m"
          }
        }
      }

      cleanupController = {
        enabled = true
        resources = {
          limits = {
            memory = "128Mi"
            cpu    = "100m"
          }
          requests = {
            memory = "64Mi"
            cpu    = "100m"
          }
        }
      }

      reportsController = {
        enabled = true
        resources = {
          limits = {
            memory = "128Mi"
            cpu    = "100m"
          }
          requests = {
            memory = "64Mi"
            cpu    = "100m"
          }
        }
      }
    })
  ]
}

# =============================================================================
# GIT REPOSITORY CONFIGURATION
# =============================================================================

# GitHub repositories
resource "github_repository" "infrastructure" {
  count = var.git_provider == "github" ? 1 : 0

  name         = local.git_config.infrastructure_repo.name
  description  = local.git_config.infrastructure_repo.description
  visibility   = local.git_config.infrastructure_repo.visibility
  topics       = local.git_config.infrastructure_repo.topics

  has_issues   = true
  has_wiki     = false
  has_projects = false

  delete_branch_on_merge = true
  vulnerability_alerts   = true

  security_and_analysis {
    secret_scanning {
      status = "enabled"
    }
    secret_scanning_push_protection {
      status = "enabled"
    }
  }

  template {
    owner      = var.template_repository_owner
    repository = var.template_repository_name
  }
}

resource "github_repository" "policies" {
  count = var.git_provider == "github" ? 1 : 0

  name         = local.git_config.policies_repo.name
  description  = local.git_config.policies_repo.description
  visibility   = local.git_config.policies_repo.visibility
  topics       = local.git_config.policies_repo.topics

  has_issues   = true
  has_wiki     = false
  has_projects = false

  delete_branch_on_merge = true
  vulnerability_alerts   = true

  security_and_analysis {
    secret_scanning {
      status = "enabled"
    }
    secret_scanning_push_protection {
      status = "enabled"
    }
  }
}

resource "github_repository" "applications" {
  count = var.git_provider == "github" ? 1 : 0

  name         = local.git_config.applications_repo.name
  description  = local.git_config.applications_repo.description
  visibility   = local.git_config.applications_repo.visibility
  topics       = local.git_config.applications_repo.topics

  has_issues   = true
  has_wiki     = false
  has_projects = false

  delete_branch_on_merge = true
  vulnerability_alerts   = true

  security_and_analysis {
    secret_scanning {
      status = "enabled"
    }
    secret_scanning_push_protection {
      status = "enabled"
    }
  }
}

# Branch protection rules
resource "github_branch_protection" "infrastructure_main" {
  count = var.git_provider == "github" ? 1 : 0

  repository_id = github_repository.infrastructure[0].node_id
  pattern       = "main"

  required_status_checks {
    strict   = true
    contexts = ["ci/validate", "ci/security-scan", "ci/compliance-check"]
  }

  required_pull_request_reviews {
    required_approving_review_count = var.environment == "prod" ? 2 : 1
    dismiss_stale_reviews           = true
    restrict_dismissals             = true
    dismissal_restrictions          = var.admin_users
  }

  enforce_admins = true
  allows_deletions = false
  allows_force_pushes = false

  restrict_pushes {
    push_allowances = var.admin_users
  }
}

# GitLab repositories (alternative to GitHub)
resource "gitlab_project" "infrastructure" {
  count = var.git_provider == "gitlab" ? 1 : 0

  name         = local.git_config.infrastructure_repo.name
  description  = local.git_config.infrastructure_repo.description
  visibility_level = "private"

  issues_enabled         = true
  wiki_enabled          = false
  snippets_enabled      = false
  container_registry_enabled = true

  push_rules {
    commit_committer_check = true
    reject_unsigned_commits = true
  }

  default_branch = "main"

  topics = local.git_config.infrastructure_repo.topics
}

# =============================================================================
# GITOPS SOURCE CONFIGURATION
# =============================================================================

# Flux Git Repository sources
resource "kubectl_manifest" "flux_infrastructure_source" {
  count = var.gitops_operator == "flux" ? 1 : 0

  yaml_body = yamlencode({
    apiVersion = "source.toolkit.fluxcd.io/v1"
    kind       = "GitRepository"
    metadata = {
      name      = "infrastructure"
      namespace = kubernetes_namespace.gitops.metadata[0].name
      labels    = local.common_labels
    }
    spec = {
      interval = var.sync_interval
      ref = {
        branch = var.git_branch
      }
      url = var.git_provider == "github" ? github_repository.infrastructure[0].clone_url : gitlab_project.infrastructure[0].http_url_to_repo
      secretRef = {
        name = "git-credentials"
      }
      verify = var.enable_git_signature_verification ? {
        mode = "head"
        secretRef = {
          name = "git-gpg-keys"
        }
      } : null
    }
  })

  depends_on = [helm_release.flux]
}

resource "kubectl_manifest" "flux_policies_source" {
  count = var.gitops_operator == "flux" ? 1 : 0

  yaml_body = yamlencode({
    apiVersion = "source.toolkit.fluxcd.io/v1"
    kind       = "GitRepository"
    metadata = {
      name      = "policies"
      namespace = kubernetes_namespace.gitops.metadata[0].name
      labels    = local.common_labels
    }
    spec = {
      interval = var.sync_interval
      ref = {
        branch = var.git_branch
      }
      url = var.git_provider == "github" ? github_repository.policies[0].clone_url : gitlab_project.infrastructure[0].http_url_to_repo
      secretRef = {
        name = "git-credentials"
      }
    }
  })

  depends_on = [helm_release.flux]
}

# Flux Kustomization for infrastructure
resource "kubectl_manifest" "flux_infrastructure_kustomization" {
  count = var.gitops_operator == "flux" ? 1 : 0

  yaml_body = yamlencode({
    apiVersion = "kustomize.toolkit.fluxcd.io/v1"
    kind       = "Kustomization"
    metadata = {
      name      = "infrastructure"
      namespace = kubernetes_namespace.gitops.metadata[0].name
      labels    = local.common_labels
    }
    spec = {
      interval = var.sync_interval
      path     = "./clusters/${var.cluster_name}"
      prune    = true
      sourceRef = {
        kind = "GitRepository"
        name = "infrastructure"
      }
      validation = "client"
      timeout    = "10m"
      healthChecks = [
        {
          apiVersion = "apps/v1"
          kind       = "Deployment"
          name       = "*"
          namespace  = "default"
        }
      ]
      dependsOn = [
        {
          name = "policies"
        }
      ]
    }
  })

  depends_on = [kubectl_manifest.flux_infrastructure_source]
}

# ArgoCD Application for infrastructure
resource "kubectl_manifest" "argocd_infrastructure_app" {
  count = var.gitops_operator == "argocd" ? 1 : 0

  yaml_body = yamlencode({
    apiVersion = "argoproj.io/v1alpha1"
    kind       = "Application"
    metadata = {
      name      = "infrastructure"
      namespace = kubernetes_namespace.gitops.metadata[0].name
      labels    = local.common_labels
      finalizers = ["resources-finalizer.argocd.argoproj.io"]
    }
    spec = {
      project = "default"
      source = {
        repoURL        = var.git_provider == "github" ? github_repository.infrastructure[0].clone_url : gitlab_project.infrastructure[0].http_url_to_repo
        targetRevision = var.git_branch
        path           = "clusters/${var.cluster_name}"
        kustomize = {
          buildOptions = "--enable-alpha-plugins"
        }
      }
      destination = {
        server    = "https://kubernetes.default.svc"
        namespace = "default"
      }
      syncPolicy = {
        automated = {
          prune    = true
          selfHeal = var.enable_auto_sync
        }
        syncOptions = [
          "CreateNamespace=true",
          "PrunePropagationPolicy=foreground",
          "PruneLast=true"
        ]
        retry = {
          limit = 5
          backoff = {
            duration    = "5s"
            factor      = 2
            maxDuration = "3m"
          }
        }
      }
      revisionHistoryLimit = 10
    }
  })

  depends_on = [helm_release.argocd]
}

# =============================================================================
# COMPLIANCE POLICIES DEPLOYMENT
# =============================================================================

# Deploy compliance policies for each framework
resource "kubectl_manifest" "compliance_policies" {
  for_each = var.gitops_operator == "flux" && contains(var.policy_engines, "gatekeeper") ? {
    for framework in var.compliance_frameworks :
    framework => {
      policies = local.compliance_policies[framework].policies
    }
  } : {}

  yaml_body = yamlencode({
    apiVersion = "kustomize.toolkit.fluxcd.io/v1"
    kind       = "Kustomization"
    metadata = {
      name      = "policies-${lower(each.key)}"
      namespace = kubernetes_namespace.gitops.metadata[0].name
      labels    = local.common_labels
    }
    spec = {
      interval = var.sync_interval
      path     = "./policies/${lower(each.key)}"
      prune    = true
      sourceRef = {
        kind = "GitRepository"
        name = "policies"
      }
      validation = "client"
      timeout    = "5m"
      healthChecks = [
        {
          apiVersion = "templates.gatekeeper.sh/v1beta1"
          kind       = "ConstraintTemplate"
          name       = "*"
          namespace  = ""
        }
      ]
      postBuild = {
        substitute = {
          cluster_name = var.cluster_name
          environment  = var.environment
        }
      }
    }
  })

  depends_on = [kubectl_manifest.flux_policies_source, helm_release.gatekeeper]
}

# =============================================================================
# POLICY MONITORING AND ALERTING
# =============================================================================

# Policy violations monitoring
resource "kubectl_manifest" "policy_violations_alert" {
  count = var.enable_prometheus_monitoring && var.enable_policy_alerts ? 1 : 0

  yaml_body = yamlencode({
    apiVersion = "monitoring.coreos.com/v1"
    kind       = "PrometheusRule"
    metadata = {
      name      = "policy-violations"
      namespace = kubernetes_namespace.gitops.metadata[0].name
      labels    = local.common_labels
    }
    spec = {
      groups = [
        {
          name = "policy.violations"
          rules = [
            {
              alert = "PolicyViolationHigh"
              expr  = "increase(gatekeeper_violations_total[5m]) > 10"
              for   = "1m"
              labels = {
                severity = "warning"
              }
              annotations = {
                summary     = "High number of policy violations detected"
                description = "{{ $value }} policy violations in the last 5 minutes"
              }
            },
            {
              alert = "PolicyViolationCritical"
              expr  = "increase(gatekeeper_violations_total{enforcement_action=\"deny\"}[5m]) > 5"
              for   = "30s"
              labels = {
                severity = "critical"
              }
              annotations = {
                summary     = "Critical policy violations blocking deployments"
                description = "{{ $value }} blocking policy violations in the last 5 minutes"
              }
            }
          ]
        }
      ]
    }
  })
}

# =============================================================================
# CONTINUOUS COMPLIANCE MONITORING
# =============================================================================

# Compliance scan CronJob
resource "kubectl_manifest" "compliance_scan_cronjob" {
  count = var.enable_compliance_scanning ? 1 : 0

  yaml_body = yamlencode({
    apiVersion = "batch/v1"
    kind       = "CronJob"
    metadata = {
      name      = "compliance-scan"
      namespace = kubernetes_namespace.gitops.metadata[0].name
      labels    = local.common_labels
    }
    spec = {
      schedule = var.compliance_scan_schedule
      jobTemplate = {
        spec = {
          template = {
            spec = {
              serviceAccountName = "compliance-scanner"
              restartPolicy      = "OnFailure"
              securityContext = {
                runAsNonRoot = true
                runAsUser    = 1000
                fsGroup      = 1000
              }
              containers = [
                {
                  name  = "compliance-scanner"
                  image = "aquasec/trivy:latest"
                  command = ["/bin/sh"]
                  args = [
                    "-c",
                    "trivy k8s --report summary cluster --compliance ${join(",", var.compliance_frameworks)}"
                  ]
                  resources = {
                    limits = {
                      cpu    = "500m"
                      memory = "512Mi"
                    }
                    requests = {
                      cpu    = "100m"
                      memory = "128Mi"
                    }
                  }
                  securityContext = {
                    allowPrivilegeEscalation = false
                    readOnlyRootFilesystem   = true
                    runAsNonRoot             = true
                    capabilities = {
                      drop = ["ALL"]
                    }
                  }
                  volumeMounts = [
                    {
                      name      = "tmp"
                      mountPath = "/tmp"
                    }
                  ]
                }
              ]
              volumes = [
                {
                  name = "tmp"
                  emptyDir = {}
                }
              ]
            }
          }
        }
      }
    }
  })
}

# Service account for compliance scanning
resource "kubernetes_service_account" "compliance_scanner" {
  count = var.enable_compliance_scanning ? 1 : 0

  metadata {
    name      = "compliance-scanner"
    namespace = kubernetes_namespace.gitops.metadata[0].name
    labels    = local.common_labels
  }

  automount_service_account_token = true
}

resource "kubernetes_cluster_role" "compliance_scanner" {
  count = var.enable_compliance_scanning ? 1 : 0

  metadata {
    name   = "compliance-scanner"
    labels = local.common_labels
  }

  rule {
    api_groups = [""]
    resources  = ["pods", "services", "configmaps", "secrets"]
    verbs      = ["get", "list"]
  }

  rule {
    api_groups = ["apps"]
    resources  = ["deployments", "daemonsets", "statefulsets", "replicasets"]
    verbs      = ["get", "list"]
  }

  rule {
    api_groups = ["networking.k8s.io"]
    resources  = ["networkpolicies", "ingresses"]
    verbs      = ["get", "list"]
  }

  rule {
    api_groups = ["policy"]
    resources  = ["podsecuritypolicies"]
    verbs      = ["get", "list"]
  }

  rule {
    api_groups = ["rbac.authorization.k8s.io"]
    resources  = ["roles", "rolebindings", "clusterroles", "clusterrolebindings"]
    verbs      = ["get", "list"]
  }
}

resource "kubernetes_cluster_role_binding" "compliance_scanner" {
  count = var.enable_compliance_scanning ? 1 : 0

  metadata {
    name   = "compliance-scanner"
    labels = local.common_labels
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = kubernetes_cluster_role.compliance_scanner[0].metadata[0].name
  }

  subject {
    kind      = "ServiceAccount"
    name      = kubernetes_service_account.compliance_scanner[0].metadata[0].name
    namespace = kubernetes_namespace.gitops.metadata[0].name
  }
}

# =============================================================================
# SECRETS MANAGEMENT FOR GITOPS
# =============================================================================

# Git credentials secret
resource "kubernetes_secret" "git_credentials" {
  metadata {
    name      = "git-credentials"
    namespace = kubernetes_namespace.gitops.metadata[0].name
    labels    = local.common_labels
  }

  type = "Opaque"

  data = {
    username = var.git_username
    password = var.git_token
  }
}

# GPG keys for git signature verification
resource "kubernetes_secret" "git_gpg_keys" {
  count = var.enable_git_signature_verification ? 1 : 0

  metadata {
    name      = "git-gpg-keys"
    namespace = kubernetes_namespace.gitops.metadata[0].name
    labels    = local.common_labels
  }

  type = "Opaque"

  data = {
    "git-gpg-keys" = var.git_gpg_public_key
  }
}

# =============================================================================
# WEBHOOK CONFIGURATION
# =============================================================================

# GitHub webhook for GitOps automation
resource "github_repository_webhook" "gitops_webhook" {
  count = var.git_provider == "github" && var.enable_webhooks ? 1 : 0

  repository = github_repository.infrastructure[0].name

  configuration {
    url          = var.webhook_url
    content_type = "json"
    insecure_ssl = false
    secret       = var.webhook_secret
  }

  active = true

  events = ["push", "pull_request", "release"]
}