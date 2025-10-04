# HashiCorp Vault Policy for Enterprise Secrets Management
# Environment: ${environment}
# Prefix: ${name_prefix}

# Database secrets engine permissions
path "${name_prefix}-database/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Database configuration paths
path "${name_prefix}-database/config/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Database roles and connections
path "${name_prefix}-database/roles/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# KV v2 secrets engine for application secrets
path "${name_prefix}-kv/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "${name_prefix}-kv/data/*" {
  capabilities = ["create", "read", "update", "delete"]
}

path "${name_prefix}-kv/metadata/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# PKI secrets engine for certificate management
path "${name_prefix}-pki/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "${name_prefix}-pki/issue/*" {
  capabilities = ["create", "update"]
}

path "${name_prefix}-pki/sign/*" {
  capabilities = ["create", "update"]
}

# Transit secrets engine for encryption as a service
path "${name_prefix}-transit/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "${name_prefix}-transit/encrypt/*" {
  capabilities = ["create", "update"]
}

path "${name_prefix}-transit/decrypt/*" {
  capabilities = ["create", "update"]
}

# SSH secrets engine for dynamic SSH keys
path "${name_prefix}-ssh/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "${name_prefix}-ssh/sign/*" {
  capabilities = ["create", "update"]
}

# AWS secrets engine for dynamic AWS credentials
path "${name_prefix}-aws/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "${name_prefix}-aws/sts/*" {
  capabilities = ["create", "update"]
}

path "${name_prefix}-aws/creds/*" {
  capabilities = ["read"]
}

# Azure secrets engine for dynamic Azure credentials
path "${name_prefix}-azure/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "${name_prefix}-azure/creds/*" {
  capabilities = ["read"]
}

# GCP secrets engine for dynamic GCP credentials
path "${name_prefix}-gcp/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "${name_prefix}-gcp/token/*" {
  capabilities = ["read"]
}

path "${name_prefix}-gcp/key/*" {
  capabilities = ["create", "read"]
}

# Identity secrets engine for identity-based access
path "identity/*" {
  capabilities = ["read", "list"]
}

# System paths for health checks and capabilities
path "sys/capabilities-self" {
  capabilities = ["update"]
}

path "sys/health" {
  capabilities = ["read"]
}

path "sys/mounts" {
  capabilities = ["read"]
}

# Auth methods for authentication
path "auth/${name_prefix}-aws/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "auth/${name_prefix}-kubernetes/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "auth/${name_prefix}-ldap/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Audit and monitoring paths (read-only)
path "sys/audit" {
  capabilities = ["read", "list"]
}

path "sys/audit-hash/*" {
  capabilities = ["create"]
}

# Lease management
path "sys/leases/lookup" {
  capabilities = ["create", "update"]
}

path "sys/leases/renew" {
  capabilities = ["create", "update"]
}

path "sys/leases/revoke" {
  capabilities = ["create", "update"]
}

# Policy management (limited)
path "sys/policies/acl/${name_prefix}-*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Token management (self)
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}

path "auth/token/revoke-self" {
  capabilities = ["update"]
}

# Cubbyhole for temporary secret storage
path "cubbyhole/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Additional paths for specific compliance requirements

# SOC2 compliance paths
%{ if contains(split(",", compliance_frameworks), "SOC2") ~}
# SOC2 specific audit paths
path "sys/audit/${name_prefix}-soc2" {
  capabilities = ["read"]
}
%{ endif ~}

# PCI-DSS compliance paths
%{ if contains(split(",", compliance_frameworks), "PCI-DSS") ~}
# PCI-DSS specific paths with restricted access
path "${name_prefix}-pci/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
  allowed_parameters = {
    "encryption" = ["required"]
    "key_type" = ["rsa-2048", "rsa-4096", "ec-p256", "ec-p384"]
  }
}
%{ endif ~}

# HIPAA compliance paths
%{ if contains(split(",", compliance_frameworks), "HIPAA") ~}
# HIPAA specific paths with additional restrictions
path "${name_prefix}-hipaa/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
  required_parameters = ["encryption", "audit_trail"]
}
%{ endif ~}

# FIPS compliance paths
%{ if contains(split(",", compliance_frameworks), "FIPS") ~}
# FIPS 140-2 compliant paths
path "${name_prefix}-fips/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
  allowed_parameters = {
    "key_type" = ["aes256-gcm96", "rsa-4096", "ec-p384"]
    "hash_function" = ["sha256", "sha384", "sha512"]
  }
}
%{ endif ~}