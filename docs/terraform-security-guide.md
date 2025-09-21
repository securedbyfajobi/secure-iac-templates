# Terraform Security Guide

## Overview

This guide provides best practices for securing Terraform infrastructure deployments, focusing on preventing security misconfigurations and implementing defense-in-depth strategies.

## Security Best Practices

### 1. State File Security

```hcl
terraform {
  backend "s3" {
    bucket         = "terraform-state-secure-bucket"
    key            = "infrastructure/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-locks"

    # Enable versioning for state recovery
    versioning = true
  }
}
```

### 2. Provider Configuration

```hcl
provider "aws" {
  region = var.aws_region

  # Enforce encryption
  default_tags {
    tags = {
      Environment   = var.environment
      Project       = var.project_name
      SecurityLevel = "high"
      Compliance    = "required"
    }
  }
}
```

### 3. Resource Security Patterns

#### Secure VPC Configuration

```hcl
resource "aws_vpc" "secure_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.project_name}-secure-vpc"
  }
}

# Private subnets only
resource "aws_subnet" "private" {
  count             = length(var.private_subnet_cidrs)
  vpc_id            = aws_vpc.secure_vpc.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]

  # Never assign public IPs
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.project_name}-private-subnet-${count.index + 1}"
    Type = "Private"
  }
}
```

#### Secure S3 Bucket

```hcl
resource "aws_s3_bucket" "secure_bucket" {
  bucket = var.bucket_name
}

resource "aws_s3_bucket_encryption" "secure_bucket" {
  bucket = aws_s3_bucket.secure_bucket.id

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "AES256"
        kms_master_key_id = aws_kms_key.bucket_key.arn
      }
      bucket_key_enabled = true
    }
  }
}

resource "aws_s3_bucket_public_access_block" "secure_bucket" {
  bucket = aws_s3_bucket.secure_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "secure_bucket" {
  bucket = aws_s3_bucket.secure_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}
```

### 4. Security Groups Best Practices

```hcl
resource "aws_security_group" "web_sg" {
  name_prefix = "${var.project_name}-web-"
  vpc_id      = aws_vpc.secure_vpc.id

  # Minimal ingress rules
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Internal only
    description = "HTTPS from internal networks"
  }

  # Explicit egress rules
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS to internet"
  }

  tags = {
    Name = "${var.project_name}-web-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}
```

### 5. IAM Security

```hcl
data "aws_iam_policy_document" "assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]

    condition {
      test     = "StringEquals"
      variable = "aws:RequestedRegion"
      values   = [var.aws_region]
    }
  }
}

resource "aws_iam_role" "secure_role" {
  name               = "${var.project_name}-secure-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role.json

  tags = {
    Name = "${var.project_name}-secure-role"
  }
}

# Least privilege policy
data "aws_iam_policy_document" "secure_policy" {
  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject",
      "s3:PutObject"
    ]
    resources = [
      "${aws_s3_bucket.secure_bucket.arn}/*"
    ]
  }
}
```

## Security Validation

### 1. Pre-deployment Checks

```bash
# Run terraform plan with security analysis
terraform plan -out=tfplan
terraform show -json tfplan | jq > plan.json

# Validate with tfsec
tfsec .

# Check with Checkov
checkov -f plan.json
```

### 2. Policy Validation

```hcl
# Use OPA for policy validation
data "opa_policy" "security_policy" {
  policy = file("${path.module}/policies/security.rego")
  input  = data.terraform_remote_state.current.outputs
}
```

## Compliance Frameworks

### CIS Controls Implementation

- **CIS-2.1**: Maintain Inventory of Authorized Software
- **CIS-4.1**: Establish and Maintain a Secure Configuration Process
- **CIS-6.1**: Establish an Access Granting Process

### NIST Framework Alignment

- **ID.AM**: Asset Management
- **PR.AC**: Access Control
- **PR.DS**: Data Security
- **DE.CM**: Security Continuous Monitoring

## Monitoring and Alerting

```hcl
resource "aws_cloudwatch_log_group" "security_logs" {
  name              = "/aws/security/${var.project_name}"
  retention_in_days = 90

  kms_key_id = aws_kms_key.log_key.arn

  tags = {
    Name = "${var.project_name}-security-logs"
  }
}

resource "aws_cloudwatch_metric_alarm" "security_events" {
  alarm_name          = "${var.project_name}-security-events"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "SecurityEvents"
  namespace           = "Custom/Security"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "This metric monitors security events"
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}
```

## Security Testing

### Infrastructure Testing

```go
package test

import (
    "testing"
    "github.com/gruntwork-io/terratest/modules/terraform"
    "github.com/stretchr/testify/assert"
)

func TestSecureInfrastructure(t *testing.T) {
    terraformOptions := &terraform.Options{
        TerraformDir: "../",
        VarFiles:     []string{"test.tfvars"},
    }

    defer terraform.Destroy(t, terraformOptions)
    terraform.InitAndApply(t, terraformOptions)

    // Test S3 bucket encryption
    bucketName := terraform.Output(t, terraformOptions, "bucket_name")
    assert.NotEmpty(t, bucketName)

    // Additional security tests...
}
```

## Remediation Procedures

### Common Security Issues

1. **Unencrypted Resources**
   ```bash
   # Find unencrypted resources
   terraform state list | xargs -I {} terraform state show {} | grep -i encrypt
   ```

2. **Overprivileged IAM**
   ```bash
   # Analyze IAM policies
   aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::123456789012:role/role-name
   ```

3. **Public Resources**
   ```bash
   # Check for public resources
   aws ec2 describe-security-groups --query 'SecurityGroups[?IpPermissions[?IpRanges[?CidrIp==`0.0.0.0/0`]]]'
   ```

## References

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [AWS Security Best Practices](https://aws.amazon.com/security/security-resources/)
- [Terraform Security](https://learn.hashicorp.com/tutorials/terraform/security)