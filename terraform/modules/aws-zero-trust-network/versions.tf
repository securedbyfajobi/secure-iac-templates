# Version constraints and provider requirements for enterprise-grade reliability

terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0, < 6.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = ">= 4.0, < 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.4, < 4.0"
    }
    time = {
      source  = "hashicorp/time"
      version = ">= 0.9, < 1.0"
    }
  }

  # Enterprise-grade state management
  experiments = [config_driven_move]
}

# Provider configuration with enterprise security defaults
provider "aws" {
  default_tags {
    tags = {
      Module             = "aws-zero-trust-network"
      Terraform          = "true"
      SecurityFramework  = "zero-trust"
      ComplianceRequired = "true"
      CreatedBy          = "terraform"
      LastModified       = timestamp()
    }
  }

  # Security best practices
  skip_region_validation      = false
  skip_credentials_validation = false
  skip_metadata_api_check     = false
}