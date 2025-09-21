# Secure Infrastructure as Code Templates

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Terraform](https://img.shields.io/badge/Terraform-1.5%2B-purple.svg)](https://terraform.io/)
[![CloudFormation](https://img.shields.io/badge/CloudFormation-AWS-orange.svg)](https://aws.amazon.com/cloudformation/)
[![Ansible](https://img.shields.io/badge/Ansible-2.12%2B-red.svg)](https://ansible.com/)
[![Security](https://img.shields.io/badge/Security-First-green.svg)](https://owasp.org/)

## Overview

A comprehensive collection of security-hardened Infrastructure as Code (IaC) templates following industry best practices. This repository provides production-ready modules for Terraform, CloudFormation, and Ansible that implement security controls from the ground up.

## Features

- **Terraform Security Modules**: Hardened AWS, Azure, and GCP resources
- **CloudFormation Templates**: Security-first AWS infrastructure patterns
- **Ansible Playbooks**: System hardening and compliance automation
- **Policy-as-Code**: Validation rules and security policies
- **Compliance Frameworks**: CIS, NIST, and SOC 2 alignment
- **Zero Trust Architecture**: Network segmentation and access controls

## Repository Structure

```
secure-iac-templates/
├── terraform/
│   ├── modules/
│   │   ├── aws-secure-vpc/
│   │   ├── azure-secure-network/
│   │   ├── gcp-secure-project/
│   │   └── kubernetes-security/
│   ├── policies/
│   │   ├── security-groups.rego
│   │   ├── s3-bucket-policies.rego
│   │   └── iam-policies.rego
│   └── examples/
├── cloudformation/
│   ├── security-templates/
│   │   ├── secure-vpc.yaml
│   │   ├── waf-protection.yaml
│   │   └── logging-compliance.yaml
│   └── nested-stacks/
├── ansible/
│   ├── playbooks/
│   │   ├── linux-hardening.yml
│   │   ├── windows-hardening.yml
│   │   └── docker-security.yml
│   ├── roles/
│   │   ├── cis-hardening/
│   │   ├── security-baseline/
│   │   └── compliance-audit/
│   └── inventories/
├── policies/
│   ├── opa/
│   ├── sentinel/
│   └── conftest/
├── docs/
│   ├── terraform-security-guide.md
│   ├── cloudformation-best-practices.md
│   └── ansible-hardening-guide.md
└── scripts/
    ├── security-scan.sh
    ├── policy-validate.sh
    └── compliance-check.sh
```

## Quick Start

### Terraform Security Module
```hcl
module "secure_vpc" {
  source = "./terraform/modules/aws-secure-vpc"

  vpc_cidr                = "10.0.0.0/16"
  enable_flow_logs        = true
  enable_vpc_endpoints    = true
  encryption_at_rest      = true
  compliance_framework    = "SOC2"
}
```

### CloudFormation Secure Template
```bash
aws cloudformation create-stack \
  --stack-name secure-infrastructure \
  --template-body file://cloudformation/security-templates/secure-vpc.yaml \
  --parameters ParameterKey=Environment,ParameterValue=production
```

### Ansible Hardening Playbook
```bash
ansible-playbook -i inventories/production \
  playbooks/linux-hardening.yml \
  --extra-vars "compliance_level=high"
```

## Security Features

### Network Security
- VPC with private subnets and NAT gateways
- Security groups with least privilege access
- Network ACLs for additional layer protection
- VPC Flow Logs for monitoring

### Data Protection
- Encryption at rest and in transit
- KMS key management and rotation
- Secure parameter storage
- Database encryption

### Access Control
- IAM roles with minimal permissions
- Multi-factor authentication enforcement
- Service account security
- Resource-based policies

### Monitoring & Compliance
- CloudTrail logging
- Security hub integration
- Compliance dashboard
- Automated security scanning

## Compliance Frameworks

- **CIS Benchmarks**: Center for Internet Security controls
- **NIST CSF**: Cybersecurity Framework alignment
- **SOC 2**: Service Organization Control requirements
- **PCI DSS**: Payment Card Industry standards
- **ISO 27001**: Information security management

## Policy Validation

All templates include policy-as-code validation using:
- **Open Policy Agent (OPA)**: Rego policy language
- **HashiCorp Sentinel**: Policy enforcement
- **Conftest**: Kubernetes policy testing

## Usage Guidelines

1. **Review Security Settings**: Understand each template's security implications
2. **Customize for Environment**: Adapt templates to your specific requirements
3. **Test in Staging**: Validate templates in non-production environments
4. **Monitor Compliance**: Use included monitoring tools
5. **Regular Updates**: Keep templates updated with latest security practices

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/security-enhancement`)
3. Commit changes (`git commit -am 'Add new security control'`)
4. Push to branch (`git push origin feature/security-enhancement`)
5. Create Pull Request

## Security Reporting

Please report security vulnerabilities to: security@example.com

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- Documentation: [docs/](docs/)
- Issues: [GitHub Issues](../../issues)
- Security: [Security Policy](SECURITY.md)

---

**Disclaimer**: These templates are provided as-is. Always review and test in your environment before production deployment.