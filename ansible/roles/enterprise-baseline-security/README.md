# Enterprise Baseline Security Role

A comprehensive Ansible role for implementing enterprise-grade security baselines across Linux systems with support for multiple compliance frameworks including SOC 2, PCI-DSS, HIPAA, NIST, and CIS benchmarks.

## Features

### 🛡️ **Comprehensive Security Hardening**
- Operating system hardening with kernel parameter tuning
- SSH daemon hardening with modern cryptographic standards
- User and access management with strong password policies
- Network security configuration with firewall rules
- File system security and permission management

### ⚖️ **Multi-Framework Compliance**
- **SOC 2 Type II**: Trust service criteria implementation
- **PCI-DSS**: Payment card industry security standards
- **HIPAA**: Healthcare data protection requirements
- **NIST**: Cybersecurity framework controls
- **CIS**: Center for Internet Security benchmarks

### 📊 **Advanced Audit and Monitoring**
- Comprehensive auditd configuration with detailed rules
- Process accounting and session tracking
- File integrity monitoring with AIDE
- Enhanced logging with rsyslog and journald integration
- Real-time security event detection

### 🔒 **Access Control and Authentication**
- Multi-factor authentication support
- Privileged access management
- Account lockout and session timeout policies
- SSH key management and restrictions
- Sudo privilege escalation monitoring

### 🚨 **Intrusion Prevention and Detection**
- Fail2ban configuration for brute force protection
- Network anomaly detection
- Rootkit and malware scanning
- Security event correlation and alerting
- Automated incident response preparation

## Quick Start

### Basic Usage

```yaml
---
- hosts: all
  become: yes
  roles:
    - role: enterprise-baseline-security
      vars:
        baseline_security_compliance_level: "high"
        baseline_security_environment: "production"
        baseline_security_compliance_frameworks:
          - "CIS"
          - "SOC2"
```

### Advanced Configuration

```yaml
---
- hosts: production_servers
  become: yes
  roles:
    - role: enterprise-baseline-security
      vars:
        # Compliance and environment
        baseline_security_compliance_level: "critical"
        baseline_security_environment: "production"
        baseline_security_compliance_frameworks:
          - "SOC2"
          - "PCI-DSS"
          - "HIPAA"

        # SSH hardening
        baseline_security_ssh_hardening:
          disable_root_ssh: true
          password_authentication: false
          change_default_port: true
          custom_ssh_port: 2222
          allowed_groups: ["ssh-users", "admins"]

        # Enhanced password policy
        baseline_security_password_policy:
          min_length: 16
          max_age: 60
          complexity_check: true
          require_special_chars: true

        # Network security
        baseline_security_firewall:
          enable: true
          allowed_tcp_ports: [22, 80, 443, 8080]
          allowed_networks:
            - "10.0.0.0/8"
            - "172.16.0.0/12"

        # Monitoring and alerting
        baseline_security_monitoring:
          notification_email: "security@company.com"
          enable_logwatch: true
          alert_on_critical_events: true
```

## Role Variables

### Core Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `baseline_security_compliance_level` | `medium` | Security level: low, medium, high, critical |
| `baseline_security_environment` | `production` | Environment type: development, staging, production |
| `baseline_security_compliance_frameworks` | `["CIS"]` | List of compliance frameworks to apply |

### Security Hardening Options

| Variable | Default | Description |
|----------|---------|-------------|
| `baseline_security_os_hardening.disable_unused_services` | `true` | Remove unnecessary services |
| `baseline_security_os_hardening.configure_kernel_parameters` | `true` | Apply security kernel parameters |
| `baseline_security_user_management.enforce_password_policy` | `true` | Enforce strong password policies |
| `baseline_security_ssh_hardening.disable_root_ssh` | `true` | Disable SSH root login |

### Compliance Framework Settings

#### SOC 2 Configuration
```yaml
baseline_security_soc2:
  enhanced_logging: true
  access_reviews: true
  encryption_required: true
  backup_verification: true
```

#### PCI-DSS Configuration
```yaml
baseline_security_pci_dss:
  file_integrity_monitoring: true
  network_segmentation: true
  quarterly_vulnerability_scans: true
  log_retention_months: 12
```

#### HIPAA Configuration
```yaml
baseline_security_hipaa:
  encryption_at_rest: true
  access_controls: true
  audit_trail_required: true
  data_backup_required: true
```

### Password Policy Configuration

```yaml
baseline_security_password_policy:
  min_length: 14
  max_age: 90
  min_age: 7
  warning_age: 14
  remember_passwords: 12
  require_uppercase: true
  require_lowercase: true
  require_numbers: true
  require_special_chars: true
  complexity_check: true
  dictionary_check: true
```

### SSH Hardening Configuration

```yaml
baseline_security_ssh_hardening:
  disable_root_ssh: true
  password_authentication: false
  change_default_port: true
  custom_ssh_port: 2222
  allowed_users: []
  allowed_groups: ["ssh-users"]
  max_auth_tries: 3
  client_alive_interval: 300
  x11_forwarding: false
  tcp_forwarding: false
```

### Audit Configuration

```yaml
baseline_security_auditd_config:
  max_log_file: 50
  num_logs: 10
  space_left_action: "email"
  disk_full_action: "halt"
  log_format: "enriched"
```

### Network Security

```yaml
baseline_security_firewall:
  enable: true
  default_policy: "DROP"
  allowed_tcp_ports: [22, 80, 443]
  allowed_udp_ports: [123, 53]
  allowed_networks:
    - "10.0.0.0/8"
    - "172.16.0.0/12"
    - "192.168.0.0/16"
```

## Compliance Matrix

| Framework | Password Policy | Audit Logging | Access Control | Encryption | File Integrity |
|-----------|----------------|---------------|----------------|------------|-----------------|
| **CIS Level 1** | ✅ Basic | ✅ Standard | ✅ Basic | ⚠️ Optional | ⚠️ Optional |
| **CIS Level 2** | ✅ Enhanced | ✅ Detailed | ✅ Enhanced | ✅ Required | ✅ Required |
| **SOC 2** | ✅ Enhanced | ✅ Detailed | ✅ Enhanced | ✅ Required | ✅ Required |
| **PCI-DSS** | ✅ Strict | ✅ Comprehensive | ✅ Strict | ✅ Required | ✅ Required |
| **HIPAA** | ✅ Strict | ✅ Comprehensive | ✅ Strict | ✅ Required | ✅ Required |
| **NIST** | ✅ Enhanced | ✅ Detailed | ✅ Enhanced | ✅ Required | ✅ Required |

## Security Controls Implemented

### Access Controls
- Strong password policies with complexity requirements
- Account lockout after failed login attempts
- Session timeout and idle user termination
- Privileged access monitoring with sudo logging
- SSH key-based authentication with restrictions

### Audit and Monitoring
- Comprehensive auditd rules for system events
- File and directory access monitoring
- User and group modification tracking
- Network configuration change detection
- Privileged command execution logging

### Network Security
- Firewall configuration with default deny policy
- Disabled unnecessary network services
- IP forwarding and routing protections
- ICMP redirect prevention
- SYN flood protection with SYN cookies

### File System Security
- Secure mount options for critical file systems
- File integrity monitoring with AIDE
- Secure permissions on sensitive directories
- Core dump restrictions
- Temporary file security

### System Hardening
- Kernel parameter tuning for security
- Removal of unnecessary packages and services
- Compiler restriction in production environments
- USB and removable media restrictions
- Memory protection mechanisms (ASLR, NX bit)

## Directory Structure

```
enterprise-baseline-security/
├── defaults/
│   └── main.yml                    # Default variables
├── handlers/
│   └── main.yml                    # Service handlers
├── meta/
│   └── main.yml                    # Role metadata
├── tasks/
│   ├── main.yml                    # Main task orchestration
│   ├── packages.yml                # Package management
│   ├── users.yml                   # User management
│   ├── ssh.yml                     # SSH hardening
│   ├── network.yml                 # Network security
│   ├── kernel.yml                  # Kernel hardening
│   ├── audit.yml                   # Audit configuration
│   ├── filesystem.yml              # File system security
│   ├── aide.yml                    # File integrity monitoring
│   ├── fail2ban.yml               # Intrusion prevention
│   ├── services.yml               # Service hardening
│   ├── advanced.yml               # Advanced security features
│   ├── monitoring.yml             # System monitoring
│   ├── validation.yml             # Post-hardening validation
│   ├── reporting.yml              # Security reporting
│   ├── backup.yml                 # Configuration backup
│   ├── assessment.yml             # Security assessment
│   └── compliance/
│       ├── soc2.yml               # SOC 2 specific controls
│       ├── pci-dss.yml            # PCI-DSS specific controls
│       ├── hipaa.yml              # HIPAA specific controls
│       └── nist.yml               # NIST specific controls
├── templates/
│   ├── ssh_banner.j2              # SSH login banner
│   ├── audit.rules.j2             # Audit rules template
│   ├── 50unattended-upgrades.j2   # Auto-update configuration
│   ├── soc2-monitoring.sh.j2      # SOC 2 monitoring script
│   └── ...                        # Additional templates
└── README.md                      # This file
```

## Usage Examples

### Development Environment
```yaml
- hosts: dev_servers
  become: yes
  roles:
    - role: enterprise-baseline-security
      vars:
        baseline_security_compliance_level: "low"
        baseline_security_environment: "development"
        baseline_security_ssh_hardening:
          password_authentication: true
          disable_root_ssh: false
```

### Production Environment with PCI-DSS
```yaml
- hosts: payment_servers
  become: yes
  roles:
    - role: enterprise-baseline-security
      vars:
        baseline_security_compliance_level: "critical"
        baseline_security_environment: "production"
        baseline_security_compliance_frameworks:
          - "PCI-DSS"
          - "SOC2"
        baseline_security_ssh_hardening:
          password_authentication: false
          change_default_port: true
          custom_ssh_port: 2222
        baseline_security_monitoring:
          notification_email: "security-team@company.com"
          enable_logwatch: true
```

### Healthcare Environment with HIPAA
```yaml
- hosts: healthcare_servers
  become: yes
  roles:
    - role: enterprise-baseline-security
      vars:
        baseline_security_compliance_level: "critical"
        baseline_security_environment: "production"
        baseline_security_compliance_frameworks:
          - "HIPAA"
          - "NIST"
        baseline_security_password_policy:
          min_length: 16
          max_age: 60
          complexity_check: true
        baseline_security_advanced:
          enable_selinux: true
          disable_core_dumps: true
```

## Post-Installation

### Verification Commands

```bash
# Check audit system status
sudo auditctl -l
sudo systemctl status auditd

# Verify SSH configuration
sudo sshd -t
sudo systemctl status ssh

# Check firewall status
sudo ufw status verbose  # Ubuntu/Debian
sudo firewall-cmd --list-all  # RHEL/CentOS

# Review security logs
sudo tail -f /var/log/security-baseline/security-report.json
sudo lynis audit system
```

### Security Testing

```bash
# Run security audit tools
sudo aide --check
sudo rkhunter --check
sudo chkrootkit
sudo lynis audit system

# Test password policy
sudo chage -l username

# Verify file permissions
sudo find /etc -type f -perm /022 -ls
```

## Monitoring and Maintenance

### Log Files

| Log File | Purpose |
|----------|---------|
| `/var/log/security-baseline/` | Role execution logs |
| `/var/log/audit/audit.log` | System audit events |
| `/var/log/auth.log` | Authentication events |
| `/var/log/sudo.log` | Privileged command execution |
| `/var/log/fail2ban.log` | Intrusion prevention events |

### Scheduled Tasks

The role creates several cron jobs for ongoing security maintenance:

- **Daily**: File integrity checks (AIDE)
- **Weekly**: Security compliance reports
- **Monthly**: User access reviews
- **Continuous**: Security event monitoring

### Alerts and Notifications

Configure email notifications for critical security events:

```yaml
baseline_security_monitoring:
  notification_email: "security-alerts@company.com"
  smtp_server: "mail.company.com"
  smtp_port: 587
```

## Troubleshooting

### Common Issues

1. **SSH Access Lost After Hardening**
   ```bash
   # Use console access to restore SSH
   sudo systemctl status ssh
   sudo journalctl -u ssh
   # Check /etc/ssh/sshd_config for errors
   sudo sshd -t
   ```

2. **Audit Service Won't Start**
   ```bash
   sudo systemctl status auditd
   sudo auditctl -l
   # Check audit rules syntax
   sudo auditd -f
   ```

3. **Firewall Blocking Services**
   ```bash
   sudo ufw status verbose
   sudo ufw allow <port>/<protocol>
   ```

### Recovery Mode

If the system becomes inaccessible, use the backup configurations:

```bash
# Restore SSH configuration
sudo cp /etc/ssh/sshd_config.backup.* /etc/ssh/sshd_config

# Restore original audit configuration
sudo cp /etc/audit/auditd.conf.backup.* /etc/audit/auditd.conf
```

## Dependencies

### Required Packages
- `auditd` - System auditing
- `fail2ban` - Intrusion prevention
- `aide` - File integrity monitoring
- `rsyslog` - System logging
- `openssh-server` - SSH daemon

### Optional Packages
- `clamav` - Antivirus scanning
- `rkhunter` - Rootkit detection
- `lynis` - Security auditing
- `tripwire` - File integrity monitoring

## Contributing

1. Test changes in a development environment
2. Ensure compliance with security frameworks
3. Update documentation for new features
4. Validate role idempotency
5. Submit pull requests with detailed descriptions

## License

This role is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Support

For enterprise support and custom compliance requirements:
- 📧 Email: security-team@company.com
- 📖 Documentation: [Security Wiki](https://wiki.company.com/security)
- 🔧 Issues: [GitHub Issues](https://github.com/company/secure-iac-templates/issues)

---

**⚠️ Important**: This role makes significant security changes to systems. Test thoroughly in development environments before applying to production systems. Always maintain console access during initial deployments.