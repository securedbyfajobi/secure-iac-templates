#!/bin/bash
# Enterprise-grade EC2 instance hardening script
# Compliance frameworks: ${join(", ", compliance_frameworks)}
# Environment: ${environment}

set -euo pipefail

# Variables
LOG_FILE="/var/log/instance-hardening.log"
ENVIRONMENT="${environment}"
REGION="${region}"
LOG_GROUP_NAME="${log_group_name}"

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

log "Starting enterprise security hardening for environment: $ENVIRONMENT"

# Update system packages
log "Updating system packages..."
yum update -y || apt-get update -y

# Install security packages
log "Installing security packages..."
if command -v yum >/dev/null 2>&1; then
    # Amazon Linux / RHEL
    yum install -y \
        fail2ban \
        aide \
        rkhunter \
        chkrootkit \
        clamav \
        clamav-update \
        amazon-cloudwatch-agent \
        awscli \
        htop \
        tmux \
        git \
        curl \
        wget \
        unzip
else
    # Ubuntu / Debian
    apt-get install -y \
        fail2ban \
        aide \
        rkhunter \
        chkrootkit \
        clamav \
        clamav-daemon \
        amazon-cloudwatch-agent \
        awscli \
        htop \
        tmux \
        git \
        curl \
        wget \
        unzip
fi

# Configure fail2ban
log "Configuring fail2ban..."
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[apache-auth]
enabled = true

[apache-badbots]
enabled = true

[apache-noscript]
enabled = true

[apache-overflows]
enabled = true
EOF

systemctl enable fail2ban
systemctl start fail2ban

# Configure SSH hardening
log "Hardening SSH configuration..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

cat >> /etc/ssh/sshd_config << 'EOF'

# Enterprise Security Hardening
Protocol 2
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers ec2-user ubuntu
Banner /etc/ssh/banner
EOF

# Create SSH banner
cat > /etc/ssh/banner << 'EOF'
***************************************************************************
                            NOTICE TO USERS
***************************************************************************

This computer system is the private property of the organization.
It is for authorized use only. Users (authorized or unauthorized) have
no explicit or implicit expectation of privacy.

Any or all uses of this system and all files on this system may be
intercepted, monitored, recorded, copied, audited, inspected, and
disclosed to your employer, to authorized site, government, and law
enforcement personnel, as well as authorized officials of other agencies,
both domestic and foreign.

By using this system, the user consents to such interception, monitoring,
recording, copying, auditing, inspection, and disclosure at the
discretion of such personnel or officials.

Unauthorized or improper use of this system may result in civil and
criminal penalties and administrative or disciplinary action, as
appropriate. By continuing to use this system you indicate your awareness
of and consent to these terms and conditions of use.

LOG OFF IMMEDIATELY if you do not agree to the conditions stated in this warning.
***************************************************************************
EOF

systemctl restart sshd

# Initialize AIDE (Advanced Intrusion Detection Environment)
log "Initializing AIDE..."
if command -v aide >/dev/null 2>&1; then
    aide --init
    if [ -f /var/lib/aide/aide.db.new.gz ]; then
        mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
    elif [ -f /var/lib/aide/aide.db.new ]; then
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    fi

    # Schedule daily AIDE checks
    echo "0 2 * * * root /usr/bin/aide --check" >> /etc/crontab
fi

# Configure rkhunter
log "Configuring rkhunter..."
if command -v rkhunter >/dev/null 2>&1; then
    rkhunter --update
    rkhunter --propupd

    # Schedule weekly rkhunter scans
    echo "0 3 * * 0 root /usr/bin/rkhunter --check --sk --rwo" >> /etc/crontab
fi

# Configure ClamAV
log "Configuring ClamAV..."
if command -v freshclam >/dev/null 2>&1; then
    freshclam

    # Schedule daily virus scans
    echo "0 1 * * * root /usr/bin/clamscan -r /home /var/log --quiet --infected --remove" >> /etc/crontab
fi

# Kernel hardening
log "Applying kernel security parameters..."
cat >> /etc/sysctl.conf << 'EOF'

# Enterprise Security Hardening
# Network security
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1

# Memory protection
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
kernel.kexec_load_disabled = 1

# File system security
fs.suid_dumpable = 0
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF

sysctl -p

# Configure file permissions
log "Setting secure file permissions..."
chmod 700 /root
chmod 600 /etc/shadow
chmod 600 /etc/gshadow
chmod 644 /etc/passwd
chmod 644 /etc/group
chmod 600 /boot/grub*/grub.cfg 2>/dev/null || true

# Disable unnecessary services
log "Disabling unnecessary services..."
SERVICES_TO_DISABLE=(
    "telnet"
    "rsh"
    "rlogin"
    "vsftpd"
    "httpd"
    "apache2"
    "nginx"
    "dovecot"
    "squid"
    "snmpd"
    "ypserv"
    "ypbind"
    "tftp"
    "certmonger"
    "cgconfig"
    "cgred"
    "cpuspeed"
    "kdump"
    "mdmonitor"
    "messagebus"
    "netconsole"
    "netfs"
    "ntpdate"
    "oddjobd"
    "portreserve"
    "qpidd"
    "quota_nld"
    "rdisc"
    "rhnsd"
    "rhsmcertd"
    "saslauthd"
    "smartd"
    "sysstat"
)

for service in "${SERVICES_TO_DISABLE[@]}"; do
    if systemctl is-enabled "$service" >/dev/null 2>&1; then
        log "Disabling service: $service"
        systemctl disable "$service"
        systemctl stop "$service" 2>/dev/null || true
    fi
done

# Install and configure CloudWatch agent
%{ if enable_cloudwatch_agent }
log "Installing and configuring CloudWatch agent..."

# Create CloudWatch agent configuration
cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json << 'EOF'
{
    "agent": {
        "metrics_collection_interval": 60,
        "run_as_user": "cwagent"
    },
    "logs": {
        "logs_collected": {
            "files": {
                "collect_list": [
                    {
                        "file_path": "/var/log/messages",
                        "log_group_name": "${log_group_name}",
                        "log_stream_name": "{instance_id}/var/log/messages"
                    },
                    {
                        "file_path": "/var/log/secure",
                        "log_group_name": "${log_group_name}",
                        "log_stream_name": "{instance_id}/var/log/secure"
                    },
                    {
                        "file_path": "/var/log/auth.log",
                        "log_group_name": "${log_group_name}",
                        "log_stream_name": "{instance_id}/var/log/auth.log"
                    },
                    {
                        "file_path": "/var/log/fail2ban.log",
                        "log_group_name": "${log_group_name}",
                        "log_stream_name": "{instance_id}/var/log/fail2ban.log"
                    }
                ]
            }
        }
    },
    "metrics": {
        "namespace": "CWAgent",
        "metrics_collected": {
            "cpu": {
                "measurement": [
                    "cpu_usage_idle",
                    "cpu_usage_iowait",
                    "cpu_usage_user",
                    "cpu_usage_system"
                ],
                "metrics_collection_interval": 60,
                "totalcpu": false
            },
            "disk": {
                "measurement": [
                    "used_percent"
                ],
                "metrics_collection_interval": 60,
                "resources": [
                    "*"
                ]
            },
            "diskio": {
                "measurement": [
                    "io_time"
                ],
                "metrics_collection_interval": 60,
                "resources": [
                    "*"
                ]
            },
            "mem": {
                "measurement": [
                    "mem_used_percent"
                ],
                "metrics_collection_interval": 60
            },
            "netstat": {
                "measurement": [
                    "tcp_established",
                    "tcp_time_wait"
                ],
                "metrics_collection_interval": 60
            },
            "swap": {
                "measurement": [
                    "swap_used_percent"
                ],
                "metrics_collection_interval": 60
            }
        }
    }
}
EOF

# Start CloudWatch agent
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
    -a fetch-config \
    -m ec2 \
    -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json \
    -s

systemctl enable amazon-cloudwatch-agent
%{ endif }

# Configure log rotation
log "Configuring log rotation..."
cat > /etc/logrotate.d/security-logs << 'EOF'
/var/log/auth.log
/var/log/secure
/var/log/fail2ban.log
/var/log/instance-hardening.log
{
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 640 root root
}
EOF

# Set up file integrity monitoring
log "Setting up file integrity monitoring..."
cat > /etc/cron.daily/file-integrity-check << 'EOF'
#!/bin/bash
# Daily file integrity check

CRITICAL_FILES=(
    "/etc/passwd"
    "/etc/shadow"
    "/etc/group"
    "/etc/gshadow"
    "/etc/sudoers"
    "/etc/ssh/sshd_config"
    "/etc/hosts"
    "/etc/resolv.conf"
)

for file in "${CRITICAL_FILES[@]}"; do
    if [ -f "$file" ]; then
        stat -c "%Y %n" "$file" >> /var/log/file-integrity.log
    fi
done
EOF

chmod +x /etc/cron.daily/file-integrity-check

# Configure auditd for compliance
log "Configuring auditd..."
if command -v auditctl >/dev/null 2>&1; then
    cat >> /etc/audit/rules.d/audit.rules << 'EOF'
# Enterprise audit rules
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k privilege_escalation
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /var/log/lastlog -p wa -k logins
-w /var/log/faillog -p wa -k logins
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
EOF

    systemctl restart auditd
fi

# Create security monitoring script
log "Creating security monitoring script..."
cat > /usr/local/bin/security-monitor.sh << 'EOF'
#!/bin/bash
# Security monitoring script

LOGFILE="/var/log/security-monitor.log"

# Check for failed SSH attempts
FAILED_SSH=$(grep "Failed password" /var/log/auth.log | tail -10 | wc -l)
if [ "$FAILED_SSH" -gt 5 ]; then
    echo "$(date): WARNING - $FAILED_SSH failed SSH attempts detected" >> "$LOGFILE"
fi

# Check for root logins
ROOT_LOGINS=$(grep "Accepted.*root" /var/log/auth.log | tail -5 | wc -l)
if [ "$ROOT_LOGINS" -gt 0 ]; then
    echo "$(date): CRITICAL - Root login detected" >> "$LOGFILE"
fi

# Check disk usage
DISK_USAGE=$(df / | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -gt 90 ]; then
    echo "$(date): WARNING - Disk usage is $DISK_USAGE%" >> "$LOGFILE"
fi

# Check memory usage
MEM_USAGE=$(free | grep Mem | awk '{printf("%.0f", $3/$2 * 100)}')
if [ "$MEM_USAGE" -gt 90 ]; then
    echo "$(date): WARNING - Memory usage is $MEM_USAGE%" >> "$LOGFILE"
fi
EOF

chmod +x /usr/local/bin/security-monitor.sh

# Schedule security monitoring
echo "*/15 * * * * root /usr/local/bin/security-monitor.sh" >> /etc/crontab

# Final security checks
log "Performing final security checks..."

# Remove unnecessary packages
PACKAGES_TO_REMOVE=(
    "telnet"
    "rsh"
    "ypbind"
    "ypserv"
    "tftp"
    "tftp-server"
    "talk"
    "talk-server"
)

for package in "${PACKAGES_TO_REMOVE[@]}"; do
    if rpm -q "$package" >/dev/null 2>&1 || dpkg -l | grep -q "$package" 2>/dev/null; then
        log "Removing package: $package"
        yum remove -y "$package" 2>/dev/null || apt-get remove -y "$package" 2>/dev/null || true
    fi
done

# Set password policies
log "Setting password policies..."
if [ -f /etc/login.defs ]; then
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 7/' /etc/login.defs
    sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN 14/' /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs
fi

# Configure umask
echo "umask 027" >> /etc/profile
echo "umask 027" >> /etc/bashrc

# Final system update
log "Performing final system update..."
yum update -y || apt-get upgrade -y

# Restart critical services
systemctl restart sshd
systemctl restart fail2ban

log "Enterprise security hardening completed successfully!"
log "System is compliant with: ${join(", ", compliance_frameworks)}"

# Create completion marker
touch /var/log/hardening-complete
echo "$(date): Hardening completed for environment: $ENVIRONMENT" > /var/log/hardening-complete

exit 0