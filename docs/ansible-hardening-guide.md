# Ansible Security Hardening Guide

## Overview

This guide provides comprehensive security hardening practices using Ansible, focusing on system-level security configurations, compliance implementation, and automated security management.

## System Hardening Playbooks

### 1. Base System Security Hardening

```yaml
---
- name: Linux System Security Hardening
  hosts: all
  become: yes
  vars:
    security_level: "high"
    compliance_framework: "CIS"

  tasks:
    # User and authentication hardening
    - name: Set password policies
      lineinfile:
        path: /etc/security/pwquality.conf
        regexp: "{{ item.regexp }}"
        line: "{{ item.line }}"
      loop:
        - { regexp: '^minlen', line: 'minlen = 14' }
        - { regexp: '^dcredit', line: 'dcredit = -1' }
        - { regexp: '^ucredit', line: 'ucredit = -1' }
        - { regexp: '^lcredit', line: 'lcredit = -1' }
        - { regexp: '^ocredit', line: 'ocredit = -1' }

    - name: Configure account lockout policies
      lineinfile:
        path: /etc/security/faillock.conf
        regexp: "{{ item.regexp }}"
        line: "{{ item.line }}"
      loop:
        - { regexp: '^deny', line: 'deny = 5' }
        - { regexp: '^unlock_time', line: 'unlock_time = 900' }
        - { regexp: '^fail_interval', line: 'fail_interval = 900' }

    # SSH hardening
    - name: Harden SSH configuration
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: "{{ item.regexp }}"
        line: "{{ item.line }}"
        backup: yes
      loop:
        - { regexp: '^Protocol', line: 'Protocol 2' }
        - { regexp: '^PermitRootLogin', line: 'PermitRootLogin no' }
        - { regexp: '^PasswordAuthentication', line: 'PasswordAuthentication no' }
        - { regexp: '^PermitEmptyPasswords', line: 'PermitEmptyPasswords no' }
        - { regexp: '^X11Forwarding', line: 'X11Forwarding no' }
        - { regexp: '^MaxAuthTries', line: 'MaxAuthTries 3' }
        - { regexp: '^ClientAliveInterval', line: 'ClientAliveInterval 300' }
        - { regexp: '^ClientAliveCountMax', line: 'ClientAliveCountMax 2' }
        - { regexp: '^LoginGraceTime', line: 'LoginGraceTime 60' }
        - { regexp: '^Banner', line: 'Banner /etc/issue.net' }
      notify: restart sshd

    # Network security
    - name: Configure kernel parameters for network security
      sysctl:
        name: "{{ item.name }}"
        value: "{{ item.value }}"
        state: present
        reload: yes
      loop:
        - { name: 'net.ipv4.ip_forward', value: '0' }
        - { name: 'net.ipv4.conf.all.send_redirects', value: '0' }
        - { name: 'net.ipv4.conf.default.send_redirects', value: '0' }
        - { name: 'net.ipv4.conf.all.accept_redirects', value: '0' }
        - { name: 'net.ipv4.conf.default.accept_redirects', value: '0' }
        - { name: 'net.ipv4.conf.all.secure_redirects', value: '0' }
        - { name: 'net.ipv4.conf.default.secure_redirects', value: '0' }
        - { name: 'net.ipv4.conf.all.log_martians', value: '1' }
        - { name: 'net.ipv4.conf.default.log_martians', value: '1' }
        - { name: 'net.ipv4.icmp_echo_ignore_broadcasts', value: '1' }
        - { name: 'net.ipv4.icmp_ignore_bogus_error_responses', value: '1' }
        - { name: 'net.ipv4.tcp_syncookies', value: '1' }

  handlers:
    - name: restart sshd
      service:
        name: sshd
        state: restarted
```

### 2. Firewall Configuration

```yaml
---
- name: Configure iptables firewall
  hosts: all
  become: yes

  tasks:
    - name: Install iptables-persistent
      package:
        name: iptables-persistent
        state: present
      when: ansible_os_family == "Debian"

    - name: Flush existing iptables rules
      iptables:
        flush: yes

    - name: Set default policies
      iptables:
        chain: "{{ item }}"
        policy: DROP
      loop:
        - INPUT
        - FORWARD
        - OUTPUT

    - name: Allow loopback traffic
      iptables:
        chain: INPUT
        in_interface: lo
        jump: ACCEPT

    - name: Allow established connections
      iptables:
        chain: INPUT
        ctstate: ESTABLISHED,RELATED
        jump: ACCEPT

    - name: Allow SSH (secure port)
      iptables:
        chain: INPUT
        protocol: tcp
        destination_port: "{{ ssh_port | default('22') }}"
        source: "{{ allowed_ssh_networks | default(['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']) }}"
        jump: ACCEPT

    - name: Allow HTTP/HTTPS for web servers
      iptables:
        chain: INPUT
        protocol: tcp
        destination_port: "{{ item }}"
        jump: ACCEPT
      loop: [80, 443]
      when: "'webservers' in group_names"

    - name: Log dropped packets
      iptables:
        chain: INPUT
        jump: LOG
        log_prefix: "iptables-dropped: "
        log_level: 4

    - name: Save iptables rules
      shell: iptables-save > /etc/iptables/rules.v4
      when: ansible_os_family == "Debian"
```

### 3. File System Security

```yaml
---
- name: File system security hardening
  hosts: all
  become: yes

  tasks:
    - name: Set permissions on critical files
      file:
        path: "{{ item.path }}"
        mode: "{{ item.mode }}"
        owner: "{{ item.owner | default('root') }}"
        group: "{{ item.group | default('root') }}"
      loop:
        - { path: '/etc/passwd', mode: '0644' }
        - { path: '/etc/shadow', mode: '0000' }
        - { path: '/etc/group', mode: '0644' }
        - { path: '/etc/gshadow', mode: '0000' }
        - { path: '/etc/ssh/sshd_config', mode: '0600' }
        - { path: '/boot/grub/grub.cfg', mode: '0600' }

    - name: Configure file system mount options
      mount:
        path: "{{ item.path }}"
        src: "{{ item.src }}"
        fstype: "{{ item.fstype }}"
        opts: "{{ item.opts }}"
        state: mounted
      loop:
        - { path: '/tmp', src: 'tmpfs', fstype: 'tmpfs', opts: 'defaults,nodev,nosuid,noexec,size=1G' }
        - { path: '/var/tmp', src: '/tmp', fstype: 'none', opts: 'bind,nodev,nosuid,noexec' }

    - name: Remove unnecessary packages
      package:
        name: "{{ item }}"
        state: absent
      loop:
        - telnet
        - rsh-server
        - rsh
        - ypbind
        - ypserv
        - tftp
        - tftp-server
        - talk
        - talk-server

    - name: Disable unnecessary services
      service:
        name: "{{ item }}"
        state: stopped
        enabled: no
      loop:
        - avahi-daemon
        - cups
        - dhcpd
        - slapd
        - nfs
        - rpcbind
        - named
        - vsftpd
        - httpd
      ignore_errors: yes
```

### 4. Audit Configuration

```yaml
---
- name: Configure system auditing
  hosts: all
  become: yes

  tasks:
    - name: Install auditd
      package:
        name: "{{ item }}"
        state: present
      loop:
        - auditd
        - audispd-plugins

    - name: Configure audit rules
      copy:
        content: |
          # Delete all existing rules
          -D

          # Buffer Size
          -b 8192

          # Failure Mode
          -f 1

          # Audit the audit logs
          -w /var/log/audit/ -p wa -k auditlog

          # Audit system configuration
          -w /etc/passwd -p wa -k identity
          -w /etc/group -p wa -k identity
          -w /etc/shadow -p wa -k identity
          -w /etc/sudoers -p wa -k identity

          # Monitor for network configuration changes
          -a exit,always -F arch=b64 -S sethostname -S setdomainname -k network
          -a exit,always -F arch=b32 -S sethostname -S setdomainname -k network
          -w /etc/issue -p wa -k network
          -w /etc/issue.net -p wa -k network
          -w /etc/hosts -p wa -k network
          -w /etc/sysconfig/network -p wa -k network

          # Monitor logins and logouts
          -w /var/log/faillog -p wa -k logins
          -w /var/log/lastlog -p wa -k logins
          -w /var/log/tallylog -p wa -k logins

          # Monitor process and session initiation
          -w /var/run/utmp -p wa -k session
          -w /var/log/wtmp -p wa -k session
          -w /var/log/btmp -p wa -k session

          # Monitor discretionary access control
          -a exit,always -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
          -a exit,always -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
          -a exit,always -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
          -a exit,always -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod

          # Monitor unsuccessful unauthorized file access attempts
          -a exit,always -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
          -a exit,always -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
          -a exit,always -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
          -a exit,always -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access

          # Make the configuration immutable
          -e 2
        dest: /etc/audit/rules.d/hardening.rules
        owner: root
        group: root
        mode: '0640'
      notify: restart auditd

    - name: Configure auditd
      lineinfile:
        path: /etc/audit/auditd.conf
        regexp: "{{ item.regexp }}"
        line: "{{ item.line }}"
      loop:
        - { regexp: '^log_file', line: 'log_file = /var/log/audit/audit.log' }
        - { regexp: '^max_log_file', line: 'max_log_file = 50' }
        - { regexp: '^max_log_file_action', line: 'max_log_file_action = rotate' }
        - { regexp: '^num_logs', line: 'num_logs = 5' }
        - { regexp: '^space_left', line: 'space_left = 75' }
        - { regexp: '^space_left_action', line: 'space_left_action = email' }
        - { regexp: '^admin_space_left_action', line: 'admin_space_left_action = halt' }

  handlers:
    - name: restart auditd
      service:
        name: auditd
        state: restarted
```

## Container Security Hardening

### 1. Docker Security Configuration

```yaml
---
- name: Docker security hardening
  hosts: docker_hosts
  become: yes

  tasks:
    - name: Install Docker with security considerations
      package:
        name: docker-ce
        state: present

    - name: Configure Docker daemon security
      copy:
        content: |
          {
            "icc": false,
            "userns-remap": "default",
            "log-driver": "json-file",
            "log-opts": {
              "max-size": "10m",
              "max-file": "3"
            },
            "disable-legacy-registry": true,
            "no-new-privileges": true,
            "seccomp-profile": "/etc/docker/seccomp.json",
            "apparmor-profile": "docker-default"
          }
        dest: /etc/docker/daemon.json
        owner: root
        group: root
        mode: '0644'
      notify: restart docker

    - name: Create Docker security profiles directory
      file:
        path: /etc/docker
        state: directory
        owner: root
        group: root
        mode: '0755'

    - name: Configure Docker seccomp profile
      copy:
        content: |
          {
            "defaultAction": "SCMP_ACT_ERRNO",
            "architectures": ["SCMP_ARCH_X86_64"],
            "syscalls": [
              {"names": ["read", "write", "open", "close"], "action": "SCMP_ACT_ALLOW"},
              {"names": ["execve"], "action": "SCMP_ACT_ALLOW"},
              {"names": ["mmap", "munmap", "mprotect"], "action": "SCMP_ACT_ALLOW"}
            ]
          }
        dest: /etc/docker/seccomp.json
        owner: root
        group: root
        mode: '0644'

  handlers:
    - name: restart docker
      service:
        name: docker
        state: restarted
```

### 2. Kubernetes Security Hardening

```yaml
---
- name: Kubernetes security hardening
  hosts: k8s_masters
  become: yes

  tasks:
    - name: Configure kubelet security parameters
      lineinfile:
        path: /etc/kubernetes/kubelet/kubelet-config.yaml
        regexp: "{{ item.regexp }}"
        line: "{{ item.line }}"
      loop:
        - { regexp: '^readOnlyPort:', line: 'readOnlyPort: 0' }
        - { regexp: '^authentication:', line: 'authentication:\n  webhook:\n    enabled: true' }
        - { regexp: '^authorization:', line: 'authorization:\n  mode: Webhook' }
        - { regexp: '^protectKernelDefaults:', line: 'protectKernelDefaults: true' }
        - { regexp: '^rotateCertificates:', line: 'rotateCertificates: true' }

    - name: Configure API server security
      lineinfile:
        path: /etc/kubernetes/manifests/kube-apiserver.yaml
        regexp: "    - {{ item.flag }}"
        line: "    - {{ item.flag }}={{ item.value }}"
      loop:
        - { flag: '--anonymous-auth', value: 'false' }
        - { flag: '--basic-auth-file', value: '' }
        - { flag: '--token-auth-file', value: '' }
        - { flag: '--authorization-mode', value: 'Node,RBAC' }
        - { flag: '--enable-admission-plugins', value: 'NodeRestriction,PodSecurityPolicy' }
        - { flag: '--audit-log-path', value: '/var/log/kubernetes/audit.log' }
        - { flag: '--audit-log-maxage', value: '30' }
        - { flag: '--audit-log-maxbackup', value: '10' }
        - { flag: '--audit-log-maxsize', value: '100' }
```

## Compliance Automation

### 1. CIS Benchmark Implementation

```yaml
---
- name: CIS Benchmark compliance
  hosts: all
  become: yes
  vars:
    cis_level: 2

  tasks:
    # CIS 1.1.1.1 - Ensure mounting of cramfs filesystems is disabled
    - name: Disable cramfs filesystem
      lineinfile:
        path: /etc/modprobe.d/blacklist-rare-filesystems.conf
        line: 'install cramfs /bin/true'
        create: yes

    # CIS 1.1.1.2 - Ensure mounting of freevxfs filesystems is disabled
    - name: Disable freevxfs filesystem
      lineinfile:
        path: /etc/modprobe.d/blacklist-rare-filesystems.conf
        line: 'install freevxfs /bin/true'

    # CIS 1.1.1.3 - Ensure mounting of jffs2 filesystems is disabled
    - name: Disable jffs2 filesystem
      lineinfile:
        path: /etc/modprobe.d/blacklist-rare-filesystems.conf
        line: 'install jffs2 /bin/true'

    # CIS 1.1.1.4 - Ensure mounting of hfs filesystems is disabled
    - name: Disable hfs filesystem
      lineinfile:
        path: /etc/modprobe.d/blacklist-rare-filesystems.conf
        line: 'install hfs /bin/true'

    # CIS 5.2.1 - Ensure permissions on /etc/ssh/sshd_config are configured
    - name: Set SSH config permissions
      file:
        path: /etc/ssh/sshd_config
        owner: root
        group: root
        mode: '0600'

    # CIS 5.2.2 - Ensure SSH Protocol is set to 2
    - name: Set SSH Protocol to 2
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^Protocol'
        line: 'Protocol 2'
      notify: restart sshd

    # CIS 5.2.3 - Ensure SSH LogLevel is set to INFO
    - name: Set SSH LogLevel to INFO
      lineinfile:
        path: /etc/ssh/sshd_config
        regexp: '^LogLevel'
        line: 'LogLevel INFO'
      notify: restart sshd
```

### 2. NIST Framework Implementation

```yaml
---
- name: NIST Cybersecurity Framework implementation
  hosts: all
  become: yes

  tasks:
    # IDENTIFY function - Asset Management
    - name: Configure system identification
      template:
        src: system-info.j2
        dest: /etc/system-identification
        owner: root
        group: root
        mode: '0644'

    # PROTECT function - Access Control
    - name: Configure account policies
      lineinfile:
        path: /etc/login.defs
        regexp: "{{ item.regexp }}"
        line: "{{ item.line }}"
      loop:
        - { regexp: '^PASS_MAX_DAYS', line: 'PASS_MAX_DAYS 90' }
        - { regexp: '^PASS_MIN_DAYS', line: 'PASS_MIN_DAYS 7' }
        - { regexp: '^PASS_WARN_AGE', line: 'PASS_WARN_AGE 14' }

    # DETECT function - Security Monitoring
    - name: Configure log monitoring
      copy:
        content: |
          # Monitor security events
          auth.info /var/log/auth.log
          authpriv.* /var/log/secure

          # Monitor system events
          kern.* /var/log/kern.log
          mail.* /var/log/mail.log

          # Send critical alerts to console
          *.emerg *
        dest: /etc/rsyslog.d/50-security.conf
      notify: restart rsyslog

    # RESPOND function - Incident Response
    - name: Create incident response directory
      file:
        path: /var/log/incident-response
        state: directory
        owner: root
        group: root
        mode: '0750'
```

## Security Monitoring and Alerting

### 1. Log Analysis and Monitoring

```yaml
---
- name: Security monitoring setup
  hosts: all
  become: yes

  tasks:
    - name: Install security monitoring tools
      package:
        name: "{{ item }}"
        state: present
      loop:
        - fail2ban
        - logwatch
        - rkhunter
        - chkrootkit

    - name: Configure fail2ban
      copy:
        content: |
          [DEFAULT]
          bantime = 3600
          findtime = 600
          maxretry = 5
          backend = systemd

          [sshd]
          enabled = true
          port = ssh
          logpath = %(sshd_log)s
          maxretry = 3

          [apache-auth]
          enabled = true
          port = http,https
          logpath = %(apache_error_log)s
          maxretry = 6
        dest: /etc/fail2ban/jail.local
      notify: restart fail2ban

    - name: Configure rkhunter
      lineinfile:
        path: /etc/rkhunter.conf
        regexp: "{{ item.regexp }}"
        line: "{{ item.line }}"
      loop:
        - { regexp: '^UPDATE_MIRRORS', line: 'UPDATE_MIRRORS=1' }
        - { regexp: '^MIRRORS_MODE', line: 'MIRRORS_MODE=0' }
        - { regexp: '^WEB_CMD', line: 'WEB_CMD=""' }

  handlers:
    - name: restart fail2ban
      service:
        name: fail2ban
        state: restarted

    - name: restart rsyslog
      service:
        name: rsyslog
        state: restarted
```

### 2. Intrusion Detection

```yaml
---
- name: AIDE intrusion detection setup
  hosts: all
  become: yes

  tasks:
    - name: Install AIDE
      package:
        name: aide
        state: present

    - name: Configure AIDE
      copy:
        content: |
          # AIDE configuration
          database_in=file:/var/lib/aide/aide.db
          database_out=file:/var/lib/aide/aide.db.new
          database_new=file:/var/lib/aide/aide.db.new
          gzip_dbout=yes

          # Rules
          BinLib = p+i+n+u+g+s+b+m+c+md5+sha1
          Logs = p+i+n+u+g+S

          # Directories to monitor
          /bin BinLib
          /sbin BinLib
          /usr/bin BinLib
          /usr/sbin BinLib
          /lib BinLib
          /usr/lib BinLib
          /etc p+i+n+u+g+s+b+m+c+md5+sha1
          /boot p+i+n+u+g+s+b+m+c+md5+sha1
          /var/log Logs
        dest: /etc/aide/aide.conf

    - name: Initialize AIDE database
      command: aide --init
      args:
        creates: /var/lib/aide/aide.db.new

    - name: Create AIDE check script
      copy:
        content: |
          #!/bin/bash
          # AIDE integrity check
          /usr/bin/aide --check 2>&1 | /usr/bin/logger -t aide
        dest: /usr/local/bin/aide-check.sh
        mode: '0755'

    - name: Schedule AIDE checks
      cron:
        name: "AIDE integrity check"
        minute: "0"
        hour: "5"
        job: "/usr/local/bin/aide-check.sh"
```

## Testing and Validation

### 1. Security Test Playbook

```yaml
---
- name: Security validation tests
  hosts: all
  become: yes

  tasks:
    - name: Test SSH configuration
      shell: sshd -T | grep -E "(protocol|permitrootlogin|passwordauthentication)"
      register: ssh_config
      changed_when: false

    - name: Validate firewall rules
      shell: iptables -L -n
      register: firewall_rules
      changed_when: false

    - name: Check for unauthorized SUID files
      find:
        paths: /
        file_type: file
        use_regex: yes
        patterns: '.*'
        recurse: yes
        hidden: yes
      register: suid_files
      become: yes

    - name: Generate security report
      template:
        src: security-report.j2
        dest: /tmp/security-validation-report.txt
```

## References

- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Ansible Security Automation](https://www.ansible.com/use-cases/security-automation)
- [RHEL Security Guide](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/security_hardening/)
- [Ubuntu Security](https://ubuntu.com/security)