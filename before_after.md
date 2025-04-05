# Ubuntu Server 20.04 LTS: Before and After Hardening

This document showcases the security state of an Ubuntu Server 20.04 LTS system before and after applying the CIS hardening script.

## System Configuration

| Setting | Before Hardening | After Hardening | Security Improvement |
|---------|------------------|-----------------|----------------------|
| Unused Filesystems | Enabled | Disabled | Reduces attack surface by preventing mount of potentially vulnerable filesystems |
| Core Dumps | Enabled | Disabled | Prevents leakage of sensitive information through core dumps |
| /tmp Partition | No separate mount with security options | Mounted with noexec, nosuid, nodev | Prevents execution of malicious code and privilege escalation via /tmp |
| Boot Settings | Default | Audit enabled, IPv6 disabled | Improves logging and reduces attack surface |

## Network Security

| Setting | Before Hardening | After Hardening | Security Improvement |
|---------|------------------|-----------------|----------------------|
| Firewall (UFW) | Disabled | Enabled, default deny | Blocks unauthorized network connections |
| IP Forwarding | Enabled | Disabled | Prevents the system from routing traffic between networks |
| ICMP Redirects | Accepted | Ignored | Prevents ICMP redirect attacks |
| TCP SYN Cookies | Disabled | Enabled | Protects against SYN flood attacks |
| Martian Packets | Not logged | Logged | Improves detection of suspicious network activity |

## Example: UFW Firewall Status

### Before Hardening
```
$ sudo ufw status
Status: inactive
```

### After Hardening
```
$ sudo ufw status
Status: active

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW       Anywhere
22/tcp (v6)                ALLOW       Anywhere (v6)
```

## Authentication and Authorization

| Setting | Before Hardening | After Hardening | Security Improvement |
|---------|------------------|-----------------|----------------------|
| Password Max Days | 99999 | 90 | Forces regular password changes |
| Password Min Days | 0 | 7 | Prevents frequent password changes that might lead to weak passwords |
| Password Warning Age | 7 | 14 | Gives users sufficient notice to change passwords |
| Password Hashing | MD5 or SHA-256 | SHA-512 | Uses stronger hashing algorithm for passwords |
| Default umask | 022 | 027 | More restrictive file permissions for new files |

## Example: Password Policy

### Before Hardening
```
$ grep -E '^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_WARN_AGE' /etc/login.defs
PASS_MAX_DAYS   99999
PASS_MIN_DAYS   0
PASS_WARN_AGE   7
```

### After Hardening
```
$ grep -E '^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_WARN_AGE' /etc/login.defs
PASS_MAX_DAYS   90
PASS_MIN_DAYS   7
PASS_WARN_AGE   14
```

## SSH Configuration

| Setting | Before Hardening | After Hardening | Security Improvement |
|---------|------------------|-----------------|----------------------|
| SSH Root Login | Permitted | Disabled | Prevents direct root login via SSH |
| X11 Forwarding | Enabled | Disabled | Reduces attack surface by disabling X11 forwarding |
| SSH Protocol | Not specified (defaults to 2) | Explicitly set to 2 | Ensures only secure SSH protocol version is used |
| Maximum Auth Tries | 6 | 4 | Reduces brute force attack window |
| Client Alive Interval | 0 (disabled) | 300 seconds | Automatically disconnects inactive sessions |
| Allowed Ciphers | Default (includes weaker ciphers) | Strong ciphers only | Enforces use of strong encryption algorithms |

## Example: SSH Configuration

### Before Hardening
```
$ grep -E '^PermitRootLogin|^X11Forwarding' /etc/ssh/sshd_config
#PermitRootLogin yes
X11Forwarding yes
```

### After Hardening
```
$ grep -E '^PermitRootLogin|^X11Forwarding' /etc/ssh/sshd_config
PermitRootLogin no
X11Forwarding no
```

## Auditing and Logging

| Setting | Before Hardening | After Hardening | Security Improvement |
|---------|------------------|-----------------|----------------------|
| Audit Daemon (auditd) | Not installed | Installed and configured | Provides comprehensive system auditing |
| Critical Files Monitoring | Not monitored | Monitored for changes | Detects unauthorized modifications to critical files |
| Time Synchronization | Not configured | Configured with chrony | Ensures accurate timestamps for logs and auditing |

## Example: Audit Rules

### Before Hardening
```
$ sudo auditctl -l
No rules
```

### After Hardening
```
$ sudo auditctl -l
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-a always,exit -F arch=b64 -S adjtimex,settimeofday,stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
-w /usr/sbin/useradd -p x -k user_modification
-w /usr/sbin/userdel -p x -k user_modification
-w /usr/sbin/usermod -p x -k user_modification
-w /usr/sbin/groupadd -p x -k group_modification
-w /usr/sbin/groupdel -p x -k group_modification
-w /usr/sbin/groupmod -p x -k group_modification
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
```

## Services

| Setting | Before Hardening | After Hardening | Security Improvement |
|---------|------------------|-----------------|----------------------|
| Unnecessary Services | Possibly installed | Removed (telnet, rsh, etc.) | Reduces attack surface by removing insecure services |
| Cron Directory Permissions | World-readable | Restricted to root | Prevents unauthorized users from viewing scheduled tasks |
| Warning Banners | Default | Warning message configured | Provides legal notification to users |

## Summary of Security Improvements

After applying the hardening script, the system has:

1. **Reduced attack surface** by disabling unnecessary services and filesystems
2. **Enhanced network security** through firewall configuration and secure network parameters
3. **Improved authentication security** with stricter password policies and SSH hardening
4. **Better monitoring and detection** through comprehensive audit rules and logging
5. **More secure file permissions** for critical system files and directories

These improvements align with CIS Ubuntu Linux 20.04 LTS Benchmark v1.1.0 and significantly enhance the system's security posture against common threats and vulnerabilities. 