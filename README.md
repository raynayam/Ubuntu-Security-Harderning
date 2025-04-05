# Ubuntu Server 20.04 LTS Hardening

This directory contains security hardening scripts for Ubuntu Server 20.04 LTS based on the CIS Ubuntu Linux 20.04 LTS Benchmark v1.1.0.

## Files Included

- `ubuntu_hardening.sh`: Main hardening script that applies CIS Benchmark recommendations
- `before_after.md`: Example of system security state before and after applying hardening

## CIS Controls Implemented

The script implements the following CIS Benchmark sections:

1. **Initial Setup**
   - Filesystem Configuration
   - Software Updates
   - Process Hardening
   - Mandatory Access Control
   - Warning Banners

2. **Services**
   - Special Purpose Services
   - Service Clients
   - Time Synchronization

3. **Network Configuration**
   - Network Parameters
   - IPv6
   - TCP Wrappers
   - Firewall Configuration

4. **Logging and Auditing**
   - Configure System Accounting (auditd)
   - Configure Logging

5. **Access, Authentication and Authorization**
   - Configure cron
   - SSH Server Configuration
   - PAM and Password Settings
   - User Accounts and Environment

6. **System Maintenance**
   - System File Permissions
   - User and Group Settings

## Usage Instructions

1. Review the script before running to understand what changes will be made.
2. Make a backup or snapshot of your system before running the script.
3. Run the script with root privileges:

```bash
# Make the script executable
chmod +x ubuntu_hardening.sh

# Run the script
sudo ./ubuntu_hardening.sh
```

4. Reboot the system after the script completes to apply all changes:

```bash
sudo reboot
```

## Notes and Customization

- The script creates a backup of important configuration files before modifying them in `/root/hardening_backup_<timestamp>/`
- The SSH configuration allows SSH access but with hardened settings
- The firewall (UFW) is configured to allow SSH connections but blocks all other incoming traffic
- Password policies enforce complexity, aging, and secure storage

## Verification

After applying the hardening script, you can verify that the system has been properly hardened using:

```bash
# Check the status of the firewall
sudo ufw status

# Check password policies
grep -E '^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_WARN_AGE' /etc/login.defs

# Check SSH configuration
grep -E '^Protocol|^PermitRootLogin|^X11Forwarding|^PermitEmptyPasswords|^MaxAuthTries' /etc/ssh/sshd_config

# Check audit rules
sudo auditctl -l
```

## Disclaimer

This script is provided as-is and should be tested in a non-production environment before applying to production systems. Review and customize the script to meet your specific security requirements. 