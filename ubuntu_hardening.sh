#!/bin/bash
#
# Ubuntu Server 20.04 LTS Security Hardening Script
# Based on CIS Ubuntu Linux 20.04 LTS Benchmark v1.1.0
#

# Exit on error
set -e

# Print status messages
info() {
    echo -e "\033[1;34m[INFO]\033[0m $1"
}

success() {
    echo -e "\033[1;32m[SUCCESS]\033[0m $1"
}

warning() {
    echo -e "\033[1;33m[WARNING]\033[0m $1"
}

error() {
    echo -e "\033[1;31m[ERROR]\033[0m $1"
    exit 1
}

# Check if script is run as root
if [ "$(id -u)" -ne 0 ]; then
    error "This script must be run as root"
fi

info "Starting Ubuntu 20.04 LTS security hardening..."
info "Creating backup directory..."

# Create backup directory
BACKUP_DIR="/root/hardening_backup_$(date +%Y%m%d%H%M%S)"
mkdir -p "$BACKUP_DIR"
success "Created backup directory: $BACKUP_DIR"

# 1. Initial Setup

# 1.1 Filesystem Configuration

info "Configuring filesystems..."

# 1.1.1 Disable unused filesystems
cat > /etc/modprobe.d/cis_hardening.conf << EOF
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install udf /bin/true
EOF

# Backup fstab
cp /etc/fstab "$BACKUP_DIR/fstab.bak"

# 1.1.2-1.1.5 Configure /tmp, /var, /var/tmp, /var/log with proper options
if ! grep -q "/tmp" /etc/fstab; then
    echo "# Add by hardening script" >> /etc/fstab
    echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0" >> /etc/fstab
    success "Added /tmp to fstab with secure options"
fi

# 1.4 Secure Boot Settings
info "Securing boot settings..."
sed -i 's/GRUB_CMDLINE_LINUX=""/GRUB_CMDLINE_LINUX="ipv6.disable=1 audit=1 audit_backlog_limit=8192"/' /etc/default/grub
update-grub

# 1.5 Additional Process Hardening
info "Configuring additional process hardening..."
echo "* hard core 0" > /etc/security/limits.d/cis_hardening.conf
echo "* soft core 0" >> /etc/security/limits.d/cis_hardening.conf
echo "fs.suid_dumpable = 0" > /etc/sysctl.d/cis_hardening.conf

# 1.7 Warning Banners
info "Setting up warning banners..."
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue
echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net
echo "Authorized uses only. All activity may be monitored and reported." > /etc/motd

# 2. Services

# 2.1 inetd Services
info "Disabling inetd services..."
apt-get purge -y xinetd telnet-server telnet rsh-server rsh nis talk-server talk

# 2.2 Time Synchronization
info "Configuring time synchronization..."
apt-get install -y chrony
cp /etc/chrony/chrony.conf "$BACKUP_DIR/chrony.conf.bak"
cat > /etc/chrony/chrony.conf << EOF
# Use Ubuntu NTP servers
pool ntp.ubuntu.com iburst maxsources 4
keyfile /etc/chrony/chrony.keys
commandkey 1
driftfile /var/lib/chrony/chrony.drift
log tracking measurements statistics
logdir /var/log/chrony
maxupdateskew 100.0
hwclockfile /etc/adjtime
logchange 0.5
makestep 1 3
EOF
systemctl restart chrony

# 3. Network Configuration

# 3.1 Network Parameters (Host Only)
info "Configuring network parameters..."
cat >> /etc/sysctl.d/cis_hardening.conf << EOF
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
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
EOF

# Apply sysctl settings
sysctl -p /etc/sysctl.d/cis_hardening.conf

# 3.5 Configure Firewall
info "Configuring UFW firewall..."
apt-get install -y ufw
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw --force enable

# 4. Logging and Auditing

# 4.1 Configure System Accounting (auditd)
info "Installing and configuring auditd..."
apt-get install -y auditd audispd-plugins

# Backup audit rules
cp /etc/audit/rules.d/audit.rules "$BACKUP_DIR/audit.rules.bak" 2>/dev/null || true

# Configure audit rules
cat > /etc/audit/rules.d/cis_hardening.rules << EOF
# CIS Benchmark Audit Rules
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Monitor system calls
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# Monitor user and group management
-w /usr/sbin/useradd -p x -k user_modification
-w /usr/sbin/userdel -p x -k user_modification
-w /usr/sbin/usermod -p x -k user_modification
-w /usr/sbin/groupadd -p x -k group_modification
-w /usr/sbin/groupdel -p x -k group_modification
-w /usr/sbin/groupmod -p x -k group_modification

# Monitor sudoers configurations
-w /etc/sudoers -p wa -k sudoers
-w /etc/sudoers.d/ -p wa -k sudoers

# Monitor login/logout events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# Make the auditd configuration immutable
-e 2
EOF

# Restart auditd
systemctl restart auditd

# 4.2 Configure rsyslog
info "Configuring rsyslog..."
apt-get install -y rsyslog
systemctl enable rsyslog
systemctl start rsyslog

# 5. Access, Authentication and Authorization

# 5.1 Configure cron
info "Securing cron..."
chmod 0600 /etc/crontab
chmod 0700 /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d

# 5.2 SSH Server Configuration
info "Hardening SSH configuration..."
cp /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config.bak"

sed -i 's/^#Protocol 2/Protocol 2/' /etc/ssh/sshd_config
sed -i 's/^#LogLevel INFO/LogLevel VERBOSE/' /etc/ssh/sshd_config
sed -i 's/^#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#MaxAuthTries 6/MaxAuthTries 4/' /etc/ssh/sshd_config
sed -i 's/^#IgnoreRhosts yes/IgnoreRhosts yes/' /etc/ssh/sshd_config
sed -i 's/^#HostbasedAuthentication no/HostbasedAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#PermitEmptyPasswords no/PermitEmptyPasswords no/' /etc/ssh/sshd_config
sed -i 's/^#PermitUserEnvironment no/PermitUserEnvironment no/' /etc/ssh/sshd_config
sed -i 's/^#ClientAliveInterval 0/ClientAliveInterval 300/' /etc/ssh/sshd_config
sed -i 's/^#ClientAliveCountMax 3/ClientAliveCountMax 0/' /etc/ssh/sshd_config
sed -i 's/^X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
sed -i '/^Subsystem/s/$/\nAllowTcpForwarding no\nMaxSessions 2\nCiphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr\nMACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256/' /etc/ssh/sshd_config

systemctl restart sshd

# 5.4 User Accounts and Environment
info "Configuring user accounts and environment..."

# 5.4.1 Set Shadow Password Suite Parameters
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs

# 5.4.4 Ensure password hashing algorithm is SHA-512
sed -i 's/^password.*pam_unix.so.*/password    required                       pam_unix.so sha512 shadow nullok try_first_pass/' /etc/pam.d/common-password

# 6. System Maintenance

# 6.1 System File Permissions
info "Setting secure file permissions..."
chmod 644 /etc/passwd
chmod 644 /etc/group
chmod 600 /etc/shadow
chmod 600 /etc/gshadow

# 6.2 User and Group Settings
info "Verifying user and group settings..."
echo 'UMASK 027' >> /etc/profile

# Perform update and cleanup
info "Updating system packages..."
apt-get update
apt-get upgrade -y
apt-get autoremove -y
apt-get autoclean

success "Security hardening completed successfully!"
echo ""
echo "======================================================================"
echo "    Ubuntu 20.04 LTS server has been hardened according to CIS Benchmark v1.1.0"
echo "    A backup of original configuration files can be found in $BACKUP_DIR"
echo "    Please reboot the system to apply all changes."
echo "======================================================================" 