#!/usr/bin/env bash
# secure-jetson.sh - Create an extremely secure Jetson Nano image
# Only does what's needed for maximum security, nothing more

set -euo pipefail
IFS=$'\n\t'

# Colors for output
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'

# Default configuration
IMAGE_ZIP=""
SSH_KEY=""
USERNAME="secureuser"
SSH_PORT=22989  # Non-standard high port
SD_DEVICE=""
WORK_DIR="${HOME}/secure_jetson"

# Help text
usage() {
  cat <<EOF
Usage: $0 -i <image.zip> -k <key.pub> [-u user] [-p port] [-d /dev/sdX]
  -i  Jetson Nano image file (ZIP/IMG)
  -k  SSH public key for authentication
  -u  Username (default: secureuser)
  -p  SSH port (default: 22989)
  -d  SD card device (e.g. /dev/sdb)
EOF
  exit 1
}

# Parse command line arguments
while getopts ":i:k:u:p:d:" opt; do
  case $opt in
    i) IMAGE_ZIP="$OPTARG" ;;
    k) SSH_KEY="$OPTARG" ;;
    u) USERNAME="$OPTARG" ;;
    p) SSH_PORT="$OPTARG" ;;
    d) SD_DEVICE="$OPTARG" ;;
    *) usage ;;
  esac
done

# Validate required parameters
[[ -z "$IMAGE_ZIP" || -z "$SSH_KEY" ]] && usage

# Create work directory
mkdir -p "$WORK_DIR"
LOG_FILE="${WORK_DIR}/secure-jetson.log"
exec &> >(tee -a "$LOG_FILE")

# Define cleanup function
cleanup() {
  echo -e "${YELLOW}Cleaning up...${NC}"
  # Unmount if mounted
  if mountpoint -q "${WORK_DIR}/mount" 2>/dev/null; then
    sudo umount "${WORK_DIR}/mount"
  fi
}
trap cleanup EXIT

# Check for required tools
for cmd in unzip lsblk dd sha256sum sshd; do
  command -v $cmd >/dev/null 2>&1 || {
    echo -e "${RED}ERROR:${NC} Required command '$cmd' is missing"; exit 1;
  }
done

echo -e "${GREEN}=== Creating Secure Jetson Nano ===${NC}"
echo "Image: $IMAGE_ZIP"
echo "SSH Key: $SSH_KEY"
echo "Username: $USERNAME"
echo "SSH Port: $SSH_PORT"

# Validate input files
[[ -f "$IMAGE_ZIP" ]] || { echo -e "${RED}Image file not found: $IMAGE_ZIP${NC}"; exit 1; }
[[ -f "$SSH_KEY" ]] || { echo -e "${RED}SSH key not found: $SSH_KEY${NC}"; exit 1; }

# Extract or copy the image
if [[ "$IMAGE_ZIP" == *.zip ]]; then
  echo "Extracting image file..."
  unzip -o "$IMAGE_ZIP" -d "$WORK_DIR"
  IMAGE_FILE=$(find "$WORK_DIR" -type f -name "*.img" | head -n1)
  [[ -n "$IMAGE_FILE" ]] || { echo -e "${RED}No .img file found after extraction${NC}"; exit 1; }
else
  IMAGE_FILE="$WORK_DIR/$(basename "$IMAGE_ZIP")"
  cp "$IMAGE_ZIP" "$IMAGE_FILE"
fi
echo "Using image: $IMAGE_FILE"

# Identify SD card device if not specified
if [[ -z "$SD_DEVICE" ]]; then
  echo -e "\nAvailable devices:"
  lsblk -p | grep -E 'disk|mmcblk'
  read -rp "Enter SD card device (e.g. /dev/sdb): " SD_DEVICE
fi

# Validate SD card device
[[ -b "$SD_DEVICE" ]] || { echo -e "${RED}Invalid device: $SD_DEVICE${NC}"; exit 1; }
echo -e "${YELLOW}WARNING: All data on $SD_DEVICE will be erased!${NC}"
lsblk -p "$SD_DEVICE"
read -rp "Type 'yes' to confirm: " CONFIRM
[[ "$CONFIRM" == "yes" ]] || { echo "Operation canceled"; exit 1; }

# Flash image to SD card
echo "Flashing image to SD card..."
sudo dd if="$IMAGE_FILE" of="$SD_DEVICE" bs=4M status=progress conv=fsync
sync
echo "Verifying flash with checksum..."
IMG_SUM=$(sha256sum "$IMAGE_FILE" | cut -d' ' -f1)
DEV_SUM=$(sudo dd if="$SD_DEVICE" bs=4M count=$(( $(stat -c %s "$IMAGE_FILE") / (4*1024*1024) )) status=none | sha256sum | cut -d' ' -f1)
[[ "$IMG_SUM" == "$DEV_SUM" ]] || { echo -e "${RED}Checksum verification failed${NC}"; exit 1; }
echo -e "${GREEN}Flash completed and verified${NC}"

# Wait for the system to recognize new partitions
echo "Waiting for device partitions..."
sleep 5

# Mount rootfs partition
MOUNT_DIR="${WORK_DIR}/mount"
mkdir -p "$MOUNT_DIR"
ROOTFS_PART="${SD_DEVICE}2"
[[ -b "${SD_DEVICE}p2" ]] && ROOTFS_PART="${SD_DEVICE}p2"
echo "Mounting rootfs partition: $ROOTFS_PART"
sudo mount "$ROOTFS_PART" "$MOUNT_DIR" || { echo -e "${RED}Failed to mount rootfs partition${NC}"; exit 1; }

# Configure SSH key authentication
echo "Setting up SSH key authentication..."
if [[ "$USERNAME" == "root" ]]; then
  SSH_DIR="${MOUNT_DIR}/root/.ssh"
else
  SSH_DIR="${MOUNT_DIR}/home/${USERNAME}/.ssh"
  # Ensure user exists
  PASSWD_FILE="${MOUNT_DIR}/etc/passwd"
  if ! grep -q "^${USERNAME}:" "$PASSWD_FILE"; then
    echo "Creating user $USERNAME..."
    sudo chroot "$MOUNT_DIR" useradd -m -s /bin/bash "$USERNAME"
  fi
fi

sudo mkdir -p "$SSH_DIR"
sudo cp "$SSH_KEY" "${SSH_DIR}/authorized_keys"
sudo chmod 700 "$SSH_DIR"
sudo chmod 600 "${SSH_DIR}/authorized_keys"
if [[ "$USERNAME" != "root" ]]; then
  USER_ID=$(grep "^${USERNAME}:" "${MOUNT_DIR}/etc/passwd" | cut -d: -f3)
  GROUP_ID=$(grep "^${USERNAME}:" "${MOUNT_DIR}/etc/passwd" | cut -d: -f4)
  sudo chown -R "${USER_ID}:${GROUP_ID}" "${MOUNT_DIR}/home/${USERNAME}"
fi

# Configure SSH for maximum security
echo "Hardening SSH configuration..."
SSHD_CONFIG="${MOUNT_DIR}/etc/ssh/sshd_config"

# Backup original config
sudo cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak"

# Configure SSH security settings
sudo tee "$SSHD_CONFIG" > /dev/null <<EOF
# Secure SSH configuration for Jetson Nano
# Generated by secure-jetson.sh

# Basic SSH settings
Port $SSH_PORT
Protocol 2
AddressFamily inet

# Authentication settings
LoginGraceTime 20
PermitRootLogin no
StrictModes yes
MaxAuthTries 3
MaxSessions 2
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

# Restrict users
AllowUsers $USERNAME

# Forwarding restrictions
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PermitTunnel no

# Other security settings
Compression no
ClientAliveInterval 300
ClientAliveCountMax 2
Banner none
DebianBanner no
PermitUserEnvironment no
UseDNS no

# Logging
SyslogFacility AUTH
LogLevel VERBOSE
EOF

# Validate SSH config
echo "Validating SSH configuration..."
sudo chroot "$MOUNT_DIR" /usr/sbin/sshd -t -f /etc/ssh/sshd_config || {
  echo -e "${RED}Invalid SSH configuration${NC}"
  sudo mv "${SSHD_CONFIG}.bak" "$SSHD_CONFIG"
  exit 1
}

# Create security setup script for first boot
echo "Creating first-boot security setup..."
SECURITY_SCRIPT="${MOUNT_DIR}/usr/local/bin/security-setup.sh"
sudo mkdir -p "$(dirname "$SECURITY_SCRIPT")"

sudo tee "$SECURITY_SCRIPT" > /dev/null <<EOF
#!/bin/bash
# First-boot security setup for Jetson Nano
set -euo pipefail
LOG="/var/log/security-setup.log"
exec > >(tee -a "\$LOG") 2>&1
echo "Starting security hardening: \$(date)"

# Exit if already configured
if [ -f "/var/lib/security-setup-done" ]; then
  echo "Security setup already completed."
  exit 0
fi

# Install security packages
echo "Installing security packages..."
apt-get update
apt-get install -y ufw fail2ban unattended-upgrades apt-listchanges rkhunter aide debsums

# Configure firewall
echo "Configuring firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw allow $SSH_PORT/tcp comment "SSH"
echo "y" | ufw enable
systemctl enable ufw

# Configure fail2ban
echo "Configuring fail2ban..."
cat > /etc/fail2ban/jail.d/custom.conf <<EOL
[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
EOL
systemctl enable fail2ban
systemctl restart fail2ban

# Configure automatic updates
echo "Setting up automatic security updates..."
cat > /etc/apt/apt.conf.d/20auto-upgrades <<EOL
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
EOL

# System hardening
echo "Applying system hardening..."

# Kernel parameters hardening
cat > /etc/sysctl.d/99-security.conf <<EOL
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Block SYN attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Disable IP source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Ignore broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Don't pass traffic between networks
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Protect against bad ICMP error messages
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Disable IPv6 if not needed
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOL
sysctl -p /etc/sysctl.d/99-security.conf

# Secure shared memory
echo "Securing shared memory..."
echo "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> /etc/fstab

# Harden password policies
echo "Hardening password policies..."
sed -i 's/PASS_MAX_DAYS\t99999/PASS_MAX_DAYS\t90/' /etc/login.defs
sed -i 's/PASS_MIN_DAYS\t0/PASS_MIN_DAYS\t1/' /etc/login.defs
sed -i 's/PASS_WARN_AGE\t7/PASS_WARN_AGE\t14/' /etc/login.defs

# PAM password policy
apt-get install -y libpam-pwquality
sed -i 's/password\s*requisite\s*pam_pwquality.so.*/password requisite pam_pwquality.so retry=3 minlen=12 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 reject_username enforce_for_root/' /etc/pam.d/common-password

# Restrict access to cron and at
echo "Restricting access to cron..."
echo "root" > /etc/cron.allow
echo "root" > /etc/at.allow
chmod 600 /etc/cron.allow /etc/at.allow
rm -f /etc/cron.deny /etc/at.deny

# Set up AIDE for file integrity monitoring
echo "Setting up file integrity monitoring..."
aideinit
cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
cat > /etc/cron.daily/aide-check <<EOL
#!/bin/bash
/usr/bin/aide.wrapper --check | mail -s "AIDE integrity check report" root
EOL
chmod +x /etc/cron.daily/aide-check

# Create security scan script
echo "Creating weekly security scan..."
cat > /etc/cron.weekly/security-scan <<EOL
#!/bin/bash
LOG="/var/log/security-scan-\$(date +%Y%m%d).log"
echo "Security scan started at \$(date)" > \$LOG
echo "----------------------" >> \$LOG
echo "rkhunter scan:" >> \$LOG
rkhunter --update >> \$LOG
rkhunter --checkall --skip-keypress >> \$LOG
echo "----------------------" >> \$LOG
echo "AIDE check:" >> \$LOG
aide --check >> \$LOG
echo "----------------------" >> \$LOG
echo "Listening ports:" >> \$LOG
netstat -tulpn >> \$LOG
echo "----------------------" >> \$LOG
echo "Failed login attempts:" >> \$LOG
grep "Failed password" /var/log/auth.log | tail -20 >> \$LOG
echo "Security scan completed at \$(date)" >> \$LOG
chmod 600 \$LOG
EOL
chmod +x /etc/cron.weekly/security-scan

# Mark security setup as done
touch /var/lib/security-setup-done
echo "Security hardening completed at $(date)"
EOF

sudo chmod +x "$SECURITY_SCRIPT"

# Create systemd service to run security setup at first boot
echo "Setting up systemd service for first boot security configuration..."
SYSTEMD_DIR="${MOUNT_DIR}/etc/systemd/system"
sudo mkdir -p "$SYSTEMD_DIR"

sudo tee "${SYSTEMD_DIR}/security-setup.service" > /dev/null <<EOF
[Unit]
Description=First Boot Security Setup
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/security-setup.sh
RemainAfterExit=true

[Install]
WantedBy=multi-user.target
EOF

sudo mkdir -p "${MOUNT_DIR}/etc/systemd/system/multi-user.target.wants"
sudo ln -sf "../security-setup.service" "${MOUNT_DIR}/etc/systemd/system/multi-user.target.wants/security-setup.service"

# Create backup rc.local as fallback to ensure security script runs
echo "Creating rc.local fallback..."
RC_LOCAL="${MOUNT_DIR}/etc/rc.local"
sudo tee "$RC_LOCAL" > /dev/null <<EOF
#!/bin/bash
# Fallback for security setup in case systemd service fails
if [ -x /usr/local/bin/security-setup.sh ]; then
  /usr/local/bin/security-setup.sh
fi
exit 0
EOF
sudo chmod +x "$RC_LOCAL"

# Unmount the filesystem
echo "Unmounting filesystem..."
sudo umount "$MOUNT_DIR"

echo -e "${GREEN}Secure Jetson Nano SD card created successfully!${NC}"
echo
echo "SECURITY FEATURES IMPLEMENTED:"
echo "- SSH access restricted to key authentication only on port $SSH_PORT"
echo "- Limited SSH access to user '$USERNAME' only"
echo "- Firewall (UFW) configured to allow only SSH"
echo "- Fail2ban configured to prevent brute force attacks"
echo "- System hardening with secure kernel parameters"
echo "- Automatic security updates"
echo "- File integrity monitoring with AIDE"
echo "- Weekly security scans"
echo "- Secure password policies"
echo
echo "Insert this SD card into your Jetson Nano and power it on."
echo "The security setup will complete automatically on first boot."
echo -e "${YELLOW}Log file saved to: $LOG_FILE${NC}"
