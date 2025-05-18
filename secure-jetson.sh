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
Usage: $0 [-i <image.zip>] [-k <key.pub>] [-u user] [-p port] [-d /dev/sdX]
  -i  Jetson Nano image file (ZIP/IMG) (default: $IMAGE_ZIP)
  -k  SSH public key for authentication (default: $SSH_KEY)
  -u  Username (default: $USERNAME)
  -p  SSH port (default: $SSH_PORT)
  -d  SD card device (e.g. /dev/sdb)
EOF
  exit 1
}

# Parse command line arguments
while getopts ":i:k:u:p:d:h" opt; do
  case $opt in
    i) IMAGE_ZIP="$OPTARG" ;;
    k) SSH_KEY="$OPTARG" ;;
    u) USERNAME="$OPTARG" ;;
    p) SSH_PORT="$OPTARG" ;;
    d) SD_DEVICE="$OPTARG" ;;
    h) usage ;;
    *) usage ;;
  esac
done

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
for cmd in unzip lsblk dd sha256sum partprobe; do
  if ! command -v $cmd >/dev/null 2>&1; then
    echo -e "${RED}ERROR:${NC} Required command '$cmd' is missing"
    echo "Please install it with: sudo apt-get install $cmd"
    exit 1
  fi
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
IMG_SIZE=$(stat -c %s "$IMAGE_FILE")
IMG_BLOCKS=$((IMG_SIZE / (4*1024*1024)))
[[ $IMG_BLOCKS -lt 1 ]] && IMG_BLOCKS=1
IMG_SUM=$(sha256sum "$IMAGE_FILE" | cut -d' ' -f1)
DEV_SUM=$(sudo dd if="$SD_DEVICE" bs=4M count=$IMG_BLOCKS status=none | sha256sum | cut -d' ' -f1)
[[ "$IMG_SUM" == "$DEV_SUM" ]] || { echo -e "${RED}Checksum verification failed${NC}"; exit 1; }
echo -e "${GREEN}Flash completed and verified${NC}"

# Force the kernel to re-read the partition table
echo "Forcing kernel to re-read partition table..."
sudo partprobe "$SD_DEVICE" || true
sleep 5  # Wait for partitions to settle

# Unmount any automounted partitions
for part in $(lsblk -p -o NAME "$SD_DEVICE" | grep -v "^$SD_DEVICE$"); do
  if mountpoint -q "$part" 2>/dev/null; then
    echo "Unmounting auto-mounted partition $part..."
    sudo umount "$part"
  fi
done

# List available partitions
echo "Available partitions:"
lsblk -p "$SD_DEVICE"

# Create mount point
MOUNT_DIR="${WORK_DIR}/mount"
mkdir -p "$MOUNT_DIR"

# Find rootfs partition - directly test the most common ones first
echo "Looking for rootfs partition..."

# Function to check if a partition looks like rootfs
check_rootfs() {
  local part=$1
  local mount_dir=$2
  
  if ! [[ -b "$part" ]]; then
    return 1
  fi
  
  # Try different filesystem types
  for fs_type in ext4 ext3 ext2; do
    echo "Trying to mount $part as $fs_type..."
    if sudo mount -t $fs_type "$part" "$mount_dir" 2>/dev/null; then
      # Check if it has typical rootfs directories
      if [[ -d "$mount_dir/etc" && -d "$mount_dir/bin" ]]; then
        echo "Found rootfs partition: $part (filesystem: $fs_type)"
        return 0
      fi
      sudo umount "$mount_dir"
    fi
  done
  
  # Also try auto detection
  echo "Trying auto filesystem detection for $part..."
  if sudo mount "$part" "$mount_dir" 2>/dev/null; then
    if [[ -d "$mount_dir/etc" && -d "$mount_dir/bin" ]]; then
      echo "Found rootfs partition: $part (auto-detected filesystem)"
      return 0
    fi
    sudo umount "$mount_dir"
  fi
  
  return 1
}

# Try partitions in the most likely order
ROOTFS_FOUND=false
ROOTFS_PART=""

# For SD cards, the rootfs is often the first partition (App partition)
for suffix in 1 p1; do
  if [[ -b "${SD_DEVICE}${suffix}" ]]; then
    if check_rootfs "${SD_DEVICE}${suffix}" "$MOUNT_DIR"; then
      ROOTFS_FOUND=true
      ROOTFS_PART="${SD_DEVICE}${suffix}"
      break
    fi
  fi
done

# If not found, try other partitions
if ! $ROOTFS_FOUND; then
  for suffix in 2 p2 3 p3 4 p4 5 p5 6 p6 7 p7 8 p8 9 p9 10 p10 11 p11 12 p12 13 p13 14 p14; do
    if [[ -b "${SD_DEVICE}${suffix}" ]]; then
      if check_rootfs "${SD_DEVICE}${suffix}" "$MOUNT_DIR"; then
        ROOTFS_FOUND=true
        ROOTFS_PART="${SD_DEVICE}${suffix}"
        break
      fi
    fi
  done
fi

# If still not found, prompt user
if ! $ROOTFS_FOUND; then
  echo -e "${YELLOW}Could not find rootfs partition automatically.${NC}"
  echo "Available partitions:"
  lsblk -p -o NAME,SIZE,FSTYPE "$SD_DEVICE"
  echo ""
  echo -e "${YELLOW}Please examine the partitions and enter the rootfs partition:${NC}"
  read -rp "Rootfs partition: " ROOTFS_PART
  
  if ! [[ -b "$ROOTFS_PART" ]]; then
    echo -e "${RED}Invalid partition: $ROOTFS_PART${NC}"
    exit 1
  fi
  
  # Try mounting the specified partition
  for fs_type in ext4 ext3 ext2 auto; do
    FS_OPTION=""
    [[ "$fs_type" != "auto" ]] && FS_OPTION="-t $fs_type"
    echo "Trying to mount user-specified partition with $fs_type..."
    if sudo mount $FS_OPTION "$ROOTFS_PART" "$MOUNT_DIR" 2>/dev/null; then
      if [[ -d "$MOUNT_DIR/etc" && -d "$MOUNT_DIR/bin" ]]; then
        echo "Successfully mounted rootfs partition"
        ROOTFS_FOUND=true
        break
      else
        echo "Mounted partition does not appear to be a rootfs"
        sudo umount "$MOUNT_DIR"
      fi
    fi
  done
  
  if ! $ROOTFS_FOUND; then
    echo -e "${RED}Could not mount $ROOTFS_PART as a valid rootfs.${NC}"
    echo "Debug information:"
    sudo file -s "$ROOTFS_PART"
    sudo blkid "$ROOTFS_PART"
    exit 1
  fi
fi

# Verify we have a mounted rootfs
if ! mountpoint -q "$MOUNT_DIR"; then
  echo -e "${RED}Failed to mount rootfs partition. This should not happen.${NC}"
  exit 1
fi

echo -e "${GREEN}Successfully mounted rootfs partition: $ROOTFS_PART${NC}"

# Configure SSH key authentication
echo "Setting up SSH key authentication..."
if [[ "$USERNAME" == "root" ]]; then
  SSH_DIR="${MOUNT_DIR}/root/.ssh"
else
  SSH_DIR="${MOUNT_DIR}/home/${USERNAME}/.ssh"
  # Ensure user exists
  PASSWD_FILE="${MOUNT_DIR}/etc/passwd"
  if ! grep -q "^${USERNAME}:" "$PASSWD_FILE" 2>/dev/null; then
    echo "Creating user $USERNAME in passwd file..."
    # Add user to passwd file directly if needed
    echo "${USERNAME}:x:1000:1000:Jetson User:/home/${USERNAME}:/bin/bash" | sudo tee -a "$PASSWD_FILE" > /dev/null
    echo "${USERNAME}:x:1000:" | sudo tee -a "${MOUNT_DIR}/etc/group" > /dev/null
    sudo mkdir -p "${MOUNT_DIR}/home/${USERNAME}"
  fi
fi

sudo mkdir -p "$SSH_DIR"
sudo cp "$SSH_KEY" "${SSH_DIR}/authorized_keys"
sudo chmod 700 "$SSH_DIR"
sudo chmod 600 "${SSH_DIR}/authorized_keys"
if [[ "$USERNAME" != "root" ]]; then
  sudo chown -R 1000:1000 "${MOUNT_DIR}/home/${USERNAME}"
fi

# Configure SSH for maximum security
echo "Hardening SSH configuration..."
SSHD_CONFIG="${MOUNT_DIR}/etc/ssh/sshd_config"

# Check if sshd_config exists
if [[ ! -f "$SSHD_CONFIG" ]]; then
  echo -e "${YELLOW}Warning: sshd_config not found. Creating new one.${NC}"
  sudo mkdir -p "$(dirname "$SSHD_CONFIG")"
  sudo touch "$SSHD_CONFIG"
else
  # Backup original config
  sudo cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak"
fi

# Configure SSH security settings
sudo tee "$SSHD_CONFIG" > /dev/null <<EOF
# Secure SSH configuration for Jetson Nano
# Generated by jetson-ssh-inject.sh

# Basic SSH settings
Port $SSH_PORT
Protocol 2

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
PermitUserEnvironment no

# Logging
LogLevel VERBOSE
EOF

# Create security setup script for first boot
echo "Creating first-boot security setup..."
SECURITY_SCRIPT="${MOUNT_DIR}/usr/local/bin/security-setup.sh"
sudo mkdir -p "$(dirname "$SECURITY_SCRIPT")"

sudo tee "$SECURITY_SCRIPT" > /dev/null <<EOF
#!/bin/bash
# First-boot security setup for Jetson Nano
set -e
LOG="/var/log/security-setup.log"
echo "Starting security hardening at \$(date)" > "\$LOG"
exec >> "\$LOG" 2>&1

# Exit if already configured
if [ -f "/var/lib/security-setup-done" ]; then
  echo "Security setup already completed."
  exit 0
fi

# Install security packages
echo "Installing security packages..."
apt-get update
apt-get install -y ufw fail2ban unattended-upgrades apt-listchanges

# Configure firewall
echo "Configuring firewall..."
ufw default deny incoming
ufw default allow outgoing
ufw allow $SSH_PORT/tcp comment "SSH"
echo "y" | ufw enable
systemctl enable ufw

# Configure fail2ban
echo "Configuring fail2ban..."
mkdir -p /etc/fail2ban/jail.d
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
EOL
sysctl -p /etc/sysctl.d/99-security.conf || echo "Some sysctl parameters may not be available on this kernel"

# Mark security setup as done
touch /var/lib/security-setup-done
echo "Security hardening completed at \$(date)"
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

# Create backup rc.local as fallback
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
echo
echo "Insert this SD card into your Jetson Nano and power it on."
echo "The security setup will complete automatically on first boot."
echo -e "${YELLOW}Log file saved to: $LOG_FILE${NC}"
