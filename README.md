# Secure Jetson Nano 🚀🔒

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Release](https://img.shields.io/github/v/release/yourusername/secure-jetson-nano)](https://github.com/yourusername/secure-jetson-nano/releases) [![CI](https://img.shields.io/github/actions/workflow/status/yourusername/secure-jetson-nano/ci.yml)](https://github.com/yourusername/secure-jetson-nano/actions)

A drop-in **Bash** utility to generate a fully **hardened Jetson Nano SD card image**, featuring secure SSH, firewall protection, automatic updates, and OS-level hardening—all automated for first-boot.

---

## 📋 Table of Contents

1. [Features](#features)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Usage](#usage)
5. [Configuration](#configuration)
6. [Customization](#customization)
7. [Contributing](#contributing)
8. [License](#license)

---

## ✨ Features

* **Image Flash & Verify**: Flashes your Jetson Nano image via `dd` and validates with SHA-256 checksums.
* **SSH Key Deployment**: Injects your SSH public key, enforces key-only auth, and runs on a custom high port.
* **Firewall (UFW) & Intrusion Prevention (Fail2Ban)**: Configures UFW default-deny and Fail2Ban with sane defaults.
* **Unattended Security Updates**: Sets up `unattended-upgrades` with optional automatic reboot.
* **Kernel & OS Hardening**: Applies `sysctl` tweaks, mounts `/dev/shm` noexec, enforces strong password policies, and file integrity via AIDE & rkhunter.
* **First-Boot Automation**: Systemd service (plus `rc.local` fallback) to run all security steps only on first startup.
* **Idempotent & Robust**: `set -euo pipefail`, traps for cleanup, logging, and marker files to resume after errors.

---

## ⚙️ Prerequisites

* **Host Machine**: Linux with Bash, `unzip`, `lsblk`, `dd`, `sha256sum`, `sshd`, and `sudo`.
* **Jetson Nano Image**: `.zip` or `.img` file.
* **SSH Public Key**: Your `.pub` file for rootless access.
* **SD Card**: Device (e.g., `/dev/sdb` or `/dev/mmcblk0`) with ≥16 GB.

---

## 🛠️ Installation

```bash
git clone https://github.com/yarpii/secure-jetson-nano.git
cd secure-jetson-nano
chmod +x secure-jetson.sh
```

---

## 🚀 Usage

Run the script with required options:

```bash
./secure-jetson.sh \
  -i /path/to/jetson-image.zip \
  -k ~/.ssh/id_rsa.pub \
  -u secureuser \
  -p 22989 \
  -d /dev/sdX
```

* **`-i`**: Jetson Nano image path (ZIP or IMG).
* **`-k`**: SSH public key file.
* **`-u`**: Username on the Nano (default: `secureuser`).
* **`-p`**: SSH port (default: `22989`).
* **`-d`**: SD card device. If omitted, script prompts interactively.

Add `-c` to **cleanup** the working directory after completion:

```bash
./secure-jetson.sh ... -c
```

---

## 🔧 Configuration

* **Logs**: Stored in `~/secure_jetson/secure-jetson.log`.
* **Work Directory**: Default `~/secure_jetson`, override with `WORK_DIR` env var.

---

## 🎨 Customization

* Edit `secure-jetson.sh` to add/remove security packages (e.g., AppArmor, SELinux).
* Tweak kernel parameters in `security-setup.sh` under `/etc/sysctl.d/99-security.conf`.
* Adjust UFW, Fail2Ban settings, or cron frequencies in the same first-boot script.

---

## 🤝 Contributing

Contributions welcome!

1. Fork repository.
2. Create a branch (`git checkout -b feature/foo`).
3. Commit your changes (`git commit -am 'Add feature'`).
4. Push to branch (`git push origin feature/foo`).
5. Open a Pull Request.

---

## 📄 License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

*Built with security-first mindset for your Jetson Nano deployments!*
