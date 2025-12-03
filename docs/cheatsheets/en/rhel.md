---
title: 'Red Hat Enterprise Linux Cheatsheet | LabEx'
description: 'Learn Red Hat Enterprise Linux (RHEL) administration with this comprehensive cheatsheet. Quick reference for RHEL commands, system management, SELinux, package management, and enterprise Linux administration.'
pdfUrl: '/cheatsheets/pdf/red-hat-linux-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Red Hat Enterprise Linux Cheatsheet
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/learn/rhel">Learn Red Hat Enterprise Linux with Hands-On Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Learn Red Hat Enterprise Linux through hands-on labs and real-world scenarios. LabEx provides comprehensive RHEL courses covering essential system administration, package management, service management, network configuration, storage management, and security. Master enterprise Linux operations and system management techniques.
</base-disclaimer-content>
</base-disclaimer>

## System Information & Monitoring

### System Version: `cat /etc/redhat-release`

Display the RHEL version and release information.

```bash
# Show RHEL version
cat /etc/redhat-release
# Alternative method
cat /etc/os-release
# Show kernel version
uname -r
# Show system architecture
uname -m
```

### System Performance: `top` / `htop`

Display running processes and system resource usage.

```bash
# Real-time process monitor
top
# Enhanced process viewer (if installed)
htop
# Show process tree
pstree
# Show all processes
ps aux
```

### Memory Information: `free` / `cat /proc/meminfo`

Display memory usage and availability.

```bash
# Show memory usage in human-readable format
free -h
# Show detailed memory information
cat /proc/meminfo
# Show swap usage
swapon --show
```

### Disk Usage: `df` / `du`

Monitor filesystem and directory usage.

```bash
# Show filesystem usage
df -h
# Show directory sizes
du -sh /var/log/*
# Show largest directories
du -h --max-depth=1 / | sort -hr
```

### System Uptime: `uptime` / `who`

Check system uptime and logged-in users.

```bash
# Show system uptime and load
uptime
# Show logged-in users
who
# Show current user
whoami
# Show last logins
last
```

### Hardware Information: `lscpu` / `lsblk`

Display hardware components and configuration.

```bash
# Show CPU information
lscpu
# Show block devices
lsblk
# Show PCI devices
lspci
# Show USB devices
lsusb
```

## Package Management

### Package Installation: `dnf install` / `yum install`

Install software packages and dependencies.

```bash
# Install a package (RHEL 8+)
sudo dnf install package-name
# Install a package (RHEL 7)
sudo yum install package-name
# Install local RPM file
sudo rpm -i package.rpm
# Install from specific repository
sudo dnf install --enablerepo=repo-
name package
```

<BaseQuiz id="rhel-package-1" correct="A">
  <template #question>
    What is the difference between <code>dnf</code> and <code>yum</code> in RHEL?
  </template>
  
  <BaseQuizOption value="A" correct>dnf is the newer package manager for RHEL 8+, yum is used in RHEL 7</BaseQuizOption>
  <BaseQuizOption value="B">dnf is for development packages, yum is for production</BaseQuizOption>
  <BaseQuizOption value="C">There is no difference, they are the same</BaseQuizOption>
  <BaseQuizOption value="D">dnf is deprecated, yum should always be used</BaseQuizOption>
  
  <BaseQuizAnswer>
    DNF (Dandified YUM) is the next-generation version of YUM and is the default package manager in RHEL 8 and later. YUM is still used in RHEL 7. DNF provides better performance and dependency resolution.
  </BaseQuizAnswer>
</BaseQuiz>

### Package Updates: `dnf update` / `yum update`

Update packages to the latest versions.

```bash
# Update all packages
sudo dnf update
# Update specific package
sudo dnf update package-name
# Check for available updates
dnf check-update
# Update security patches only
sudo dnf update --security
```

### Package Information: `dnf info` / `rpm -q`

Query package information and dependencies.

```bash
# Show package information
dnf info package-name
# List installed packages
rpm -qa
# Search for packages
dnf search keyword
# Show package dependencies
dnf deplist package-name
```

## File & Directory Operations

### Navigation: `cd` / `pwd` / `ls`

Navigate filesystem and list contents.

```bash
# Change directory
cd /path/to/directory
# Show current directory
pwd
# List files and directories
ls -la
# List with file sizes
ls -lh
# Show hidden files
ls -a
```

### File Operations: `cp` / `mv` / `rm`

Copy, move, and delete files and directories.

```bash
# Copy file
cp source.txt destination.txt
# Copy directory recursively
cp -r /source/dir/ /dest/dir/
# Move/rename file
mv oldname.txt newname.txt
# Remove file
rm filename.txt
# Remove directory recursively
rm -rf directory/
```

<BaseQuiz id="rhel-file-ops-1" correct="B">
  <template #question>
    What does <code>cp -r</code> do?
  </template>
  
  <BaseQuizOption value="A">Copies files only</BaseQuizOption>
  <BaseQuizOption value="B" correct>Copies directories recursively, including all subdirectories and files</BaseQuizOption>
  <BaseQuizOption value="C">Removes files</BaseQuizOption>
  <BaseQuizOption value="D">Renames files</BaseQuizOption>
  
  <BaseQuizAnswer>
    The <code>-r</code> flag (recursive) allows <code>cp</code> to copy directories and their contents, including all subdirectories and files within them. Without <code>-r</code>, <code>cp</code> cannot copy directories.
  </BaseQuizAnswer>
</BaseQuiz>

### File Content: `cat` / `less` / `head` / `tail`

View and examine file contents.

```bash
# Display file content
cat filename.txt
# View file page by page
less filename.txt
# Show first 10 lines
head filename.txt
# Show last 10 lines
tail filename.txt
# Follow log file in real-time
tail -f /var/log/messages
```

<BaseQuiz id="rhel-tail-1" correct="C">
  <template #question>
    What does <code>tail -f /var/log/messages</code> do?
  </template>
  
  <BaseQuizOption value="A">Shows only the first 10 lines</BaseQuizOption>
  <BaseQuizOption value="B">Deletes the log file</BaseQuizOption>
  <BaseQuizOption value="C" correct>Displays the last 10 lines and follows new entries in real-time</BaseQuizOption>
  <BaseQuizOption value="D">Archives the log file</BaseQuizOption>
  
  <BaseQuizAnswer>
    The <code>-f</code> flag makes <code>tail</code> follow the file, displaying new log entries as they are written. This is essential for real-time log monitoring and troubleshooting.
  </BaseQuizAnswer>
</BaseQuiz>

### File Permissions: `chmod` / `chown` / `chgrp`

Manage file permissions and ownership.

```bash
# Change file permissions
chmod 755 script.sh
# Change file ownership
sudo chown user:group filename.txt
# Change group ownership
sudo chgrp newgroup filename.txt
# Recursive permission change
sudo chmod -R 644 /path/to/directory/
```

### File Search: `find` / `locate` / `grep`

Search for files and content within files.

```bash
# Find files by name
find /path -name "*.txt"
# Find files by size
find /path -size +100M
# Search text in files
grep "pattern" filename.txt
# Recursive text search
grep -r "pattern" /path/to/directory/
```

### Archive & Compression: `tar` / `gzip`

Create and extract compressed archives.

```bash
# Create tar archive
tar -czf archive.tar.gz /path/to/directory/
# Extract tar archive
tar -xzf archive.tar.gz
# Create zip archive
zip -r archive.zip /path/to/directory/
# Extract zip archive
unzip archive.zip
```

## Service Management

### Service Control: `systemctl`

Manage system services using systemd.

```bash
# Start a service
sudo systemctl start service-name
# Stop a service
sudo systemctl stop service-name
# Restart a service
sudo systemctl restart service-name
# Check service status
systemctl status service-name
# Enable service at boot
sudo systemctl enable service-name
# Disable service at boot
sudo systemctl disable service-name
```

### Service Information: `systemctl list-units`

List and query system services.

```bash
# List all active services
systemctl list-units --type=service
# List all enabled services
systemctl list-unit-files --type=service --state=enabled
# Show service dependencies
systemctl list-dependencies service-name
```

### System Logs: `journalctl`

View and analyze system logs using journald.

```bash
# View all logs
journalctl
# View logs for specific service
journalctl -u service-name
# Follow logs in real-time
journalctl -f
# View logs from last boot
journalctl -b
# View logs by time range
journalctl --since "2024-01-01" --until "2024-01-31"
```

### Process Management: `ps` / `kill` / `killall`

Monitor and control running processes.

```bash
# Show running processes
ps aux
# Kill process by PID
kill 1234
# Kill process by name
killall process-name
# Force kill process
kill -9 1234
# Show process hierarchy
pstree
```

## User & Group Management

### User Management: `useradd` / `usermod` / `userdel`

Create, modify, and delete user accounts.

```bash
# Add new user
sudo useradd -m username
# Set user password
sudo passwd username
# Modify user account
sudo usermod -aG groupname
username
# Delete user account
sudo userdel -r username
# Lock user account
sudo usermod -L username
```

### Group Management: `groupadd` / `groupmod` / `groupdel`

Create, modify, and delete groups.

```bash
# Add new group
sudo groupadd groupname
# Add user to group
sudo usermod -aG groupname
username
# Remove user from group
sudo gpasswd -d username
groupname
# Delete group
sudo groupdel groupname
# List user groups
groups username
```

### Access Control: `su` / `sudo`

Switch users and execute commands with elevated privileges.

```bash
# Switch to root user
su -
# Switch to specific user
su - username
# Execute command as root
sudo command
# Edit sudoers file
sudo visudo
# Check sudo permissions
sudo -l
```

## Network Configuration

### Network Information: `ip` / `nmcli`

Display network interface and configuration details.

```bash
# Show network interfaces
ip addr show
# Show routing table
ip route show
# Show network manager connections
nmcli connection show
# Show interface status
nmcli device status
```

### Network Configuration: `nmtui` / `nmcli`

Configure network settings using NetworkManager.

```bash
# Text-based network configuration
sudo nmtui
# Add new connection
sudo nmcli connection add type ethernet con-name
"eth0" ifname eth0
# Modify connection
sudo nmcli connection modify "eth0" ipv4.addresses
192.168.1.100/24
# Activate connection
sudo nmcli connection up "eth0"
```

### Network Testing: `ping` / `curl` / `wget`

Test network connectivity and download files.

```bash
# Test connectivity
ping google.com
# Test specific port
telnet hostname 80
# Download file
wget http://example.com/file.txt
# Test HTTP requests
curl -I http://example.com
```

### Firewall Management: `firewall-cmd`

Configure firewall rules using firewalld.

```bash
# Show firewall status
sudo firewall-cmd --state
# List active zones
sudo firewall-cmd --get-active-zones
# Add service to firewall
sudo firewall-cmd --permanent --add-service=http
# Reload firewall rules
sudo firewall-cmd --reload
```

## Storage Management

### Disk Management: `fdisk` / `parted`

Create and manage disk partitions.

```bash
# List disk partitions
sudo fdisk -l
# Interactive partition editor
sudo fdisk /dev/sda
# Create partition table
sudo parted /dev/sda mklabel gpt
# Create new partition
sudo parted /dev/sda mkpart primary ext4 1MiB 100GiB
```

### Filesystem Management: `mkfs` / `mount`

Create filesystems and mount storage devices.

```bash
# Create ext4 filesystem
sudo mkfs.ext4 /dev/sda1
# Mount filesystem
sudo mount /dev/sda1 /mnt/data
# Unmount filesystem
sudo umount /mnt/data
# Check filesystem
sudo fsck /dev/sda1
```

### LVM Management: `pvcreate` / `vgcreate` / `lvcreate`

Manage Logical Volume Manager (LVM) storage.

```bash
# Create physical volume
sudo pvcreate /dev/sdb
# Create volume group
sudo vgcreate vg_data /dev/sdb
# Create logical volume
sudo lvcreate -L 10G -n lv_data vg_data
# Extend logical volume
sudo lvextend -L +5G /dev/vg_data/lv_data
```

### Mount Configuration: `/etc/fstab`

Configure permanent mount points.

```bash
# Edit fstab file
sudo vi /etc/fstab
# Test fstab entries
sudo mount -a
# Show mounted filesystems
mount | column -t
```

## Security & SELinux

### SELinux Management: `getenforce` / `setenforce`

Control SELinux enforcement and policies.

```bash
# Check SELinux status
getenforce
# Set SELinux to permissive
sudo setenforce 0
# Set SELinux to enforcing
sudo setenforce 1
# Check SELinux context
ls -Z filename
# Change SELinux context
sudo chcon -t httpd_exec_t /path/to/file
```

### SELinux Tools: `sealert` / `ausearch`

Analyze SELinux denials and audit logs.

```bash
# Check SELinux alerts
sudo sealert -a /var/log/audit/audit.log
# Search audit logs
sudo ausearch -m avc -ts recent
# Generate SELinux policy
sudo audit2allow -M mypolicy < /var/log/audit/audit.log
```

### SSH Configuration: `/etc/ssh/sshd_config`

Configure SSH daemon for secure remote access.

```bash
# Edit SSH configuration
sudo vi /etc/ssh/sshd_config
# Restart SSH service
sudo systemctl restart sshd
# Test SSH connection
ssh user@hostname
# Copy SSH key
ssh-copy-id user@hostname
```

### System Updates: `dnf update`

Keep system secure with regular updates.

```bash
# Update all packages
sudo dnf update
# Update security patches only
sudo dnf update --security
# Check for available updates
dnf check-update --security
# Enable automatic updates
sudo systemctl enable dnf-automatic.timer
```

## Performance Monitoring

### System Monitoring: `iostat` / `vmstat`

Monitor system performance and resource usage.

```bash
# Show I/O statistics
iostat -x 1
# Show virtual memory statistics
vmstat 1
# Show network statistics
ss -tuln
# Show disk I/O
iotop
```

### Resource Usage: `sar` / `top`

Analyze historical and real-time system metrics.

```bash
# System activity report
sar -u 1 3
# Memory usage report
sar -r
# Network activity report
sar -n DEV
# Load average monitoring
uptime
```

### Process Analysis: `strace` / `lsof`

Debug processes and file access.

```bash
# Trace system calls
strace -p 1234
# List open files
lsof
# Show files opened by process
lsof -p 1234
# Show network connections
lsof -i
```

### Performance Tuning: `tuned`

Optimize system performance for specific workloads.

```bash
# List available profiles
tuned-adm list
# Show active profile
tuned-adm active
# Set performance profile
sudo tuned-adm profile throughput-performance
# Create custom profile
sudo tuned-adm profile_mode
```

## RHEL Installation & Setup

### System Registration: `subscription-manager`

Register system with Red Hat Customer Portal.

```bash
# Register system
sudo subscription-manager
register --username
your_username
# Auto-attach subscriptions
sudo subscription-manager
attach --auto
# List available subscriptions
subscription-manager list --
available
# Show system status
subscription-manager status
```

### Repository Management: `dnf config-manager`

Manage software repositories.

```bash
# List enabled repositories
dnf repolist
# Enable repository
sudo dnf config-manager --
enable repository-name
# Disable repository
sudo dnf config-manager --
disable repository-name
# Add new repository
sudo dnf config-manager --add-
repo https://example.com/repo
```

### System Configuration: `hostnamectl` / `timedatectl`

Configure basic system settings.

```bash
# Set hostname
sudo hostnamectl set-hostname
new-hostname
# Show system information
hostnamectl
# Set timezone
sudo timedatectl set-timezone
America/New_York
# Show time settings
timedatectl
```

## Troubleshooting & Diagnostics

### System Logs: `/var/log/`

Examine system log files for issues.

```bash
# View system messages
sudo tail -f /var/log/messages
# View authentication logs
sudo tail -f /var/log/secure
# View boot logs
sudo journalctl -b
# View kernel messages
dmesg | tail
```

### Hardware Diagnostics: `dmidecode` / `lshw`

Examine hardware information and health.

```bash
# Show hardware information
sudo dmidecode -t system
# List hardware components
sudo lshw -short
# Check memory information
sudo dmidecode -t memory
# Show CPU information
lscpu
```

### Network Troubleshooting: `netstat` / `ss`

Network diagnostic tools and utilities.

```bash
# Show network connections
ss -tuln
# Show routing table
ip route show
# Test DNS resolution
nslookup google.com
# Trace network path
traceroute google.com
```

### Recovery & Rescue: `systemctl rescue`

System recovery and emergency procedures.

```bash
# Enter rescue mode
sudo systemctl rescue
# Enter emergency mode
sudo systemctl emergency
# Reset failed services
sudo systemctl reset-failed
# Reconfigure boot loader
sudo grub2-mkconfig -o /boot/grub2/grub.cfg
```

## Automation & Scripting

### Cron Jobs: `crontab`

Schedule automated tasks and maintenance.

```bash
# Edit user crontab
crontab -e
# List user crontab
crontab -l
# Remove user crontab
crontab -r
# Example: Run script daily at 2 AM
0 2 * * * /path/to/script.sh
```

### Shell Scripting: `bash`

Create and execute shell scripts for automation.

```bash
#!/bin/bash
# Simple backup script
DATE=$(date +%Y%m%d)
tar -czf backup_$DATE.tar.gz /home/user/documents
echo "Backup completed: backup_$DATE.tar.gz"
```

### Environment Variables: `export` / `env`

Manage environment variables and shell settings.

```bash
# Set environment variable
export MY_VAR="value"
# Show all environment variables
env
# Show specific variable
echo $PATH
# Add to PATH
export PATH=$PATH:/new/directory
```

### System Automation: `systemd timers`

Create systemd-based scheduled tasks.

```bash
# Create timer unit file
sudo vi /etc/systemd/system/backup.timer
# Enable and start timer
sudo systemctl enable backup.timer
sudo systemctl start backup.timer
# List active timers
systemctl list-timers
```

## Relevant Links

- <router-link to="/linux">Linux Cheatsheet</router-link>
- <router-link to="/shell">Shell Cheatsheet</router-link>
- <router-link to="/git">Git Cheatsheet</router-link>
- <router-link to="/docker">Docker Cheatsheet</router-link>
- <router-link to="/kubernetes">Kubernetes Cheatsheet</router-link>
- <router-link to="/ansible">Ansible Cheatsheet</router-link>
- <router-link to="/devops">DevOps Cheatsheet</router-link>
- <router-link to="/cybersecurity">Cybersecurity Cheatsheet</router-link>
