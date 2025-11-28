---
title: 'Linux Cheatsheet | LabEx'
description: 'Learn Linux administration with this comprehensive cheatsheet. Quick reference for Linux commands, file management, system administration, networking, and shell scripting.'
pdfUrl: '/cheatsheets/pdf/linux-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Linux Cheatsheet
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a href="https://linux-commands.labex.io/" target="_blank">Visit Linux Commands</a>
</base-disclaimer-title>
<base-disclaimer-content>
For comprehensive Linux command reference materials, syntax examples, and detailed documentation, please visit <a href="https://linux-commands.labex.io/" target="_blank">linux-commands.labex.io</a>. This independent site provides extensive Linux cheatsheets covering essential commands, concepts, and best practices for Linux administrators and developers.
</base-disclaimer-content>
</base-disclaimer>

## System Information & Status

### System Information: `uname`

Display system information including kernel and architecture.

```bash
# Show kernel name
uname
# Show all system information
uname -a
# Show kernel version
uname -r
# Show architecture
uname -m
# Show operating system
uname -o
```

### Hardware Information: `lscpu`, `lsblk`

View detailed hardware specifications and block devices.

```bash
# CPU information
lscpu
# Block devices (disks, partitions)
lsblk
# Memory information
free -h
# Disk usage by filesystem
df -h
```

### System Uptime: `uptime`

Show system uptime and load averages.

```bash
# System uptime and load
uptime
# More detailed uptime information
uptime -p
# Show uptime since specific date
uptime -s
```

### Current Users: `who`, `w`

Display currently logged-in users and their activities.

```bash
# Show logged-in users
who
# Detailed user information with activities
w
# Show current username
whoami
# Show login history
last
```

### Environment Variables: `env`

Display and manage environment variables.

```bash
# Show all environment variables
env
# Show specific variable
echo $HOME
# Set environment variable
export PATH=$PATH:/new/path
# Show PATH variable
echo $PATH
```

### Date & Time: `date`, `timedatectl`

Display and set system date and time.

```bash
# Current date and time
date
# Set system time (as root)
date MMddhhmmyyyy
# Time zone information
timedatectl
# Set timezone
timedatectl set-timezone America/New_York
```

## File & Directory Operations

### List Files: `ls`

Display files and directories with various formatting options.

```bash
# List files in current directory
ls
# Detailed listing with permissions
ls -l
# Show hidden files
ls -la
# Human-readable file sizes
ls -lh
# Sort by modification time
ls -lt
```

### Navigate Directories: `cd`, `pwd`

Change directories and display current location.

```bash
# Go to home directory
cd
# Go to specific directory
cd /path/to/directory
# Go up one level
cd ..
# Show current directory
pwd
# Go to previous directory
cd -
```

### Create & Remove: `mkdir`, `rmdir`, `rm`

Create and delete files and directories.

```bash
# Create directory
mkdir newdir
# Create nested directories
mkdir -p path/to/nested/dir
# Remove empty directory
rmdir dirname
# Remove file
rm filename
# Remove directory recursively
rm -rf dirname
```

### View File Contents: `cat`, `less`, `head`, `tail`

Display file contents using various methods and pagination.

```bash
# Display entire file
cat filename
# View file with pagination
less filename
# Show first 10 lines
head filename
# Show last 10 lines
tail filename
# Follow file changes in real-time
tail -f logfile
```

### Copy & Move: `cp`, `mv`

Copy and move files and directories.

```bash
# Copy file
cp source.txt destination.txt
# Copy directory recursively
cp -r sourcedir/ destdir/
# Move/rename file
mv oldname.txt newname.txt
# Move to different directory
mv file.txt /path/to/destination/
# Copy with preservation of attributes
cp -p file.txt backup.txt
```

### Find Files: `find`, `locate`

Search for files and directories by name, type, or properties.

```bash
# Find by name
find /path -name "filename"
# Find files modified in last 7 days
find /path -mtime -7
# Find by file type
find /path -type f -name "*.txt"
# Locate files quickly (requires updatedb)
locate filename
# Find and execute command
find /path -name "*.log" -exec rm {} \;
```

### File Permissions: `chmod`, `chown`

Modify file permissions and ownership.

```bash
# Change permissions (numeric)
chmod 755 filename
# Add execute permission
chmod +x script.sh
# Change ownership
chown user:group filename
# Change ownership recursively
chown -R user:group directory/
# View file permissions
ls -l filename
```

## Process Management

### Process Listing: `ps`

Display running processes and their details.

```bash
# Show user processes
ps
# Show all processes with details
ps aux
# Show process tree
ps -ef --forest
# Show processes by user
ps -u username
```

### Kill Processes: `kill`, `killall`

Terminate processes by PID or name.

```bash
# Real-time process monitor
top
# Kill process by PID
kill 1234
# Force kill process
kill -9 1234
# Kill by process name
killall processname
# List all signals
kill -l
# Send specific signal
kill -HUP 1234
```

### Background Jobs: `jobs`, `bg`, `fg`

Manage background and foreground processes.

```bash
# List active jobs
jobs
# Send job to background
bg %1
# Bring job to foreground
fg %1
# Run command in background
command &
# Detach from terminal
nohup command &
```

### System Monitor: `htop`, `systemctl`

Monitor system resources and manage services.

```bash
# Enhanced process viewer (if installed)
htop
# Check service status
systemctl status servicename
# Start service
systemctl start servicename
# Enable service at boot
systemctl enable servicename
# View system logs
journalctl -f
```

## Network Operations

### Network Configuration: `ip`, `ifconfig`

Display and configure network interfaces.

```bash
# Show network interfaces
ip addr show
# Show routing table
ip route show
# Configure interface (temporary)
ip addr add 192.168.1.10/24 dev eth0
# Bring interface up/down
ip link set eth0 up
# Legacy interface configuration
ifconfig
```

### Network Testing: `ping`, `traceroute`

Test network connectivity and trace packet routes.

```bash
# Test connectivity
ping google.com
# Ping with count limit
ping -c 4 192.168.1.1
# Trace route to destination
traceroute google.com
# MTR - network diagnostic tool
mtr google.com
```

### Port & Connection Analysis: `netstat`, `ss`

Display network connections and listening ports.

```bash
# Show all connections
netstat -tuln
# Show listening ports
netstat -tuln | grep LISTEN
# Modern replacement for netstat
ss -tuln
# Show processes using ports
netstat -tulnp
# Check specific port
netstat -tuln | grep :80
```

### File Transfer: `scp`, `rsync`

Securely transfer files between systems.

```bash
# Copy file to remote host
scp file.txt user@host:/path/
# Copy from remote host
scp user@host:/path/file.txt ./
# Synchronize directories
rsync -avz localdir/ user@host:/remotedir/
# Rsync with progress
rsync -avz --progress src/ dest/
```

## Text Processing & Search

### Text Search: `grep`

Search for patterns in files and command output.

```bash
# Search for pattern in file
grep "pattern" filename
# Case-insensitive search
grep -i "pattern" filename
# Recursive search in directories
grep -r "pattern" /path/
# Show line numbers
grep -n "pattern" filename
# Count matching lines
grep -c "pattern" filename
```

### Text Manipulation: `sed`, `awk`

Edit and process text using stream editors and pattern scanners.

```bash
# Replace text in file
sed 's/old/new/g' filename
# Delete lines containing pattern
sed '/pattern/d' filename
# Print specific fields
awk '{print $1, $3}' filename
# Sum values in column
awk '{sum += $1} END {print sum}' filename
```

### Sort & Count: `sort`, `uniq`, `wc`

Sort data, remove duplicates, and count lines, words, or characters.

```bash
# Sort file contents
sort filename
# Sort numerically
sort -n numbers.txt
# Remove duplicate lines
uniq filename
# Sort and remove duplicates
sort filename | uniq
# Count lines, words, characters
wc filename
# Count only lines
wc -l filename
```

### Cut & Paste: `cut`, `paste`

Extract specific columns and combine files.

```bash
# Extract first column
cut -d',' -f1 file.csv
# Extract character range
cut -c1-10 filename
# Combine files side by side
paste file1.txt file2.txt
# Use custom delimiter
cut -d':' -f1,3 /etc/passwd
```

## Archive & Compression

### Create Archives: `tar`

Create and extract compressed archives.

```bash
# Create tar archive
tar -cf archive.tar files/
# Create compressed archive
tar -czf archive.tar.gz files/
# Extract archive
tar -xf archive.tar
# Extract compressed archive
tar -xzf archive.tar.gz
# List archive contents
tar -tf archive.tar
```

### Compression: `gzip`, `zip`

Compress and decompress files using various algorithms.

```bash
# Compress file with gzip
gzip filename
# Decompress gzip file
gunzip filename.gz
# Create zip archive
zip archive.zip file1 file2
# Extract zip archive
unzip archive.zip
# List zip contents
unzip -l archive.zip
```

### Advanced Archives: `tar` Options

Advanced tar operations for backup and restoration.

```bash
# Create archive with compression
tar -czvf backup.tar.gz /home/user/
# Extract to specific directory
tar -xzf archive.tar.gz -C /destination/
# Add files to existing archive
tar -rf archive.tar newfile.txt
# Update archive with newer files
tar -uf archive.tar files/
```

### Disk Space: `du`

Analyze disk usage and directory sizes.

```bash
# Show directory sizes
du -h /path/
# Summary of total size
du -sh /path/
# Show sizes of all subdirectories
du -h --max-depth=1 /path/
# Largest directories first
du -h | sort -hr | head -10
```

## System Monitoring & Performance

### Memory Usage: `free`, `vmstat`

Monitor memory usage and virtual memory statistics.

```bash
# Memory usage summary
free -h
# Detailed memory stats
cat /proc/meminfo
# Virtual memory statistics
vmstat
# Memory usage every 2 seconds
vmstat 2
# Show swap usage
swapon --show
```

### Disk I/O: `iostat`, `iotop`

Monitor disk input/output performance and identify bottlenecks.

```bash
# I/O statistics (requires sysstat)
iostat
# I/O stats every 2 seconds
iostat 2
# Monitor disk I/O by process
iotop
# Show I/O usage for specific device
iostat -x /dev/sda
```

### System Load: `top`, `htop`

Monitor system load, CPU usage, and running processes.

```bash
# Real-time process monitor
top
# Enhanced process viewer
htop
# Show load averages
uptime
# Show CPU information
lscpu
# Monitor specific process
top -p PID
```

### Log Files: `journalctl`, `dmesg`

View and analyze system logs for troubleshooting.

```bash
# View system logs
journalctl
# Follow logs in real-time
journalctl -f
# Show logs for specific service
journalctl -u servicename
# Kernel messages
dmesg
# Last boot messages
dmesg | tail
```

## User & Permission Management

### User Operations: `useradd`, `usermod`, `userdel`

Create, modify, and delete user accounts.

```bash
# Add new user
useradd username
# Add user with home directory
useradd -m username
# Modify user account
usermod -aG groupname username
# Delete user account
userdel username
# Delete user with home directory
userdel -r username
```

### Group Management: `groupadd`, `groups`

Create and manage user groups.

```bash
# Create new group
groupadd groupname
# Show user's groups
groups username
# Show all groups
cat /etc/group
# Add user to group
usermod -aG groupname username
# Change user's primary group
usermod -g groupname username
```

### Switch Users: `su`, `sudo`

Switch users and execute commands with elevated privileges.

```bash
# Switch to root user
su -
# Switch to specific user
su - username
# Execute command as root
sudo command
# Execute command as specific user
sudo -u username command
# Edit sudoers file
visudo
```

### Password Management: `passwd`, `chage`

Manage user passwords and account policies.

```bash
# Change password
passwd
# Change another user's password (as root)
passwd username
# Show password aging info
chage -l username
# Set password expiry
chage -M 90 username
# Force password change on next login
passwd -e username
```

## Package Management

### APT (Debian/Ubuntu): `apt`, `apt-get`

Manage packages on Debian-based systems.

```bash
# Update package list
apt update
# Upgrade all packages
apt upgrade
# Install package
apt install packagename
# Remove package
apt remove packagename
# Search for packages
apt search packagename
# Show package information
apt show packagename
```

### YUM/DNF (RHEL/Fedora): `yum`, `dnf`

Manage packages on Red Hat-based systems.

```bash
# Install package
yum install packagename
# Update all packages
yum update
# Remove package
yum remove packagename
# Search for packages
yum search packagename
# List installed packages
yum list installed
```

### Snap Packages: `snap`

Install and manage snap packages across distributions.

```bash
# Install snap package
snap install packagename
# List installed snaps
snap list
# Update snap packages
snap refresh
# Remove snap package
snap remove packagename
# Search for snap packages
snap find packagename
```

### Flatpak Packages: `flatpak`

Manage Flatpak applications for sandboxed software.

```bash
# Install flatpak
flatpak install packagename
# List installed flatpaks
flatpak list
# Update flatpak packages
flatpak update
# Remove flatpak
flatpak uninstall packagename
# Search flatpak packages
flatpak search packagename
```

## Shell & Scripting

### Command History: `history`

Access and manage command line history.

```bash
# Show command history
history
# Show last 10 commands
history 10
# Execute previous command
!!
# Execute command by number
!123
# Search history interactively
Ctrl+R
```

### Aliases & Functions: `alias`

Create shortcuts for frequently used commands.

```bash
# Create alias
alias ll='ls -la'
# Show all aliases
alias
# Remove alias
unalias ll
# Make alias permanent (add to .bashrc)
echo "alias ll='ls -la'" >> ~/.bashrc
```

### Input/Output Redirection

Redirect command input and output to files or other commands.

```bash
# Redirect output to file
command > output.txt
# Append output to file
command >> output.txt
# Redirect input from file
command < input.txt
# Redirect both stdout and stderr
command &> output.txt
# Pipe output to another command
command1 | command2
```

### Environment Setup: `.bashrc`, `.profile`

Configure shell environment and startup scripts.

```bash
# Edit bash configuration
nano ~/.bashrc
# Reload configuration
source ~/.bashrc
# Set environment variable
export VARIABLE=value
# Add to PATH
export PATH=$PATH:/new/path
# Show environment variables
printenv
```

## System Installation & Setup

### Distribution Options: Ubuntu, CentOS, Debian

Choose and install Linux distributions for different use cases.

```bash
# Ubuntu Server
wget ubuntu-server.iso
# CentOS Stream
wget centos-stream.iso
# Debian Stable
wget debian.iso
# Verify ISO integrity
sha256sum linux.iso
```

### Boot & Installation: USB, Network

Create bootable media and perform system installation.

```bash
# Create bootable USB (Linux)
dd if=linux.iso of=/dev/sdX bs=4M
# Create bootable USB (cross-platform)
# Use tools like Rufus, Etcher, or UNetbootin
# Network installation
# Configure PXE boot for network installs
```

### Initial Configuration: Users, Network, SSH

Set up basic system configuration after installation.

```bash
# Set hostname
hostnamectl set-hostname newname
# Configure static IP
# Edit /etc/netplan/ (Ubuntu) or /etc/network/interfaces
# Enable SSH service
systemctl enable ssh
systemctl start ssh
# Configure firewall
ufw enable
ufw allow ssh
```

## Security & Best Practices

### Firewall Configuration: `ufw`, `iptables`

Configure firewall rules to protect system from network threats.

```bash
# Enable UFW firewall
ufw enable
# Allow specific port
ufw allow 22/tcp
# Allow service by name
ufw allow ssh
# Deny access
ufw deny 23
# Show firewall status
ufw status verbose
# Advanced rules with iptables
iptables -L
```

### File Integrity: `checksums`

Verify file integrity and detect unauthorized changes.

```bash
# Generate MD5 checksum
md5sum filename
# Generate SHA256 checksum
sha256sum filename
# Verify checksum
sha256sum -c checksums.txt
# Create checksum file
sha256sum *.txt > checksums.txt
```

### System Updates: Security Patches

Keep system secure with regular updates and security patches.

```bash
# Ubuntu security updates
apt update && apt upgrade
# Automatic security updates
unattended-upgrades
# CentOS/RHEL updates
yum update --security
# List available updates
apt list --upgradable
```

### Log Monitoring: Security Events

Monitor system logs for security events and anomalies.

```bash
# Monitor authentication logs
tail -f /var/log/auth.log
# Check failed login attempts
grep "Failed password" /var/log/auth.log
# Monitor system logs
tail -f /var/log/syslog
# View login history
last
# Check for suspicious activities
journalctl -p err
```

## Troubleshooting & Recovery

### Boot Issues: GRUB Recovery

Recover from boot loader and kernel problems.

```bash
# Boot from rescue mode
# Access GRUB menu during boot
# Mount root filesystem
mount /dev/sda1 /mnt
# Chroot into system
chroot /mnt
# Reinstall GRUB
grub-install /dev/sda
# Update GRUB configuration
update-grub
```

### File System Repair: `fsck`

Check and repair file system corruption.

```bash
# Check file system
fsck /dev/sda1
# Force file system check
fsck -f /dev/sda1
# Automatic repair
fsck -y /dev/sda1
# Check all mounted filesystems
fsck -A
```

### Service Issues: `systemctl`

Diagnose and fix service-related problems.

```bash
# Check service status
systemctl status servicename
# View service logs
journalctl -u servicename
# Restart failed service
systemctl restart servicename
# Enable service at boot
systemctl enable servicename
# List failed services
systemctl --failed
```

### Performance Issues: Resource Analysis

Identify and resolve system performance bottlenecks.

```bash
# Check disk space
df -h
# Monitor I/O usage
iotop
# Check memory usage
free -h
# Identify CPU usage
top
# List open files
lsof
```

## Relevant Links

- <router-link to="/shell">Shell Cheatsheet</router-link>
- <router-link to="/rhel">Red Hat Enterprise Linux Cheatsheet</router-link>
- <router-link to="/docker">Docker Cheatsheet</router-link>
- <router-link to="/kubernetes">Kubernetes Cheatsheet</router-link>
- <router-link to="/git">Git Cheatsheet</router-link>
- <router-link to="/ansible">Ansible Cheatsheet</router-link>
- <router-link to="/devops">DevOps Cheatsheet</router-link>
- <router-link to="/cybersecurity">Cybersecurity Cheatsheet</router-link>
