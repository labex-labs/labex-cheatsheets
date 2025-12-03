---
title: 'Shell Cheatsheet | LabEx'
description: 'Learn shell scripting with this comprehensive cheatsheet. Quick reference for bash commands, shell scripting, automation, command-line tools, and Linux/Unix system administration.'
pdfUrl: '/cheatsheets/pdf/shell-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
Shell Cheatsheet
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/learn/shell">Learn Shell with Hands-On Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Learn Shell scripting and command-line operations through hands-on labs and real-world scenarios. LabEx provides comprehensive Shell courses covering essential Bash commands, file operations, text processing, process management, and automation. Master command-line efficiency and shell scripting techniques.
</base-disclaimer-content>
</base-disclaimer>

## File & Directory Operations

### List Files: `ls`

Display files and directories in the current location.

```bash
# List files in current directory
ls
# List with detailed information
ls -l
# Show hidden files
ls -a
# List with human-readable file sizes
ls -lh
# Sort by modification time
ls -lt
```

### Create Files: `touch`

Create empty files or update timestamps.

```bash
# Create a new file
touch newfile.txt
# Create multiple files
touch file1.txt file2.txt file3.txt
# Update timestamp of existing file
touch existing_file.txt
```

### Create Directories: `mkdir`

Create new directories.

```bash
# Create a directory
mkdir my_directory
# Create nested directories
mkdir -p parent/child/grandchild
# Create multiple directories
mkdir dir1 dir2 dir3
```

### Copy Files: `cp`

Copy files and directories.

```bash
# Copy a file
cp source.txt destination.txt
# Copy directory recursively
cp -r source_dir dest_dir
# Copy with confirmation prompt
cp -i file1.txt file2.txt
# Preserve file attributes
cp -p original.txt copy.txt
```

### Move/Rename: `mv`

Move or rename files and directories.

```bash
# Rename a file
mv oldname.txt newname.txt
# Move file to directory
mv file.txt /path/to/directory/
# Move multiple files
mv file1 file2 file3 target_directory/
```

### Delete Files: `rm`

Remove files and directories.

```bash
# Delete a file
rm file.txt
# Delete directory and contents
rm -r directory/
# Force delete without confirmation
rm -f file.txt
# Interactive deletion (confirm each)
rm -i *.txt
```

## Navigation & Path Management

### Current Directory: `pwd`

Print the current working directory path.

```bash
# Show current directory
pwd
# Example output:
/home/user/documents
```

### Change Directory: `cd`

Change to a different directory.

```bash
# Go to home directory
cd ~
# Go to parent directory
cd ..
# Go to previous directory
cd -
# Go to specific directory
cd /path/to/directory
```

<BaseQuiz id="shell-cd-1" correct="A">
  <template #question>
    What does <code>cd ~</code> do?
  </template>
  
  <BaseQuizOption value="A" correct>Changes to the home directory</BaseQuizOption>
  <BaseQuizOption value="B">Changes to the root directory</BaseQuizOption>
  <BaseQuizOption value="C">Changes to the parent directory</BaseQuizOption>
  <BaseQuizOption value="D">Creates a new directory</BaseQuizOption>
  
  <BaseQuizAnswer>
    The <code>~</code> symbol is a shortcut for the home directory. <code>cd ~</code> navigates to your home directory, which is equivalent to <code>cd $HOME</code> or <code>cd /home/username</code>.
  </BaseQuizAnswer>
</BaseQuiz>

### Directory Tree: `tree`

Display directory structure in tree format.

```bash
# Show directory tree
tree
# Limit depth to 2 levels
tree -L 2
# Show only directories
tree -d
```

## Text Processing & Search

### View Files: `cat` / `less` / `head` / `tail`

Display file contents in different ways.

```bash
# Display entire file
cat file.txt
# View file page by page
less file.txt
# Show first 10 lines
head file.txt
# Show last 10 lines
tail file.txt
# Show last 20 lines
tail -n 20 file.txt
# Follow file changes (useful for logs)
tail -f logfile.txt
```

### Search in Files: `grep`

Search for patterns in text files.

```bash
# Search for pattern in file
grep "pattern" file.txt
# Case-insensitive search
grep -i "pattern" file.txt
# Search recursively in directories
grep -r "pattern" directory/
# Show line numbers
grep -n "pattern" file.txt
# Count matching lines
grep -c "pattern" file.txt
```

<BaseQuiz id="shell-grep-1" correct="B">
  <template #question>
    What does <code>grep -r "pattern" directory/</code> do?
  </template>
  
  <BaseQuizOption value="A">Searches only in the current file</BaseQuizOption>
  <BaseQuizOption value="B" correct>Searches recursively through all files in the directory</BaseQuizOption>
  <BaseQuizOption value="C">Replaces the pattern in files</BaseQuizOption>
  <BaseQuizOption value="D">Deletes files containing the pattern</BaseQuizOption>
  
  <BaseQuizAnswer>
    The <code>-r</code> flag makes grep search recursively through all files and subdirectories. This is useful for finding text patterns across an entire directory tree.
  </BaseQuizAnswer>
</BaseQuiz>

### Find Files: `find`

Locate files and directories based on criteria.

```bash
# Find files by name
find . -name "*.txt"
# Find files by type
find . -type f -name "config*"
# Find directories
find . -type d -name "backup"
# Find files modified in last 7 days
find . -mtime -7
# Find and execute command
find . -name "*.log" -delete
```

### Text Manipulation: `sed` / `awk` / `sort`

Process and manipulate text data.

```bash
# Replace text in file
sed 's/old/new/g' file.txt
# Extract specific columns
awk '{print $1, $3}' file.txt
# Sort file contents
sort file.txt
# Remove duplicate lines
sort file.txt | uniq
# Count word frequency
cat file.txt | tr ' ' '\n' | sort | uniq -c
```

## File Permissions & Ownership

### View Permissions: `ls -l`

Display detailed file permissions and ownership.

```bash
# Show detailed file information
ls -l
# Example output:
# -rw-r--r-- 1 user group 1024 Jan 1 12:00 file.txt
# d = directory, r = read, w = write, x = execute
```

### Change Permissions: `chmod`

Modify file and directory permissions.

```bash
# Give execute permission to owner
chmod +x script.sh
# Set specific permissions (755)
chmod 755 file.txt
# Remove write permission for group/others
chmod go-w file.txt
# Recursive permission change
chmod -R 644 directory/
```

<BaseQuiz id="shell-chmod-1" correct="C">
  <template #question>
    What does <code>chmod 755 file.txt</code> set?
  </template>
  
  <BaseQuizOption value="A">Read, write, execute for all users</BaseQuizOption>
  <BaseQuizOption value="B">Read and write for owner, read for others</BaseQuizOption>
  <BaseQuizOption value="C" correct>Read, write, execute for owner; read, execute for group and others</BaseQuizOption>
  <BaseQuizOption value="D">Read only for all users</BaseQuizOption>
  
  <BaseQuizAnswer>
    <code>chmod 755</code> sets permissions as: owner = 7 (rwx), group = 5 (r-x), others = 5 (r-x). This is a common permission set for executable files and directories.
  </BaseQuizAnswer>
</BaseQuiz>

### Change Ownership: `chown` / `chgrp`

Change file owner and group.

```bash
# Change owner
chown newowner file.txt
# Change owner and group
chown newowner:newgroup file.txt
# Change group only
chgrp newgroup file.txt
# Recursive ownership change
chown -R user:group directory/
```

### Permission Numbers

Understanding numeric permission notation.

```text
# Permission calculation:
# 4 = read (r), 2 = write (w), 1 = execute (x)
# 755 = rwxr-xr-x (owner: rwx, group: r-x, others: r-x)
# 644 = rw-r--r-- (owner: rw-, group: r--, others: r--)
# 777 = rwxrwxrwx (full permissions for all)
# 600 = rw------- (owner: rw-, group: ---, others: ---)
```

## Process Management

### View Processes: `ps` / `top` / `htop`

Display information about running processes.

```bash
# Show processes for current user
ps
# Show all processes with details
ps aux
# Show processes in tree format
ps -ef --forest
# Interactive process viewer
top
# Enhanced process viewer (if available)
htop
```

### Background Jobs: `&` / `jobs` / `fg` / `bg`

Manage background and foreground processes.

```bash
# Run command in background
command &
# List active jobs
jobs
# Bring job to foreground
fg %1
# Send job to background
bg %1
# Suspend current process
Ctrl+Z
```

### Kill Processes: `kill` / `killall`

Terminate processes by PID or name.

```bash
# Kill process by PID
kill 1234
# Force kill process
kill -9 1234
# Kill all processes with name
killall firefox
# Send specific signal
kill -TERM 1234
```

### System Monitoring: `free` / `df` / `du`

Monitor system resources and disk usage.

```bash
# Show memory usage
free -h
# Show disk space
df -h
# Show directory size
du -sh directory/
# Show largest directories
du -h --max-depth=1 | sort -hr
```

## Input/Output Redirection

### Redirection: `>` / `>>` / `<`

Redirect command output and input.

```bash
# Redirect output to file (overwrite)
command > output.txt
# Append output to file
command >> output.txt
# Redirect input from file
command < input.txt
# Redirect both output and errors
command > output.txt 2>&1
# Discard output
command > /dev/null
```

<BaseQuiz id="shell-redirect-1" correct="B">
  <template #question>
    What is the difference between <code>></code> and <code>>></code> in shell redirection?
  </template>
  
  <BaseQuizOption value="A"><code>></code> appends, <code>>></code> overwrites</BaseQuizOption>
  <BaseQuizOption value="B" correct><code>></code> overwrites the file, <code>>></code> appends to the file</BaseQuizOption>
  <BaseQuizOption value="C"><code>></code> redirects stdout, <code>>></code> redirects stderr</BaseQuizOption>
  <BaseQuizOption value="D">There is no difference</BaseQuizOption>
  
  <BaseQuizAnswer>
    The <code>></code> operator overwrites the target file if it exists, while <code>>></code> appends output to the end of the file. Use <code>>></code> when you want to preserve existing content.
  </BaseQuizAnswer>
</BaseQuiz>

### Pipes: `|`

Chain commands together using pipes.

```bash
# Basic pipe usage
command1 | command2
# Multiple pipes
cat file.txt | grep "pattern" | sort | uniq
# Count lines in output
ps aux | wc -l
# Page through long output
ls -la | less
```

### Tee: `tee`

Write output to both file and stdout.

```bash
# Save output and display it
command | tee output.txt
# Append to file
command | tee -a output.txt
# Multiple outputs
command | tee file1.txt file2.txt
```

### Here Documents: `<<`

Provide multi-line input to commands.

```bash
# Create file with here document
cat << EOF > file.txt
Line 1
Line 2
Line 3
EOF
# Send email with here document
mail user@example.com << EOF
Subject: Test
This is a test message.
EOF
```

## Variables & Environment

### Variables: Assignment & Usage

Create and use shell variables.

```bash
# Assign variables (no spaces around =)
name="John"
count=42
# Use variables
echo $name
echo "Hello, $name"
echo "Count: ${count}"
# Command substitution
current_dir=$(pwd)
date_today=$(date +%Y-%m-%d)
```

### Environment Variables: `export` / `env`

Manage environment variables.

```bash
# Export variable to environment
export PATH="/new/path:$PATH"
export MY_VAR="value"
# View all environment variables
env
# View specific variable
echo $HOME
echo $PATH
# Unset variable
unset MY_VAR
```

### Special Variables

Built-in shell variables with special meanings.

```bash
# Script arguments
$0  # Script name
$1, $2, $3...  # First, second, third argument
$#  # Number of arguments
$@  # All arguments as separate words
$*  # All arguments as single word
$?  # Exit status of last command
# Process information
$$  # Current shell PID
$!  # PID of last background command
```

### Parameter Expansion

Advanced variable manipulation techniques.

```bash
# Default values
${var:-default}  # Use default if var is empty
${var:=default}  # Set var to default if empty
# String manipulation
${var#pattern}   # Remove shortest match from
beginning
${var##pattern}  # Remove longest match from
beginning
${var%pattern}   # Remove shortest match from end
${var%%pattern}  # Remove longest match from end
```

## Scripting Basics

### Script Structure

Basic script format and execution.

```bash
#!/bin/bash
# This is a comment
# Variables
greeting="Hello, World!"
user=$(whoami)
# Output
echo $greeting
echo "Current user: $user"
# Make script executable:
chmod +x script.sh
# Run script:
./script.sh
```

### Conditional Statements: `if`

Control script flow with conditions.

```bash
#!/bin/bash
if [ -f "file.txt" ]; then
    echo "File exists"
elif [ -d "directory" ]; then
    echo "Directory exists"
else
    echo "Neither exists"
fi
# String comparison
if [ "$USER" = "root" ]; then
    echo "Running as root"
fi
# Numeric comparison
if [ $count -gt 10 ]; then
    echo "Count is greater than 10"
fi
```

### Loops: `for` / `while`

Repeat commands using loops.

```bash
#!/bin/bash
# For loop with range
for i in {1..5}; do
    echo "Number: $i"
done
# For loop with files
for file in *.txt; do
    echo "Processing: $file"
done
# While loop
count=1
while [ $count -le 5 ]; do
    echo "Count: $count"
    count=$((count + 1))
done
```

### Functions

Create reusable code blocks.

```bash
#!/bin/bash
# Define function
greet() {
    local name=$1
    echo "Hello, $name!"
}
# Function with return value
add_numbers() {
    local sum=$(($1 + $2))
    echo $sum
}
# Call functions
greet "Alice"
result=$(add_numbers 5 3)
echo "Sum: $result"
```

## Network & System Commands

### Network Commands

Test connectivity and network configuration.

```bash
# Test network connectivity
ping google.com
ping -c 4 google.com  # Send only 4 packets
# DNS lookup
nslookup google.com
dig google.com
# Network configuration
ip addr show  # Show IP addresses
ip route show # Show routing table
# Download files
wget https://example.com/file.txt
curl -O https://example.com/file.txt
```

### System Information: `uname` / `whoami` / `date`

Get system and user information.

```bash
# System information
uname -a      # All system info
uname -r      # Kernel version
hostname      # Computer name
whoami        # Current username
id            # User ID and groups
# Date and time
date          # Current date/time
date +%Y-%m-%d # Custom format
uptime        # System uptime
```

### Archive & Compression: `tar` / `zip`

Create and extract compressed archives.

```bash
# Create tar archive
tar -czf archive.tar.gz directory/
# Extract tar archive
tar -xzf archive.tar.gz
# Create zip archive
zip -r archive.zip directory/
# Extract zip archive
unzip archive.zip
# View archive contents
tar -tzf archive.tar.gz
unzip -l archive.zip
```

### File Transfer: `scp` / `rsync`

Transfer files between systems.

```bash
# Copy file to remote server
scp file.txt user@server:/path/to/destination
# Copy from remote server
scp user@server:/path/to/file.txt .
# Sync directories (local to remote)
rsync -avz local_dir/ user@server:/remote_dir/
# Sync with delete (mirror)
rsync -avz --delete local_dir/ user@server:/remote_dir/
```

## Command History & Shortcuts

### Command History: `history`

View and reuse previous commands.

```bash
# Show command history
history
# Show last 10 commands
history 10
# Execute previous command
!!
# Execute command by number
!123
# Execute last command starting with 'ls'
!ls
# Search history interactively
Ctrl+R
```

### History Expansion

Reuse parts of previous commands.

```bash
# Last command's arguments
!$    # Last argument of previous command
!^    # First argument of previous command
!*    # All arguments of previous command
# Example usage:
ls /very/long/path/to/file.txt
cd !$  # Goes to /very/long/path/to/file.txt
```

### Keyboard Shortcuts

Essential shortcuts for efficient command line usage.

```bash
# Navigation
Ctrl+A  # Move to beginning of line
Ctrl+E  # Move to end of line
Ctrl+F  # Move forward one character
Ctrl+B  # Move backward one character
Alt+F   # Move forward one word
Alt+B   # Move backward one word
# Editing
Ctrl+U  # Clear line before cursor
Ctrl+K  # Clear line after cursor
Ctrl+W  # Delete word before cursor
Ctrl+Y  # Paste last deleted text
# Process control
Ctrl+C  # Interrupt current command
Ctrl+Z  # Suspend current command
Ctrl+D  # Exit shell or EOF
```

## Command Combinations & Tips

### Useful Command Combinations

Powerful one-liners for common tasks.

```bash
# Find and replace text in multiple files
find . -name "*.txt" -exec sed -i 's/old/new/g' {} \;
# Find largest files in current directory
du -ah . | sort -rh | head -10
# Monitor log file for specific pattern
tail -f /var/log/syslog | grep "ERROR"
# Count files in directory
ls -1 | wc -l
# Create backup with timestamp
cp file.txt file.txt.backup.$(date +%Y%m%d-%H%M%S)
```

### Aliases & Functions

Create shortcuts for frequently used commands.

```bash
# Create aliases (add to ~/.bashrc)
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'
# View all aliases
alias
# Create persistent aliases in ~/.bashrc:
echo "alias mycommand='long command here'" >>
~/.bashrc
source ~/.bashrc
```

### Job Control & Screen Sessions

Manage long-running processes and sessions.

```bash
# Start command in background
nohup long_running_command &
# Start screen session
screen -S mysession
# Detach from screen: Ctrl+A then D
# Reattach to screen
screen -r mysession
# List screen sessions
screen -ls
# Alternative: tmux
tmux new -s mysession
# Detach: Ctrl+B then D
tmux attach -t mysession
```

### System Maintenance

Common system administration tasks.

```bash
# Check disk usage
df -h
du -sh /*
# Check memory usage
free -h
cat /proc/meminfo
# Check running services
systemctl status service_name
systemctl list-units --type=service
# Update package lists (Ubuntu/Debian)
sudo apt update && sudo apt upgrade
# Search for installed packages
dpkg -l | grep package_name
```

## Relevant Links

- <router-link to="/linux">Linux Cheatsheet</router-link>
- <router-link to="/rhel">Red Hat Enterprise Linux Cheatsheet</router-link>
- <router-link to="/git">Git Cheatsheet</router-link>
- <router-link to="/docker">Docker Cheatsheet</router-link>
- <router-link to="/kubernetes">Kubernetes Cheatsheet</router-link>
- <router-link to="/ansible">Ansible Cheatsheet</router-link>
- <router-link to="/devops">DevOps Cheatsheet</router-link>
- <router-link to="/python">Python Cheatsheet</router-link>
