---
title: 'CompTIA Cheatsheet | LabEx'
description: 'Learn CompTIA IT certifications with this comprehensive cheatsheet. Quick reference for CompTIA A+, Network+, Security+, Linux+, and IT fundamentals for certification exam preparation.'
pdfUrl: '/cheatsheets/pdf/comptia-cheatsheet.pdf'
---

<base-title :title="frontmatter.title" :description="frontmatter.description">
CompTIA Cheatsheet
</base-title>

<base-pdf-url :url="frontmatter.pdfUrl" />

<base-disclaimer>
<base-disclaimer-title>
<a target="_blank" href="https://labex.io/learn/comptia">Learn CompTIA with Hands-On Labs</a>
</base-disclaimer-title>
<base-disclaimer-content>
Learn CompTIA certifications through hands-on labs and real-world scenarios. LabEx provides comprehensive CompTIA courses covering A+, Network+, Security+, and specialized certifications. Master IT fundamentals, networking, security, and advance your IT career with industry-recognized credentials.
</base-disclaimer-content>
</base-disclaimer>

## CompTIA Certification Overview

### Core Certifications

Foundation certifications for IT career success.

```text
# CompTIA A+ (220-1101, 220-1102)
- Hardware and mobile devices
- Operating systems and software
- Security and networking basics
- Operational procedures

# CompTIA Network+ (N10-008)
- Network fundamentals
- Network implementations
- Network operations
- Network security
- Network troubleshooting

# CompTIA Security+ (SY0-601)
- Attacks, threats, and vulnerabilities
- Architecture and design
- Implementation
- Operations and incident response
- Governance, risk, and compliance
```

### Specialized Certifications

Advanced and specialized IT credentials.

```text
# CompTIA PenTest+ (PT0-002)
- Planning and scoping penetration tests
- Information gathering and vulnerability identification
- Attacks and exploits
- Reporting and communication

# CompTIA CySA+ (CS0-002)
- Threat and vulnerability management
- Software and systems security
- Security operations and monitoring
- Incident response
- Compliance and assessment

# CompTIA Cloud+ (CV0-003)
- Cloud architecture and design
- Security
- Deployment
- Operations and support
- Troubleshooting

# CompTIA Server+ (SK0-005)
- Server hardware installation and management
- Server administration
- Security and disaster recovery
- Troubleshooting

# CompTIA Project+ (PK0-005)
- Project life cycle
- Project tools and documentation
- Basics of project cost and time management
- Project execution and closure

# CompTIA Linux+ (XK0-005)
- System management
- Security
- Scripting and containers
- Troubleshooting
```

## CompTIA A+ Essentials

### Hardware Components

Essential computer hardware knowledge and troubleshooting.

```text
# CPU Types and Features
- Intel vs AMD processors
- Socket types (LGA, PGA, BGA)
- Core counts and threading
- Cache levels (L1, L2, L3)

# Memory (RAM)
- DDR4, DDR5 specifications
- ECC vs non-ECC memory
- SODIMM vs DIMM form factors
- Memory channels and speeds

# Storage Technologies
- HDD vs SSD vs NVMe
- SATA, PCIe interfaces
- RAID configurations (0,1,5,10)
- M.2 form factors
```

### Mobile Devices

Smartphones, tablets, and mobile device management.

```text
# Mobile Device Types
- iOS vs Android architecture
- Laptop vs tablet form factors
- Wearable devices
- E-readers and smart devices

# Mobile Connectivity
- Wi-Fi standards (802.11a/b/g/n/ac/ax)
- Cellular technologies (3G, 4G, 5G)
- Bluetooth versions and profiles
- NFC and mobile payments

# Mobile Security
- Screen locks and biometrics
- Mobile device management (MDM)
- App security and permissions
- Remote wipe capabilities
```

### Operating Systems

Windows, macOS, Linux, and mobile OS management.

```text
# Windows Administration
- Windows 10/11 editions
- User Account Control (UAC)
- Group Policy and Registry
- Windows Update management

# macOS Management
- System Preferences
- Keychain Access
- Time Machine backups
- App Store and Gatekeeper

# Linux Basics
- File system hierarchy
- Command line operations
- Package management
- User and group permissions
```

## Network+ Fundamentals

### OSI Model & TCP/IP

Network layer understanding and protocol knowledge.

```text
# OSI 7-Layer Model
Layer 7: Application (HTTP, HTTPS, FTP)
Layer 6: Presentation (SSL, TLS)
Layer 5: Session (NetBIOS, RPC)
Layer 4: Transport (TCP, UDP)
Layer 3: Network (IP, ICMP, OSPF)
Layer 2: Data Link (Ethernet, PPP)
Layer 1: Physical (Cables, Hubs)

# TCP/IP Suite
- IPv4 vs IPv6 addressing
- Subnetting and CIDR notation
- DHCP and DNS services
- ARP and ICMP protocols
```

### Network Devices

Routers, switches, and networking equipment.

```text
# Layer 2 Devices
- Switches and VLANs
- Spanning Tree Protocol (STP)
- Port security and MAC filtering

# Layer 3 Devices
- Routers and routing tables
- Static vs dynamic routing
- OSPF, EIGRP, BGP protocols
- NAT and PAT translation
```

### Wireless Networking

Wi-Fi standards, security, and troubleshooting.

```text
# Wi-Fi Standards
802.11a: 5GHz, 54Mbps
802.11b: 2.4GHz, 11Mbps
802.11g: 2.4GHz, 54Mbps
802.11n: 2.4/5GHz, 600Mbps
802.11ac: 5GHz, 6.9Gbps
802.11ax (Wi-Fi 6): 9.6Gbps

# Wireless Security
- WEP (deprecated)
- WPA/WPA2-PSK
- WPA2/WPA3-Enterprise
- EAP authentication methods
```

### Network Troubleshooting

Common tools and diagnostic procedures.

```bash
# Command Line Tools
ping                    # Test connectivity
tracert/traceroute      # Path analysis
nslookup/dig            # DNS queries
netstat                 # Network connections
ipconfig/ifconfig       # IP configuration

# Network Testing
- Cable testers and tone generators
- Protocol analyzers (Wireshark)
- Speed and throughput testing
- Wi-Fi analyzers
```

## Security+ Core Concepts

### Security Fundamentals

CIA triad and basic security principles.

```text
# CIA Triad
Confidentiality: Data privacy and encryption
Integrity: Data accuracy and authenticity
Availability: System uptime and accessibility

# Authentication Factors
Something you know: Passwords, PINs
Something you have: Tokens, smart cards
Something you are: Biometrics
Something you do: Behavior patterns
Somewhere you are: Location-based
```

### Threat Landscape

Common attacks and threat actors.

```text
# Attack Types
- Phishing and social engineering
- Malware (viruses, trojans, ransomware)
- DDoS and DoS attacks
- Man-in-the-middle attacks
- SQL injection and XSS
- Zero-day exploits

# Threat Actors
- Script kiddies
- Hacktivists
- Organized crime
- Nation-state actors
- Insider threats
```

### Cryptography

Encryption methods and key management.

```text
# Encryption Types
Symmetric: AES, 3DES (same key)
Asymmetric: RSA, ECC (key pairs)
Hashing: SHA-256, MD5 (one-way)
Digital Signatures: Non-repudiation

# Key Management
- Key generation and distribution
- Key escrow and recovery
- Certificate authorities (CA)
- Public Key Infrastructure (PKI)
```

### Access Control

Identity management and authorization models.

```text
# Access Control Models
DAC: Discretionary Access Control
MAC: Mandatory Access Control
RBAC: Role-Based Access Control
ABAC: Attribute-Based Access Control

# Identity Management
- Single Sign-On (SSO)
- Multi-factor Authentication (MFA)
- LDAP and Active Directory
- Federation and SAML
```

## Study Strategies & Tips

### Study Planning

Create a structured approach to certification preparation.

```text
# Study Schedule
Week 1-2: Review exam objectives
Week 3-6: Core material study
Week 7-8: Hands-on practice
Week 9-10: Practice exams
Week 11-12: Final review and exam

# Study Materials
- Official CompTIA study guides
- Video training courses
- Practice exams and simulators
- Hands-on lab exercises
- Study groups and forums
```

### Hands-On Practice

Practical experience to reinforce theoretical knowledge.

```text
# Lab Environments
- VMware or VirtualBox VMs
- Home lab setup
- Cloud-based labs (AWS, Azure)
- CompTIA simulation software

# Practical Skills
- Building and troubleshooting PCs
- Network configuration
- Security tool implementation
- Command line proficiency
```

### Exam Strategies

Test-taking techniques for CompTIA exams.

```text
# Question Types
Multiple choice: Read all options
Performance-based: Practice simulations
Drag-and-drop: Understand relationships
Hot spot: Know interface layouts

# Time Management
- Allocate time per question
- Mark difficult questions for review
- Don't spend too long on single questions
- Review flagged questions at end
```

### Common Exam Topics

High-frequency topics across CompTIA exams.

```text
# Frequently Tested Areas
- Troubleshooting methodologies
- Security best practices
- Network protocols and ports
- Operating system features
- Hardware specifications
- Risk management concepts
```

## Technical Acronyms & Terminology

### Networking Acronyms

Common networking terms and abbreviations.

```text
# Protocols & Standards
HTTP/HTTPS: Web protocols
FTP/SFTP: File transfer
SMTP/POP3/IMAP: Email
DNS: Domain Name System
DHCP: Dynamic Host Configuration
TCP/UDP: Transport protocols
IP: Internet Protocol
ICMP: Internet Control Message

# Wireless & Security
WPA/WPA2: Wi-Fi Protected Access
SSID: Service Set Identifier
MAC: Media Access Control
VPN: Virtual Private Network
VLAN: Virtual Local Area Network
QoS: Quality of Service
```

### Hardware & Software

Computer hardware and software terminology.

```text
# Storage & Memory
HDD: Hard Disk Drive
SSD: Solid State Drive
RAM: Random Access Memory
ROM: Read-Only Memory
BIOS/UEFI: System firmware
RAID: Redundant Array of Independent Disks

# Interfaces & Ports
USB: Universal Serial Bus
SATA: Serial ATA
PCIe: Peripheral Component Interconnect Express
HDMI: High-Definition Multimedia Interface
VGA: Video Graphics Array
RJ45: Ethernet connector
```

### Security Terminology

Information security terms and concepts.

```text
# Security Frameworks
CIA: Confidentiality, Integrity, Availability
AAA: Authentication, Authorization, Accounting
PKI: Public Key Infrastructure
IAM: Identity and Access Management
SIEM: Security Information and Event Management
SOC: Security Operations Center

# Compliance & Risk
GDPR: General Data Protection Regulation
HIPAA: Health Insurance Portability Act
PCI DSS: Payment Card Industry Data Security
SOX: Sarbanes-Oxley Act
NIST: National Institute of Standards
ISO 27001: Security management standard
```

### Cloud & Virtualization

Modern IT infrastructure terminology.

```text
# Cloud Services
IaaS: Infrastructure as a Service
PaaS: Platform as a Service
SaaS: Software as a Service
VM: Virtual Machine
API: Application Programming Interface
CDN: Content Delivery Network
```

## Certification Career Paths

### Entry Level

Foundation certification for IT support roles, covering hardware, software, and basic troubleshooting skills.

```text
1. Entry Level
CompTIA A+
Foundation certification for IT support roles, covering
hardware, software, and basic troubleshooting skills.
```

### Infrastructure

Build networking and server administration expertise for infrastructure roles.

```text
2. Infrastructure
Network+ & Server+
Build networking and server administration expertise for
infrastructure roles.
```

### Security Focus

Develop cybersecurity knowledge for security analyst and administrator positions.

```text
3. Security Focus
Security+ & CySA+
Develop cybersecurity knowledge for security analyst and
administrator positions.
```

### Specialization

Advanced specializations in penetration testing and cloud technologies.

```text
4. Specialization
PenTest+ & Cloud+
Advanced specializations in penetration testing and cloud
technologies.
```

## Common Port Numbers

### Well-Known Ports (0-1023)

Standard ports for common network services.

```text
Port 20/21: FTP (File Transfer Protocol)
Port 22: SSH (Secure Shell)
Port 23: Telnet
Port 25: SMTP (Simple Mail Transfer Protocol)
Port 53: DNS (Domain Name System)
Port 67/68: DHCP (Dynamic Host Configuration)
Port 69: TFTP (Trivial File Transfer Protocol)
Port 80: HTTP (Hypertext Transfer Protocol)
Port 110: POP3 (Post Office Protocol v3)
Port 143: IMAP (Internet Message Access Protocol)
Port 161/162: SNMP (Simple Network Management)
Port 443: HTTPS (HTTP Secure)
Port 993: IMAPS (IMAP Secure)
Port 995: POP3S (POP3 Secure)
```

### Registered Ports (1024-49151)

Common application and database ports.

```text
# Database & Applications
Port 1433: Microsoft SQL Server
Port 1521: Oracle Database
Port 3306: MySQL Database
Port 3389: RDP (Remote Desktop Protocol)
Port 5432: PostgreSQL Database

# Network Services
Port 1812/1813: RADIUS Authentication
Port 1701: L2TP (Layer 2 Tunneling Protocol)
Port 1723: PPTP (Point-to-Point Tunneling)
Port 5060/5061: SIP (Session Initiation Protocol)

# Security Services
Port 636: LDAPS (LDAP Secure)
Port 989/990: FTPS (FTP Secure)
```

## Troubleshooting Methodologies

### CompTIA Troubleshooting Steps

Standard methodology for technical problem resolution.

```text
# 6-Step Process
1. Identify the problem
   - Gather information
   - Question users about symptoms
   - Identify changes to system
   - Duplicate problem if possible

2. Establish a theory of probable cause
   - Question the obvious
   - Consider multiple approaches
   - Start with simple solutions

3. Test the theory to determine cause
   - If theory confirmed, proceed
   - If not, establish new theory
   - Escalate if necessary
```

### Implementation & Documentation

Final steps in the troubleshooting process.

```text
# Remaining Steps
4. Establish plan of action
   - Determine steps to resolve
   - Identify potential effects
   - Implement solution or escalate

5. Implement the solution or escalate
   - Apply appropriate fix
   - Test solution thoroughly
   - Verify full functionality

6. Document findings, actions, and outcomes
   - Update ticket systems
   - Share lessons learned
   - Prevent future occurrences
```

## Performance-Based Question Tips

### A+ Performance Questions

Common simulation scenarios and solutions.

```text
# Hardware Troubleshooting
- Identify failed components in PC builds
- Configure BIOS/UEFI settings
- Install and configure RAM
- Connect storage devices properly
- Troubleshoot power supply issues

# Operating System Tasks
- Windows installation and configuration
- User account and permission management
- Network settings configuration
- Device driver installation
- System file and registry repairs
```

### Network+ Simulations

Network configuration and troubleshooting scenarios.

```text
# Network Configuration
- VLAN setup and port assignments
- Router ACL configuration
- Switch port security settings
- Wireless network setup
- IP addressing and subnetting

# Troubleshooting Tasks
- Cable testing and replacement
- Network connectivity diagnosis
- DNS and DHCP troubleshooting
- Performance optimization
- Security implementation
```

### Security+ Scenarios

Security implementation and incident response.

```text
# Security Configuration
- Firewall rule creation
- User access control setup
- Certificate management
- Encryption implementation
- Network segmentation

# Incident Response
- Log analysis and interpretation
- Threat identification
- Vulnerability assessment
- Security control implementation
- Risk mitigation strategies
```

### General Simulation Tips

Best practices for performance-based questions.

```text
# Success Strategies
- Read instructions carefully and completely
- Take screenshots before making changes
- Test configurations after implementation
- Use process of elimination
- Manage time effectively
- Practice with simulation software
- Understand underlying concepts, not just steps
```

## Exam Registration & Logistics

### Exam Registration Process

Steps to schedule and prepare for CompTIA exams.

```text
# Registration Steps
1. Create Pearson VUE account
2. Select certification exam
3. Choose testing center or online option
4. Schedule exam date and time
5. Pay exam fee
6. Receive confirmation email

# Exam Costs (USD, approximate)
CompTIA A+: $239 per exam (2 exams)
CompTIA Network+: $358
CompTIA Security+: $370
CompTIA Cloud+: $358
CompTIA PenTest+: $370
CompTIA CySA+: $392
```

### Test Day Preparation

What to expect and bring on exam day.

```text
# Required Items
- Valid government-issued photo ID
- Confirmation email/number
- Arrive 30 minutes early
- No personal items in testing room

# Exam Format
- Multiple choice questions
- Performance-based questions (simulations)
- Drag-and-drop questions
- Hot spot questions
- Time limits vary by exam (90-165 minutes)
```

## Certification Maintenance

### Certification Validity

Continuing education and certification renewal.

```text
# Certification Validity
Most CompTIA certifications: 3 years
CompTIA A+: Permanent (no expiration)

# Continuing Education Units (CEUs)
Security+: 50 CEUs over 3 years
Network+: 30 CEUs over 3 years
Cloud+: 30 CEUs over 3 years

# CEU Activities
- Training courses and webinars
- Industry conferences
- Publishing articles
- Volunteering
- Higher-level certifications
```

### Career Benefits

Value and recognition of CompTIA certifications.

```text
# Industry Recognition
- DOD 8570 approved (Security+)
- Government contractor requirements
- HR filtering for job applications
- Salary improvements
- Career advancement opportunities
- Technical credibility
- Foundation for advanced certifications
```

## Relevant Links

- <router-link to="/linux">Linux Cheatsheet</router-link>
- <router-link to="/cybersecurity">Cybersecurity Cheatsheet</router-link>
- <router-link to="/network">Network Cheatsheet</router-link>
- <router-link to="/rhel">Red Hat Enterprise Linux Cheatsheet</router-link>
- <router-link to="/devops">DevOps Cheatsheet</router-link>
- <router-link to="/docker">Docker Cheatsheet</router-link>
- <router-link to="/kubernetes">Kubernetes Cheatsheet</router-link>
- <router-link to="/ansible">Ansible Cheatsheet</router-link>
