# 🔒 Linux Vulnerability Report Generator

> A Python security auditing tool that scans a Linux system for common vulnerabilities and automatically generates a **professional, dark-themed PDF report** with colour-coded severity ratings, a visual severity distribution bar, and a printable remediation checklist.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux-orange?logo=linux)
![License](https://img.shields.io/badge/License-MIT-green)
![Security](https://img.shields.io/badge/Domain-Security%20Auditing-red)
![Checks](https://img.shields.io/badge/Security%20Checks-10-cyan)

---

## 📋 Table of Contents

- [Features](#-features)
- [Security Checks Performed](#-security-checks-performed)
- [Sample Report](#-sample-report)
- [Installation](#-installation)
- [Usage](#-usage)
- [Project Structure](#-project-structure)
- [Skills Demonstrated](#-skills-demonstrated)
- [Disclaimer](#-disclaimer)

---

## ✨ Features

| Feature | Details |
|---|---|
| **10 Security Checks** | Ports, SSH, packages, permissions, passwords, firewall, SUID, IPS, Sysctl, Rootkit |
| **Premium PDF Report** | Dark-themed multi-page PDF with colour-coded severity badges and visual charts |
| **Severity Ratings** | CRITICAL / HIGH / MEDIUM / LOW / INFO with overall risk rating |
| **Severity Distribution Bar** | Visual bar chart showing finding breakdown at a glance |
| **Remediation Checklist** | Printable checklist page with tick boxes — included in every report |
| **Console Output** | ANSI colour-coded terminal output for quick review |
| **CLI Flags** | `--output`, `--quiet`, `--console-only` |
| **No External APIs** | Fully offline — uses only standard Linux commands + Python |

---

## 🔍 Security Checks Performed

| # | Check | Tools Used | What It Detects |
|---|---|---|---|
| 1 | **Open Ports** | `ss`, `netstat` | FTP, Telnet, Redis, MongoDB, unencrypted services |
| 2 | **SSH Configuration** | `/etc/ssh/sshd_config` | Root login, password auth, SSHv1, empty passwords |
| 3 | **Outdated Packages** | `apt` | Pending upgrades, security patches |
| 4 | **World-Writable Files** | `find` | Files in `/etc`, `/usr/bin` writable by anyone |
| 5 | **Empty Passwords** | `/etc/shadow` | User accounts with no password set |
| 6 | **Firewall Status** | `ufw`, `iptables` | Inactive or misconfigured firewall |
| 7 | **SUID/SGID Binaries** | `find` | Unusual privilege-escalation vectors |
| 8 | **Intrusion Prevention** | `systemctl` | Missing `fail2ban` or `sshguard` — brute-force protection |
| 9 | **Kernel Parameters** | `sysctl` | Insecure ASLR, IP forwarding, ICMP redirects |
| 10 | **Rootkit Hunter** | `which` | Missing `rkhunter` or `chkrootkit` |

---

## 📄 Sample Report

The generated PDF includes:

- **Cover page** — host metadata, scan timestamp, and overall risk rating
- **Executive summary** — severity stat boxes + colour-coded distribution bar
- **Security checks table** — all 10 checks with tools and detection details
- **Colour-coded findings** — grouped by severity (CRITICAL → INFO) with left accent bars
- **Evidence snippets** — raw command output shown where relevant
- **Remediation checklist** — tick off each fix as you go, then re-scan to verify

> 📎 See [`vuln_report_demo.pdf`](vuln_report_demo.pdf) for a sample output.

---

## ⚙️ Installation

### Prerequisites

- Python 3.8+
- Linux system (Ubuntu/Debian recommended)
- `sudo` access (required for shadow file and some checks)

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/harshhhhhhhhhh12/vuln_report_generator.git
cd vuln_report_generator

# 2. (Optional) Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Usage

```bash
# Full scan + PDF report (recommended: run with sudo for all checks)
sudo python main.py

# Specify custom output path
sudo python main.py --output /tmp/audit_report.pdf

# Console output only (no PDF)
sudo python main.py --console-only

# Suppress per-check progress
sudo python main.py --quiet
```

### Example Console Output

```
[CRITICAL]  No firewall detected (ufw or iptables)
             Check       : Firewall
             Description : Neither ufw nor iptables is configured. The system is completely unfiltered.
             Recommend   : sudo apt install ufw && sudo ufw enable && sudo ufw default deny incoming

[CRITICAL]  Intrusion Prevention not installed
             Check       : Intrusion Prevention (Fail2Ban / SSHGuard)
             Description : Neither fail2ban nor sshguard was detected. Brute-force attacks go unblocked.
             Recommend   : sudo apt install fail2ban && sudo systemctl enable --now fail2ban

[HIGH]      Insecure sysctl kernel parameters detected
             Check       : Sysctl Kernel Parameters
             Description : ASLR disabled, IP forwarding enabled, ICMP redirects accepted.
             Recommend   : Update /etc/sysctl.conf and run sudo sysctl -p
```

---

## 📁 Project Structure

```
vuln_report_generator/
│
├── main.py              # CLI entry point — orchestrates scan + report
├── scanner.py           # All 10 security check functions
├── report.py            # PDF generator (ReportLab Platypus)
├── requirements.txt     # Python dependencies
├── vuln_report_demo.pdf # Sample output report
├── .gitignore           # Git ignore rules
└── README.md            # This file
```

---

## 🛠 Skills Demonstrated

This project covers skills directly relevant to **Security Auditing / SOC Analyst / Junior Penetration Tester** roles:

- **Shell command execution** via Python `subprocess` module
- **Linux security concepts** — SSH hardening, firewall config, SUID binaries, file permissions, kernel hardening, intrusion prevention, rootkit detection
- **Automated reporting** with `reportlab` (PDF generation with custom layouts, flowables, and theming)
- **Severity classification** aligned with industry standards (CVSS-inspired)
- **Clean CLI tooling** with `argparse`
- **Structured data modelling** with Python `dataclasses`
- **Regex parsing** of command output

---

## ⚠️ Disclaimer

> This tool is intended for **authorised security auditing only**.  
> Only run it on systems you own or have **explicit written permission** to test.  
> Misuse may violate computer fraud laws in your jurisdiction.

---

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built as a portfolio project for entry-level Security Auditing roles.*
