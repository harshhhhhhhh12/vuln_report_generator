# 🔒 Linux Vulnerability Report Generator

> A Python + Bash security auditing tool that scans a Linux system for common vulnerabilities and automatically generates a professional, colour-coded PDF report with severity ratings.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux-orange?logo=linux)
![License](https://img.shields.io/badge/License-MIT-green)
![Security](https://img.shields.io/badge/Domain-Security%20Auditing-red)

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
| **7 Security Checks** | Ports, SSH, packages, permissions, passwords, firewall, SUID |
| **PDF Report** | Professional multi-page PDF with colour-coded severity badges |
| **Severity Ratings** | CRITICAL / HIGH / MEDIUM / LOW / INFO with risk summary |
| **Remediation Checklist** | Printable checklist page included in every report |
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

---

## 📄 Sample Report

The generated PDF includes:

- **Cover page** with host metadata and scan timestamp
- **Executive summary** with risk rating and finding counts
- **Colour-coded findings** grouped by severity (CRITICAL → INFO)
- **Remediation checklist** — tick off fixes as you go

---

## ⚙️ Installation

### Prerequisites

- Python 3.8+
- Linux system (Ubuntu/Debian recommended)
- `sudo` access (required for shadow file and some checks)

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/<your-username>/vuln-report-generator.git
cd vuln-report-generator

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

### Example Output

```
[CRITICAL]  SSH misconfiguration: PermitRootLogin
             Check       : SSH Configuration
             Description : Root SSH login is enabled — a direct path to full system compromise.
             Recommend   : Set 'PermitRootLogin no' in /etc/ssh/sshd_config

[HIGH]      UFW firewall is INACTIVE
             Check       : Firewall
             Description : UFW is installed but not running — all ports are unfiltered.
             Recommend   : sudo ufw enable && sudo ufw default deny incoming
```

---

## 📁 Project Structure

```
vuln-report-generator/
│
├── main.py            # CLI entry point — orchestrates scan + report
├── scanner.py         # All 7 security check functions
├── report.py          # PDF generator (ReportLab Platypus)
├── requirements.txt   # Python dependencies
├── .gitignore         # Git ignore rules
└── README.md          # This file
```

---

## 🛠 Skills Demonstrated

This project covers skills directly relevant to **Security Auditing / SOC Analyst / Junior Penetration Tester** roles:

- **Shell command execution** via Python `subprocess` module
- **Linux security concepts**: SSH hardening, firewall config, SUID binaries, file permissions
- **Automated reporting** with `reportlab` (PDF generation)
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
