"""
scanner.py — Core security checks for the Vulnerability Report Generator.

Checks performed:
  1. Open ports            (ss / netstat fallback)
  2. SSH configuration     (/etc/ssh/sshd_config)
  3. Outdated packages     (apt)
  4. World-writable files  (sensitive directories)
  5. Empty-password users  (/etc/shadow)
  6. Firewall status       (ufw / iptables)
  7. SUID/SGID binaries    (/usr /bin /sbin)
"""

import subprocess
import re
import datetime
import platform
from dataclasses import dataclass, field
from typing import List

# ── Severity constants ────────────────────────────────────────────────────────
CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"
INFO     = "INFO"

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}


@dataclass
class Finding:
    check:          str
    severity:       str
    title:          str
    description:    str
    recommendation: str
    raw_output:     str = ""


@dataclass
class ScanResult:
    hostname:  str
    os_info:   str
    scan_time: str
    findings:  List[Finding] = field(default_factory=list)

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER[f.severity])

    def summary(self) -> dict:
        counts = {CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0}
        for f in self.findings:
            counts[f.severity] += 1
        return counts


# ── Helper ────────────────────────────────────────────────────────────────────
def _run(cmd: str, timeout: int = 20) -> tuple:
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


# ── Check 1: Open Ports ───────────────────────────────────────────────────────
def check_open_ports() -> List[Finding]:
    findings = []
    rc, out, _ = _run("ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null")

    dangerous = {
        "21":    ("FTP",       HIGH,    "FTP transmits credentials in plaintext."),
        "23":    ("Telnet",    CRITICAL,"Telnet is completely unencrypted; replace with SSH."),
        "25":    ("SMTP",      MEDIUM,  "Open SMTP relay can be abused for spam/phishing."),
        "53":    ("DNS",       MEDIUM,  "Public DNS port may allow zone-transfer abuse."),
        "80":    ("HTTP",      LOW,     "Unencrypted web traffic exposed; prefer HTTPS."),
        "110":   ("POP3",      MEDIUM,  "POP3 sends mail credentials in cleartext."),
        "143":   ("IMAP",      MEDIUM,  "IMAP without TLS leaks mail credentials."),
        "445":   ("SMB",       HIGH,    "SMB exposed — historically exploited (EternalBlue)."),
        "3306":  ("MySQL",     HIGH,    "Database port exposed; restrict to localhost."),
        "5432":  ("Postgres",  HIGH,    "Database port exposed; restrict to localhost."),
        "6379":  ("Redis",     CRITICAL,"Redis has no auth by default — restrict immediately."),
        "27017": ("MongoDB",   CRITICAL,"MongoDB defaults to no auth — restrict immediately."),
        "8080":  ("HTTP-Alt",  LOW,     "Alternative HTTP port open; verify if intentional."),
    }

    found_ports = []
    for line in out.splitlines():
        m = re.search(r"[:\s](\d{2,5})\s", line)
        if m:
            port = m.group(1)
            if port in dangerous and port not in found_ports:
                found_ports.append(port)
                name, sev, desc = dangerous[port]
                findings.append(Finding(
                    check="Open Ports",
                    severity=sev,
                    title=f"Dangerous port {port}/{name} is open",
                    description=desc,
                    recommendation=f"Close port {port} if unused, or restrict with: sudo ufw deny {port}",
                    raw_output=line.strip(),
                ))

    if not found_ports:
        findings.append(Finding(
            check="Open Ports",
            severity=INFO,
            title="No commonly dangerous ports detected",
            description="Scanned known dangerous ports — none were found listening.",
            recommendation="Schedule periodic port scans with nmap for continuous monitoring.",
        ))
    return findings


# ── Check 2: SSH Configuration ────────────────────────────────────────────────
def check_ssh_config() -> List[Finding]:
    findings = []
    rc, out, _ = _run("cat /etc/ssh/sshd_config 2>/dev/null")

    if rc != 0 or not out:
        findings.append(Finding(
            check="SSH Configuration",
            severity=INFO,
            title="sshd_config not readable",
            description="SSH may not be installed or this tool lacks read permission.",
            recommendation="Ensure SSH is hardened if used. See: ssh-audit tool.",
        ))
        return findings

    rules = [
        ("PermitRootLogin",        r"^\s*PermitRootLogin\s+yes",          CRITICAL,
         "Root SSH login is enabled — a direct path to full system compromise.",
         "Set 'PermitRootLogin no' in /etc/ssh/sshd_config, then: systemctl restart sshd"),

        ("PasswordAuthentication", r"^\s*PasswordAuthentication\s+yes",   HIGH,
         "Password-based SSH auth is on — vulnerable to brute-force attacks.",
         "Set 'PasswordAuthentication no' and use SSH key pairs only."),

        ("PermitEmptyPasswords",   r"^\s*PermitEmptyPasswords\s+yes",     CRITICAL,
         "SSH accepts accounts with blank passwords — trivial to exploit.",
         "Set 'PermitEmptyPasswords no' immediately."),

        ("X11Forwarding",          r"^\s*X11Forwarding\s+yes",            LOW,
         "X11 forwarding enabled — unnecessary attack surface if GUI not needed.",
         "Set 'X11Forwarding no' unless graphical sessions are required."),

        ("Protocol 1",             r"^\s*Protocol\s+1",                   CRITICAL,
         "SSHv1 enabled — contains known cryptographic vulnerabilities.",
         "Remove the Protocol line or set 'Protocol 2' only."),

        ("MaxAuthTries",           r"^\s*MaxAuthTries\s+([6-9]|[1-9]\d+)",MEDIUM,
         "MaxAuthTries is set high — allows excessive login attempts before lockout.",
         "Set 'MaxAuthTries 3' to limit brute-force opportunities."),
    ]

    matched = []
    for name, pattern, sev, desc, rec in rules:
        for line in out.splitlines():
            if not line.strip().startswith("#") and re.search(pattern, line, re.IGNORECASE):
                matched.append(name)
                findings.append(Finding(
                    check="SSH Configuration",
                    severity=sev,
                    title=f"SSH misconfiguration: {name}",
                    description=desc,
                    recommendation=rec,
                    raw_output=line.strip(),
                ))

    if not matched:
        findings.append(Finding(
            check="SSH Configuration",
            severity=INFO,
            title="No SSH misconfigurations detected",
            description="Common dangerous SSH directives were not found enabled.",
            recommendation="Regularly audit sshd_config against CIS SSH Benchmark.",
        ))
    return findings


# ── Check 3: Outdated Packages ────────────────────────────────────────────────
def check_outdated_packages() -> List[Finding]:
    findings = []
    rc, out, _ = _run("apt list --upgradable 2>/dev/null | grep -v '^Listing'")

    if rc == 0 and out:
        lines = [l for l in out.splitlines() if l.strip()]
        count = len(lines)
        security_pkgs = [l for l in lines if "security" in l.lower()]
        sev = CRITICAL if security_pkgs else (HIGH if count > 20 else MEDIUM)
        findings.append(Finding(
            check="Outdated Packages",
            severity=sev,
            title=f"{count} apt package(s) need upgrading ({len(security_pkgs)} security-related)",
            description=(
                f"{count} installed packages have available updates. "
                f"{len(security_pkgs)} are tagged as security patches and should be applied urgently."
            ),
            recommendation="Run: sudo apt update && sudo apt upgrade -y",
            raw_output="\n".join(lines[:10]) + ("\n... (truncated)" if count > 10 else ""),
        ))
    else:
        findings.append(Finding(
            check="Outdated Packages",
            severity=INFO,
            title="apt not available or all packages are up to date",
            description="apt reported no pending upgrades, or is not the package manager on this system.",
            recommendation="Verify using your system's package manager (yum, dnf, pacman).",
        ))
    return findings


# ── Check 4: World-Writable Files ─────────────────────────────────────────────
def check_world_writable() -> List[Finding]:
    findings = []
    paths = ["/etc", "/usr/bin", "/usr/sbin", "/bin", "/sbin"]
    all_ww = []

    for path in paths:
        rc, out, _ = _run(f"find {path} -maxdepth 2 -perm -o+w -not -type l 2>/dev/null")
        if rc == 0 and out:
            all_ww.extend([l for l in out.splitlines() if l.strip()])

    if all_ww:
        findings.append(Finding(
            check="World-Writable Files",
            severity=HIGH,
            title=f"{len(all_ww)} world-writable file(s) in sensitive directories",
            description=(
                "World-writable files in system directories can be modified by any user, "
                "enabling privilege escalation or trojanizing system binaries."
            ),
            recommendation="Fix permissions: chmod o-w <file>  — Investigate how they became world-writable.",
            raw_output="\n".join(all_ww[:15]) + ("\n... (truncated)" if len(all_ww) > 15 else ""),
        ))
    else:
        findings.append(Finding(
            check="World-Writable Files",
            severity=INFO,
            title="No world-writable files found in sensitive directories",
            description="Checked /etc, /usr/bin, /usr/sbin, /bin, /sbin — permissions look clean.",
            recommendation="Run periodic checks with: find /etc /usr/bin -perm -o+w",
        ))
    return findings


# ── Check 5: Empty-Password Users ─────────────────────────────────────────────
def check_empty_passwords() -> List[Finding]:
    findings = []
    rc, out, _ = _run("sudo awk -F: '($2==\"\") {print $1}' /etc/shadow 2>/dev/null")

    if rc == 0:
        users = [u for u in out.splitlines() if u.strip()]
        if users:
            findings.append(Finding(
                check="Empty Passwords",
                severity=CRITICAL,
                title=f"Account(s) with empty passwords: {', '.join(users)}",
                description="Accounts with empty passwords can be accessed without any credentials.",
                recommendation="Set strong passwords immediately: sudo passwd <username>",
                raw_output="\n".join(users),
            ))
        else:
            findings.append(Finding(
                check="Empty Passwords",
                severity=INFO,
                title="No accounts with empty passwords found",
                description="All accounts in /etc/shadow have a password hash set.",
                recommendation="Periodically audit user accounts and remove inactive ones.",
            ))
    else:
        findings.append(Finding(
            check="Empty Passwords",
            severity=INFO,
            title="Could not read /etc/shadow (requires root)",
            description="This check needs sudo privileges to inspect password hashes.",
            recommendation="Run this tool with sudo for a complete password audit.",
        ))
    return findings


# ── Check 6: Firewall Status ──────────────────────────────────────────────────
def check_firewall() -> List[Finding]:
    findings = []

    rc, out, _ = _run("ufw status 2>/dev/null")
    if rc == 0:
        if "inactive" in out.lower():
            findings.append(Finding(
                check="Firewall",
                severity=HIGH,
                title="UFW firewall is INACTIVE",
                description="UFW is installed but not running — all ports are unfiltered.",
                recommendation="Enable immediately: sudo ufw enable && sudo ufw default deny incoming",
                raw_output=out,
            ))
        elif "active" in out.lower():
            findings.append(Finding(
                check="Firewall",
                severity=INFO,
                title="UFW firewall is active",
                description="UFW is running and filtering traffic.",
                recommendation="Review rules regularly: sudo ufw status verbose",
                raw_output=out[:300],
            ))
        return findings

    rc2, out2, _ = _run("iptables -L -n 2>/dev/null | head -20")
    if rc2 == 0 and out2:
        if "DROP" in out2 or "REJECT" in out2:
            findings.append(Finding(
                check="Firewall",
                severity=INFO,
                title="iptables is configured with filtering rules",
                description="iptables rules detected with DROP or REJECT policies.",
                recommendation="Review: sudo iptables -L -n -v",
                raw_output=out2[:300],
            ))
        else:
            findings.append(Finding(
                check="Firewall",
                severity=HIGH,
                title="iptables has no DROP/REJECT rules — traffic is unfiltered",
                description="iptables is present but all policies appear to be ACCEPT.",
                recommendation="Configure rules or use ufw: sudo apt install ufw && sudo ufw enable",
                raw_output=out2,
            ))
        return findings

    findings.append(Finding(
        check="Firewall",
        severity=CRITICAL,
        title="No firewall detected (ufw or iptables)",
        description="Neither ufw nor iptables is configured. The system is completely unfiltered.",
        recommendation="Install and enable ufw: sudo apt install ufw && sudo ufw enable && sudo ufw default deny incoming",
    ))
    return findings


# ── Check 7: SUID/SGID Binaries ──────────────────────────────────────────────
def check_suid_sgid() -> List[Finding]:
    findings = []
    known_safe = {
        "/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/su",
        "/usr/bin/newgrp", "/usr/bin/chsh", "/usr/bin/chfn",
        "/usr/bin/gpasswd", "/bin/mount", "/bin/umount",
        "/bin/ping", "/usr/bin/pkexec",
        "/usr/lib/openssh/ssh-keysign",
    }

    rc, out, _ = _run("find /usr /bin /sbin -perm /6000 -type f 2>/dev/null")
    if rc == 0 and out:
        all_suid = [l.strip() for l in out.splitlines() if l.strip()]
        unusual  = [f for f in all_suid if f not in known_safe]

        if unusual:
            findings.append(Finding(
                check="SUID/SGID Binaries",
                severity=MEDIUM,
                title=f"{len(unusual)} unusual SUID/SGID binary(ies) found",
                description=(
                    "SUID/SGID binaries run with elevated privileges. "
                    "Unexpected ones can be exploited for local privilege escalation."
                ),
                recommendation="Check each at https://gtfobins.github.io — remove SUID if not needed: chmod u-s <file>",
                raw_output="\n".join(unusual),
            ))

        findings.append(Finding(
            check="SUID/SGID Binaries",
            severity=INFO,
            title=f"{len(all_suid)} total SUID/SGID binaries found ({len(all_suid) - len(unusual)} standard)",
            description="Standard SUID binaries like sudo and passwd are expected and normal.",
            recommendation="Audit any unusual binaries listed above using GTFOBins.",
        ))
    else:
        findings.append(Finding(
            check="SUID/SGID Binaries",
            severity=INFO,
            title="Could not enumerate SUID/SGID binaries",
            description="find returned no results or encountered permission errors.",
            recommendation="Run manually: find /usr /bin /sbin -perm /6000 -type f",
        ))
    return findings


# ── Master runner ─────────────────────────────────────────────────────────────
def run_all_checks(verbose: bool = True) -> ScanResult:
    _, hostname, _ = _run("hostname")
    _, os_raw, _   = _run(
        "cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '\"'"
    )
    os_info = os_raw or platform.platform()

    result = ScanResult(
        hostname  = hostname or "unknown",
        os_info   = os_info,
        scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )

    checks = [
        ("Open Ports",           check_open_ports),
        ("SSH Configuration",    check_ssh_config),
        ("Outdated Packages",    check_outdated_packages),
        ("World-Writable Files", check_world_writable),
        ("Empty Passwords",      check_empty_passwords),
        ("Firewall Status",      check_firewall),
        ("SUID/SGID Binaries",   check_suid_sgid),
    ]

    for name, fn in checks:
        if verbose:
            print(f"  [*] Running: {name}...")
        try:
            result.findings.extend(fn())
        except Exception as e:
            result.findings.append(Finding(
                check=name,
                severity=INFO,
                title=f"Check '{name}' encountered an error",
                description=str(e),
                recommendation="Review scanner.py for this check.",
            ))

    return result
