#!/usr/bin/env python3
"""
main.py — Entry point for the Linux Vulnerability Report Generator.

Usage:
    python main.py                        # scan + PDF report
    python main.py --output my_report.pdf
    python main.py --quiet                # suppress scan output
    python main.py --console-only         # print findings, skip PDF
"""

import argparse
import sys
import os
import datetime

from scanner import run_all_checks, SEVERITY_ORDER, CRITICAL, HIGH, MEDIUM, LOW, INFO
from report  import generate_pdf

SEV_COLORS = {
    CRITICAL: "\033[91m",   # bright red
    HIGH:     "\033[33m",   # yellow
    MEDIUM:   "\033[93m",   # light yellow
    LOW:      "\033[92m",   # green
    INFO:     "\033[94m",   # blue
}
RESET = "\033[0m"
BOLD  = "\033[1m"


def print_banner():
    print(f"""
{BOLD}\033[94m
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗    ███████╗ ██████╗ █████╗ ███╗  ██╗
 ██║   ██║██║   ██║██║     ████╗  ██║    ██╔════╝██╔════╝██╔══██╗████╗ ██║
 ██║   ██║██║   ██║██║     ██╔██╗ ██║    ███████╗██║     ███████║██╔██╗██║
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║    ╚════██║██║     ██╔══██║██║╚████║
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║    ███████║╚██████╗██║  ██║██║ ╚███║
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚══╝
{RESET}
  {BOLD}Linux Vulnerability Report Generator{RESET}  |  v1.0.0
  ──────────────────────────────────────────────────────────
""")


def print_console_results(result):
    counts = result.summary()
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  SCAN COMPLETE — {result.hostname} | {result.scan_time}{RESET}")
    print(f"{'='*60}")
    print(f"  CRITICAL: {SEV_COLORS[CRITICAL]}{counts[CRITICAL]}{RESET}  "
          f"HIGH: {SEV_COLORS[HIGH]}{counts[HIGH]}{RESET}  "
          f"MEDIUM: {SEV_COLORS[MEDIUM]}{counts[MEDIUM]}{RESET}  "
          f"LOW: {SEV_COLORS[LOW]}{counts[LOW]}{RESET}  "
          f"INFO: {SEV_COLORS[INFO]}{counts[INFO]}{RESET}")
    print(f"{'='*60}\n")

    for f in result.sorted_findings():
        col = SEV_COLORS.get(f.severity, "")
        print(f"{col}{BOLD}[{f.severity}]{RESET}  {f.title}")
        print(f"         Check       : {f.check}")
        print(f"         Description : {f.description}")
        print(f"         Recommend   : {f.recommendation}")
        if f.raw_output:
            preview = f.raw_output[:120].replace("\n", " | ")
            print(f"         Evidence    : {preview}")
        print()


def main():
    if not sys.platform.startswith("linux"):
        print(f"{BOLD}\033[91m[ERROR] This tool must be run on Linux. Current OS: {sys.platform}{RESET}")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Linux Vulnerability Report Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python main.py
  sudo python main.py --output /tmp/audit_$(hostname).pdf
  sudo python main.py --quiet
  sudo python main.py --console-only
        """
    )
    parser.add_argument("--output", "-o",
                        default=None,
                        help="Output PDF filename (default: vuln_report_<hostname>_<date>.pdf)")
    parser.add_argument("--quiet", "-q",
                        action="store_true",
                        help="Suppress per-check progress output")
    parser.add_argument("--console-only", "-c",
                        action="store_true",
                        help="Print findings to console only; skip PDF generation")
    args = parser.parse_args()

    print_banner()

    # ── Run checks ────────────────────────────────────────────────────────────
    print(f"{BOLD}[*] Starting security scan...{RESET}\n")
    result = run_all_checks(verbose=not args.quiet)

    # ── Console output ────────────────────────────────────────────────────────
    print_console_results(result)

    if args.console_only:
        print(f"{BOLD}[i] Console-only mode — PDF not generated.{RESET}")
        return

    # ── Generate PDF ──────────────────────────────────────────────────────────
    if args.output:
        out_path = args.output
    else:
        date_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = f"vuln_report_{result.hostname}_{date_str}.pdf"

    print(f"{BOLD}[*] Generating PDF report...{RESET}")
    final_path = generate_pdf(result, out_path)
    size_kb    = os.path.getsize(final_path) // 1024

    print(f"\n{BOLD}\033[92m[✓] Report saved:{RESET}  {final_path}  ({size_kb} KB)")
    print(f"    Open it with:  xdg-open {final_path}  (Linux)")
    print(f"                   open {final_path}       (macOS)\n")


if __name__ == "__main__":
    main()
