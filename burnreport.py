#!/usr/bin/env python3

# ================================================================
#  BURN REPORT v1.0
#  Cross-Tool Report Combiner
#  Part of the Burn Suite
#  Built for Kali Linux
#
#  Combines findings and diagnostics from multiple Burn Suite reports
#  (burnscanner / burnrecon / burnweb / burncracker) into one summarized
#  report. Does not run any scans itself — it only reads existing .txt
#  reports out of burn_report/.
#
#  Usage: python3 ./burnreport.py
#
#  Copyright (C) 2026 Thomas Burns
#  License: GNU GPLv3 or later. Free software with NO WARRANTY; you may
#  redistribute and modify it under the GPL. See the LICENSE file or
#  <https://www.gnu.org/licenses/gpl-3.0.html>.
# ================================================================

import os
import re
import sys
import glob
import datetime

# ----------------------------------------------------------------
# CONFIG
# ----------------------------------------------------------------
REPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(os.path.realpath(__file__))), "burn_report")

TOOL_PREFIXES = {
    "burnscan_":     "Burn Scanner",
    "burncracker_":  "Burn Crack",
    "burnrecon_":    "Burn Recon",
    "burnweb_":      "Burn Web",
    "burnreport_":   "Burn Report",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "N/A": 4, "INFO": 5}

# ----------------------------------------------------------------
# DIAGNOSTICS — codes logged on failure/empty-result, see ERROR_CODES.txt
# ----------------------------------------------------------------
DIAGNOSTICS = []

def note(code, msg, level="dim"):
    print_status(f"{code}: {msg}", level)
    DIAGNOSTICS.append(f"{code}: {msg}")

# ----------------------------------------------------------------
# BANNER
# ----------------------------------------------------------------
def banner():
    print("""
\033[91m
  ██████╗ ██╗   ██╗██████╗ ███╗   ██╗
  ██╔══██╗██║   ██║██╔══██╗████╗  ██║
  ██████╔╝██║   ██║██████╔╝██╔██╗ ██║
  ██╔══██╗██║   ██║██╔══██╗██║╚██╗██║
  ██████╔╝╚██████╔╝██║  ██║██║ ╚████║
  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝
\033[0m\033[92m
  ██████╗ ███████╗██████╗  ██████╗ ██████╗ ████████╗
  ██╔══██╗██╔════╝██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝
  ██████╔╝█████╗  ██████╔╝██║   ██║██████╔╝   ██║
  ██╔══██╗██╔══╝  ██╔═══╝ ██║   ██║██╔══██╗   ██║
  ██║  ██║███████╗██║     ╚██████╔╝██║  ██║   ██║
  ╚═╝  ╚═╝╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝
\033[0m
\033[90m  Cross-Tool Report Combiner v1.0
  Combines existing reports — does not scan anything itself.
\033[0m""")

# ----------------------------------------------------------------
# HELPERS
# ----------------------------------------------------------------
def print_status(msg, level="info"):
    colors = {"info": "\033[93m", "ok": "\033[92m", "err": "\033[91m", "dim": "\033[90m", "find": "\033[96m"}
    prefix = {"info": "[*]", "ok": "[+]", "err": "[!]", "dim": "[~]", "find": "[>]"}
    c = colors.get(level, "\033[0m")
    p = prefix.get(level, "[*]")
    print(f"{c}{p}\033[0m {msg}")

def separator():
    print(f"\033[90m{'─'*60}\033[0m")

def identify_tool(path):
    base = os.path.basename(path)
    for prefix, name in TOOL_PREFIXES.items():
        if base.startswith(prefix):
            return name
    return "Unknown"

# ----------------------------------------------------------------
# LIST AVAILABLE REPORTS
# ----------------------------------------------------------------
def list_reports():
    files = glob.glob(os.path.join(REPORT_DIR, "*.txt"))
    files.sort(key=os.path.getmtime, reverse=True)
    return files

def read_report_lines(path):
    with open(path, encoding='utf-8', errors='ignore') as f:
        return f.read().splitlines()

# ----------------------------------------------------------------
# REPORT PARSING — these match the exact format burnscanner.py /
# burncracker.py / burnrecon.py / burnweb.py write. Not a general-purpose
# parser; if those report formats change, update this to match.
# ----------------------------------------------------------------
def parse_target(lines):
    for line in lines[:8]:
        m = re.match(r'\s*Target(?:\s+SSID)?\s*:\s*(.+)', line)
        if m:
            return m.group(1).strip()
    return "Unknown"

def parse_findings_section(lines):
    """Parses a 'FINDINGS SUMMARY' or 'VULNERABILITY SUMMARY' block: each
    finding is exactly 3 lines — '[SEVERITY] Title', '    detail',
    '    FIX -> remediation' — followed by a blank line ending the section."""
    start = None
    for i, line in enumerate(lines):
        s = line.strip()
        if s == "FINDINGS SUMMARY" or s.startswith("FINDINGS SUMMARY ") or \
           s == "VULNERABILITY SUMMARY" or s.startswith("VULNERABILITY SUMMARY "):
            start = i
            break
    if start is None:
        return []

    i = start + 2   # skip the header line and its dashed underline
    findings = []
    while i < len(lines) and lines[i].strip() != "":
        title_line = lines[i].strip()
        m = re.match(r'^\[([^\]]+)\]\s*(.+)$', title_line)
        if not m:
            break   # e.g. "No actionable findings..." — nothing structured here
        severity = m.group(1).strip()
        title    = m.group(2).strip()
        detail      = lines[i + 1].strip() if i + 1 < len(lines) else ""
        fix_line    = lines[i + 2].strip() if i + 2 < len(lines) else ""
        remediation = fix_line[len("FIX ->"):].strip() if fix_line.startswith("FIX ->") else ""
        findings.append({"severity": severity, "title": title,
                          "detail": detail, "remediation": remediation})
        i += 3
    return findings

def parse_diagnostics_section(lines):
    """Parses the 'DIAGNOSTICS' block: one 'CODE: message' per line until
    a blank line. Filler text ('No issues...', 'See ERROR_CODES...') is
    naturally excluded since it doesn't match the CODE: pattern."""
    start = None
    for i, line in enumerate(lines):
        if line.strip() == "DIAGNOSTICS":
            start = i
            break
    if start is None:
        return []

    i = start + 2   # skip the header line and its underline
    codes = []
    while i < len(lines) and lines[i].strip() != "":
        s = lines[i].strip()
        if re.match(r'^[A-Z]+-\d+:\s*.+', s):
            codes.append(s)
        i += 1
    return codes

# ----------------------------------------------------------------
# GENERATE COMBINED REPORT
# ----------------------------------------------------------------
def generate_combined_report(sources):
    os.makedirs(REPORT_DIR, exist_ok=True)
    ts       = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = os.path.join(REPORT_DIR,
               f"burnreport_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")

    lines = []
    def w(s=""):
        lines.append(s)

    bar = "=" * 70

    w(bar)
    w("  BURN REPORT v1.0 — COMBINED SECURITY ASSESSMENT")
    w(bar)
    w(f"  Generated  : {ts}")
    w(f"  Sources    : {len(sources)} report(s) combined")
    w(bar)
    w()

    w("SOURCE REPORTS")
    w("-" * 70)
    for s in sources:
        w(f"  [{s['tool']}] {s['target']}  <- {os.path.basename(s['path'])}")
    w()

    all_findings = []
    for s in sources:
        for f in s["findings"]:
            all_findings.append({**f, "source": s["tool"]})
    all_findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"].upper(), 99))

    if all_findings:
        counts = {}
        for f in all_findings:
            counts[f["severity"].upper()] = counts.get(f["severity"].upper(), 0) + 1
        count_str = "  ".join(
            f"{counts[s]} {s}" for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "N/A", "INFO"] if s in counts
        )
        w(f"COMBINED FINDINGS  ({count_str})")
        w("-" * 70)
        for f in all_findings:
            w(f"  [{f['severity']:<8}] ({f['source']}) {f['title']}")
            if f["detail"]:
                w(f"      {f['detail']}")
            if f["remediation"]:
                w(f"      FIX -> {f['remediation']}")
        w()
    else:
        w("COMBINED FINDINGS")
        w("-" * 70)
        w("  No findings across the combined reports.")
        w()

    all_diag = []
    for s in sources:
        for d in s["diagnostics"]:
            all_diag.append(f"[{s['tool']}] {d}")

    w("COMBINED DIAGNOSTICS")
    w("-" * 70)
    if all_diag:
        for d in all_diag:
            w(f"  {d}")
        w("  See ERROR_CODES.txt for what each code means.")
    else:
        w("  No issues encountered across any source report.")
    w()

    w(bar)
    w(f"  BURN REPORT v1.0 | {ts} | FOR AUTHORIZED USE ONLY")
    w(bar)

    with open(filename, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines) + "\n")
    return filename

# ----------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------
def main():
    banner()

    reports = list_reports()
    if not reports:
        note("REPORT-101", f"No reports found in {REPORT_DIR}. Run a scan with another tool first.", "err")
        sys.exit(3)

    print_status(f"Found {len(reports)} report(s):", "info")
    separator()
    for i, path in enumerate(reports):
        lines  = read_report_lines(path)
        tool   = identify_tool(path)
        target = parse_target(lines)
        mtime  = datetime.datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M:%S")
        print(f"  \033[96m{i:<3}\033[0m [{tool:<13}] {target:<32} {mtime}  \033[90m{os.path.basename(path)}\033[0m")
    separator()

    choice = input("\033[93m[?]\033[0m Select report #s to combine (comma-separated), or 'all': ").strip()
    if choice.lower() == 'all':
        selected = list(range(len(reports)))
    else:
        try:
            selected = [int(x.strip()) for x in choice.split(",") if x.strip() != ""]
        except ValueError:
            note("REPORT-102", "Invalid selection — enter numbers separated by commas, or 'all'.", "err")
            sys.exit(1)

    selected = sorted(set(i for i in selected if 0 <= i < len(reports)))
    if not selected:
        note("REPORT-103", "No valid reports selected.", "err")
        sys.exit(1)

    sources = []
    for i in selected:
        path   = reports[i]
        lines  = read_report_lines(path)
        sources.append({
            "path":        path,
            "tool":        identify_tool(path),
            "target":      parse_target(lines),
            "findings":    parse_findings_section(lines),
            "diagnostics": parse_diagnostics_section(lines),
        })

    print_status(f"Combining {len(sources)} report(s)...", "info")
    report = generate_combined_report(sources)
    print_status(f"Combined report saved to: \033[96m{report}\033[0m", "ok")
    print_status(f"View it with: \033[96mcat {report}\033[0m\n", "ok")

if __name__ == "__main__":
    main()
