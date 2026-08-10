#!/usr/bin/env python3

# ================================================================
#  BURN SCANNER v1.0
#  Automated Network Vulnerability Scanner
#  Built for Kali Linux
#  Usage: sudo python3 ./burnscanner.py
#
#  Copyright (C) 2026 Thomas Burns
#  License: GNU GPLv3 or later. Free software with NO WARRANTY; you may
#  redistribute and modify it under the GPL. See the LICENSE file or
#  <https://www.gnu.org/licenses/gpl-3.0.html>.
# ================================================================

import subprocess
import sys
import os
import json
import shutil
import datetime
import requests
import xml.etree.ElementTree as ET
import time

# ----------------------------------------------------------------
# CONFIG — change these if needed
# ----------------------------------------------------------------
REPORT_DIR = os.path.join(os.path.dirname(os.path.abspath(os.path.realpath(__file__))), "burn_report")
SCAN_DIR   = "/tmp/burnscan"

# ----------------------------------------------------------------
# DIAGNOSTICS — codes logged on failure/empty-result, see ERROR_CODES.txt
# ----------------------------------------------------------------
DIAGNOSTICS = []

def note(code, msg, level="dim"):
    colors = {"info": "\033[93m", "ok": "\033[92m", "err": "\033[91m", "dim": "\033[90m"}
    c = colors.get(level, "\033[90m")
    print(f"  {c}[{code}]\033[0m {msg}")
    DIAGNOSTICS.append(f"{code}: {msg}")

# ----------------------------------------------------------------
# BANNER
# ----------------------------------------------------------------
def banner():
    print("""
\033[91m
██████╗ ██╗   ██╗██████╗ ███╗   ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔══██╗██║   ██║██╔══██╗████╗  ██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║
██████╔╝██║   ██║██████╔╝██╔██╗ ██║    ███████╗██║     ███████║██╔██╗ ██║
██╔══██╗██║   ██║██╔══██╗██║╚██╗██║    ╚════██║██║     ██╔══██║██║╚██╗██║
██████╔╝╚██████╔╝██║  ██║██║ ╚████║    ███████║╚██████╗██║  ██║██║ ╚████║
╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
\033[0m
\033[90m         Automated Network Vulnerability Scanner v1.0
         For authorized testing only. Don't be evil.
\033[0m""")

# ----------------------------------------------------------------
# SETUP — create working directories
# ----------------------------------------------------------------
def setup():
    os.makedirs(REPORT_DIR, exist_ok=True)
    os.makedirs(SCAN_DIR, exist_ok=True)

# ----------------------------------------------------------------
# GET TARGET from user
# ----------------------------------------------------------------
def get_target():
    print("\033[92m[?]\033[0m Enter target network or IP")
    print("    Examples: 192.168.1.0/24  |  192.168.1.50  |  192.168.1.1-50")
    target = input("\033[92m>>> \033[0m").strip()
    return target

# ----------------------------------------------------------------
# STEP 1 — Ping sweep to find live hosts
# ----------------------------------------------------------------
def ping_sweep(target):
    print(f"\n\033[93m[*]\033[0m Running ping sweep on {target}...")
    try:
        subprocess.run(
            ["nmap", "-sn", "-oX", f"{SCAN_DIR}/hosts.xml", target],
            capture_output=True, text=True, timeout=120
        )
    except subprocess.TimeoutExpired:
        note("SCAN-301", "Ping sweep timed out after 120s — target range may be too large.", "err")
    hosts = []
    try:
        tree = ET.parse(f"{SCAN_DIR}/hosts.xml")
        root = tree.getroot()
        for host in root.findall('host'):
            status = host.find('status')
            if status is not None and status.get('state') == 'up':
                addr = host.find('address')
                hostname_el = host.find('.//hostname')
                ip   = addr.get('addr') if addr is not None else 'Unknown'
                name = hostname_el.get('name') if hostname_el is not None else 'Unknown'
                # Get MAC if present
                mac_el = host.find(".//address[@addrtype='mac']")
                mac    = mac_el.get('addr') if mac_el is not None else 'Unknown'
                vendor = mac_el.get('vendor', 'Unknown') if mac_el is not None else 'Unknown'
                hosts.append({'ip': ip, 'hostname': name, 'mac': mac, 'vendor': vendor})
                print(f"  \033[92m[+]\033[0m {ip} ({name}) — {vendor}")
    except Exception as e:
        note("SCAN-304", f"Could not parse ping-sweep output: {e}", "err")
    return hosts

# ----------------------------------------------------------------
# STEP 2 — Service and port scan
# ----------------------------------------------------------------
def service_scan(host):
    ip = host['ip']
    print(f"\n\033[93m[*]\033[0m Port/service scan on {ip}...")
    try:
        subprocess.run(
            ["nmap", "-sV", "-sC", "--open", "--host-timeout", "120s",
             "-oX", f"{SCAN_DIR}/{ip}_services.xml", ip],
            capture_output=True, text=True, timeout=180
        )
    except subprocess.TimeoutExpired:
        note("SCAN-302", f"Service scan on {ip} timed out — results may be incomplete.", "err")
    services = []
    try:
        tree = ET.parse(f"{SCAN_DIR}/{ip}_services.xml")
        root = tree.getroot()
        for port in root.findall('.//port'):
            state = port.find('state')
            if state is not None and state.get('state') == 'open':
                portid   = port.get('portid')
                protocol = port.get('protocol')
                service  = port.find('service')
                svc_name    = service.get('name', 'unknown')    if service is not None else 'unknown'
                svc_version = service.get('version', '')        if service is not None else ''
                svc_product = service.get('product', '')        if service is not None else ''
                services.append({
                    'port': portid, 'protocol': protocol,
                    'name': svc_name, 'product': svc_product, 'version': svc_version
                })
                print(f"  \033[92m[+]\033[0m {portid}/{protocol} — {svc_name} {svc_product} {svc_version}")
    except Exception as e:
        note("SCAN-304", f"Could not parse service-scan results for {ip}: {e}", "err")
        return services
    if not services:
        note("SCAN-401", f"No open ports found on {ip} — filtered by firewall, or none exposed.", "dim")
    return services

# ----------------------------------------------------------------
# STEP 3 — Query NVD for CVEs by service
# ----------------------------------------------------------------
CVE_CACHE = {}   # (product, version) -> (cves, ok) — avoids redundant NVD
                 # queries (and their 6s rate-limit sleep) for software that
                 # shows up on multiple ports/hosts in the same scan

def lookup_cves(svc):
    """Returns (cves, ok, from_cache). ok=False means the lookup itself
    failed/was rate-limited — an empty cves list with ok=True is a real
    negative result. from_cache=True means no network request was made,
    so the caller shouldn't apply the rate-limit sleep. Failed lookups are
    NOT cached, so a transient rate-limit/error gets retried if the same
    product/version comes up again later in the scan."""
    cves = []
    if not svc.get('product'):
        return cves, True, True

    key = (svc['product'], svc.get('version', ''))
    if key in CVE_CACHE:
        cached_cves, cached_ok = CVE_CACHE[key]
        return cached_cves, cached_ok, True

    try:
        query = f"{svc['product']} {svc['version']}".strip()
        url   = (f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                 f"?keywordSearch={requests.utils.quote(query)}&resultsPerPage=3")
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            for vuln in r.json().get('vulnerabilities', []):
                cve  = vuln.get('cve', {})
                cid  = cve.get('id', '')
                desc = next((d['value'] for d in cve.get('descriptions', [])
                             if d['language'] == 'en'), '')[:300]
                metrics  = cve.get('metrics', {})
                score    = 'N/A'
                severity = 'N/A'
                if 'cvssMetricV31' in metrics:
                    score    = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                    severity = metrics['cvssMetricV31'][0]['cvssData']['baseSeverity']
                cves.append({'id': cid, 'description': desc,
                             'score': score, 'severity': severity})
            CVE_CACHE[key] = (cves, True)
            return cves, True, False
        return cves, False, False
    except Exception:
        return cves, False, False

# ----------------------------------------------------------------
# STEP 4 — Nmap vuln scripts
# ----------------------------------------------------------------
def vuln_scan(host):
    ip = host['ip']
    print(f"\n\033[93m[*]\033[0m Running vuln scripts on {ip} (this may take a few minutes)...")
    try:
        subprocess.run(
            ["nmap", "--script", "vuln", "-oX", f"{SCAN_DIR}/{ip}_vulns.xml", ip],
            capture_output=True, text=True, timeout=300
        )
    except subprocess.TimeoutExpired:
        note("SCAN-303", f"Vuln scan on {ip} timed out after 300s — results incomplete.", "err")
    vulns = []
    try:
        tree = ET.parse(f"{SCAN_DIR}/{ip}_vulns.xml")
        root = tree.getroot()
        for script in root.findall('.//script'):
            script_id = script.get('id', '')
            output    = script.get('output', '')
            if 'VULNERABLE' in output or 'vulnerable' in output.lower():
                vulns.append({'script': script_id, 'output': output})
                print(f"  \033[91m[!]\033[0m VULNERABILITY: {script_id}")
    except Exception as e:
        note("SCAN-304", f"Could not parse vuln-scan results for {ip}: {e}", "err")
        return vulns
    if not vulns:
        note("SCAN-403", f"No script-detected vulnerabilities on {ip} — nmap's vuln scripts found nothing confirmable.", "ok")
    return vulns

# ----------------------------------------------------------------
# STEP 5 — Optional Metasploit exploit attempts
# ----------------------------------------------------------------
def attempt_exploits(host, vulns):
    if not vulns:
        return []
    results = []
    print(f"\n\033[91m[!]\033[0m {len(vulns)} vulnerability(s) found on {host['ip']}")
    answer = input("\033[93m[?]\033[0m Attempt Metasploit exploits? (yes/no): ").strip().lower()
    if answer != 'yes':
        print("  \033[90m[*]\033[0m Skipping exploits.")
        return results
    if not shutil.which("msfconsole"):
        note("SCAN-503", "msfconsole not found — cannot attempt exploits. Install Metasploit Framework.", "err")
        return results
    for vuln in vulns:
        print(f"\n\033[93m[*]\033[0m Searching Metasploit for: {vuln['script']}")
        try:
            msf_search = subprocess.run(
                ["msfconsole", "-q", "-x", f"search {vuln['script']}; exit"],
                capture_output=True, text=True, timeout=60
            )
        except subprocess.TimeoutExpired:
            note("SCAN-502", f"Metasploit search timed out for {vuln['script']} — skipping.", "err")
            continue
        print(msf_search.stdout)
        choice = input("\033[93m[?]\033[0m Enter module name to run or 'skip': ").strip()
        if choice.lower() == 'skip':
            continue
        cmds = f"use {choice}; set RHOSTS {host['ip']}; run; exit"
        try:
            msf_out = subprocess.run(
                ["msfconsole", "-q", "-x", cmds],
                capture_output=True, text=True, timeout=120
            )
        except subprocess.TimeoutExpired:
            note("SCAN-502", f"Metasploit module '{choice}' timed out against {host['ip']}.", "err")
            continue
        results.append({'module': choice, 'output': msf_out.stdout})
        print(msf_out.stdout)
    return results

# ----------------------------------------------------------------
# REMEDIATION LOOKUP
# ----------------------------------------------------------------
def get_remediation(script_id):
    remediations = {
        'smb-vuln':   'Disable SMBv1. Apply MS17-010 patch. Keep Windows updated.',
        'http-vuln':  'Update web server. Apply security patches. Disable unused features.',
        'ssl':        'Disable SSLv2/v3 and weak ciphers. Enforce TLS 1.2+. Renew certificates.',
        'ftp-vuln':   'Disable anonymous FTP. Switch to SFTP. Update FTP server software.',
        'ssh':        'Update OpenSSH. Disable root login. Use key-based auth only.',
        'rdp-vuln':   'Apply BlueKeep patches. Enable NLA. Restrict RDP to VPN only.',
        'ms17':       'Apply MS17-010 immediately. Disable SMBv1. Isolate unpatched systems.',
        'upnp':       'Disable UPnP on router and devices. Use static port forwarding instead.',
        'default':    'Update to latest software version. Review service config. Apply vendor patches.'
    }
    for key, val in remediations.items():
        if key in script_id.lower():
            return val
    return remediations['default']

# ----------------------------------------------------------------
# FINDINGS ANALYSIS — unified severity-tagged findings list, same shape
# as burnrecon.py/burnweb.py's, so reports can be combined by burnreport.py
# ----------------------------------------------------------------
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "N/A": 4}

def analyze_findings(scan_results):
    findings = []

    def add(title, detail, severity, remediation):
        findings.append({"title": title, "detail": detail, "severity": severity, "remediation": remediation})

    for h in scan_results:
        ip = h['ip']
        services = h.get('services', [])
        cves_map = h.get('cves', {})

        for svc in services:
            for cve in cves_map.get(svc['port'], []):
                sev = str(cve.get('severity', 'N/A')).upper()
                add(
                    f"{cve['id']} on {ip}:{svc['port']} ({svc['product']} {svc['version']})",
                    cve['description'],
                    sev,
                    f"Update {svc['product']} {svc['version']} to a patched version. Review {cve['id']} for details."
                )

        for v in h.get('vulns', []):
            add(
                f"{v['script']} on {ip}",
                v['output'][:300],
                "HIGH",
                get_remediation(v['script'])
            )

        for ex in h.get('exploits', []):
            add(
                f"Exploit executed: {ex['module']} on {ip}",
                "A Metasploit module was run against this host — review the exploit output above for signs of actual compromise.",
                "CRITICAL",
                "Treat this host as potentially compromised: patch the vulnerability, rotate credentials, and investigate further."
            )

    findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
    return findings

# ----------------------------------------------------------------
# GENERATE TXT REPORT
# ----------------------------------------------------------------
def generate_report(scan_results, target, findings):
    ts       = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = os.path.join(REPORT_DIR,
               f"burnscan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")

    total_hosts = len(scan_results)
    total_ports = sum(len(h.get('services', [])) for h in scan_results)
    total_vulns = sum(len(h.get('vulns', [])) for h in scan_results)

    lines = []
    def w(s=""):
        lines.append(s)

    bar = "=" * 70

    w(bar)
    w("  BURN SCANNER v1.0 — NETWORK VULNERABILITY SCAN REPORT")
    w(bar)
    w(f"  Target     : {target}")
    w(f"  Scan Time  : {ts}")
    w(f"  Hosts      : {total_hosts}")
    w(f"  Open Ports : {total_ports}")
    w(f"  Vulns      : {total_vulns}")
    w(bar)
    w()

    if findings:
        counts = {}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        count_str = "  ".join(
            f"{counts[s]} {s}" for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "N/A"] if s in counts
        )
        w(f"FINDINGS SUMMARY  ({count_str})")
        w("-" * 70)
        for f in findings:
            w(f"  [{f['severity']:<8}] {f['title']}")
            w(f"      {f['detail']}")
            w(f"      FIX -> {f['remediation']}")
        w()
    else:
        w("FINDINGS SUMMARY")
        w("-" * 70)
        w("  No actionable findings from this scan.")
        w()

    for h in scan_results:
        ip        = h['ip']
        hostname  = h.get('hostname', 'Unknown')
        mac       = h.get('mac', 'Unknown')
        vendor    = h.get('vendor', 'Unknown')
        services  = h.get('services', [])
        cves_map  = h.get('cves', {})
        vulns     = h.get('vulns', [])
        exploits  = h.get('exploits', [])

        w("-" * 70)
        w(f"  HOST: {ip}  ({hostname})")
        w(f"  MAC : {mac}  [{vendor}]")
        w("-" * 70)

        w("  OPEN PORTS")
        if services:
            for s in services:
                version = s['version'] or '—'
                w(f"    {s['port']}/{s['protocol']:<4} {s['name']:<12} {s['product']} {version}")
        else:
            w("    No open ports detected.")
        w()

        w("  CVE LOOKUP")
        found_cves = False
        for svc in services:
            for cve in cves_map.get(svc['port'], []):
                found_cves = True
                w(f"    [{cve['severity']:<8}] {cve['id']}  (CVSS {cve['score']})")
                w(f"      {cve['description']}")
        if not found_cves:
            w("    No CVEs matched for detected services.")
        w()

        w("  VULNERABILITY SCAN")
        if vulns:
            for v in vulns:
                rem = get_remediation(v['script'])
                w(f"    [!] {v['script']}")
                for out_line in v['output'][:600].splitlines():
                    w(f"        {out_line}")
                w(f"        REMEDIATION -> {rem}")
        else:
            w("    No script-detected vulnerabilities.")
        w()

        if exploits:
            w("  EXPLOIT RESULTS")
            for ex in exploits:
                w(f"    MODULE: {ex['module']}")
                for out_line in ex['output'][:600].splitlines():
                    w(f"        {out_line}")
            w()

    w("DIAGNOSTICS")
    w("-" * 70)
    if DIAGNOSTICS:
        for d in DIAGNOSTICS:
            w(f"  {d}")
        w("  See ERROR_CODES.txt for what each code means.")
    else:
        w("  No issues encountered — all checks completed normally.")
    w()

    w(bar)
    w(f"  BURN SCANNER v1.0 | {ts} | FOR AUTHORIZED USE ONLY")
    w(bar)

    with open(filename, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines) + "\n")
    return filename

# ----------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------
def main():
    banner()
    setup()

    if os.geteuid() != 0:
        note("SCAN-101", "Not running as root — SYN scans, OS detection, and some NSE scripts may be degraded.", "dim")

    if not shutil.which("nmap"):
        note("SCAN-102", "nmap not found — cannot scan without it. Install: sudo apt install nmap", "err")
        sys.exit(2)

    target = get_target()
    if not target:
        note("SCAN-201", "No target entered.", "err")
        sys.exit(1)
    scan_results = []

    # Step 1: Host discovery
    hosts = ping_sweep(target)
    if not hosts:
        note("SCAN-202", "No live hosts found in target range — host(s) may be down, ICMP filtered by a firewall, or the range/IP was mistyped.", "err")
        sys.exit(3)

    print(f"\n\033[92m[+]\033[0m Found {len(hosts)} host(s). Starting detailed scan...\n")

    for host in hosts:
        print(f"\n\033[96m{'='*55}\033[0m")
        print(f"\033[96m  TARGET: {host['ip']} ({host['hostname']})\033[0m")
        print(f"\033[96m{'='*55}\033[0m")

        # Step 2: Service scan
        services = service_scan(host)

        # Step 3: CVE lookup
        cves = {}
        for svc in services:
            if svc.get('product'):
                print(f"  \033[90m[*]\033[0m CVE lookup: {svc['product']} {svc['version']}...")
                found, ok, from_cache = lookup_cves(svc)
                cves[svc['port']] = found
                if from_cache:
                    print(f"  \033[90m[~]\033[0m (already looked up this scan — reused cached result)")
                if not ok:
                    note("SCAN-501", f"NVD lookup failed/rate-limited for {svc['product']} {svc['version']} on {host['ip']} — CVE results may be incomplete.", "err")
                elif not found:
                    note("SCAN-402", f"No CVEs matched {svc['product']} {svc['version']} on {host['ip']} — appears current/patched.", "dim")
                if not from_cache:
                    time.sleep(6)  # NVD allows ~5 requests/30s without an API key

        # Step 4: Vuln scripts
        vulns = vuln_scan(host)

        # Step 5: Optional exploits
        exploits = attempt_exploits(host, vulns)

        scan_results.append({
            'ip':       host['ip'],
            'hostname': host['hostname'],
            'mac':      host.get('mac', 'Unknown'),
            'vendor':   host.get('vendor', 'Unknown'),
            'services': services,
            'cves':     cves,
            'vulns':    vulns,
            'exploits': exploits
        })

    # Step 6: Report
    print(f"\n\033[93m[*]\033[0m Analyzing findings...")
    findings = analyze_findings(scan_results)
    print(f"\033[93m[*]\033[0m Generating report...")
    report = generate_report(scan_results, target, findings)
    print(f"\033[92m[+]\033[0m Done! Report saved to: \033[96m{report}\033[0m")
    print(f"\033[92m[+]\033[0m View it with: \033[96mcat {report}\033[0m\n")

if __name__ == "__main__":
    main()
