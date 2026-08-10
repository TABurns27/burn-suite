#!/usr/bin/env python3

# ================================================================
#  BURN WEB v1.0
#  Automated Web Application Recon & Weakness Scanner
#  Part of the Burn Suite
#  Built for Kali Linux
#
#  LEGAL NOTICE: Only use on web applications you own or have
#  explicit written permission to test.
#
#  By default this tool is PASSIVE / DISCOVERY ONLY — it fingerprints,
#  checks for exposed files, and looks for known misconfigurations.
#  It will NEVER attempt SQL injection or any other active exploitation
#  without a separate, explicit, typed confirmation at the end of the
#  scan. Do not confirm that step unless the site owner has given you
#  written permission to actively exploit the target.
#
#  Usage: python3 ./burnweb.py
#
#  Dependencies: sudo apt install nikto gobuster sslscan sqlmap
#                pip3 install requests --break-system-packages
#
#  Copyright (C) 2026 Thomas Burns
#  License: GNU GPLv3 or later. Free software with NO WARRANTY; you may
#  redistribute and modify it under the GPL. See the LICENSE file or
#  <https://www.gnu.org/licenses/gpl-3.0.html>.
# ================================================================

import subprocess
import sys
import os
import re
import shutil
import datetime
import requests
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor

# ----------------------------------------------------------------
# CONFIG
# ----------------------------------------------------------------
REPORT_DIR   = os.path.join(os.path.dirname(os.path.abspath(os.path.realpath(__file__))), "burn_report")
TIMEOUT      = 10   # seconds for HTTP requests
DIR_WORDLIST = "/usr/share/wordlists/dirb/common.txt"   # used by gobuster if installed
SQLMAP_ARGS  = ["--batch", "--level=1", "--risk=1", "--random-agent"]   # deliberately conservative
MAX_WORKERS  = 8     # concurrent requests for path-probing checks against a single target

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
\033[0m\033[96m
  ██╗    ██╗███████╗██████╗
  ██║    ██║██╔════╝██╔══██╗
  ██║ █╗ ██║█████╗  ██████╔╝
  ██║███╗██║██╔══╝  ██╔══██╗
  ╚███╔███╔╝███████╗██████╔╝
   ╚══╝╚══╝ ╚══════╝╚═════╝
\033[0m
\033[90m  Automated Web Application Recon & Weakness Scanner v1.0
  PASSIVE BY DEFAULT. FOR AUTHORIZED TESTING ONLY.
\033[0m""")

# ----------------------------------------------------------------
# HELPERS
# ----------------------------------------------------------------
def run(cmd, timeout=60):
    """Run a command from an argument list (never a shell string built from
    target input — avoids shell injection via a malicious/mistyped target)."""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None
    except Exception:
        return None

def print_status(msg, level="info"):
    colors = {"info": "\033[93m", "ok": "\033[92m", "err": "\033[91m", "dim": "\033[90m", "find": "\033[96m"}
    prefix = {"info": "[*]", "ok": "[+]", "err": "[!]", "dim": "[~]", "find": "[>]"}
    c = colors.get(level, "\033[0m")
    p = prefix.get(level, "[*]")
    print(f"{c}{p}\033[0m {msg}")

def separator():
    print(f"\033[90m{'─'*60}\033[0m")

def tool_available(name):
    return shutil.which(name) is not None

# ----------------------------------------------------------------
# DIAGNOSTICS — codes logged on failure/empty-result, see ERROR_CODES.txt
# ----------------------------------------------------------------
DIAGNOSTICS = []

def note(code, msg, level="dim"):
    print_status(f"{code}: {msg}", level)
    DIAGNOSTICS.append(f"{code}: {msg}")

def get_target():
    print("\n\033[92m[?]\033[0m Enter target URL or domain")
    print("    Examples: https://example.com  |  example.com  |  192.168.1.50")
    target = input("\033[92m>>> \033[0m").strip().rstrip("/")
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "https://" + target
    return target

def resolve_base_url(target):
    """Try the given scheme, fall back https -> http if it fails."""
    try:
        r = requests.get(target, timeout=TIMEOUT, allow_redirects=True,
                          headers={"User-Agent": "Mozilla/5.0"})
        return target, r
    except requests.exceptions.RequestException:
        pass
    if target.startswith("https://"):
        fallback = "http://" + target[len("https://"):]
        try:
            r = requests.get(fallback, timeout=TIMEOUT, allow_redirects=True,
                              headers={"User-Agent": "Mozilla/5.0"})
            print_status(f"HTTPS unreachable, falling back to {fallback}", "dim")
            return fallback, r
        except requests.exceptions.RequestException:
            pass
    return None, None

def check_soft_404(base_url):
    """Detect servers that return 200 for everything (breaks path-existence checks)."""
    canary = urljoin(base_url + "/", "burnweb-canary-404-check-9f8a2b")
    try:
        r = requests.get(canary, timeout=TIMEOUT, allow_redirects=True,
                          headers={"User-Agent": "Mozilla/5.0"})
        return r.status_code == 200
    except requests.exceptions.RequestException:
        return False

# ----------------------------------------------------------------
# FINGERPRINT
# ----------------------------------------------------------------
def fingerprint(base_url, resp):
    print_status("Fingerprinting server and technology stack...", "info")
    info = {}
    headers = resp.headers
    for h in ["Server", "X-Powered-By", "Set-Cookie"]:
        if h in headers:
            info[h] = headers[h]
            print_status(f"{h}: {headers[h][:120]}", "find")

    body = resp.text if resp.text else ""
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', body, re.I)
    if gen:
        info["Generator"] = gen.group(1)
        print_status(f"Generator meta tag: {gen.group(1)}", "find")

    signatures = {
        "WordPress": ["wp-content", "wp-includes", "/wp-json/"],
        "Joomla":    ["/media/jui/", "Joomla!"],
        "Drupal":    ["/sites/default/", "Drupal.settings"],
        "Laravel":   ["laravel_session", "XSRF-TOKEN"],
        "Django":    ["csrftoken"],
    }
    detected = [name for name, needles in signatures.items()
                if any(n in body or n in str(headers) for n in needles)]
    if detected:
        info["Detected"] = ", ".join(detected)
        for d in detected:
            print_status(f"Detected: {d}", "find")

    info["status_code"] = resp.status_code
    info["final_url"]   = resp.url
    print_status(f"Status: {resp.status_code} | URL: {resp.url}", "ok")
    return info

# ----------------------------------------------------------------
# ROBOTS.TXT / SITEMAP.XML
# ----------------------------------------------------------------
def get_robots_sitemap(base_url):
    print_status("Checking robots.txt and sitemap.xml...", "info")
    result = {"disallow": [], "sitemap_found": False}
    try:
        r = requests.get(urljoin(base_url + "/", "robots.txt"), timeout=TIMEOUT)
        if r.status_code == 200:
            for line in r.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path:
                        result["disallow"].append(path)
                        print_status(f"robots.txt Disallow: {path}", "find")
    except requests.exceptions.RequestException:
        pass
    try:
        r = requests.get(urljoin(base_url + "/", "sitemap.xml"), timeout=TIMEOUT)
        if r.status_code == 200 and "<" in r.text:
            result["sitemap_found"] = True
            print_status("sitemap.xml found", "find")
    except requests.exceptions.RequestException:
        pass
    if not result["disallow"] and not result["sitemap_found"]:
        print_status("No robots.txt/sitemap.xml data found.", "dim")
    return result

# ----------------------------------------------------------------
# SHARED PATH PROBE — used by both the sensitive-path check and the
# fallback directory fuzzer, run concurrently via ThreadPoolExecutor
# ----------------------------------------------------------------
def _probe_path(base_url, path):
    try:
        r = requests.get(urljoin(base_url, path), timeout=TIMEOUT, allow_redirects=False)
        return path, r.status_code
    except requests.exceptions.RequestException:
        return path, None

# ----------------------------------------------------------------
# EXPOSED SENSITIVE PATHS
# ----------------------------------------------------------------
SENSITIVE_PATHS = {
    "/.git/HEAD":              ("Exposed .git repository — full source history may be downloadable", "CRITICAL"),
    "/.git/config":            ("Exposed .git config", "CRITICAL"),
    "/.env":                   ("Exposed .env file — may contain DB credentials and API keys", "CRITICAL"),
    "/wp-config.php.bak":      ("Exposed WordPress config backup — contains DB credentials", "CRITICAL"),
    "/config.php.bak":         ("Exposed config backup file", "HIGH"),
    "/backup.zip":             ("Exposed backup archive", "HIGH"),
    "/backup.sql":             ("Exposed database dump", "CRITICAL"),
    "/db.sql":                 ("Exposed database dump", "CRITICAL"),
    "/.htpasswd":              ("Exposed .htpasswd — may contain crackable credential hashes", "HIGH"),
    "/phpinfo.php":            ("phpinfo() exposed — reveals full server configuration", "MEDIUM"),
    "/server-status":          ("Apache server-status exposed — reveals internal request info", "MEDIUM"),
    "/.DS_Store":              ("Exposed .DS_Store — can reveal directory structure and filenames", "LOW"),
}

def check_sensitive_paths(base_url, soft_404):
    if soft_404:
        print_status("Skipping exposed-path checks (soft-404 — see WEB-202 above).", "dim")
        return []
    print_status("Checking for exposed sensitive files...", "info")
    found = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        results = pool.map(lambda p: _probe_path(base_url, p), SENSITIVE_PATHS.keys())
    for path, status in results:
        if status == 200:
            desc, sev = SENSITIVE_PATHS[path]
            found.append({"path": path, "detail": desc, "severity": sev})
            print_status(f"EXPOSED: {path} ({sev})", "err")
    if not found:
        note("WEB-401", "No exposed sensitive files found (.git, .env, backups, etc.).", "ok")
    return found

# ----------------------------------------------------------------
# DIRECTORY / FILE FUZZING
# ----------------------------------------------------------------
FALLBACK_PATHS = [
    "/admin", "/admin/login", "/login", "/wp-admin", "/wp-login.php",
    "/administrator", "/phpmyadmin", "/api", "/api/docs", "/uploads",
    "/backup", "/config", "/test", "/dev", "/staging", "/.well-known/security.txt",
]

def dir_fuzz(base_url, soft_404):
    if soft_404:
        print_status("Skipping directory fuzzing (soft-404 — see WEB-202 above).", "dim")
        return []
    print_status("Fuzzing for hidden directories/files...", "info")
    found = []

    if tool_available("gobuster") and os.path.exists(DIR_WORDLIST):
        result = run(
            ["gobuster", "dir", "-u", base_url, "-w", DIR_WORDLIST,
             "-t", "30", "-q", "--no-error"],
            timeout=180
        )
        if result and result.stdout:
            for line in result.stdout.splitlines():
                m = re.match(r"(/\S+)\s+\(Status:\s*(\d+)\)", line.strip())
                if m:
                    found.append({"path": m.group(1), "status": m.group(2)})
                    print_status(f"{m.group(1)} (Status: {m.group(2)})", "find")
        else:
            print_status("gobuster returned no results (or timed out).", "dim")
    else:
        note("WEB-501", f"gobuster not found — using a small built-in path list ({len(FALLBACK_PATHS)} paths, far less thorough).", "dim")
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
            results = pool.map(lambda p: _probe_path(base_url, p), FALLBACK_PATHS)
        for path, status in results:
            if status in (200, 301, 302, 401, 403):
                found.append({"path": path, "status": str(status)})
                print_status(f"{path} (Status: {status})", "find")

    if not found:
        note("WEB-402", "No hidden directories/files discovered (does not rule out paths outside the wordlist used).", "ok")
    return found

# ----------------------------------------------------------------
# NIKTO SCAN
# ----------------------------------------------------------------
def nikto_scan(base_url):
    if not tool_available("nikto"):
        note("WEB-502", "nikto not found — skipping known-vuln/misconfig scan. Install: sudo apt install nikto", "dim")
        return []
    print_status("Running nikto (this may take a few minutes)...", "info")
    result = run(["nikto", "-h", base_url, "-Tuning", "x", "-nointeractive"], timeout=300)
    findings = []
    if result is None:
        note("WEB-506", "nikto timed out after 300s — scan incomplete, not a security finding.", "err")
        return findings
    if result.stdout:
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("+") and "Target" not in line and "Server:" not in line[:12]:
                findings.append(line.lstrip("+ ").strip())
        for f in findings:
            print_status(f, "find")
    if not findings:
        note("WEB-403", "nikto found nothing notable — no known misconfig/vuln signatures matched.", "ok")
    return findings

# ----------------------------------------------------------------
# TLS / SSL CHECK
# ----------------------------------------------------------------
def tls_check(base_url):
    if not base_url.startswith("https://"):
        print_status("Target is HTTP only — skipping TLS check.", "dim")
        return []
    if not tool_available("sslscan"):
        note("WEB-503", "sslscan not found — skipping TLS check. Install: sudo apt install sslscan", "dim")
        return []
    print_status("Checking TLS/SSL configuration...", "info")
    host = urlparse(base_url).netloc
    result = run(["sslscan", "--no-colour", host], timeout=60)
    issues = []
    if result is None:
        note("WEB-507", "sslscan timed out after 60s — TLS check incomplete, not a security finding.", "err")
        return issues
    if result.stdout:
        for line in result.stdout.splitlines():
            line = line.strip()
            if re.search(r"(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1)\s+enabled", line, re.I):
                issues.append(line)
                print_status(f"Weak protocol: {line}", "err")
            elif "weak" in line.lower() or "vulnerable" in line.lower():
                issues.append(line)
                print_status(line, "err")
    if not issues:
        note("WEB-404", "No weak TLS protocols/ciphers found — modern TLS configuration only.", "ok")
    return issues

# ----------------------------------------------------------------
# PASSIVE INJECTION-CANDIDATE DISCOVERY (no requests sent beyond the
# normal page load — just parses links/forms already fetched)
# ----------------------------------------------------------------
def discover_candidates(base_url, html):
    candidates = set()
    for m in re.finditer(r'href=["\']([^"\']+\?[^"\']+=[^"\']*)["\']', html, re.I):
        url = urljoin(base_url, m.group(1))
        if urlparse(url).netloc == urlparse(base_url).netloc:
            candidates.add(url)
    for m in re.finditer(r'<form[^>]+action=["\']([^"\']*)["\']', html, re.I):
        action = m.group(1) or base_url
        url = urljoin(base_url, action)
        if urlparse(url).netloc == urlparse(base_url).netloc:
            candidates.add(url)
    return sorted(candidates)[:20]

# ----------------------------------------------------------------
# SECURITY HEADER / FINDINGS ANALYSIS
# ----------------------------------------------------------------
REQUIRED_HEADERS = {
    "Strict-Transport-Security": ("Missing HSTS — vulnerable to SSL stripping attacks", "HIGH"),
    "Content-Security-Policy":   ("Missing CSP — vulnerable to XSS attacks", "HIGH"),
    "X-Frame-Options":           ("Missing X-Frame-Options — vulnerable to clickjacking", "MEDIUM"),
    "X-Content-Type-Options":    ("Missing X-Content-Type-Options — MIME sniffing possible", "LOW"),
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

def analyze_findings(data):
    findings = []

    def add(title, detail, severity, remediation):
        findings.append({"title": title, "detail": detail, "severity": severity, "remediation": remediation})

    info = data.get("fingerprint", {})
    for header, (desc, sev) in REQUIRED_HEADERS.items():
        if header not in info:
            add(f"Missing Security Header: {header}", desc, sev,
                f"Add the {header} header to all HTTP responses via web server/app config.")

    server = info.get("Server", "")
    if server and any(c.isdigit() for c in server):
        add("Server Version Disclosed", f"Server header reveals version info: {server}", "LOW",
            "Configure the web server to suppress version info from the Server header.")

    cookie = info.get("Set-Cookie", "")
    if cookie and "secure" not in cookie.lower():
        add("Cookie Missing Secure Flag", "Session cookie set without the Secure attribute", "MEDIUM",
            "Set the Secure attribute on all session cookies.")
    if cookie and "httponly" not in cookie.lower():
        add("Cookie Missing HttpOnly Flag", "Session cookie set without HttpOnly — readable by JavaScript", "MEDIUM",
            "Set the HttpOnly attribute on all session cookies.")

    for p in data.get("exposed_paths", []):
        add(f"Exposed File: {p['path']}", p["detail"], p["severity"],
            f"Remove or restrict access to {p['path']} immediately.")

    for line in data.get("nikto", []):
        sev = "HIGH" if any(k in line for k in ("OSVDB", "vulnerable", "CVE")) else "MEDIUM"
        add("Nikto Finding", line, sev, "Review and patch/remediate per the finding detail above.")

    for line in data.get("tls", []):
        sev = "HIGH" if re.search(r"SSLv|TLSv1\.0", line) else "MEDIUM"
        add("TLS/SSL Weakness", line, sev, "Disable outdated protocols/ciphers; enforce TLS 1.2+.")

    findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
    return findings

# ----------------------------------------------------------------
# ACTIVE EXPLOITATION — gated, opt-in, off by default
# ----------------------------------------------------------------
def offer_exploitation(base_url, candidates):
    print()
    separator()
    print(f"\033[91m{'#'*68}\033[0m")
    print(f"\033[91m#{'  STOP — ACTIVE EXPLOITATION AHEAD':^66}#\033[0m")
    print(f"\033[91m{'#'*68}\033[0m")
    print_status("Everything above this point was passive/discovery only.", "dim")
    print_status("The step below sends real SQL injection payloads to the live", "err")
    print_status("target using sqlmap. This is active exploitation, not a scan.", "err")
    print_status("Only proceed if the site owner has given you EXPLICIT WRITTEN", "err")
    print_status("permission to actively exploit it. Unauthorized exploitation is", "err")
    print_status("a federal crime under the CFAA and equivalent laws worldwide.", "err")
    print(f"\033[91m{'#'*68}\033[0m")
    print()

    if not candidates:
        note("WEB-405", "No parameterized URLs or forms were discovered — nothing to test.", "dim")
        return None

    if not tool_available("sqlmap"):
        note("WEB-504", "sqlmap not found — active exploitation unavailable even if authorized. Install: sudo apt install sqlmap", "dim")
        return None

    confirm = input("\033[91m[!]\033[0m Type EXACTLY 'I HAVE PERMISSION' to proceed, or press Enter to skip: ").strip()
    if confirm != "I HAVE PERMISSION":
        print_status("Skipping exploitation. Passive findings only will be reported.", "dim")
        return None

    print()
    print_status(f"Discovered {len(candidates)} candidate parameterized URL(s):", "info")
    for i, c in enumerate(candidates):
        print(f"  \033[96m{i}\033[0m  {c}")
    print()

    choice = input("\033[93m[?]\033[0m Select # to test, or press Enter to skip: ").strip()
    if not choice.isdigit() or not (0 <= int(choice) < len(candidates)):
        print_status("No valid selection — skipping exploitation.", "dim")
        return None
    target_url = candidates[int(choice)]

    confirm2 = input(f"\033[91m[!]\033[0m Confirm you have written authorization to actively test\n"
                      f"    {target_url}\n"
                      f"    Type 'yes' to proceed: ").strip().lower()
    if confirm2 != "yes":
        print_status("Not confirmed — skipping exploitation.", "dim")
        return None

    print_status(f"Running sqlmap against {target_url} (conservative settings: level=1, risk=1)...", "info")
    separator()
    result = run(["sqlmap", "-u", target_url] + SQLMAP_ARGS, timeout=600)
    separator()

    if result is None:
        note("WEB-505", "sqlmap timed out (600s) — inconclusive, not a confirmation the target is safe.", "err")
        return {"target": target_url, "output": "sqlmap timed out or failed to run."}

    vulnerable = "is vulnerable" in result.stdout.lower() or "parameter:" in result.stdout.lower()
    if vulnerable:
        print_status("sqlmap reports a possible injection point!", "err")
    else:
        note("WEB-406", f"sqlmap did not confirm an injection point at conservative settings (level=1, risk=1) for {target_url}.", "ok")

    return {"target": target_url, "output": result.stdout[-4000:]}

# ----------------------------------------------------------------
# GENERATE TXT REPORT
# ----------------------------------------------------------------
def generate_report(target, data, findings, exploit):
    os.makedirs(REPORT_DIR, exist_ok=True)
    ts       = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = os.path.join(REPORT_DIR,
               f"burnweb_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")

    lines = []
    def w(s=""):
        lines.append(s)

    bar = "=" * 70

    w(bar)
    w("  BURN WEB v1.0 — WEB APPLICATION RECON REPORT")
    w(bar)
    w(f"  Target     : {target}")
    w(f"  Scan Time  : {ts}")
    w(bar)
    w()

    if findings:
        counts = {}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        count_str = "  ".join(f"{counts[s]} {s}" for s in
                               ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] if s in counts)
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
        w("  No actionable findings from passive checks.")
        w()

    def section(title, entries, empty_message="No data found."):
        w(title.upper())
        w("-" * 70)
        if entries:
            for e in entries:
                w(f"  {e}")
        else:
            w(f"  {empty_message}")
        w()

    fp = data.get("fingerprint", {})
    fp_entries = [f"{k}: {v}" for k, v in fp.items()]
    section("Fingerprint", fp_entries)

    robots = data.get("robots", {})
    robots_entries = [f"Disallow: {d}" for d in robots.get("disallow", [])]
    if robots.get("sitemap_found"):
        robots_entries.append("sitemap.xml: found")
    section("Robots.txt / Sitemap", robots_entries)

    exposed_entries = [f"{p['path']}  [{p['severity']}]  {p['detail']}" for p in data.get("exposed_paths", [])]
    section("Exposed Sensitive Paths", exposed_entries)

    dir_entries = [f"{d['path']} (Status: {d['status']})" for d in data.get("dir_fuzz", [])]
    section("Directory/File Discovery", dir_entries)

    section("Nikto Scan", data.get("nikto", []))
    section("TLS/SSL Check", data.get("tls", []))

    w("EXPLOITATION")
    w("-" * 70)
    if exploit:
        w(f"  Target tested : {exploit['target']}")
        w("  sqlmap output (tail):")
        for line in exploit["output"].splitlines():
            w(f"    {line}")
    else:
        w("  Not performed — passive/discovery only. Exploitation requires")
        w("  explicit typed confirmation each run and was either skipped or")
        w("  not confirmed.")
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
    w(f"  BURN WEB v1.0 | {ts} | FOR AUTHORIZED USE ONLY")
    w(bar)

    with open(filename, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines) + "\n")
    return filename

# ----------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------
def main():
    banner()

    target = get_target()
    separator()
    print_status(f"Starting web recon on: \033[96m{target}\033[0m", "ok")
    separator()

    base_url, resp = resolve_base_url(target)
    if resp is None:
        # NB: must be "is None", not "not resp" — requests.Response.__bool__
        # returns .ok, which is False for any 4xx/5xx. A target that answers
        # 401/403/404/500 on its landing page IS reachable and must be scanned,
        # not aborted as unreachable.
        note("WEB-201", "Could not connect to target over HTTPS or HTTP — target may be down, DNS may be failing, or the URL was mistyped.", "err")
        sys.exit(3)

    data = {}
    print()
    data["fingerprint"] = fingerprint(base_url, resp)
    soft_404 = check_soft_404(base_url)
    if soft_404:
        note("WEB-202", "Server returns HTTP 200 for unknown paths (soft-404) — exposed-file and directory-fuzzing checks are unreliable here and will be skipped.", "dim")
    separator()

    print()
    data["robots"] = get_robots_sitemap(base_url)
    separator()

    print()
    data["exposed_paths"] = check_sensitive_paths(base_url, soft_404)
    separator()

    print()
    data["dir_fuzz"] = dir_fuzz(base_url, soft_404)
    separator()

    print()
    data["nikto"] = nikto_scan(base_url)
    separator()

    print()
    data["tls"] = tls_check(base_url)
    separator()

    print()
    print_status("Analyzing findings...", "info")
    findings = analyze_findings(data)
    if findings:
        print_status(f"Found {len(findings)} finding(s).", "err")
    else:
        print_status("No findings from passive checks.", "ok")
    separator()

    candidates = discover_candidates(base_url, resp.text or "")
    exploit = offer_exploitation(base_url, candidates)
    separator()

    print()
    print_status("Generating report...", "info")
    report = generate_report(target, data, findings, exploit)
    print_status(f"Report saved to: \033[96m{report}\033[0m", "ok")
    print_status(f"View it with: \033[96mcat {report}\033[0m\n", "ok")

if __name__ == "__main__":
    main()
