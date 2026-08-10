#!/usr/bin/env python3

# ================================================================
#  BURN RECON v1.2.0
#  Automated OSINT Reconnaissance Tool
#  Part of the Burn Suite
#  Built for Kali Linux
#
#  LEGAL NOTICE: Only use on domains/targets you own or have
#  explicit written permission to investigate.
#
#  Usage: python3 ./burnrecon.py [target] [options]
#         python3 ./burnrecon.py            (interactive, passive)
#         python3 ./burnrecon.py acme.com --active -o both
#         python3 ./burnrecon.py acme.com --aggressive
#
#  Recon is PASSIVE by default (no packets to the target's own
#  infrastructure). --active enables direct probing; --aggressive
#  adds loud techniques (DNS brute-force, full port scan).
#
#  Dependencies: sudo apt install whois dnsutils nmap
#                pip3 install requests cryptography --break-system-packages
#                (cryptography is optional — enables full parsing of TLS
#                 certificates that fail validation; degrades gracefully.)
#
#  Copyright (C) 2026 Thomas Burns
#  License: GNU GPLv3 or later. Free software with NO WARRANTY; you may
#  redistribute and modify it under the GPL. See the LICENSE file or
#  <https://www.gnu.org/licenses/gpl-3.0.html>.
# ================================================================

import subprocess
import sys
import os
import socket
import shutil
import ipaddress
import datetime
import argparse
import json
import ssl
import re
import tempfile
import requests

# Optional: full certificate parsing (SANs, exact expiry, signature algorithm)
# even for certs that FAIL validation. Falls back gracefully if not installed.
try:
    from cryptography import x509 as _x509
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

VERSION = "1.2.0"

# ----------------------------------------------------------------
# CONFIG
# ----------------------------------------------------------------
REPORT_DIR   = os.path.join(os.path.dirname(os.path.abspath(os.path.realpath(__file__))), "burn_report")
TIMEOUT      = 10   # seconds for HTTP requests
QUIET        = False

def _load_key(filename):
    """Read an API key from <filename> next to this script (optional)."""
    key_file = os.path.join(os.path.dirname(os.path.abspath(os.path.realpath(__file__))), filename)
    try:
        with open(key_file) as f:
            key = f.read().strip()
        # Ignore the shipped placeholder so a copied-but-unedited template
        # doesn't get sent to an API as if it were a real key.
        if key.upper().startswith("PASTE_YOUR"):
            return ""
        return key
    except OSError:
        return ""

def _load_shodan_key():
    """Backwards-compatible alias — Shodan key loader."""
    return _load_key("shodan_api.txt")

SHODAN_KEY = _load_key("shodan_api.txt")
HUNTER_KEY = _load_key("hunter_api.txt")
HIBP_KEY   = _load_key("hibp_api.txt")

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
\033[0m\033[93m
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
\033[0m
\033[90m  Automated OSINT Reconnaissance Tool v%s
  FOR AUTHORIZED TESTING ONLY.
\033[0m""" % VERSION)

# ----------------------------------------------------------------
# HELPERS
# ----------------------------------------------------------------
def run(cmd, timeout=15):
    """Run a command. Pass a list to run without a shell (preferred whenever
    target/domain input is involved, to avoid shell injection)."""
    try:
        return subprocess.run(
            cmd, shell=isinstance(cmd, str),
            capture_output=True, text=True, timeout=timeout
        )
    except Exception:
        return None

def print_status(msg, level="info"):
    # --quiet suppresses routine progress chatter but never error lines.
    if QUIET and level != "err":
        return
    colors  = {"info": "\033[93m", "ok": "\033[92m", "err": "\033[91m", "dim": "\033[90m", "find": "\033[96m"}
    prefix  = {"info": "[*]", "ok": "[+]", "err": "[!]", "dim": "[~]", "find": "[>]"}
    c = colors.get(level, "\033[0m")
    p = prefix.get(level, "[*]")
    print(f"{c}{p}\033[0m {msg}")

def separator():
    if QUIET:
        return
    print(f"\033[90m{'─'*60}\033[0m")

# ----------------------------------------------------------------
# DIAGNOSTICS — codes logged on failure/empty-result, see ERROR_CODES.txt
# ----------------------------------------------------------------
DIAGNOSTICS = []

def note(code, msg, level="dim"):
    print_status(f"{code}: {msg}", level)
    DIAGNOSTICS.append(f"{code}: {msg}")

def get_target():
    print("\n\033[92m[?]\033[0m Enter target domain or company name")
    print("    Examples: example.com  |  192.168.1.1  |  Tesla Inc")
    target = input("\033[92m>>> \033[0m").strip()
    # Strip protocol if included
    target = target.replace("https://", "").replace("http://", "").rstrip("/")
    return target

def is_ip(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False

def _in_scope(sub, domain):
    """True if sub is the apex domain or a real subdomain of it — guards
    against substring false positives like notexample.com."""
    return sub == domain or sub.endswith("." + domain)

# ================================================================
# PASSIVE MODULES  (no packets to the target's own infrastructure)
# ================================================================

# ----------------------------------------------------------------
# DNS RECORDS
# ----------------------------------------------------------------
def get_dns_records(domain):
    if not shutil.which("dig"):
        note("RECON-101", "dig not found — DNS record lookup skipped. Install: sudo apt install dnsutils", "err")
        return {}
    print_status(f"Pulling DNS records for {domain}...", "info")
    records = {}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    for rtype in record_types:
        result = run(["dig", "+short", rtype, domain])
        if result and result.stdout.strip():
            entries = [l.strip() for l in result.stdout.strip().splitlines() if l.strip()]
            records[rtype] = entries
            for entry in entries:
                print_status(f"{rtype}: {entry}", "find")

    if not records:
        note("RECON-201", "No DNS records found — domain may not exist, or has a minimal DNS footprint.", "dim")
    return records

# ----------------------------------------------------------------
# WHOIS
# ----------------------------------------------------------------
def _whois_norm(val):
    """Comparison key so near-duplicate WHOIS values collapse to one entry.
    gTLD whois repeats fields across its registry and registrar sections in
    different spellings; this unifies case, trailing dots, punctuation, and
    ISO-8601 timezone forms (Z / +00:00 / +0000) so each fact appears once."""
    k = val.strip().lower().rstrip(".")
    k = k.replace(",", "")
    k = re.sub(r"\s+", " ", k)
    k = re.sub(r"(t[\d:]+)z$", r"\1+0000", k)   # ...T10:32:49Z -> ...+0000
    k = k.replace("+00:00", "+0000")
    return k

def get_whois(target):
    if not shutil.which("whois"):
        note("RECON-102", "whois not found — WHOIS lookup skipped. Install: sudo apt install whois", "err")
        return {}
    print_status(f"Running WHOIS on {target}...", "info")
    result = run(["whois", target], timeout=20)
    if result and result.stdout.strip():
        # Extract key fields
        fields = {}
        seen   = {}   # term -> set of normalized values already recorded
        key_terms = [
            "Registrar:", "Registrar URL:", "Registered On:", "Expires On:",
            "Updated On:", "Registrant Organization:", "Registrant Country:",
            "Name Server:", "DNSSEC:", "Creation Date:", "Updated Date:",
            "Expiry Date:", "Registry Expiry Date:",
            "Registrar Registration Expiration Date:",
            "Registry Domain ID:", "Admin Email:",
            "Tech Email:", "Registrant Email:"
        ]
        raw = result.stdout
        for line in raw.splitlines():
            for term in key_terms:
                if line.strip().startswith(term):
                    val = line.split(":", 1)[1].strip()
                    if not val:
                        continue
                    norm   = _whois_norm(val)
                    bucket = seen.setdefault(term, set())
                    if norm in bucket:
                        continue
                    bucket.add(norm)
                    fields.setdefault(term, []).append(val)
                    print_status(f"{term} {val}", "find")
        return {"fields": fields, "raw": raw}
    else:
        note("RECON-202", "WHOIS lookup failed or returned no data — privacy protection may be enabled, or `whois` isn't installed.", "err")
        return {}

# ----------------------------------------------------------------
# SUBDOMAIN ENUMERATION via crt.sh (certificate transparency)
# ----------------------------------------------------------------
def get_subdomains(domain):
    print_status(f"Enumerating subdomains via certificate transparency logs...", "info")
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        r = requests.get(url, timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.splitlines():
                    sub = sub.strip().lstrip("*.")
                    # Match only the apex or a real subdomain of it — a bare
                    # substring test would wrongly pull in unrelated names like
                    # notexample.com or example.com.attacker.net.
                    if _in_scope(sub, domain):
                        subdomains.add(sub)
            for sub in sorted(subdomains):
                print_status(sub, "find")
            if not subdomains:
                note("RECON-203", "No subdomains found via certificate transparency logs — minimal public subdomain footprint.", "dim")
        else:
            note("RECON-503", f"crt.sh returned status {r.status_code} — subdomain results may be incomplete.", "err")
    except Exception as e:
        note("RECON-503", f"crt.sh request failed: {e} — subdomain results may be incomplete.", "err")
    return sorted(subdomains)

# ----------------------------------------------------------------
# PASSIVE DNS / EXTRA CT SOURCES
# Broadens subdomain coverage beyond crt.sh. Each source is best-effort;
# a failure is a RECON-504 note, never fatal.
# ----------------------------------------------------------------
def get_passive_dns(domain):
    print_status("Querying additional passive-DNS sources...", "info")
    found = set()

    def _certspotter():
        url = (f"https://api.certspotter.com/v1/issuances?domain={domain}"
               f"&include_subdomains=true&expand=dns_names")
        r = requests.get(url, timeout=TIMEOUT)
        if r.status_code == 200:
            for cert in r.json():
                for n in cert.get("dns_names", []):
                    yield n

    def _hackertarget():
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=TIMEOUT)
        if r.status_code == 200 and "error" not in r.text.lower():
            for line in r.text.splitlines():
                if "," in line:
                    yield line.split(",", 1)[0]

    def _otx():
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        r = requests.get(url, timeout=TIMEOUT)
        if r.status_code == 200:
            for rec in r.json().get("passive_dns", []):
                if rec.get("hostname"):
                    yield rec["hostname"]

    for name, src in (("certspotter", _certspotter),
                      ("hackertarget", _hackertarget),
                      ("otx", _otx)):
        try:
            for host in src():
                host = host.strip().lstrip("*.").lower()
                if _in_scope(host, domain):
                    found.add(host)
        except Exception as e:
            note("RECON-504", f"passive-DNS source '{name}' failed: {e}", "dim")

    for sub in sorted(found):
        print_status(sub, "find")
    return sorted(found)

# ----------------------------------------------------------------
# IP GEOLOCATION  (resolves ALL A/AAAA records, geolocates the primary)
# ----------------------------------------------------------------
def _resolve_all(target):
    """Return every unique IP a hostname resolves to (A + AAAA)."""
    ips = []
    for res in socket.getaddrinfo(target, None):
        ip = res[4][0]
        if ip not in ips:
            ips.append(ip)
    return ips

def get_ip_info(target):
    print_status(f"Getting IP/geolocation info...", "info")
    info = {}
    try:
        if is_ip(target):
            ips = [target]
        else:
            ips = _resolve_all(target)
            if ips:
                print_status(f"Resolved to IP(s): {', '.join(ips)}", "find")
        if not ips:
            note("RECON-204", "Could not resolve target to an IP address — DNS resolution failed.", "err")
            return info

        info["all_ips"] = ips
        ip = ips[0]

        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            fields = ["ip", "city", "region", "country_name", "org", "asn", "timezone", "latitude", "longitude"]
            for f in fields:
                if data.get(f):
                    info[f] = data[f]
                    print_status(f"{f.upper()}: {data[f]}", "find")
    except socket.gaierror:
        note("RECON-204", "Could not resolve target to an IP address — DNS resolution failed.", "err")
    except Exception as e:
        print_status(f"IP lookup failed: {e}", "err")
    return info

# ----------------------------------------------------------------
# ASN -> NETBLOCK EXPANSION (RIPEstat, no key required)
# ----------------------------------------------------------------
def get_asn_netblocks(asn):
    if not asn:
        return []
    asn_num = re.sub(r"[^0-9]", "", str(asn))
    if not asn_num:
        return []
    print_status(f"Expanding AS{asn_num} to announced netblocks...", "info")
    prefixes = []
    try:
        r = requests.get(
            f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_num}",
            timeout=TIMEOUT
        )
        if r.status_code == 200:
            for p in r.json().get("data", {}).get("prefixes", []):
                if p.get("prefix"):
                    prefixes.append(p["prefix"])
                    print_status(p["prefix"], "find")
        if not prefixes:
            note("RECON-214", "ASN expansion returned no announced prefixes.", "dim")
    except Exception as e:
        note("RECON-214", f"ASN/netblock expansion failed: {e}", "dim")
    return prefixes

# ----------------------------------------------------------------
# EMAIL AUTHENTICATION (SPF / DMARC)
# ----------------------------------------------------------------
def get_email_auth(domain, dns_records):
    print_status("Analyzing email authentication (SPF/DMARC)...", "info")
    result = {"spf": None, "spf_all": None, "dmarc": None, "dmarc_policy": None}

    # SPF lives in the domain's TXT records (already pulled in get_dns_records).
    for txt in dns_records.get("TXT", []):
        low = txt.lower()
        if "v=spf1" in low:
            result["spf"] = txt.strip('"')
            m = re.search(r"([-+~?])all", low)
            if m:
                result["spf_all"] = m.group(0)
            print_status(f"SPF: {result['spf']}", "find")
            break

    # DMARC is a TXT record on _dmarc.<domain>.
    if shutil.which("dig"):
        res = run(["dig", "+short", "TXT", f"_dmarc.{domain}"])
        if res and res.stdout.strip():
            for line in res.stdout.splitlines():
                if "v=dmarc1" in line.lower():
                    result["dmarc"] = line.strip().strip('"')
                    m = re.search(r"p=([a-z]+)", line.lower())
                    if m:
                        result["dmarc_policy"] = m.group(1)
                    print_status(f"DMARC: {result['dmarc']}", "find")
                    break

    if result["spf"] and result["dmarc"] and result["dmarc_policy"] in ("quarantine", "reject") \
       and result["spf_all"] in ("-all", "~all"):
        note("RECON-207", "Email authentication present and reasonably strict (SPF + enforcing DMARC).", "ok")
    return result

# ----------------------------------------------------------------
# EMAIL FORMAT GUESSER
# ----------------------------------------------------------------
def guess_email_formats(domain):
    print_status("Generating common email format patterns...", "info")
    formats = [
        f"firstname.lastname@{domain}",
        f"firstname@{domain}",
        f"f.lastname@{domain}",
        f"flastname@{domain}",
        f"firstnamel@{domain}",
        f"lastname@{domain}",
        f"firstname_lastname@{domain}",
    ]
    for fmt in formats:
        print_status(fmt, "find")
    return formats

# ----------------------------------------------------------------
# OSINT DORK URL GENERATOR
# ----------------------------------------------------------------
def generate_dorks(domain):
    print_status("Generating OSINT dork URLs...", "info")
    import urllib.parse as _up
    def g(q):
        return "https://www.google.com/search?q=" + _up.quote(q)
    dorks = [
        g(f"site:{domain}"),
        g(f"site:{domain} ext:pdf OR ext:xls OR ext:docx"),
        g(f"site:{domain} intitle:index.of"),
        g(f"site:{domain} inurl:admin OR inurl:login"),
        g(f'site:pastebin.com "{domain}"'),
        f"https://github.com/search?q=%22{_up.quote(domain)}%22&type=code",
        f"https://github.com/search?q=%22{_up.quote(domain)}%22+password&type=code",
    ]
    for d in dorks:
        print_status(d, "find")
    return dorks

# ----------------------------------------------------------------
# SHODAN LOOKUP (optional — requires API key)
# ----------------------------------------------------------------
def get_shodan(target, api_key):
    if not api_key:
        note("RECON-501", "No Shodan API key configured — skipping. Copy shodan_api.txt.example to shodan_api.txt (next to this script) and paste in your own key.", "dim")
        return {}

    print_status("Querying Shodan...", "info")
    try:
        if not is_ip(target):
            ip = socket.gethostbyname(target)
        else:
            ip = target
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}?key={api_key}",
            timeout=TIMEOUT
        )
        if r.status_code == 200:
            data = r.json()
            result = {
                "ip":         data.get("ip_str", ""),
                "org":        data.get("org", ""),
                "os":         data.get("os", "Unknown"),
                "ports":      data.get("ports", []),
                "vulns":      list(data.get("vulns", {}).keys()),
                "hostnames":  data.get("hostnames", []),
                "tags":       data.get("tags", []),
                "last_update": data.get("last_update", "")
            }
            print_status(f"Ports: {', '.join(str(p) for p in result['ports'])}", "find")
            if result["vulns"]:
                print_status(f"Vulns: {', '.join(result['vulns'])}", "err")
            return result
        else:
            note("RECON-502", f"Shodan API returned {r.status_code} — rate-limited, invalid key, or no data for this IP.", "err")
    except socket.gaierror:
        note("RECON-204", "Could not resolve target to an IP address — DNS resolution failed.", "err")
    except Exception as e:
        print_status(f"Shodan lookup failed: {e}", "err")
    return {}

# ----------------------------------------------------------------
# HUNTER.IO — turn guessed email formats into real addresses (key-gated)
# ----------------------------------------------------------------
def get_hunter(domain, api_key):
    if not api_key:
        note("RECON-505", "No Hunter.io API key configured — email enrichment skipped. Add one to hunter_api.txt.", "dim")
        return {}
    print_status("Querying Hunter.io for known email addresses...", "info")
    try:
        r = requests.get(
            f"https://api.hunter.io/v2/domain-search?domain={domain}&api_key={api_key}",
            timeout=TIMEOUT
        )
        if r.status_code == 200:
            data = r.json().get("data", {})
            emails = [e.get("value") for e in data.get("emails", []) if e.get("value")]
            result = {"pattern": data.get("pattern", ""), "emails": emails}
            for e in emails:
                print_status(e, "find")
            return result
        else:
            note("RECON-506", f"Hunter.io returned {r.status_code} — rate-limited, invalid key, or no data.", "err")
    except Exception as e:
        note("RECON-506", f"Hunter.io lookup failed: {e}", "err")
    return {}

# ----------------------------------------------------------------
# HAVE I BEEN PWNED — breaches affecting the domain (key-gated)
# ----------------------------------------------------------------
def get_hibp(domain, api_key):
    if not api_key:
        note("RECON-507", "No HIBP API key configured — breach lookup skipped. Add one to hibp_api.txt.", "dim")
        return {}
    print_status("Querying HaveIBeenPwned for domain breaches...", "info")
    try:
        r = requests.get(
            f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}",
            timeout=TIMEOUT,
            headers={"hibp-api-key": api_key, "User-Agent": "BurnRecon"}
        )
        if r.status_code == 200:
            breaches = [b.get("Name") for b in r.json() if b.get("Name")]
            for b in breaches:
                print_status(f"Breach: {b}", "err")
            return {"breaches": breaches}
        else:
            note("RECON-508", f"HIBP returned {r.status_code} — rate-limited, invalid key, or no data.", "err")
    except Exception as e:
        note("RECON-508", f"HIBP lookup failed: {e}", "err")
    return {}

# ================================================================
# ACTIVE MODULES  (direct contact with the target's infrastructure)
# ================================================================

# ----------------------------------------------------------------
# HEADER GRABBING (web fingerprint)
# ----------------------------------------------------------------
def get_headers(target):
    print_status("Grabbing HTTP headers...", "info")
    headers_found = {}
    for scheme in ["https", "http"]:
        try:
            r = requests.get(
                f"{scheme}://{target}",
                timeout=TIMEOUT,
                allow_redirects=True,
                headers={"User-Agent": "Mozilla/5.0"}
            )
            interesting = [
                "Server", "X-Powered-By", "X-Frame-Options", "X-XSS-Protection",
                "Content-Security-Policy", "Strict-Transport-Security",
                "X-Content-Type-Options", "Set-Cookie", "WWW-Authenticate",
                "Access-Control-Allow-Origin"
            ]
            for h in interesting:
                if h in r.headers:
                    headers_found[h] = r.headers[h]
                    print_status(f"{h}: {r.headers[h][:100]}", "find")
            headers_found["status_code"] = r.status_code
            headers_found["final_url"]   = r.url
            print_status(f"Status: {r.status_code} | URL: {r.url}", "ok")
            break
        except Exception:
            continue
    if not headers_found:
        note("RECON-205", "Could not connect to a web server on this target — may be down, firewalled, or not serving HTTP/HTTPS.", "dim")
    return headers_found

# ----------------------------------------------------------------
# TLS / CERTIFICATE INSPECTION (+ SAN harvest for more subdomains)
# ----------------------------------------------------------------
def _fetch_cert(host, port=443):
    """Return (peer-certificate dict, negotiated protocol) for host:port.
    Uses a validating context because getpeercert() returns an EMPTY dict
    when verification is disabled (CERT_NONE). Raises SSLCertVerificationError
    when the chain doesn't validate. Isolated so tests can patch it without a
    real TLS handshake."""
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            return ssock.getpeercert(), ssock.version()

def _fetch_chain_der(host, port=443):
    """Return (list of DER certs [leaf, intermediates...], negotiated protocol)
    via a NON-validating handshake — so we can retrieve and parse the whole
    chain even when it fails validation. Falls back to just the peer cert on
    Python builds without get_unverified_chain()."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            proto = ssock.version()
            chain = []
            if hasattr(ssock, "get_unverified_chain"):
                try:
                    chain = [bytes(c) for c in (ssock.get_unverified_chain() or [])]
                except Exception:
                    chain = []
            if not chain:
                der = ssock.getpeercert(binary_form=True)
                if der:
                    chain = [der]
            return chain, proto

WEAK_SIG_ALGOS = {"md2", "md4", "md5", "sha1"}

def _cert_sig_and_cn(der):
    """(signature-hash-algo lowercased, common name) for a DER cert."""
    if not _HAS_CRYPTO or not der:
        return "", ""
    try:
        c = _x509.load_der_x509_certificate(der)
        algo = c.signature_hash_algorithm.name if c.signature_hash_algorithm else ""
        try:
            cn = c.subject.get_attributes_for_oid(_x509.NameOID.COMMON_NAME)[0].value
        except Exception:
            cn = ""
        return (algo or "").lower(), cn
    except Exception:
        return "", ""

def _scan_weak_sigs(chain):
    """Flag any cert in the chain (leaf OR intermediate) signed with a broken
    hash. A SHA-1 intermediate under a SHA-256 leaf is a real, common finding
    that a leaf-only check would miss entirely."""
    weak = []
    for i, der in enumerate(chain):
        algo, cn = _cert_sig_and_cn(der)
        if algo in WEAK_SIG_ALGOS:
            weak.append({"position": "leaf" if i == 0 else "intermediate",
                         "cn": cn or "(unknown)", "algo": algo})
    return weak

def _classify_tls_failure(msg):
    """Map an OpenSSL verification message to a specific reason. A blanket
    'self-signed' label would misreport expired/mismatched/untrusted certs."""
    m = (msg or "").lower()
    if "expired" in m:
        return "expired"
    if "self signed" in m or "self-signed" in m:
        return "self-signed"
    if "mismatch" in m or "doesn't match" in m or "not valid for" in m:
        return "hostname-mismatch"
    return "untrusted"

def _parse_cert_der(der):
    """Parse raw DER into structured fields using cryptography. Works for any
    certificate, valid or not. Returns {} if cryptography isn't installed."""
    if not _HAS_CRYPTO or not der:
        return {}
    cert = _x509.load_der_x509_certificate(der)

    def _attr(name, oid):
        try:
            return name.get_attributes_for_oid(oid)[0].value
        except Exception:
            return ""

    try:
        sans = cert.extensions.get_extension_for_class(
            _x509.SubjectAlternativeName).value.get_values_for_type(_x509.DNSName)
    except Exception:
        sans = []

    # not_valid_after_utc is timezone-aware (cryptography >= 42); fall back for older.
    try:
        not_after = cert.not_valid_after_utc
        now = datetime.datetime.now(datetime.timezone.utc)
    except AttributeError:
        not_after = cert.not_valid_after
        now = datetime.datetime.utcnow()
    try:
        days_left = (not_after - now).days
    except Exception:
        days_left = None

    try:
        sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else ""
    except Exception:
        sig_algo = ""

    return {
        "subject_cn": _attr(cert.subject, _x509.NameOID.COMMON_NAME),
        "issuer_cn":  _attr(cert.issuer, _x509.NameOID.COMMON_NAME),
        "issuer_org": _attr(cert.issuer, _x509.NameOID.ORGANIZATION_NAME),
        "not_after":  not_after.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "days_left":  days_left,
        "sans":       list(sans),
        "self_signed": cert.subject == cert.issuer,
        "sig_algo":   sig_algo,
    }

def get_tls_info(target):
    host = target
    print_status("Inspecting TLS certificate...", "info")

    # 1) Cert DETAIL first, from the raw chain — works for any cert and is
    #    independent of whether the trust check below succeeds.
    detail, weak, chain_len, proto = {}, [], 0, None
    got_cert = False
    try:
        chain, proto = _fetch_chain_der(host)
        chain_len = len(chain)
        if chain:
            got_cert = True
            detail = _parse_cert_der(chain[0])
            weak = _scan_weak_sigs(chain)
    except Exception:
        pass  # we may still be able to learn the trust status below

    # 2) TRUST status — a separate validating handshake. A connection error
    #    here must NOT wipe out the detail we already have.
    reason = None
    try:
        _dict, vproto = _fetch_cert(host)
        reason = "valid"
        proto = proto or vproto
    except ssl.SSLCertVerificationError as e:
        reason = _classify_tls_failure(getattr(e, "verify_message", "") or str(e))
    except Exception as e:
        reason = "unknown" if got_cert else None
        if not got_cert:
            note("RECON-209", f"TLS certificate inspection failed: {e}", "dim")
            return {}

    if reason is None:
        reason = "unknown"
    if not detail and not _HAS_CRYPTO:
        note("RECON-209", "Install 'cryptography' for full certificate detail "
                          "(SANs, expiry, chain signatures) on invalid certs.", "dim")

    info = {
        "valid":    reason == "valid",
        "reason":   None if reason == "valid" else reason,
        "protocol": proto,
        "weak_sigs": weak,
        "chain_len": chain_len,
        **detail,
    }
    info.setdefault("subject_cn", host)     # never render "None"
    info.setdefault("sans", [])
    info.setdefault("days_left", None)
    if "self_signed" not in info:
        info["self_signed"] = (reason == "self-signed")

    if reason == "valid":
        print_status(f"Issuer: {info.get('issuer_cn') or info.get('issuer_org','')} | Proto: {proto}", "find")
    else:
        print_status(f"TLS cert: {reason} | Proto: {proto}", "find")
        note("RECON-209", f"TLS certificate did not validate ({reason}).", "dim")
    if info.get("sans"):
        print_status(f"SAN entries: {len(info['sans'])}", "find")
    return info

# ----------------------------------------------------------------
# SUBDOMAIN TAKEOVER DETECTION (dangling CNAMEs)
# ----------------------------------------------------------------
TAKEOVER_FINGERPRINTS = {
    "GitHub Pages":  ("github.io",        "There isn't a GitHub Pages site here"),
    "AWS S3":        ("s3.amazonaws.com", "NoSuchBucket"),
    "Heroku":        ("herokuapp.com",    "No such app"),
    "Azure":         ("azurewebsites.net","404 Web Site not found"),
    "Fastly":        ("fastly.net",       "Fastly error: unknown domain"),
    "Shopify":       ("myshopify.com",    "Sorry, this shop is currently unavailable"),
    "Zendesk":       ("zendesk.com",      "Help Center Closed"),
    "Read the Docs": ("readthedocs.io",   "unknown to Read the Docs"),
    "Ghost":         ("ghost.io",         "The thing you were looking for is no longer here"),
    "Surge.sh":      ("surge.sh",         "project not found"),
}

def _cname_of(host):
    res = run(["dig", "+short", "CNAME", host])
    if res and res.stdout.strip():
        return res.stdout.strip().splitlines()[0].rstrip(".")
    return ""

def check_subdomain_takeover(subdomains):
    if not shutil.which("dig"):
        return []
    print_status("Checking for subdomain takeover (dangling CNAMEs)...", "info")
    findings = []
    for sub in subdomains:
        cname = _cname_of(sub)
        if not cname:
            continue
        for service, (cname_sig, body_sig) in TAKEOVER_FINGERPRINTS.items():
            if cname_sig in cname:
                # CNAME points at the provider — confirm it's actually unclaimed.
                try:
                    r = requests.get(f"http://{sub}", timeout=TIMEOUT,
                                     headers={"User-Agent": "Mozilla/5.0"})
                    if body_sig.lower() in r.text.lower():
                        findings.append({"subdomain": sub, "cname": cname, "service": service})
                        print_status(f"POSSIBLE TAKEOVER: {sub} -> {cname} ({service})", "err")
                except Exception:
                    pass
                break
    if not findings:
        note("RECON-210", "No subdomain-takeover candidates found.", "dim")
    return findings

# ----------------------------------------------------------------
# DNS ZONE TRANSFER (AXFR)
# ----------------------------------------------------------------
def try_zone_transfer(domain, ns_list):
    if not shutil.which("dig"):
        return {}
    print_status("Attempting DNS zone transfer (AXFR)...", "info")
    for ns in ns_list:
        ns = ns.rstrip(".")
        res = run(["dig", "AXFR", domain, f"@{ns}"], timeout=20)
        if not res or not res.stdout:
            continue
        out = res.stdout
        if "Transfer failed" in out or "failed" in out.lower() or "connection timed out" in out.lower():
            continue
        # A successful transfer returns real zone records (SOA appears twice).
        records = [l.strip() for l in out.splitlines()
                   if l.strip() and not l.startswith(";")]
        if out.count("SOA") >= 2 and len(records) > 1:
            print_status(f"ZONE TRANSFER ALLOWED by {ns} ({len(records)} records)", "err")
            return {"vulnerable": True, "ns": ns, "records": records}
    note("RECON-208", "Zone transfer refused by all name servers (expected).", "dim")
    return {"vulnerable": False}

# ----------------------------------------------------------------
# WEB METADATA FILES
# ----------------------------------------------------------------
def get_web_metadata(target):
    print_status("Fetching exposed web metadata files...", "info")
    found = {}
    paths = {
        "robots.txt":              "robots.txt",
        "sitemap.xml":             "sitemap.xml",
        ".well-known/security.txt":".well-known/security.txt",
    }
    for label, path in paths.items():
        for scheme in ("https", "http"):
            try:
                r = requests.get(f"{scheme}://{target}/{path}", timeout=TIMEOUT,
                                 headers={"User-Agent": "Mozilla/5.0"})
                if r.status_code == 200 and r.text.strip():
                    found[label] = r.text.strip()[:2000]
                    print_status(f"Found /{path} ({len(r.text)} bytes)", "find")
                    break
            except Exception:
                continue
    if not found:
        note("RECON-211", "No exposed web metadata files (robots.txt/sitemap.xml/security.txt).", "dim")
    return found

# ----------------------------------------------------------------
# CORS MISCONFIGURATION TEST
# ----------------------------------------------------------------
def check_cors(target):
    print_status("Testing CORS policy...", "info")
    evil = "https://evil.example"
    for scheme in ("https", "http"):
        try:
            r = requests.get(f"{scheme}://{target}", timeout=TIMEOUT,
                             headers={"User-Agent": "Mozilla/5.0", "Origin": evil})
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            result = {"acao": acao, "acac": acac, "vulnerable": False}
            if acao == evil or (acao == "*" and acac.lower() == "true"):
                result["vulnerable"] = True
                print_status(f"CORS reflects arbitrary origin: {acao} (creds={acac})", "err")
            return result
        except Exception:
            continue
    note("RECON-212", "CORS not testable — no reachable web server.", "dim")
    return {}

# ----------------------------------------------------------------
# QUICK PORT SCAN (active, common ports)
# ----------------------------------------------------------------
def quick_port_scan(target):
    if not shutil.which("nmap"):
        note("RECON-103", "nmap not found — quick port scan skipped. Install: sudo apt install nmap", "err")
        return []
    print_status("Running quick port scan on common ports...", "info")
    result = run(
        ["nmap", "-sV", "--open", "-p",
         "21,22,23,25,53,80,110,143,443,445,3306,3389,8080,8443", target],
        timeout=60
    )
    return _parse_nmap(result)

def _parse_nmap(result):
    open_ports = []
    if result and result.stdout:
        for line in result.stdout.splitlines():
            if "/tcp" in line and "open" in line:
                open_ports.append(line.strip())
                print_status(line.strip(), "find")
    if not open_ports:
        note("RECON-206", "No common ports open — firewall filtering, or genuinely minimal exposed services.", "dim")
    return open_ports

# ================================================================
# AGGRESSIVE MODULES  (loud — opt-in via --aggressive)
# ================================================================

# ----------------------------------------------------------------
# FULL / SCRIPTED PORT SCAN
# ----------------------------------------------------------------
def aggressive_port_scan(target):
    if not shutil.which("nmap"):
        note("RECON-103", "nmap not found — port scan skipped. Install: sudo apt install nmap", "err")
        return []
    print_status("Running aggressive scan (top 1000 ports + default scripts)...", "info")
    result = run(
        ["nmap", "-sV", "-sC", "--open", "--top-ports", "1000", target],
        timeout=300
    )
    return _parse_nmap(result)

# ----------------------------------------------------------------
# DNS SUBDOMAIN BRUTE-FORCE
# ----------------------------------------------------------------
BRUTE_WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "admin", "portal", "dev", "staging", "test",
    "api", "cdn", "git", "gitlab", "jenkins", "jira", "shop", "store",
    "app", "mobile", "m", "beta", "demo", "cloud", "backup", "db",
    "sql", "ftp", "files", "download", "support", "help", "docs", "wiki",
]

def _wildcard_active(domain):
    """Detect wildcard DNS — if a random label resolves, brute results are noise."""
    import random, string
    rnd = "".join(random.choice(string.ascii_lowercase) for _ in range(12))
    try:
        socket.gethostbyname(f"{rnd}.{domain}")
        return True
    except Exception:
        return False

def dns_brute(domain, wordlist=None):
    words = wordlist if wordlist else BRUTE_WORDLIST
    print_status(f"Brute-forcing {len(words)} subdomain candidates...", "info")
    if _wildcard_active(domain):
        note("RECON-213", "Wildcard DNS detected — subdomain brute-force skipped (would be all false positives).", "dim")
        return []
    found = []
    for w in words:
        host = f"{w}.{domain}"
        try:
            ip = socket.gethostbyname(host)
            found.append(host)
            print_status(f"{host} -> {ip}", "find")
        except Exception:
            continue
    if not found:
        note("RECON-213", "DNS brute-force found no additional hosts.", "dim")
    return found

# ----------------------------------------------------------------
# VULNERABILITY ANALYSIS ENGINE
# ----------------------------------------------------------------
RISKY_PORTS = {
    "21":   ("FTP — unencrypted file transfer, often allows anonymous access", "HIGH"),
    "23":   ("Telnet — completely unencrypted, credentials sent in plaintext", "CRITICAL"),
    "25":   ("SMTP — open relay potential, check if auth required", "MEDIUM"),
    "110":  ("POP3 — unencrypted email retrieval", "MEDIUM"),
    "143":  ("IMAP — unencrypted email, credentials at risk", "MEDIUM"),
    "445":  ("SMB — common ransomware/lateral movement vector (EternalBlue etc.)", "CRITICAL"),
    "3306": ("MySQL — database exposed to network, should never be public", "HIGH"),
    "3389": ("RDP — remote desktop, frequent brute force and exploit target", "HIGH"),
    "8080": ("HTTP alternate — often dev/admin panels with weak auth", "MEDIUM"),
    "8443": ("HTTPS alternate — check for self-signed certs and weak configs", "LOW"),
}

REQUIRED_HEADERS = {
    "Strict-Transport-Security": ("Missing HSTS — site vulnerable to SSL stripping attacks", "HIGH"),
    "Content-Security-Policy":   ("Missing CSP — site vulnerable to XSS attacks", "HIGH"),
    "X-Frame-Options":           ("Missing X-Frame-Options — site vulnerable to clickjacking", "MEDIUM"),
    "X-Content-Type-Options":    ("Missing X-Content-Type-Options — MIME sniffing attacks possible", "LOW"),
    "X-XSS-Protection":          ("Missing X-XSS-Protection header", "LOW"),
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

def analyze_cookies(headers):
    """Flag insecure Set-Cookie flags. Returns a list of (issue, severity)."""
    issues = []
    cookie = headers.get("Set-Cookie", "")
    if not cookie:
        return issues
    low = cookie.lower()
    if "secure" not in low:
        issues.append(("Set-Cookie missing the Secure flag — cookies may be sent over plain HTTP", "MEDIUM"))
    if "httponly" not in low:
        issues.append(("Set-Cookie missing HttpOnly — cookies readable by JavaScript (XSS theft)", "MEDIUM"))
    if "samesite" not in low:
        issues.append(("Set-Cookie missing SameSite — cross-site request forgery risk", "LOW"))
    return issues

def analyze_vulnerabilities(data):
    findings = []

    def add(title, detail, severity, remediation):
        findings.append({
            "title":       title,
            "detail":      detail,
            "severity":    severity,
            "remediation": remediation
        })

    # --- Port analysis (nmap output AND Shodan-reported ports) ---
    open_port_nums = set()
    for port_line in data.get("ports", []):
        # nmap lines look like "3306/tcp open mysql" — pull the leading
        # "<port>/tcp" token and match it exactly, so port 3306 can't be
        # falsely matched inside 13306 (and 21 inside 2121, etc.).
        token     = port_line.split()[0] if port_line.split() else ""
        line_port = token.split("/")[0] if "/tcp" in token else ""
        if line_port:
            open_port_nums.add(line_port)
    # Shodan also reports open ports — feed them through the same risk table
    # so findings still appear when nmap is unavailable/skipped.
    for p in data.get("shodan", {}).get("ports", []):
        open_port_nums.add(str(p))

    for port_num in sorted(open_port_nums):
        if port_num in RISKY_PORTS:
            desc, sev = RISKY_PORTS[port_num]
            add(
                f"Risky Port Open: {port_num}/tcp",
                desc,
                sev,
                f"Restrict port {port_num} to trusted IPs only or disable if not needed. "
                f"Consider replacing with encrypted alternatives where available."
            )

    # --- HTTP header analysis ---
    # Only judge headers if we actually reached a web server (status_code is
    # set only on a successful fetch). An unreachable target must not be
    # reported as "missing" every security header — that's the RECON-205
    # "couldn't connect" case, not a real finding.
    headers = data.get("headers", {})
    if headers.get("status_code"):
        for header, (desc, sev) in REQUIRED_HEADERS.items():
            if header not in headers:
                add(
                    f"Missing Security Header: {header}",
                    desc,
                    sev,
                    f"Add the {header} header to all HTTP responses via web server config."
                )

    # --- Server version disclosure ---
    server = headers.get("Server", "")
    if server and any(c.isdigit() for c in server):
        add(
            "Server Version Disclosed",
            f"Server header reveals version info: {server}. Attackers use this to target known exploits.",
            "LOW",
            "Configure web server to suppress version info from the Server header."
        )

    # --- X-Powered-By disclosure ---
    powered = headers.get("X-Powered-By", "")
    if powered:
        add(
            "Technology Stack Disclosed",
            f"X-Powered-By header reveals backend: {powered}",
            "LOW",
            "Remove X-Powered-By header from web server or application config."
        )

    # --- Insecure cookies ---
    for issue, sev in analyze_cookies(headers):
        add("Insecure Cookie Configuration", issue, sev,
            "Set Secure, HttpOnly and SameSite attributes on all cookies.")

    # --- CORS misconfiguration ---
    cors = data.get("cors", {})
    if cors.get("vulnerable"):
        add(
            "CORS Misconfiguration",
            f"Server reflects an arbitrary Origin in Access-Control-Allow-Origin "
            f"({cors.get('acao')}), credentials={cors.get('acac')}. Enables cross-origin data theft.",
            "HIGH",
            "Whitelist specific trusted origins; never reflect arbitrary Origin with credentials enabled."
        )

    # --- Email authentication (SPF/DMARC) ---
    email = data.get("email_auth", {})
    if email:
        if not email.get("spf"):
            add("Missing SPF Record",
                "No SPF record — anyone can spoof email from this domain.",
                "MEDIUM",
                "Publish an SPF TXT record listing authorized mail senders, ending in -all.")
        elif email.get("spf_all") in ("+all", "?all"):
            add("Weak SPF Policy",
                f"SPF ends in '{email.get('spf_all')}', which does not restrict senders — spoofing still possible.",
                "MEDIUM",
                "Tighten the SPF record to end in -all (hard fail) or ~all (soft fail).")
        if not email.get("dmarc"):
            add("Missing DMARC Record",
                "No DMARC policy — spoofed mail is not rejected or reported.",
                "MEDIUM",
                "Publish a _dmarc TXT record with p=quarantine or p=reject.")
        elif email.get("dmarc_policy") == "none":
            add("DMARC Policy Not Enforced",
                "DMARC is set to p=none (monitor only) — spoofed mail is still delivered.",
                "LOW",
                "Move DMARC to p=quarantine or p=reject once monitoring looks clean.")

    # --- TLS certificate issues ---
    tls = data.get("tls", {})
    if tls:
        subj = tls.get("subject_cn") or "this host"
        reason = tls.get("reason")
        if reason == "expired":
            add("Expired TLS Certificate",
                f"The TLS certificate presented by {subj} has expired — browsers warn "
                f"and the connection can't be trusted.",
                "HIGH", "Renew the TLS certificate immediately.")
        elif reason == "self-signed":
            add("Self-Signed TLS Certificate",
                f"The TLS certificate for {subj} is self-signed — not issued by a trusted CA (MITM risk).",
                "MEDIUM", "Install a certificate from a trusted CA (e.g. Let's Encrypt).")
        elif reason == "hostname-mismatch":
            add("TLS Hostname Mismatch",
                f"The certificate served for {subj} does not match the hostname — misissued or misconfigured.",
                "MEDIUM", "Install a certificate whose CN/SAN covers this hostname.")
        elif reason == "untrusted":
            add("Untrusted TLS Certificate",
                f"The TLS certificate for {subj} failed validation (untrusted CA or broken chain).",
                "MEDIUM", "Install a certificate from a trusted CA and serve the full chain.")
        elif tls.get("self_signed"):
            # Valid-path edge: chain validated but subject == issuer.
            add("Self-Signed TLS Certificate",
                f"The TLS certificate for {subj} is self-signed — no trusted CA, MITM risk.",
                "MEDIUM", "Install a certificate from a trusted CA (e.g. Let's Encrypt).")

        proto = (tls.get("protocol") or "")
        if proto in ("TLSv1", "TLSv1.1", "SSLv3"):
            add(f"Weak TLS Protocol: {proto}",
                f"Server negotiated {proto}, which is deprecated and vulnerable.",
                "HIGH",
                "Disable TLS 1.1 and below; require TLS 1.2+.")

        # Weak signatures anywhere in the chain (leaf or intermediate).
        weak = tls.get("weak_sigs", [])
        if weak:
            algos = ", ".join(sorted({w["algo"].upper() for w in weak}))
            who = "; ".join(f"{w['position']} '{w['cn']}' ({w['algo'].upper()})" for w in weak)
            # MD5, or a weak LEAF, is worse than a weak intermediate (browsers
            # already distrust SHA-1 intermediates, but it's still misconfig).
            sev = "HIGH" if any(w["algo"] == "md5" or w["position"] == "leaf" for w in weak) else "MEDIUM"
            add(f"Weak Certificate Signature: {algos}",
                f"The TLS certificate chain contains weakly-signed certificate(s): {who}. "
                f"MD5/SHA-1 signatures are cryptographically broken and enable forgery.",
                sev,
                "Reissue/replace the affected certificate(s) with SHA-256 or stronger signatures.")

        # Expiry from the parsed cert. Skip when reason=='expired' — that
        # branch above already reported it, so we don't double-count.
        days = tls.get("days_left")
        if isinstance(days, int) and reason != "expired":
            if days < 0:
                add("Expired TLS Certificate",
                    f"Certificate expired {abs(days)} days ago.",
                    "HIGH", "Renew the TLS certificate immediately.")
            elif days < 15:
                add(f"TLS Certificate Expiring: {days} Days",
                    f"Certificate expires in {days} days.",
                    "MEDIUM", "Renew the TLS certificate soon.")

    # --- Zone transfer ---
    zt = data.get("zone_transfer", {})
    if zt.get("vulnerable"):
        add("DNS Zone Transfer Allowed",
            f"Name server {zt.get('ns')} allowed a full AXFR zone transfer "
            f"({len(zt.get('records', []))} records) — exposes the entire internal DNS layout.",
            "CRITICAL",
            "Restrict zone transfers (allow-transfer) to authorized secondary name servers only.")

    # --- Subdomain takeover ---
    for t in data.get("takeover", []):
        add(f"Possible Subdomain Takeover: {t['subdomain']}",
            f"{t['subdomain']} has a dangling CNAME to {t['cname']} ({t['service']}) that appears unclaimed.",
            "HIGH",
            f"Remove the dangling DNS record or reclaim the {t['service']} resource.")

    # --- Shodan vulns ---
    shodan = data.get("shodan", {})
    for vuln in shodan.get("vulns", []):
        add(
            f"Shodan CVE: {vuln}",
            f"Shodan intelligence identified this CVE against the target.",
            "CRITICAL",
            f"Research {vuln} immediately and apply vendor patches. Check CVE database for details."
        )

    # --- HIBP breaches ---
    for b in data.get("hibp", {}).get("breaches", []):
        add(f"Domain Present in Breach: {b}",
            f"HaveIBeenPwned lists this domain in the '{b}' breach — credentials may be exposed.",
            "MEDIUM",
            "Force password resets for affected accounts and enable MFA.")

    # --- Subdomain count ---
    subs = data.get("subdomains", [])
    if len(subs) > 10:
        add(
            f"Large Attack Surface: {len(subs)} Subdomains Found",
            "High subdomain count increases attack surface. Forgotten or unmaintained subdomains are common entry points.",
            "MEDIUM",
            "Audit all subdomains. Decommission unused ones. Ensure all are patched and monitored."
        )

    # --- WHOIS expiry check ---
    whois = data.get("whois", {})
    fields = whois.get("fields", {})
    for key in ["Expires On:", "Expiry Date:", "Registry Expiry Date:",
                "Registrar Registration Expiration Date:"]:
        if key in fields:
            try:
                from datetime import datetime
                expiry_str = fields[key][0].split("T")[0]
                expiry = datetime.strptime(expiry_str[:10], "%Y-%m-%d")
                days_left = (expiry - datetime.now()).days
                if days_left < 30:
                    add(
                        f"Domain Expiring Soon: {days_left} Days",
                        f"Domain expires on {expiry_str}. Expired domains can be hijacked.",
                        "CRITICAL",
                        "Renew the domain immediately."
                    )
                elif days_left < 90:
                    add(
                        f"Domain Expiring: {days_left} Days Remaining",
                        f"Domain expires on {expiry_str}.",
                        "MEDIUM",
                        "Schedule domain renewal before expiry."
                    )
            except Exception:
                pass

    # Sort by severity
    findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))
    return findings

# ----------------------------------------------------------------
# GENERATE TXT REPORT
# ----------------------------------------------------------------
def _ensure_report_dir():
    """Return a writable directory for reports. Falls back to ~/burn_report
    then a temp dir if REPORT_DIR isn't writable (e.g. it was created by an
    earlier sudo run and is now owned by root) — so a completed scan is never
    lost to a final file-write failure."""
    candidates = [
        REPORT_DIR,
        os.path.join(os.path.expanduser("~"), "burn_report"),
        os.path.join(tempfile.gettempdir(), "burn_report"),
    ]
    for d in candidates:
        try:
            os.makedirs(d, exist_ok=True)
            probe = os.path.join(d, ".burnrecon_write_test")
            with open(probe, "w") as f:
                f.write("")
            os.remove(probe)
            if os.path.abspath(d) != os.path.abspath(REPORT_DIR):
                note("RECON-105", f"Report directory '{REPORT_DIR}' is not writable — "
                                  f"saving to '{d}' instead. Fix with: chown -R $USER "
                                  f"'{REPORT_DIR}'", "err")
            return d
        except OSError:
            continue
    return REPORT_DIR  # nothing worked; let the caller surface the error

def generate_report(target, data, findings, mode="passive"):
    rdir     = _ensure_report_dir()
    ts       = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = os.path.join(rdir,
               f"burnrecon_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")

    lines = []
    def w(s=""):
        lines.append(s)

    bar = "=" * 70

    w(bar)
    w(f"  BURN RECON v{VERSION} — OSINT RECONNAISSANCE REPORT")
    w(bar)
    w(f"  Target     : {target}")
    w(f"  Scan Mode  : {mode.upper()}")
    w(f"  Scan Time  : {ts}")
    w(bar)
    w()

    # --- Findings summary ---
    if findings:
        counts = {}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        count_str = "  ".join(
            f"{counts[s]} {s}" for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] if s in counts
        )
        w(f"VULNERABILITY SUMMARY  ({count_str})")
        w("-" * 70)
        for f in findings:
            w(f"  [{f['severity']:<8}] {f['title']}")
            w(f"      {f['detail']}")
            w(f"      FIX -> {f['remediation']}")
        w()
    else:
        w("VULNERABILITY SUMMARY")
        w("-" * 70)
        w("  No actionable vulnerabilities found in this scan.")
        w("  This does not guarantee the target is fully secure.")
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

    # DNS section
    dns_entries = []
    dns = data.get("dns", {})
    for rtype, values in dns.items():
        for v in values:
            dns_entries.append(f"{rtype:<8} {v}")
    section("DNS Records", dns_entries)

    # Email authentication section
    email = data.get("email_auth", {})
    email_entries = []
    if email:
        email_entries.append(f"SPF   : {email.get('spf') or '(none)'}")
        email_entries.append(f"DMARC : {email.get('dmarc') or '(none)'}")
    section("Email Authentication", email_entries,
            empty_message="Not analyzed (passive email-auth check did not run).")

    # WHOIS section
    whois_entries = []
    whois = data.get("whois", {})
    for field, values in whois.get("fields", {}).items():
        for v in values:
            whois_entries.append(f"{field.rstrip(':'):<28} {v}")
    section("WHOIS Information", whois_entries)

    # Subdomains section
    section("Subdomains (Certificate Transparency + Passive DNS)", data.get("subdomains", []))

    # DNS brute-force section (aggressive)
    if data.get("brute"):
        section("Subdomains (DNS Brute-Force)", data.get("brute", []))

    # IP info section
    ip_entries = []
    for k, v in data.get("ip_info", {}).items():
        if k == "all_ips":
            ip_entries.append(f"ALL IPS: {', '.join(v)}")
        else:
            ip_entries.append(f"{k.upper().replace('_', ' ')}: {v}")
    section("IP & Geolocation", ip_entries)

    # ASN netblocks
    section("ASN Announced Netblocks", data.get("asn_netblocks", []))

    # Shodan section
    shodan_entries = []
    shodan = data.get("shodan", {})
    if shodan:
        if shodan.get("ports"):
            shodan_entries.append("OPEN PORTS: " + ", ".join(str(p) for p in shodan["ports"]))
        if shodan.get("org"):
            shodan_entries.append(f"ORG: {shodan['org']}")
        if shodan.get("os"):
            shodan_entries.append(f"OS: {shodan['os']}")
        if shodan.get("hostnames"):
            shodan_entries.append("HOSTNAMES: " + ", ".join(shodan["hostnames"]))
        for v in shodan.get("vulns", []):
            shodan_entries.append(f"VULN: {v}")
    section("Shodan Intelligence", shodan_entries,
             empty_message="No Shodan data — add your API key to shodan_api.txt to enable.")

    # TLS section
    tls = data.get("tls", {})
    tls_entries = []
    if tls:
        status = "VALID" if tls.get("valid") else f"INVALID ({tls.get('reason')})"
        tls_entries.append(f"STATUS     : {status}")
        tls_entries.append(f"SUBJECT CN : {tls.get('subject_cn', '')}")
        issuer = tls.get("issuer_cn", "") or ""
        if tls.get("issuer_org"):
            issuer = f"{issuer} ({tls['issuer_org']})" if issuer else tls["issuer_org"]
        tls_entries.append(f"ISSUER     : {issuer}")
        tls_entries.append(f"PROTOCOL   : {tls.get('protocol', '')}")
        if tls.get("chain_len"):
            tls_entries.append(f"CHAIN      : {tls['chain_len']} cert(s)")
        if tls.get("sig_algo"):
            tls_entries.append(f"SIGNATURE  : {tls['sig_algo'].upper()} (leaf)")
        for w in tls.get("weak_sigs", []):
            tls_entries.append(f"WEAK SIG   : {w['position']} '{w['cn']}' — {w['algo'].upper()}")
        expires = tls.get("not_after", "") or ""
        if isinstance(tls.get("days_left"), int):
            expires += f"  ({tls['days_left']} days)"
        tls_entries.append(f"EXPIRES    : {expires}")
        if tls.get("sans"):
            tls_entries.append("SAN: " + ", ".join(tls["sans"]))
    section("TLS Certificate", tls_entries,
            empty_message="Not inspected (active mode required).")

    # Takeover section
    takeover_entries = [f"{t['subdomain']} -> {t['cname']} ({t['service']})"
                        for t in data.get("takeover", [])]
    section("Subdomain Takeover Candidates", takeover_entries,
            empty_message="None found.")

    # Zone transfer section
    zt = data.get("zone_transfer", {})
    zt_entries = []
    if zt.get("vulnerable"):
        zt_entries.append(f"VULNERABLE via {zt.get('ns')} — {len(zt.get('records', []))} records exposed")
    section("DNS Zone Transfer", zt_entries,
            empty_message="Not vulnerable / not tested.")

    # Web metadata section
    meta_entries = [f"/{k}" for k in data.get("web_metadata", {}).keys()]
    section("Exposed Web Metadata Files", meta_entries, empty_message="None found.")

    # Headers section
    header_entries = [f"{k}: {str(v)[:150]}" for k, v in data.get("headers", {}).items()]
    section("HTTP Headers & Fingerprint", header_entries)

    # Hunter.io section
    hunter = data.get("hunter", {})
    hunter_entries = []
    if hunter:
        if hunter.get("pattern"):
            hunter_entries.append(f"PATTERN: {hunter['pattern']}")
        hunter_entries.extend(hunter.get("emails", []))
    section("Discovered Emails (Hunter.io)", hunter_entries,
            empty_message="No Hunter.io data — add your API key to hunter_api.txt to enable.")

    # HIBP section
    section("Domain Breaches (HaveIBeenPwned)", data.get("hibp", {}).get("breaches", []),
            empty_message="No HIBP data — add your API key to hibp_api.txt to enable.")

    # Email formats section
    section("Email Format Patterns", data.get("email_formats", []))

    # Dork URLs
    section("OSINT Dork URLs", data.get("dorks", []))

    # Ports section
    section("Open Ports", data.get("ports", []))

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
    w(f"  BURN RECON v{VERSION} | {ts} | FOR AUTHORIZED USE ONLY")
    w(bar)

    with open(filename, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines) + "\n")
    return filename

# ----------------------------------------------------------------
# GENERATE JSON REPORT
# ----------------------------------------------------------------
def generate_json_report(target, data, findings, mode="passive"):
    rdir = _ensure_report_dir()
    ts = datetime.datetime.now()
    filename = os.path.join(rdir,
               f"burnrecon_{ts.strftime('%Y%m%d_%H%M%S')}.json")
    payload = {
        "tool":        "burnrecon",
        "version":     VERSION,
        "target":      target,
        "mode":        mode,
        "scan_time":   ts.strftime("%Y-%m-%d %H:%M:%S"),
        "findings":    findings,
        "data":        data,
        "diagnostics": DIAGNOSTICS,
    }
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(payload, f, indent=2, default=str)
    return filename

# ----------------------------------------------------------------
# ORCHESTRATION — run one target under a given config
# ----------------------------------------------------------------
def run_recon(target, cfg):
    data = {}
    mode = "aggressive" if cfg.aggressive else ("active" if cfg.active else "passive")

    separator()
    print_status(f"Starting {mode.upper()} recon on: \033[96m{target}\033[0m", "ok")
    separator()

    # ---- PASSIVE ----
    print()
    data["dns"] = get_dns_records(target)
    separator()

    print()
    data["whois"] = get_whois(target)
    separator()

    print()
    if not is_ip(target):
        subs = set(get_subdomains(target))
        subs.update(get_passive_dns(target))
        data["subdomains"] = sorted(subs)
    else:
        print_status("Target is an IP — skipping subdomain enum.", "dim")
        data["subdomains"] = []
    separator()

    print()
    data["ip_info"] = get_ip_info(target)
    separator()

    print()
    data["asn_netblocks"] = get_asn_netblocks(data["ip_info"].get("asn"))
    separator()

    print()
    if not is_ip(target):
        data["email_auth"] = get_email_auth(target, data.get("dns", {}))
    else:
        data["email_auth"] = {}
    separator()

    print()
    data["shodan"] = get_shodan(target, SHODAN_KEY)
    separator()

    print()
    if not is_ip(target):
        data["email_formats"] = guess_email_formats(target)
        data["dorks"]         = generate_dorks(target)
        data["hunter"]        = get_hunter(target, HUNTER_KEY)
        data["hibp"]          = get_hibp(target, HIBP_KEY)
    else:
        print_status("Target is an IP — skipping email/dork/OSINT enrichment.", "dim")
        data["email_formats"] = []
        data["dorks"] = []
        data["hunter"] = {}
        data["hibp"] = {}
    separator()

    # ---- ACTIVE ----
    if cfg.active or cfg.aggressive:
        print()
        data["headers"] = get_headers(target)
        separator()

        print()
        data["cors"] = check_cors(target)
        separator()

        print()
        data["tls"] = get_tls_info(target)
        # SAN entries are extra subdomains — merge them in.
        if not is_ip(target) and data["tls"].get("sans"):
            merged = set(data.get("subdomains", []))
            for s in data["tls"]["sans"]:
                s = s.lstrip("*.").lower()
                if _in_scope(s, target):
                    merged.add(s)
            data["subdomains"] = sorted(merged)
        separator()

        print()
        if not is_ip(target):
            data["zone_transfer"] = try_zone_transfer(target, data.get("dns", {}).get("NS", []))
        else:
            data["zone_transfer"] = {}
        separator()

        print()
        data["takeover"] = check_subdomain_takeover(data.get("subdomains", []))
        separator()

        print()
        data["web_metadata"] = get_web_metadata(target)
        separator()

        print()
        if not cfg.no_portscan:
            if cfg.aggressive:
                data["ports"] = aggressive_port_scan(target)
            else:
                data["ports"] = quick_port_scan(target)
        else:
            print_status("Port scan skipped (--no-portscan).", "dim")
            data["ports"] = []
        separator()
    else:
        # Passive defaults — no direct contact with the target.
        for k in ("headers", "cors", "tls", "zone_transfer", "web_metadata"):
            data[k] = {}
        data["takeover"] = []
        data["ports"] = []
        print_status("Passive mode — skipping active probes (use --active to enable).", "dim")
        separator()

    # ---- AGGRESSIVE ----
    if cfg.aggressive:
        print()
        data["brute"] = dns_brute(target, cfg.wordlist_words) if not is_ip(target) else []
        separator()
        # Fold brute-forced hosts into the subdomain set.
        if data.get("brute"):
            merged = set(data.get("subdomains", []))
            merged.update(data["brute"])
            data["subdomains"] = sorted(merged)
    else:
        data["brute"] = []

    # ---- ANALYSIS ----
    print()
    print_status("Analyzing vulnerabilities...", "info")
    findings = analyze_vulnerabilities(data)
    if findings:
        print_status(f"Found {len(findings)} vulnerability finding(s).", "err")
    else:
        note("RECON-401", "No vulnerability findings — nothing actionable surfaced in this scan.", "ok")
    separator()

    # ---- REPORTS ----
    print()
    print_status("Generating report...", "info")
    reports = []
    if cfg.output in ("txt", "both"):
        reports.append(generate_report(target, data, findings, mode))
    if cfg.output in ("json", "both"):
        reports.append(generate_json_report(target, data, findings, mode))
    for report in reports:
        print_status(f"Report saved to: \033[96m{report}\033[0m", "ok")
    print()
    return reports

# ----------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------
def _load_wordlist(path):
    try:
        with open(path) as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except OSError:
        note("RECON-104", f"Wordlist '{path}' not found — falling back to built-in list.", "err")
        return None

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="burnrecon",
        description="Burn Recon — passive-by-default OSINT reconnaissance. "
                    "Use --active for direct probing, --aggressive for loud techniques.")
    p.add_argument("target", nargs="?", help="Domain, IP, or company name. Omit for interactive prompt.")
    p.add_argument("--active", action="store_true", help="Enable active probes (HTTP/TLS grab, port scan, zone transfer, takeover).")
    p.add_argument("--aggressive", action="store_true", help="Enable active + aggressive (DNS brute-force, full port scan). Implies --active.")
    p.add_argument("-o", "--output", choices=["txt", "json", "both"], default="txt", help="Report format (default: txt).")
    p.add_argument("--output-dir", help="Directory to write reports into (overrides default burn_report/).")
    p.add_argument("--no-portscan", action="store_true", help="Skip the nmap port scan even in active/aggressive mode.")
    p.add_argument("--wordlist", help="Custom wordlist file for --aggressive DNS brute-force.")
    p.add_argument("-f", "--file", help="Batch mode: file with one target per line.")
    p.add_argument("-q", "--quiet", action="store_true", help="Reduce console output.")
    return p.parse_args(argv)

def main(argv=None):
    global REPORT_DIR, QUIET
    cfg = parse_args(argv)

    # --aggressive implies --active.
    if cfg.aggressive:
        cfg.active = True

    QUIET = cfg.quiet
    if cfg.output_dir:
        REPORT_DIR = os.path.abspath(cfg.output_dir)

    cfg.wordlist_words = _load_wordlist(cfg.wordlist) if cfg.wordlist else None

    banner()

    # Build the target list.
    targets = []
    if cfg.file:
        try:
            with open(cfg.file) as fh:
                targets = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        except OSError as e:
            print_status(f"Could not read target file '{cfg.file}': {e}", "err")
            sys.exit(1)
    elif cfg.target:
        targets = [cfg.target]
    else:
        try:
            t = get_target()
        except EOFError:
            print_status("No target given and no interactive input available. "
                         "Pass a target: burnrecon <domain> [options]", "err")
            sys.exit(1)
        if t:
            targets = [t]

    if not targets:
        print_status("No target provided. Nothing to do.", "err")
        sys.exit(1)

    for raw in targets:
        target = raw.replace("https://", "").replace("http://", "").rstrip("/")
        # Fresh diagnostics per target so batch reports don't leak into each other.
        DIAGNOSTICS.clear()
        run_recon(target, cfg)

if __name__ == "__main__":
    main()
