import os
import sys
import json
import unittest
import tempfile
from contextlib import ExitStack
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _loader import load, read_file


def _make_cert(cn, hash_name):
    """Build a self-signed DER cert signed with the given hash, for exercising
    the certificate parser. Requires cryptography (callers guard on it).
    Note: cryptography refuses to sign with SHA-1, so use 'sha256' here."""
    import datetime as _dt
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    algo = {"sha1": hashes.SHA1(), "sha256": hashes.SHA256()}[hash_name]
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(_dt.datetime(2020, 1, 1))
            .not_valid_after(_dt.datetime(2030, 1, 1))
            .sign(key, algo))
    return cert.public_bytes(serialization.Encoding.DER)


class BurnReconPreflightTests(unittest.TestCase):
    """Missing dependencies must produce a distinct [ENV] code, not get
    mislabeled as a [HARDENED] 'genuinely found nothing' result."""

    def setUp(self):
        self.mod = load("burnrecon")

    def test_dig_missing_is_recon_101_not_recon_201(self):
        with patch.object(self.mod.shutil, "which", return_value=None):
            result = self.mod.get_dns_records("example.com")
            self.assertEqual(result, {})
            self.assertTrue(any("RECON-101" in d for d in self.mod.DIAGNOSTICS))
            self.assertFalse(any("RECON-201" in d for d in self.mod.DIAGNOSTICS))

    def test_whois_missing_is_recon_102_not_recon_202(self):
        with patch.object(self.mod.shutil, "which", return_value=None):
            result = self.mod.get_whois("example.com")
            self.assertEqual(result, {})
            self.assertTrue(any("RECON-102" in d for d in self.mod.DIAGNOSTICS))
            self.assertFalse(any("RECON-202" in d for d in self.mod.DIAGNOSTICS))

    def test_nmap_missing_is_recon_103_not_recon_206(self):
        with patch.object(self.mod.shutil, "which", return_value=None):
            result = self.mod.quick_port_scan("example.com")
            self.assertEqual(result, [])
            self.assertTrue(any("RECON-103" in d for d in self.mod.DIAGNOSTICS))
            self.assertFalse(any("RECON-206" in d for d in self.mod.DIAGNOSTICS))


class BurnReconDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.mod = load("burnrecon")

    def test_dns_empty_but_dig_present_is_recon_201(self):
        # Force shutil.which("dig") truthy so this exercises "dig ran and
        # found nothing", not the RECON-101 "dig isn't installed" path —
        # this test machine may not actually have dig installed.
        with patch.object(self.mod.shutil, "which", return_value="/usr/bin/dig"), \
             patch.object(self.mod, "run", return_value=None):
            result = self.mod.get_dns_records("example.com")
            self.assertEqual(result, {})
            self.assertTrue(any("RECON-201" in d for d in self.mod.DIAGNOSTICS))

    def test_whois_failure_is_recon_202(self):
        with patch.object(self.mod.shutil, "which", return_value="/usr/bin/whois"), \
             patch.object(self.mod, "run", return_value=None):
            result = self.mod.get_whois("example.com")
            self.assertTrue(any("RECON-202" in d for d in self.mod.DIAGNOSTICS))

    def test_subdomains_empty_is_recon_203(self):
        resp = MagicMock(status_code=200)
        resp.json.return_value = []
        with patch.object(self.mod.requests, "get", return_value=resp):
            result = self.mod.get_subdomains("example.com")
            self.assertEqual(result, [])
            self.assertTrue(any("RECON-203" in d for d in self.mod.DIAGNOSTICS))

    def test_subdomains_crtsh_failure_is_recon_503_not_recon_203(self):
        resp = MagicMock(status_code=503)
        with patch.object(self.mod.requests, "get", return_value=resp):
            self.mod.get_subdomains("example.com")
            self.assertTrue(any("RECON-503" in d for d in self.mod.DIAGNOSTICS))
            self.assertFalse(any("RECON-203" in d for d in self.mod.DIAGNOSTICS))

    def test_shodan_no_key_is_recon_501(self):
        result = self.mod.get_shodan("example.com", "")
        self.assertEqual(result, {})
        self.assertTrue(any("RECON-501" in d for d in self.mod.DIAGNOSTICS))

    def test_shodan_error_status_is_recon_502(self):
        resp = MagicMock(status_code=401)
        with patch.object(self.mod, "is_ip", return_value=True), \
             patch.object(self.mod.requests, "get", return_value=resp):
            self.mod.get_shodan("1.2.3.4", "badkey")
            self.assertTrue(any("RECON-502" in d for d in self.mod.DIAGNOSTICS))

    def test_headers_connection_failure_is_recon_205(self):
        with patch.object(self.mod.requests, "get", side_effect=Exception("refused")):
            result = self.mod.get_headers("unreachable.example")
            self.assertEqual(result, {})
            self.assertTrue(any("RECON-205" in d for d in self.mod.DIAGNOSTICS))


class BurnReconIsIpTests(unittest.TestCase):
    def setUp(self):
        self.mod = load("burnrecon")

    def test_valid_ip(self):
        self.assertTrue(self.mod.is_ip("192.168.1.1"))

    def test_domain_is_not_ip(self):
        self.assertFalse(self.mod.is_ip("example.com"))

    def test_inet_aton_loophole_is_rejected(self):
        """socket.inet_aton would accept this as valid — ipaddress.ip_address
        correctly rejects it. Guards against regressing to the old check."""
        self.assertFalse(self.mod.is_ip("127.1"))


class BurnReconWhoisExpiryTests(unittest.TestCase):
    """Regression: gTLD WHOIS uses 'Registry Expiry Date:'. get_whois must
    capture it, and analyze_vulnerabilities must raise an expiry finding from
    it — previously the field was never parsed, so the expiry check was dead
    code for .com/.net/.org (the most common TLDs)."""

    def setUp(self):
        self.mod = load("burnrecon")

    def _whois_stdout(self, expiry_line):
        return (
            "   Registrar: Example Registrar, Inc.\n"
            "   Registry Domain ID: 12345_DOMAIN_COM-VRSN\n"
            f"   {expiry_line}\n"
        )

    def _run_whois(self, stdout):
        result = MagicMock()
        result.stdout = stdout
        with patch.object(self.mod.shutil, "which", return_value="/usr/bin/whois"), \
             patch.object(self.mod, "run", return_value=result):
            return self.mod.get_whois("example.com")

    def test_registry_expiry_date_is_captured(self):
        whois = self._run_whois(
            self._whois_stdout("Registry Expiry Date: 2027-01-01T04:00:00Z")
        )
        self.assertIn("Registry Expiry Date:", whois["fields"])

    def test_near_expiry_registry_date_yields_critical_finding(self):
        # 3 days out — must surface as a CRITICAL "Domain Expiring Soon".
        soon = (datetime.now() + timedelta(days=3)).strftime("%Y-%m-%d")
        whois = self._run_whois(
            self._whois_stdout(f"Registry Expiry Date: {soon}T04:00:00Z")
        )
        findings = self.mod.analyze_vulnerabilities({"whois": whois})
        expiry = [f for f in findings if "Expiring" in f["title"]]
        self.assertTrue(expiry, "expected an expiry finding from Registry Expiry Date")
        self.assertEqual(expiry[0]["severity"], "CRITICAL")


class BurnReconWhoisDedupTests(unittest.TestCase):
    """gTLD whois repeats fields in different spellings across its registry
    and registrar sections — those near-duplicates must collapse to one."""

    def setUp(self):
        self.mod = load("burnrecon")

    def _whois(self, stdout):
        result = MagicMock()
        result.stdout = stdout
        with patch.object(self.mod.shutil, "which", return_value="/usr/bin/whois"), \
             patch.object(self.mod, "run", return_value=result):
            return self.mod.get_whois("example.com")

    def test_collapses_near_duplicates(self):
        stdout = (
            "   Registrar: MarkMonitor Inc.\n"
            "   Registrar: MarkMonitor, Inc.\n"
            "   Updated Date: 2026-03-06T10:32:49Z\n"
            "   Updated Date: 2026-03-06T10:32:49+0000\n"
            "   Name Server: NS1.EXAMPLE.COM\n"
            "   Name Server: ns1.example.com.\n"
            "   Name Server: NS2.EXAMPLE.COM\n"
        )
        fields = self._whois(stdout)["fields"]
        self.assertEqual(len(fields["Registrar:"]), 1)
        self.assertEqual(len(fields["Updated Date:"]), 1)
        # ns1 (case/dot variant) collapses; ns2 is genuinely distinct.
        self.assertEqual(len(fields["Name Server:"]), 2)

    def test_distinct_values_preserved(self):
        stdout = ("   Name Server: a.iana-servers.net\n"
                  "   Name Server: b.iana-servers.net\n")
        fields = self._whois(stdout)["fields"]
        self.assertEqual(len(fields["Name Server:"]), 2)


class BurnReconSubdomainMatchTests(unittest.TestCase):
    """Subdomain matching must not accept unrelated names that merely contain
    the domain as a substring (notexample.com, example.com.attacker.net)."""

    def setUp(self):
        self.mod = load("burnrecon")

    def test_only_apex_and_real_subdomains_are_kept(self):
        resp = MagicMock(status_code=200)
        resp.json.return_value = [
            {"name_value": "example.com"},
            {"name_value": "www.example.com"},
            {"name_value": "notexample.com"},
            {"name_value": "example.com.attacker.net"},
        ]
        with patch.object(self.mod.requests, "get", return_value=resp):
            subs = self.mod.get_subdomains("example.com")
        self.assertIn("example.com", subs)
        self.assertIn("www.example.com", subs)
        self.assertNotIn("notexample.com", subs)
        self.assertNotIn("example.com.attacker.net", subs)


class BurnReconReportTests(unittest.TestCase):
    def setUp(self):
        self.mod = load("burnrecon")
        self.tmpdir = tempfile.TemporaryDirectory()
        self.mod.REPORT_DIR = self.tmpdir.name

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_report_includes_findings_and_diagnostics(self):
        self.mod.note("RECON-401", "No vulnerability findings.")
        findings = [{"title": "Missing CSP", "detail": "d", "severity": "HIGH", "remediation": "r"}]
        report = self.mod.generate_report("example.com", {}, findings)
        content = read_file(report)
        self.assertIn("VULNERABILITY SUMMARY", content)
        self.assertIn("Missing CSP", content)
        self.assertIn("DIAGNOSTICS", content)
        self.assertIn("RECON-401", content)

    def test_report_clean_run_shows_no_issues(self):
        report = self.mod.generate_report("example.com", {}, [])
        content = read_file(report)
        self.assertIn("No issues encountered", content)


# --- v1.2.0 additions -------------------------------------------------------

PASSIVE_FN_RETURNS = {
    "get_dns_records": {}, "get_whois": {}, "get_subdomains": [],
    "get_passive_dns": [], "get_ip_info": {}, "get_asn_netblocks": [],
    "get_email_auth": {}, "get_shodan": {}, "guess_email_formats": [],
    "generate_dorks": [], "get_hunter": {}, "get_hibp": {},
}
ACTIVE_FN_RETURNS = {
    "get_headers": {}, "check_cors": {}, "get_tls_info": {},
    "try_zone_transfer": {}, "check_subdomain_takeover": [],
    "get_web_metadata": {}, "quick_port_scan": [],
}
AGGRESSIVE_FN_RETURNS = {"aggressive_port_scan": [], "dns_brute": []}


class BurnReconArgparseTests(unittest.TestCase):
    def setUp(self):
        self.mod = load("burnrecon")

    def test_target_and_flags_parse(self):
        ns = self.mod.parse_args(["example.com", "--active", "-o", "json"])
        self.assertEqual(ns.target, "example.com")
        self.assertTrue(ns.active)
        self.assertFalse(ns.aggressive)
        self.assertEqual(ns.output, "json")

    def test_default_is_passive_txt(self):
        ns = self.mod.parse_args(["example.com"])
        self.assertFalse(ns.active)
        self.assertFalse(ns.aggressive)
        self.assertEqual(ns.output, "txt")

    def test_aggressive_implies_active_in_main(self):
        captured = {}
        with patch.object(self.mod, "banner"), \
             patch.object(self.mod, "run_recon",
                          side_effect=lambda t, c: captured.setdefault("cfg", c)):
            self.mod.main(["example.com", "--aggressive"])
        self.assertTrue(captured["cfg"].active)
        self.assertTrue(captured["cfg"].aggressive)


class BurnReconModeGatingTests(unittest.TestCase):
    """Passive (default) must never invoke active/aggressive probes; --active
    enables active but not aggressive; --aggressive enables everything."""

    def setUp(self):
        self.mod = load("burnrecon")
        self.mod.QUIET = True
        self.tmpdir = tempfile.TemporaryDirectory()
        self.mod.REPORT_DIR = self.tmpdir.name

    def tearDown(self):
        self.tmpdir.cleanup()

    def _run(self, argv):
        cfg = self.mod.parse_args(argv)
        if cfg.aggressive:
            cfg.active = True
        cfg.wordlist_words = None
        mocks = {}
        with ExitStack() as stack:
            for name, ret in {**PASSIVE_FN_RETURNS, **ACTIVE_FN_RETURNS,
                              **AGGRESSIVE_FN_RETURNS}.items():
                mocks[name] = stack.enter_context(
                    patch.object(self.mod, name, MagicMock(return_value=ret)))
            self.mod.run_recon("example.com", cfg)
        return mocks

    def test_passive_calls_no_active_or_aggressive(self):
        m = self._run(["example.com"])
        for name in PASSIVE_FN_RETURNS:
            self.assertTrue(m[name].called, f"{name} should run in passive mode")
        for name in {**ACTIVE_FN_RETURNS, **AGGRESSIVE_FN_RETURNS}:
            self.assertFalse(m[name].called, f"{name} must NOT run in passive mode")

    def test_active_calls_active_not_aggressive(self):
        m = self._run(["example.com", "--active"])
        for name in ACTIVE_FN_RETURNS:
            self.assertTrue(m[name].called, f"{name} should run in active mode")
        for name in AGGRESSIVE_FN_RETURNS:
            self.assertFalse(m[name].called, f"{name} must NOT run without --aggressive")

    def test_aggressive_calls_everything(self):
        m = self._run(["example.com", "--aggressive"])
        for name in AGGRESSIVE_FN_RETURNS:
            self.assertTrue(m[name].called, f"{name} should run in aggressive mode")

    def test_no_portscan_skips_scans(self):
        m = self._run(["example.com", "--aggressive", "--no-portscan"])
        self.assertFalse(m["quick_port_scan"].called)
        self.assertFalse(m["aggressive_port_scan"].called)


class BurnReconEmailAuthTests(unittest.TestCase):
    def setUp(self):
        self.mod = load("burnrecon")

    def test_parses_spf_all_and_dmarc_policy(self):
        dmarc = MagicMock()
        dmarc.stdout = '"v=DMARC1; p=reject; rua=mailto:x@y"'
        dns = {"TXT": ['"v=spf1 include:_spf.google.com ~all"']}
        with patch.object(self.mod.shutil, "which", return_value="/usr/bin/dig"), \
             patch.object(self.mod, "run", return_value=dmarc):
            res = self.mod.get_email_auth("example.com", dns)
        self.assertEqual(res["spf_all"], "~all")
        self.assertEqual(res["dmarc_policy"], "reject")
        self.assertTrue(any("RECON-207" in d for d in self.mod.DIAGNOSTICS))

    def test_weak_spf_and_missing_dmarc_findings(self):
        data = {"email_auth": {"spf": "v=spf1 +all", "spf_all": "+all",
                               "dmarc": None, "dmarc_policy": None}}
        titles = [f["title"] for f in self.mod.analyze_vulnerabilities(data)]
        self.assertIn("Weak SPF Policy", titles)
        self.assertIn("Missing DMARC Record", titles)

    def test_dmarc_none_is_flagged(self):
        data = {"email_auth": {"spf": "v=spf1 -all", "spf_all": "-all",
                               "dmarc": "v=DMARC1; p=none", "dmarc_policy": "none"}}
        titles = [f["title"] for f in self.mod.analyze_vulnerabilities(data)]
        self.assertIn("DMARC Policy Not Enforced", titles)


class BurnReconTlsTests(unittest.TestCase):
    def setUp(self):
        self.mod = load("burnrecon")

    def _detail(self, **over):
        d = {"subject_cn": "example.com", "issuer_cn": "R3",
             "issuer_org": "Let's Encrypt", "not_after": "2030-01-01 00:00:00 UTC",
             "days_left": 365, "sans": ["example.com", "www.example.com"],
             "self_signed": False, "sig_algo": "sha256"}
        d.update(over)
        return d

    def _valid(self, detail=None, proto="TLSv1.3", weak=None):
        detail = detail if detail is not None else self._detail()
        with patch.object(self.mod, "_fetch_cert", return_value=({}, proto)), \
             patch.object(self.mod, "_fetch_chain_der", return_value=([b"DER"], proto)), \
             patch.object(self.mod, "_parse_cert_der", return_value=detail), \
             patch.object(self.mod, "_scan_weak_sigs", return_value=(weak or [])):
            return self.mod.get_tls_info("example.com")

    def _fail(self, message, detail=None, proto="TLSv1.2", weak=None):
        detail = detail if detail is not None else self._detail(subject_cn="target.example")
        with patch.object(self.mod, "_fetch_cert",
                          side_effect=self.mod.ssl.SSLCertVerificationError(message)), \
             patch.object(self.mod, "_fetch_chain_der", return_value=([b"DER"], proto)), \
             patch.object(self.mod, "_parse_cert_der", return_value=detail), \
             patch.object(self.mod, "_scan_weak_sigs", return_value=(weak or [])):
            return self.mod.get_tls_info("target.example")

    def test_valid_cert_parsed_and_sans_harvested(self):
        info = self._valid()
        self.assertTrue(info["valid"])
        self.assertIsNone(info["reason"])
        self.assertEqual(info["protocol"], "TLSv1.3")
        self.assertIn("www.example.com", info["sans"])
        self.assertFalse(info["self_signed"])

    def test_self_signed_via_parsed_subject_equals_issuer(self):
        info = self._valid(detail=self._detail(self_signed=True))
        self.assertTrue(info["self_signed"])

    def test_invalid_cert_is_still_fully_parsed(self):
        # Robustness win: an expired cert still yields SANs + expiry detail.
        detail = self._detail(subject_cn="expired.badssl.com", days_left=-800,
                              sans=["*.badssl.com", "badssl.com"])
        info = self._fail("certificate has expired", detail=detail)
        self.assertEqual(info["reason"], "expired")
        self.assertEqual(info["days_left"], -800)
        self.assertIn("badssl.com", info["sans"])

    def test_expired_classified_not_selfsigned(self):
        info = self._fail("certificate has expired")
        self.assertEqual(info["reason"], "expired")
        self.assertTrue(info["subject_cn"])  # never None

    def test_self_signed_classified(self):
        info = self._fail("self-signed certificate", detail=self._detail(self_signed=True))
        self.assertEqual(info["reason"], "self-signed")
        self.assertTrue(info["self_signed"])

    def test_hostname_mismatch_classified(self):
        info = self._fail("hostname 'x' doesn't match 'y'")
        self.assertEqual(info["reason"], "hostname-mismatch")

    def test_expired_finding_is_high_and_named(self):
        data = {"tls": {"valid": False, "reason": "expired",
                        "subject_cn": "expired.badssl.com", "self_signed": False}}
        findings = self.mod.analyze_vulnerabilities(data)
        exp = [f for f in findings if f["title"] == "Expired TLS Certificate"]
        self.assertTrue(exp)
        self.assertEqual(exp[0]["severity"], "HIGH")
        self.assertIn("expired.badssl.com", exp[0]["detail"])
        self.assertNotIn("None", exp[0]["detail"])

    def test_expired_not_double_counted(self):
        # reason=='expired' AND days_left<0 must produce exactly ONE finding.
        data = {"tls": {"valid": False, "reason": "expired",
                        "subject_cn": "x", "self_signed": False, "days_left": -800}}
        exp = [f for f in self.mod.analyze_vulnerabilities(data)
               if f["title"] == "Expired TLS Certificate"]
        self.assertEqual(len(exp), 1)

    def test_weak_signature_in_chain_finding(self):
        # SHA-1 intermediate under a SHA-256 leaf — the case a leaf-only
        # check misses. Intermediate-only weakness is MEDIUM.
        data = {"tls": {"reason": None, "self_signed": False, "sig_algo": "sha256",
                        "weak_sigs": [{"position": "intermediate",
                                       "cn": "COMODO SSL CA", "algo": "sha1"}]}}
        findings = self.mod.analyze_vulnerabilities(data)
        f = [x for x in findings if x["title"].startswith("Weak Certificate Signature")]
        self.assertTrue(f)
        self.assertIn("COMODO SSL CA", f[0]["detail"])
        self.assertEqual(f[0]["severity"], "MEDIUM")

    def test_weak_leaf_signature_is_high(self):
        data = {"tls": {"reason": None, "self_signed": False,
                        "weak_sigs": [{"position": "leaf", "cn": "x", "algo": "md5"}]}}
        f = [x for x in self.mod.analyze_vulnerabilities(data)
             if x["title"].startswith("Weak Certificate Signature")]
        self.assertEqual(f[0]["severity"], "HIGH")

    def test_chain_scan_flags_sha1_intermediate(self):
        # cryptography refuses to *sign* with SHA-1, so stub the per-cert
        # parser to model a SHA-256 leaf over a SHA-1 intermediate.
        def fake(der):
            return {b"L": ("sha256", "leaf.example"),
                    b"I": ("sha1", "Intermediate CA")}[der]
        with patch.object(self.mod, "_cert_sig_and_cn", side_effect=fake):
            weak = self.mod._scan_weak_sigs([b"L", b"I"])
        self.assertEqual(len(weak), 1)
        self.assertEqual(weak[0]["position"], "intermediate")
        self.assertEqual(weak[0]["algo"], "sha1")

    def test_cert_sig_and_cn_parses_real_cert(self):
        # Validates the real DER→(algo, CN) path against a generated cert.
        if not self.mod._HAS_CRYPTO:
            self.skipTest("cryptography not installed")
        der = _make_cert("leaf.example", "sha256")
        algo, cn = self.mod._cert_sig_and_cn(der)
        self.assertEqual(algo, "sha256")
        self.assertEqual(cn, "leaf.example")

    def test_weak_protocol_finding(self):
        data = {"tls": {"protocol": "TLSv1", "self_signed": False, "days_left": 200}}
        titles = [f["title"] for f in self.mod.analyze_vulnerabilities(data)]
        self.assertTrue(any("Weak TLS Protocol" in t for t in titles))


class BurnReconZoneTransferTests(unittest.TestCase):
    def setUp(self):
        self.mod = load("burnrecon")

    def test_successful_axfr_is_vulnerable(self):
        axfr = MagicMock()
        axfr.stdout = ("example.com.  IN SOA ns1.example.com. admin. 1 2 3 4 5\n"
                       "example.com.  IN NS ns1.example.com.\n"
                       "www.example.com. IN A 1.2.3.4\n"
                       "example.com.  IN SOA ns1.example.com. admin. 1 2 3 4 5\n")
        with patch.object(self.mod.shutil, "which", return_value="/usr/bin/dig"), \
             patch.object(self.mod, "run", return_value=axfr):
            res = self.mod.try_zone_transfer("example.com", ["ns1.example.com"])
        self.assertTrue(res["vulnerable"])

    def test_refused_axfr_is_recon_208(self):
        failed = MagicMock()
        failed.stdout = "; Transfer failed."
        with patch.object(self.mod.shutil, "which", return_value="/usr/bin/dig"), \
             patch.object(self.mod, "run", return_value=failed):
            res = self.mod.try_zone_transfer("example.com", ["ns1.example.com"])
        self.assertFalse(res["vulnerable"])
        self.assertTrue(any("RECON-208" in d for d in self.mod.DIAGNOSTICS))

    def test_zone_transfer_finding_is_critical(self):
        data = {"zone_transfer": {"vulnerable": True, "ns": "ns1", "records": ["a", "b"]}}
        findings = self.mod.analyze_vulnerabilities(data)
        zt = [f for f in findings if "Zone Transfer" in f["title"]]
        self.assertTrue(zt)
        self.assertEqual(zt[0]["severity"], "CRITICAL")


class BurnReconTakeoverTests(unittest.TestCase):
    def setUp(self):
        self.mod = load("burnrecon")

    def test_dangling_cname_detected(self):
        resp = MagicMock()
        resp.text = "404 Not Found: NoSuchBucket"
        with patch.object(self.mod.shutil, "which", return_value="/usr/bin/dig"), \
             patch.object(self.mod, "_cname_of", return_value="bucket.s3.amazonaws.com"), \
             patch.object(self.mod.requests, "get", return_value=resp):
            found = self.mod.check_subdomain_takeover(["assets.example.com"])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["service"], "AWS S3")


class BurnReconCorsCookieTests(unittest.TestCase):
    def setUp(self):
        self.mod = load("burnrecon")

    def test_cors_reflection_detected(self):
        resp = MagicMock()
        resp.headers = {"Access-Control-Allow-Origin": "https://evil.example",
                        "Access-Control-Allow-Credentials": "true"}
        with patch.object(self.mod.requests, "get", return_value=resp):
            res = self.mod.check_cors("example.com")
        self.assertTrue(res["vulnerable"])

    def test_insecure_cookie_flags(self):
        issues = self.mod.analyze_cookies({"Set-Cookie": "id=abc"})
        joined = " ".join(i[0] for i in issues)
        self.assertIn("Secure", joined)
        self.assertIn("HttpOnly", joined)
        self.assertIn("SameSite", joined)

    def test_secure_cookie_no_issues(self):
        issues = self.mod.analyze_cookies(
            {"Set-Cookie": "id=abc; Secure; HttpOnly; SameSite=Lax"})
        self.assertEqual(issues, [])


class BurnReconGapFixTests(unittest.TestCase):
    def setUp(self):
        self.mod = load("burnrecon")

    def test_shodan_ports_are_risk_analyzed(self):
        # Gap fix 1: Shodan-reported ports must go through RISKY_PORTS even
        # when nmap produced nothing.
        data = {"shodan": {"ports": [23, 3306]}, "ports": []}
        titles = [f["title"] for f in self.mod.analyze_vulnerabilities(data)]
        self.assertIn("Risky Port Open: 23/tcp", titles)
        self.assertIn("Risky Port Open: 3306/tcp", titles)

    def test_port_token_still_matched_exactly(self):
        # Regression: 13306 must NOT match 3306.
        data = {"ports": ["13306/tcp open unknown"], "shodan": {}}
        titles = [f["title"] for f in self.mod.analyze_vulnerabilities(data)]
        self.assertFalse(any("3306" in t for t in titles))

    def test_all_a_records_captured(self):
        # Gap fix 2: every resolved IP is recorded, not just the first.
        resp = MagicMock(status_code=200)
        resp.json.return_value = {"ip": "1.2.3.4", "city": "Testville"}
        with patch.object(self.mod, "_resolve_all", return_value=["1.2.3.4", "5.6.7.8"]), \
             patch.object(self.mod.requests, "get", return_value=resp):
            info = self.mod.get_ip_info("example.com")
        self.assertEqual(info["all_ips"], ["1.2.3.4", "5.6.7.8"])


class BurnReconKeyGateTests(unittest.TestCase):
    def setUp(self):
        self.mod = load("burnrecon")

    def test_hunter_no_key_is_recon_505(self):
        self.assertEqual(self.mod.get_hunter("example.com", ""), {})
        self.assertTrue(any("RECON-505" in d for d in self.mod.DIAGNOSTICS))

    def test_hibp_no_key_is_recon_507(self):
        self.assertEqual(self.mod.get_hibp("example.com", ""), {})
        self.assertTrue(any("RECON-507" in d for d in self.mod.DIAGNOSTICS))

    def test_load_key_ignores_placeholder(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "k.txt")
            with open(p, "w") as fh:
                fh.write("PASTE_YOUR_SHODAN_API_KEY_HERE\n")
            # _load_key resolves relative to the script dir, so test the
            # placeholder-rejection logic by pointing it at our file directly.
            with patch.object(self.mod.os.path, "dirname", return_value=d):
                self.assertEqual(self.mod._load_key("k.txt"), "")


class BurnReconJsonReportTests(unittest.TestCase):
    def setUp(self):
        self.mod = load("burnrecon")
        self.tmpdir = tempfile.TemporaryDirectory()
        self.mod.REPORT_DIR = self.tmpdir.name

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_json_report_is_valid(self):
        findings = [{"title": "X", "detail": "d", "severity": "HIGH", "remediation": "r"}]
        data = {"subdomains": ["a.example.com"], "ports": []}
        path = self.mod.generate_json_report("example.com", data, findings, "active")
        with open(path) as f:
            parsed = json.load(f)
        self.assertEqual(parsed["target"], "example.com")
        self.assertEqual(parsed["mode"], "active")
        self.assertEqual(parsed["version"], self.mod.VERSION)
        self.assertEqual(len(parsed["findings"]), 1)

    def test_txt_report_records_mode(self):
        path = self.mod.generate_report("example.com", {}, [], "aggressive")
        self.assertIn("AGGRESSIVE", read_file(path))

    def test_report_renders_with_weak_sig_tls(self):
        # Regression: a populated tls.weak_sigs list must not shadow the report
        # writer w() and crash every section that follows the TLS section.
        data = {"tls": {"valid": False, "reason": "untrusted", "subject_cn": "x",
                        "issuer_cn": "CA", "protocol": "TLSv1.2", "chain_len": 2,
                        "sig_algo": "sha256", "not_after": "2030-01-01", "days_left": 100,
                        "sans": ["x.example.com"],
                        "weak_sigs": [{"position": "intermediate",
                                       "cn": "Old CA", "algo": "sha1"}]}}
        content = read_file(self.mod.generate_report("example.com", data, [], "active"))
        self.assertIn("WEAK SIG", content)
        self.assertIn("Old CA", content)
        # Sections that come AFTER TLS must still render — proof no crash/shadow.
        self.assertIn("OPEN PORTS", content)
        self.assertIn("DIAGNOSTICS", content)

    def test_unwritable_report_dir_falls_back(self):
        # Simulate a root-owned/unwritable REPORT_DIR by pointing it at an
        # existing *file*, and redirect the ~ fallback into a temp home.
        with tempfile.TemporaryDirectory() as home:
            badfile = os.path.join(home, "not_a_dir")
            open(badfile, "w").close()
            self.mod.REPORT_DIR = badfile
            with patch.object(self.mod.os.path, "expanduser", return_value=home):
                path = self.mod.generate_report("example.com", {}, [], "passive")
            self.assertTrue(os.path.exists(path))
            self.assertTrue(path.startswith(home))
            self.assertTrue(any("RECON-105" in d for d in self.mod.DIAGNOSTICS))


class BurnReconSubdomainMergeTests(unittest.TestCase):
    def setUp(self):
        self.mod = load("burnrecon")

    def test_passive_dns_respects_scope(self):
        resp = MagicMock(status_code=200)
        # hackertarget-style CSV; only in-scope names should survive.
        resp.text = ("www.example.com,1.2.3.4\n"
                     "evil-example.com,9.9.9.9\n"
                     "api.example.com,1.2.3.5\n")
        resp.json.return_value = []
        with patch.object(self.mod.requests, "get", return_value=resp):
            subs = self.mod.get_passive_dns("example.com")
        self.assertIn("www.example.com", subs)
        self.assertIn("api.example.com", subs)
        self.assertNotIn("evil-example.com", subs)


if __name__ == "__main__":
    unittest.main()
