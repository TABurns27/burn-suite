import os
import sys
import unittest
import tempfile
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _loader import load, read_file


class BurnScannerTests(unittest.TestCase):
    def setUp(self):
        self.mod = load("burnscanner")
        self.tmpdir = tempfile.TemporaryDirectory()
        self.mod.REPORT_DIR = self.tmpdir.name

    def tearDown(self):
        self.tmpdir.cleanup()

    # --- CVE lookup: ok/found/from_cache semantics ---

    def test_lookup_cves_no_product_is_treated_as_cached(self):
        with patch.object(self.mod.requests, "get") as mock_get:
            cves, ok, cached = self.mod.lookup_cves({'product': '', 'version': ''})
            self.assertEqual(cves, [])
            self.assertTrue(ok)
            self.assertTrue(cached)
            mock_get.assert_not_called()

    def test_lookup_cves_success_empty_result_is_a_real_finding(self):
        resp = MagicMock(status_code=200)
        resp.json.return_value = {"vulnerabilities": []}
        with patch.object(self.mod.requests, "get", return_value=resp):
            cves, ok, cached = self.mod.lookup_cves({'product': 'OpenSSH', 'version': '8.2'})
            self.assertEqual(cves, [])
            self.assertTrue(ok)
            self.assertFalse(cached)

    def test_lookup_cves_rate_limited_is_not_ok(self):
        resp = MagicMock(status_code=429)
        with patch.object(self.mod.requests, "get", return_value=resp):
            cves, ok, cached = self.mod.lookup_cves({'product': 'OpenSSH', 'version': '8.2'})
            self.assertFalse(ok)
            self.assertFalse(cached)

    def test_lookup_cves_caches_success_but_not_failure(self):
        resp = MagicMock(status_code=200)
        resp.json.return_value = {"vulnerabilities": []}
        with patch.object(self.mod.requests, "get", return_value=resp) as mock_get:
            self.mod.lookup_cves({'product': 'nginx', 'version': '1.18'})
            self.mod.lookup_cves({'product': 'nginx', 'version': '1.18'})
            self.assertEqual(mock_get.call_count, 1, "second identical lookup should hit the cache")

        fail_resp = MagicMock(status_code=500)
        with patch.object(self.mod.requests, "get", return_value=fail_resp) as mock_get:
            self.mod.lookup_cves({'product': 'apache', 'version': '2.4'})
            self.mod.lookup_cves({'product': 'apache', 'version': '2.4'})
            self.assertEqual(mock_get.call_count, 2, "failed lookups must be retried, not cached")

    # --- Findings analysis ---

    def test_analyze_findings_covers_cve_vuln_and_exploit_sources(self):
        scan_results = [{
            'ip': '192.168.1.10', 'hostname': 'router.lan',
            'services': [{'port': '22', 'protocol': 'tcp', 'name': 'ssh',
                          'product': 'OpenSSH', 'version': '8.2'}],
            'cves': {'22': [{'id': 'CVE-2020-1234', 'description': 'd',
                              'score': 7.5, 'severity': 'HIGH'}]},
            'vulns': [{'script': 'ssh-vuln-test', 'output': 'VULNERABLE: bad'}],
            'exploits': [{'module': 'exploit/test', 'output': 'session opened'}],
        }]
        findings = self.mod.analyze_findings(scan_results)
        self.assertEqual(len(findings), 3)
        self.assertEqual([f["severity"] for f in findings], ["CRITICAL", "HIGH", "HIGH"])

    def test_analyze_findings_empty_on_clean_scan(self):
        scan_results = [{'ip': '1.2.3.4', 'services': [], 'cves': {}, 'vulns': [], 'exploits': []}]
        self.assertEqual(self.mod.analyze_findings(scan_results), [])

    # --- Report generation ---

    def test_report_includes_findings_and_diagnostics(self):
        scan_results = [{
            'ip': '192.168.1.10', 'hostname': 'router.lan', 'mac': 'AA:BB:CC:DD:EE:FF', 'vendor': 'Acme',
            'services': [{'port': '22', 'protocol': 'tcp', 'name': 'ssh',
                          'product': 'OpenSSH', 'version': '8.2'}],
            'cves': {'22': [{'id': 'CVE-2020-1234', 'description': 'd',
                              'score': 7.5, 'severity': 'HIGH'}]},
            'vulns': [], 'exploits': [],
        }]
        findings = self.mod.analyze_findings(scan_results)
        self.mod.note("SCAN-401", "test diagnostic")
        report = self.mod.generate_report(scan_results, "192.168.1.0/24", findings)
        content = read_file(report)
        self.assertIn("FINDINGS SUMMARY", content)
        self.assertIn("CVE-2020-1234", content)
        self.assertIn("DIAGNOSTICS", content)
        self.assertIn("SCAN-401", content)

    def test_report_clean_run_shows_no_issues(self):
        report = self.mod.generate_report([], "192.168.1.0/24", [])
        content = read_file(report)
        self.assertIn("No actionable findings", content)
        self.assertIn("No issues encountered", content)

    # --- Pre-flight / crash-prevention ---

    def test_attempt_exploits_without_msfconsole_logs_code_and_does_not_crash(self):
        with patch.object(self.mod.shutil, "which", return_value=None), \
             patch("builtins.input", return_value="yes"):
            result = self.mod.attempt_exploits(
                {"ip": "1.2.3.4"},
                [{"script": "test-vuln", "output": "VULNERABLE"}]
            )
            self.assertEqual(result, [])
            self.assertTrue(any("SCAN-503" in d for d in self.mod.DIAGNOSTICS))


if __name__ == "__main__":
    unittest.main()
