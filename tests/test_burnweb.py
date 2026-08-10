import os
import sys
import unittest
import tempfile
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _loader import load, read_file


class BurnWebPathCheckTests(unittest.TestCase):
    def setUp(self):
        self.mod = load("burnweb")

    def test_no_exposed_paths_found_is_web_401(self):
        resp = MagicMock(status_code=404)
        with patch.object(self.mod.requests, "get", return_value=resp):
            result = self.mod.check_sensitive_paths("http://x", soft_404=False)
            self.assertEqual(result, [])
            self.assertTrue(any("WEB-401" in d for d in self.mod.DIAGNOSTICS))

    def test_exposed_path_is_detected(self):
        def fake_get(url, timeout=None, allow_redirects=None):
            status = 200 if url.endswith("/.env") else 404
            return MagicMock(status_code=status)
        with patch.object(self.mod.requests, "get", side_effect=fake_get):
            result = self.mod.check_sensitive_paths("http://x", soft_404=False)
            self.assertEqual([r["path"] for r in result], ["/.env"])

    def test_soft_404_skips_the_check_entirely(self):
        with patch.object(self.mod.requests, "get") as mock_get:
            result = self.mod.check_sensitive_paths("http://x", soft_404=True)
            self.assertEqual(result, [])
            mock_get.assert_not_called()

    def test_gobuster_missing_falls_back_and_logs_web_501(self):
        resp = MagicMock(status_code=404)
        with patch.object(self.mod, "tool_available", return_value=False), \
             patch.object(self.mod.requests, "get", return_value=resp):
            result = self.mod.dir_fuzz("http://x", soft_404=False)
            self.assertTrue(any("WEB-501" in d for d in self.mod.DIAGNOSTICS))
            self.assertTrue(any("WEB-402" in d for d in self.mod.DIAGNOSTICS))


class BurnWebTimeoutDistinctionTests(unittest.TestCase):
    """A tool timing out must never be reported the same way as the tool
    actually running and finding nothing clean — that would overstate
    how thoroughly the target was tested."""

    def setUp(self):
        self.mod = load("burnweb")

    def test_nikto_missing_is_web_502(self):
        with patch.object(self.mod, "tool_available", return_value=False):
            result = self.mod.nikto_scan("http://x")
            self.assertEqual(result, [])
            self.assertTrue(any("WEB-502" in d for d in self.mod.DIAGNOSTICS))

    def test_nikto_timeout_is_web_506_not_web_403(self):
        with patch.object(self.mod, "tool_available", return_value=True), \
             patch.object(self.mod, "run", return_value=None):
            result = self.mod.nikto_scan("http://x")
            self.assertEqual(result, [])
            self.assertTrue(any("WEB-506" in d for d in self.mod.DIAGNOSTICS))
            self.assertFalse(any("WEB-403" in d for d in self.mod.DIAGNOSTICS))

    def test_nikto_clean_run_is_web_403(self):
        nikto_result = MagicMock(stdout="+ Target IP: 1.2.3.4\n+ Server: nginx\n")
        with patch.object(self.mod, "tool_available", return_value=True), \
             patch.object(self.mod, "run", return_value=nikto_result):
            self.mod.nikto_scan("http://x")
            self.assertTrue(any("WEB-403" in d for d in self.mod.DIAGNOSTICS))

    def test_sslscan_timeout_is_web_507_not_web_404(self):
        with patch.object(self.mod, "tool_available", return_value=True), \
             patch.object(self.mod, "run", return_value=None):
            result = self.mod.tls_check("https://x")
            self.assertEqual(result, [])
            self.assertTrue(any("WEB-507" in d for d in self.mod.DIAGNOSTICS))
            self.assertFalse(any("WEB-404" in d for d in self.mod.DIAGNOSTICS))


class BurnWebExploitationGateTests(unittest.TestCase):
    """The exploitation gate must never run sqlmap without an exact typed
    confirmation, even when everything else lines up."""

    def setUp(self):
        self.mod = load("burnweb")
        self.candidates = ["http://x/page?id=1", "http://x/search"]

    def test_no_candidates_skips_without_prompting(self):
        with patch.object(self.mod, "tool_available", return_value=True), \
             patch("builtins.input", side_effect=AssertionError("should not prompt")):
            result = self.mod.offer_exploitation("http://x", [])
            self.assertIsNone(result)
            self.assertTrue(any("WEB-405" in d for d in self.mod.DIAGNOSTICS))

    def test_sqlmap_missing_skips_without_prompting(self):
        with patch.object(self.mod, "tool_available", return_value=False), \
             patch("builtins.input", side_effect=AssertionError("should not prompt")):
            result = self.mod.offer_exploitation("http://x", self.candidates)
            self.assertIsNone(result)
            self.assertTrue(any("WEB-504" in d for d in self.mod.DIAGNOSTICS))

    def test_wrong_confirmation_phrase_skips(self):
        with patch.object(self.mod, "tool_available", return_value=True), \
             patch("builtins.input", side_effect=["not the phrase"]):
            result = self.mod.offer_exploitation("http://x", self.candidates)
            self.assertIsNone(result)

    def test_declining_second_confirm_skips(self):
        with patch.object(self.mod, "tool_available", return_value=True), \
             patch("builtins.input", side_effect=["I HAVE PERMISSION", "0", "no"]):
            result = self.mod.offer_exploitation("http://x", self.candidates)
            self.assertIsNone(result)

    def test_full_confirmation_chain_runs_sqlmap_on_the_selected_target(self):
        fake_result = MagicMock(stdout="not vulnerable")
        with patch.object(self.mod, "tool_available", return_value=True), \
             patch.object(self.mod, "run", return_value=fake_result) as mock_run, \
             patch("builtins.input", side_effect=["I HAVE PERMISSION", "1", "yes"]):
            result = self.mod.offer_exploitation("http://x", self.candidates)
            self.assertIsNotNone(result)
            self.assertEqual(result["target"], self.candidates[1])
            called_cmd = mock_run.call_args.args[0]
            self.assertEqual(called_cmd[:3], ["sqlmap", "-u", self.candidates[1]])
            self.assertTrue(any("WEB-406" in d for d in self.mod.DIAGNOSTICS))

    def test_sqlmap_timeout_is_web_505(self):
        with patch.object(self.mod, "tool_available", return_value=True), \
             patch.object(self.mod, "run", return_value=None), \
             patch("builtins.input", side_effect=["I HAVE PERMISSION", "0", "yes"]):
            result = self.mod.offer_exploitation("http://x", self.candidates)
            self.assertIsNotNone(result)
            self.assertTrue(any("WEB-505" in d for d in self.mod.DIAGNOSTICS))


class BurnWebParallelizationTests(unittest.TestCase):
    def setUp(self):
        self.mod = load("burnweb")

    def test_sensitive_path_check_probes_every_path_concurrently(self):
        """Correctness check for the ThreadPoolExecutor rewrite: every path
        must still be probed exactly once, regardless of execution order."""
        seen = []

        def fake_probe(base_url, path):
            seen.append(path)
            return path, 404

        with patch.object(self.mod, "_probe_path", side_effect=fake_probe):
            self.mod.check_sensitive_paths("http://x", soft_404=False)
        self.assertEqual(sorted(seen), sorted(self.mod.SENSITIVE_PATHS.keys()))


class BurnWebReachabilityGateTests(unittest.TestCase):
    """A target that answers 4xx/5xx on its landing page IS reachable and
    must be scanned — never aborted with WEB-201. Guards against
    reintroducing the `if not resp:` bug: requests.Response.__bool__ returns
    .ok, which is False for any status >= 400, so `not resp` on a 403/401/500
    landing page would falsely look like a connection failure."""

    def setUp(self):
        self.mod = load("burnweb")
        self.tmpdir = tempfile.TemporaryDirectory()
        self.mod.REPORT_DIR = self.tmpdir.name

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_403_landing_page_is_scanned_not_aborted(self):
        # A REAL Response (not a MagicMock, which is always truthy) — a real
        # 403 Response is falsy via .ok, which is the exact condition the old
        # `if not resp:` bug tripped on.
        resp = self.mod.requests.models.Response()
        resp.status_code = 403
        assert not resp, "sanity: a 403 Response must be falsy for this test to mean anything"
        with patch.object(self.mod, "banner"), \
             patch.object(self.mod, "get_target", return_value="http://x"), \
             patch.object(self.mod, "resolve_base_url", return_value=("http://x", resp)), \
             patch.object(self.mod, "fingerprint", return_value={"status_code": 403}), \
             patch.object(self.mod, "check_soft_404", return_value=False), \
             patch.object(self.mod, "get_robots_sitemap",
                          return_value={"disallow": [], "sitemap_found": False}), \
             patch.object(self.mod, "check_sensitive_paths", return_value=[]), \
             patch.object(self.mod, "dir_fuzz", return_value=[]), \
             patch.object(self.mod, "nikto_scan", return_value=[]), \
             patch.object(self.mod, "tls_check", return_value=[]), \
             patch.object(self.mod, "discover_candidates", return_value=[]), \
             patch.object(self.mod, "offer_exploitation", return_value=None):
            # Must run to a written report, not raise SystemExit(3).
            self.mod.main()
        reports = [f for f in os.listdir(self.tmpdir.name) if f.startswith("burnweb_")]
        self.assertTrue(reports, "burnweb aborted a reachable 403 target instead of scanning it")
        self.assertFalse(any("WEB-201" in d for d in self.mod.DIAGNOSTICS))


class BurnWebReportTests(unittest.TestCase):
    def setUp(self):
        self.mod = load("burnweb")
        self.tmpdir = tempfile.TemporaryDirectory()
        self.mod.REPORT_DIR = self.tmpdir.name

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_report_includes_findings_and_diagnostics(self):
        self.mod.note("WEB-401", "No exposed sensitive files found.")
        findings = [{"title": "Missing CSP", "detail": "d", "severity": "HIGH", "remediation": "r"}]
        report = self.mod.generate_report("http://x", {}, findings, None)
        content = read_file(report)
        self.assertIn("FINDINGS SUMMARY", content)
        self.assertIn("Missing CSP", content)
        self.assertIn("DIAGNOSTICS", content)
        self.assertIn("WEB-401", content)

    def test_report_clean_run_shows_no_issues(self):
        report = self.mod.generate_report("http://x", {}, [], None)
        content = read_file(report)
        self.assertIn("No issues encountered", content)


if __name__ == "__main__":
    unittest.main()
