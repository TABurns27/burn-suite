import os
import sys
import unittest
import tempfile
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _loader import load, read_file


class BurnCrackerWordlistTests(unittest.TestCase):
    """check_wordlist() is now an interactive picker: it lists installed
    wordlists (rockyou pinned as the default) and also accepts a custom path.

    NOTE: every test here must feed input that eventually SATISFIES the
    prompt. A mock that returns the same invalid answer forever would spin
    the re-prompt loop infinitely (that's a test bug, not a tool bug — a real
    human can't type infinitely fast), so inputs are given as terminating
    side_effect sequences, never a constant invalid return_value.
    """

    def setUp(self):
        self.mod = load("burncracker")

    def test_select_installed_wordlist_by_number(self):
        # rockyou (the default) is pinned first, so "1" selects it.
        with patch("os.path.isdir", return_value=True), \
             patch("os.listdir", return_value=["alpha.txt", "rockyou.txt", "beta.lst"]), \
             patch("os.path.isfile", return_value=True), \
             patch("os.path.getsize", return_value=1024), \
             patch("os.path.exists", side_effect=lambda p: p == self.mod.WORDLIST), \
             patch("builtins.input", return_value="1"):
            self.assertEqual(self.mod.check_wordlist(), self.mod.WORDLIST)

    def test_custom_path_via_C_option(self):
        with patch("os.path.isdir", return_value=True), \
             patch("os.listdir", return_value=["rockyou.txt"]), \
             patch("os.path.isfile", return_value=True), \
             patch("os.path.getsize", return_value=1024), \
             patch("os.path.exists", side_effect=lambda p: p == self.mod.WORDLIST), \
             patch("builtins.input", side_effect=["C", "/home/me/custom.txt"]):
            self.assertEqual(self.mod.check_wordlist(), "/home/me/custom.txt")

    def test_no_installed_lists_falls_back_to_custom_prompt(self):
        with patch("os.path.isdir", return_value=False), \
             patch("os.path.exists", return_value=False), \
             patch("os.path.isfile", return_value=True), \
             patch("builtins.input", return_value="/tmp/wl.txt"):
            self.assertEqual(self.mod.check_wordlist(), "/tmp/wl.txt")

    def test_invalid_then_valid_choice_reprompts(self):
        # "9" is out of range and "x" is junk; the loop must recover, not die.
        with patch("os.path.isdir", return_value=True), \
             patch("os.listdir", return_value=["rockyou.txt"]), \
             patch("os.path.isfile", return_value=True), \
             patch("os.path.getsize", return_value=1024), \
             patch("os.path.exists", side_effect=lambda p: p == self.mod.WORDLIST), \
             patch("builtins.input", side_effect=["9", "x", "1"]):
            self.assertEqual(self.mod.check_wordlist(), self.mod.WORDLIST)

    def test_gz_selection_is_decompressed(self):
        # Selecting a .gz list decompresses it (gunzip via run()) and returns
        # the plain-text path. Target is absent first (so gunzip runs), then
        # present (so it's returned) — mimicking a successful decompress.
        seen = {"n": 0}

        def fake_exists(path):
            if path.endswith("big.txt"):
                seen["n"] += 1
                return seen["n"] > 1
            return False

        with patch("os.path.isdir", return_value=True), \
             patch("os.listdir", return_value=["big.txt.gz"]), \
             patch("os.path.isfile", return_value=True), \
             patch("os.path.getsize", return_value=10), \
             patch("os.path.exists", side_effect=fake_exists), \
             patch.object(self.mod, "run") as mock_run, \
             patch("builtins.input", return_value="1"):
            result = self.mod.check_wordlist()
        self.assertTrue(result.endswith("big.txt"))
        self.assertTrue(mock_run.called)   # gunzip was invoked

    def test_ensure_uncompressed_never_uses_a_shell(self):
        """A wordlist path with shell metacharacters must not be shell-
        interpreted: the gunzip call must pass a LIST (shell=False), so a
        malicious custom path can't inject commands."""
        seen = {"n": 0}

        def fake_exists(path):
            seen["n"] += 1
            return seen["n"] > 1   # absent first → triggers gunzip

        evil = "/tmp/na me;$(touch pwned).txt.gz"
        with patch("os.path.exists", side_effect=fake_exists), \
             patch.object(self.mod, "run") as mock_run:
            self.mod.ensure_uncompressed(evil)
        self.assertTrue(mock_run.called)
        passed = mock_run.call_args[0][0]
        self.assertIsInstance(passed, list)          # list form => no shell
        self.assertIn(evil, passed)


class BurnCrackerPasswordDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.mod = load("burncracker")
        self.mod.DIAGNOSTICS.clear()
        # crack_password() now prompts for the wordlist itself (after the
        # method is chosen), so stub it out to avoid the interactive menu.
        p = patch.object(self.mod, "check_wordlist", return_value="wl.txt")
        p.start()
        self.addCleanup(p.stop)

    def test_password_found_no_hardened_claim(self):
        with patch.object(self.mod, "crack_aircrack", return_value=("hunter2", True)), \
             patch("builtins.input", return_value="1"):
            pw = self.mod.crack_password("cap.cap")
            self.assertEqual(pw, "hunter2")
            self.assertFalse(any("CRACK-401" in d for d in self.mod.DIAGNOSTICS))

    def test_completed_no_password_fires_hardened_finding(self):
        with patch.object(self.mod, "crack_aircrack", return_value=(None, True)), \
             patch("builtins.input", return_value="1"):
            pw = self.mod.crack_password("cap.cap")
            self.assertIsNone(pw)
            self.assertTrue(any("CRACK-401" in d for d in self.mod.DIAGNOSTICS))

    def test_incomplete_crack_does_not_fire_hardened_finding(self):
        """A timeout must never be reported as 'password resists this wordlist' — that would be a lie."""
        with patch.object(self.mod, "crack_aircrack", return_value=(None, False)), \
             patch("builtins.input", return_value="1"):
            pw = self.mod.crack_password("cap.cap")
            self.assertIsNone(pw)
            self.assertFalse(any("CRACK-401" in d for d in self.mod.DIAGNOSTICS))

    def test_missing_hashcat_falls_back_and_logs_code(self):
        with patch.object(self.mod, "check_hashcat", return_value=False), \
             patch.object(self.mod, "crack_aircrack", return_value=("found_it", True)) as mock_aircrack, \
             patch("builtins.input", return_value="2"):
            pw = self.mod.crack_password("cap.cap")
            self.assertEqual(pw, "found_it")
            self.assertTrue(mock_aircrack.called)
            self.assertTrue(any("CRACK-501" in d for d in self.mod.DIAGNOSTICS))


class BurnCrackerReportTests(unittest.TestCase):
    def setUp(self):
        self.mod = load("burncracker")
        self.mod.DIAGNOSTICS.clear()
        self.tmpdir = tempfile.TemporaryDirectory()
        self.mod.REPORT_DIR = self.tmpdir.name
        self.target = {"essid": "TestNet", "bssid": "AA:BB:CC:DD:EE:FF", "channel": "6", "enc": "WPA2"}

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_report_written_as_utf8_and_includes_diagnostics(self):
        self.mod.note("CRACK-302", "No handshake captured.")
        report = self.mod.save_results(self.target, None)
        # This must not raise UnicodeDecodeError — the em-dashes in the
        # generated text require the file to actually be UTF-8.
        content = read_file(report)
        self.assertIn("DIAGNOSTICS", content)
        self.assertIn("CRACK-302: No handshake captured.", content)
        self.assertIn("ERROR_CODES.txt", content)

    def test_report_clean_run_shows_no_issues(self):
        report = self.mod.save_results(self.target, "found_password")
        content = read_file(report)
        self.assertIn("No issues encountered", content)
        self.assertIn("STATUS     : CRACKED", content)


class BurnCrackerSecurityClassificationTests(unittest.TestCase):
    """classify_security() decides what is actually attackable. The point of
    the WPA3 handling is honesty: SAE-only is NOT offline-crackable, so it
    must be classified distinctly from the attackable WPA2/transition cases."""

    def setUp(self):
        self.mod = load("burncracker")

    def test_open_and_enterprise(self):
        self.assertEqual(self.mod.classify_security("OPN", ""), "open")
        self.assertEqual(self.mod.classify_security("", ""), "open")
        self.assertEqual(self.mod.classify_security("WPA2", "MGT"), "enterprise")

    def test_wpa2_psk_is_crackable(self):
        self.assertEqual(self.mod.classify_security("WPA2", "PSK"), "wpa-psk")

    def test_wpa3_sae_only_is_not_offline_attackable(self):
        self.assertEqual(self.mod.classify_security("WPA3", "SAE"), "wpa3-sae")
        # WPA3 Privacy with no PSK fallback, even if auth field is blank.
        self.assertEqual(self.mod.classify_security("WPA3", ""), "wpa3-sae")

    def test_transition_mode_detected_via_auth_or_privacy(self):
        # Both PSK and SAE offered => transition (attackable via WPA2).
        self.assertEqual(self.mod.classify_security("WPA3", "PSK SAE"), "wpa3-transition")
        # Privacy listing both WPA2 and WPA3 => transition, even if auth blank.
        self.assertEqual(self.mod.classify_security("WPA2 WPA3", ""), "wpa3-transition")


class BurnCrackerPmkidCaptureTests(unittest.TestCase):
    """Clientless PMKID capture (hcxdumptool) and its plumbing."""

    def setUp(self):
        self.mod = load("burncracker")
        self.mod.DIAGNOSTICS.clear()

    def test_capture_method_gated_on_hcxdumptool(self):
        # No hcxdumptool -> no prompt, straight to handshake.
        with patch.object(self.mod.shutil, "which", return_value=None):
            self.assertEqual(self.mod.choose_capture_method("wlan1"), "handshake")
        # Present -> the menu is offered.
        with patch.object(self.mod.shutil, "which", return_value="/usr/bin/hcxdumptool"), \
             patch("builtins.input", return_value="2"):
            self.assertEqual(self.mod.choose_capture_method("wlan1"), "pmkid")

    def test_convert_handles_pcapng_extension(self):
        # PMKID captures are .pcapng; the output name must not keep .pcapng.
        with patch.object(self.mod, "run", side_effect=lambda *a, **k: MagicMock()), \
             patch("os.path.exists", return_value=True), \
             patch("os.path.getsize", return_value=500):
            hc_file, mode = self.mod.convert_to_hccapx("/tmp/burncracker/pmkid.pcapng")
        self.assertEqual(hc_file, "/tmp/burncracker/pmkid.hc22000")
        self.assertEqual(mode, 22000)

    def test_pmkid_no_capture_logs_crack_305(self):
        target = {"bssid": "AA:BB:CC:DD:EE:FF", "channel": "6", "essid": "t"}
        with patch.object(self.mod, "run", side_effect=lambda *a, **k: MagicMock()), \
             patch.object(self.mod, "run_streaming", return_value=(0, None)), \
             patch("os.path.exists", return_value=False), \
             patch("time.sleep"):
            cap, reselect = self.mod.capture_pmkid(target, "wlan1", seconds=1)
        self.assertIsNone(cap)
        self.assertTrue(any("CRACK-305" in d for d in self.mod.DIAGNOSTICS))

    def test_pmkid_capture_without_crackable_hash_logs_crack_306(self):
        target = {"bssid": "AA:BB:CC:DD:EE:FF", "channel": "6", "essid": "t"}
        with patch.object(self.mod, "run", side_effect=lambda *a, **k: MagicMock()), \
             patch.object(self.mod, "run_streaming", return_value=(0, None)), \
             patch.object(self.mod, "convert_to_hccapx", return_value=(None, None)), \
             patch("os.path.exists", return_value=True), \
             patch("os.path.getsize", return_value=1000), \
             patch("time.sleep"):
            cap, reselect = self.mod.capture_pmkid(target, "wlan1", seconds=1)
        self.assertIsNone(cap)
        self.assertTrue(any("CRACK-306" in d for d in self.mod.DIAGNOSTICS))


class BurnCrackerDeauthConfirmTests(unittest.TestCase):
    """The broadcast-deauth CONFIRM gate must be un-fat-fingerable: a blank
    Enter (or anything != 'CONFIRM') sends NO deauth and returns to the menu
    rather than silently downgrading to passive capture and proceeding."""

    def setUp(self):
        self.mod = load("burncracker")
        self.mod.DIAGNOSTICS.clear()

    def _capture_with_inputs(self, inputs):
        target = {"bssid": "AA:BB:CC:DD:EE:FF", "channel": "6", "essid": "t"}
        stations = ["11:22:33:44:55:66", "77:88:99:AA:BB:CC"]
        calls = []

        def fake_run(cmd, *a, **k):
            calls.append(cmd)
            return MagicMock(stdout="")          # aircrack: "no handshake"

        with patch.object(self.mod, "run", side_effect=fake_run), \
             patch.object(self.mod, "spawn", return_value=MagicMock()), \
             patch.object(self.mod, "reap"), \
             patch("time.sleep"), \
             patch("builtins.input", side_effect=inputs):
            self.mod.capture_handshake(target, stations, "wlan1")

        return [c for c in calls if isinstance(c, str) and "aireplay-ng" in c]

    def test_blank_confirm_sends_no_deauth_and_reprompts(self):
        # choose broadcast (2), press Enter (blank -> back to menu), then skip (3)
        aireplay = self._capture_with_inputs(["2", "", "3"])
        self.assertEqual(aireplay, [])           # nothing was broadcast

    def test_typed_confirm_actually_broadcasts(self):
        aireplay = self._capture_with_inputs(["2", "CONFIRM"])
        self.assertTrue(any("-0 3 -a AA:BB:CC:DD:EE:FF" in c for c in aireplay))


class BurnCrackerNetworkParsingTests(unittest.TestCase):
    def setUp(self):
        self.mod = load("burncracker")
        self.mod.DIAGNOSTICS.clear()

    def test_scan_networks_returns_empty_tuple_not_bare_list(self):
        """scan_networks() must return (list, csv_path) even on failure —
        the caller always unpacks two values."""
        with patch("os.path.exists", return_value=False), \
             patch("subprocess.Popen"), \
             patch("time.sleep"):
            networks, csv_file = self.mod.scan_networks("wlan1")
            self.assertEqual(networks, [])
            self.assertIsNone(csv_file)


class BurnCrackerVendorLookupTests(unittest.TestCase):
    """mac_vendor() annotates the connected-device list. Randomized
    (locally-administered) MACs must be flagged rather than given a bogus
    vendor, since modern phones rotate them."""

    def setUp(self):
        self.mod = load("burncracker")

    def test_locally_administered_mac_flagged_as_randomized(self):
        # The 0x02 bit in the first octet marks a locally-administered MAC.
        self.assertIn("randomized", self.mod.mac_vendor("8A:11:22:33:44:55"))
        self.assertIn("randomized", self.mod.mac_vendor("02:00:00:00:00:00"))

    def test_known_oui_resolves_to_vendor(self):
        self.mod._OUI_MAP = {"FC65DE": "Amazon Technologies"}
        self.assertEqual(self.mod.mac_vendor("FC:65:DE:11:22:33"), "Amazon Technologies")

    def test_unknown_oui_returns_placeholder(self):
        self.mod._OUI_MAP = {}
        self.assertEqual(self.mod.mac_vendor("FC:65:DE:11:22:33"), "unknown vendor")

    def test_malformed_mac_returns_empty_string(self):
        self.assertEqual(self.mod.mac_vendor("zz"), "")


class BurnCrackerPreflightTests(unittest.TestCase):
    """The startup/--check preflight reports on the runtime environment.
    Missing REQUIRED tools fail it (CRACK-104); optional ones never do."""

    def setUp(self):
        self.mod = load("burncracker")
        self.mod.DIAGNOSTICS.clear()

    def test_all_required_present_passes(self):
        with patch.object(self.mod.shutil, "which", return_value="/usr/bin/x"), \
             patch("os.path.exists", return_value=True):
            self.assertTrue(self.mod.preflight(verbose=False))
        self.assertFalse(any("CRACK-104" in d for d in self.mod.DIAGNOSTICS))

    def test_missing_required_tool_fails_and_logs_crack_104(self):
        def which(tool):
            return None if tool == "aircrack-ng" else "/usr/bin/x"
        with patch.object(self.mod.shutil, "which", side_effect=which), \
             patch("os.path.exists", return_value=True):
            self.assertFalse(self.mod.preflight(verbose=False))
        self.assertTrue(any("CRACK-104" in d for d in self.mod.DIAGNOSTICS))

    def test_missing_optional_tool_does_not_fail(self):
        # hashcat/hcxtools/OUI absent, but all REQUIRED present -> still OK.
        required = {t for t, _ in self.mod.REQUIRED_TOOLS}
        with patch.object(self.mod.shutil, "which",
                          side_effect=lambda t: "/usr/bin/x" if t in required else None), \
             patch("os.path.exists", return_value=False):
            self.assertTrue(self.mod.preflight(verbose=False))
        self.assertFalse(any("CRACK-104" in d for d in self.mod.DIAGNOSTICS))


class BurnCrackerProcessTeardownTests(unittest.TestCase):
    """Safety guard around the process-group teardown: a failed or mocked
    spawn (pid None/0) must NEVER let killpg hit our own session — that's
    what would black-screen a desktop. _signal_group() enforces this."""

    def setUp(self):
        self.mod = load("burncracker")

    def test_non_int_pid_never_reaches_killpg(self):
        # A MagicMock proc has a non-int .pid — it must be ignored entirely.
        with patch("os.getpgid") as gpg, patch("os.killpg") as kpg:
            self.mod._signal_group(MagicMock(), self.mod.signal.SIGTERM)
            gpg.assert_not_called()
            kpg.assert_not_called()

    def test_own_process_group_is_never_signalled(self):
        proc = MagicMock()
        proc.pid = 4242
        with patch("os.getpgid", return_value=os.getpgrp()), \
             patch("os.killpg") as kpg:
            self.mod._signal_group(proc, self.mod.signal.SIGTERM)
            kpg.assert_not_called()

    def test_valid_foreign_group_is_signalled(self):
        proc = MagicMock()
        proc.pid = 4242
        with patch("os.getpgid", return_value=9999), \
             patch("os.killpg") as kpg:
            self.mod._signal_group(proc, self.mod.signal.SIGTERM)
            kpg.assert_called_once()

    def test_reap_of_mock_process_is_safe_and_untracks(self):
        # Mimics how scan_networks/get_stations teardown runs under mocks:
        # no real signal, and the proc is removed from ACTIVE_PROCS.
        proc = MagicMock()
        self.mod.ACTIVE_PROCS.add(proc)
        with patch("os.killpg") as kpg:
            self.mod.reap(proc)
            kpg.assert_not_called()
        self.assertNotIn(proc, self.mod.ACTIVE_PROCS)


class BurnCrackerInterfaceEnumerationTests(unittest.TestCase):
    def setUp(self):
        self.mod = load("burncracker")

    def test_parses_iw_dev_output_into_interface_list(self):
        fake_iw_dev = MagicMock(returncode=0, stdout=(
            "phy#0\n"
            "\tInterface wlan0\n"
            "\t\tifindex 3\n"
            "\t\ttype managed\n"
            "phy#1\n"
            "\tInterface wlan1\n"
            "\t\tifindex 4\n"
            "\t\ttype managed\n"
        ))
        with patch.object(self.mod, "run", return_value=fake_iw_dev), \
             patch("os.readlink", side_effect=OSError):
            interfaces = self.mod.list_wireless_interfaces()
            self.assertEqual([i["iface"] for i in interfaces], ["wlan0", "wlan1"])

    def test_returns_empty_list_when_iw_dev_fails(self):
        with patch.object(self.mod, "run", return_value=None):
            self.assertEqual(self.mod.list_wireless_interfaces(), [])

    def test_returns_empty_list_on_nonzero_returncode(self):
        fake_result = MagicMock(returncode=1, stdout="")
        with patch.object(self.mod, "run", return_value=fake_result):
            self.assertEqual(self.mod.list_wireless_interfaces(), [])

    def test_get_driver_name_reads_sys_symlink(self):
        with patch("os.readlink", return_value="../../../../bus/usb/drivers/mt76x2u"):
            self.assertEqual(self.mod.get_driver_name("wlan1"), "mt76x2u")

    def test_get_driver_name_returns_none_on_oserror(self):
        with patch("os.readlink", side_effect=OSError):
            self.assertIsNone(self.mod.get_driver_name("wlan1"))


class BurnCrackerInterfaceSelectionTests(unittest.TestCase):
    def setUp(self):
        self.mod = load("burncracker")
        self.mod.DIAGNOSTICS.clear()

    def test_valid_selection_returns_chosen_iface(self):
        fake_list = [{"iface": "wlan0", "driver": "iwlwifi"}, {"iface": "wlan1", "driver": "mt76x2u"}]
        with patch.object(self.mod, "list_wireless_interfaces", return_value=fake_list), \
             patch("builtins.input", return_value="1"):
            self.assertEqual(self.mod.select_interface(), "wlan1")

    def test_invalid_then_valid_input_reprompts(self):
        fake_list = [{"iface": "wlan0", "driver": None}]
        with patch.object(self.mod, "list_wireless_interfaces", return_value=fake_list), \
             patch("builtins.input", side_effect=["not a number", "99", "0"]):
            self.assertEqual(self.mod.select_interface(), "wlan0")

    def test_no_interfaces_logs_crack_106_and_returns_none(self):
        with patch.object(self.mod, "list_wireless_interfaces", return_value=[]), \
             patch("builtins.input", side_effect=AssertionError("should not prompt")):
            result = self.mod.select_interface()
            self.assertIsNone(result)
            self.assertTrue(any("CRACK-106" in d for d in self.mod.DIAGNOSTICS))


class BurnCrackerMonitorModeTests(unittest.TestCase):
    def setUp(self):
        self.mod = load("burncracker")
        self.mod.DIAGNOSTICS.clear()

    def test_start_monitor_full_sequence_with_nmcli(self):
        calls = []

        def fake_run(cmd, timeout=None, capture=True):
            calls.append(cmd)
            if "info" in cmd:
                return MagicMock(stdout="type monitor\n", returncode=0)
            return MagicMock(stdout="", returncode=0)

        with patch.object(self.mod, "run", side_effect=fake_run), \
             patch.object(self.mod.shutil, "which", return_value="/usr/bin/nmcli"), \
             patch("time.sleep"):
            result = self.mod.start_monitor("wlan1")
            self.assertTrue(result)
            self.assertTrue(any("nmcli device set wlan1 managed no" in c for c in calls))
            self.assertTrue(any("ip link set wlan1 down" in c for c in calls))
            self.assertTrue(any("iw dev wlan1 set type monitor" in c for c in calls))
            self.assertTrue(any("ip link set wlan1 up" in c for c in calls))
            idx_nmcli   = next(i for i, c in enumerate(calls) if "managed no" in c)
            idx_down    = next(i for i, c in enumerate(calls) if "ip link set wlan1 down" in c)
            idx_monitor = next(i for i, c in enumerate(calls) if "set type monitor" in c)
            idx_up      = next(i for i, c in enumerate(calls) if "ip link set wlan1 up" in c)
            self.assertTrue(idx_nmcli < idx_down < idx_monitor < idx_up)

    def test_start_monitor_without_nmcli_skips_isolation_and_logs_neutral_note(self):
        def fake_run(cmd, timeout=None, capture=True):
            if "info" in cmd:
                return MagicMock(stdout="type monitor\n", returncode=0)
            return MagicMock(stdout="", returncode=0)

        with patch.object(self.mod, "run", side_effect=fake_run), \
             patch.object(self.mod.shutil, "which", return_value=None), \
             patch("time.sleep"):
            result = self.mod.start_monitor("wlan1")
            self.assertTrue(result)
            self.assertTrue(any("CRACK-503" in d for d in self.mod.DIAGNOSTICS))

    def test_start_monitor_verification_uses_iw_info_not_ip_link_show(self):
        """Regression guard: a decoy 'wlan0mon' string anywhere in an
        unrelated ip-link-show-style blob must NOT cause a false positive —
        only the specific iface's own `iw ... info` output counts."""
        def fake_run(cmd, timeout=None, capture=True):
            if "iw dev wlan1 info" in cmd:
                return MagicMock(stdout="type managed\n", returncode=0)  # NOT monitor
            if cmd == "ip link show":
                # decoy: an unrelated interface happens to be named wlan0mon
                return MagicMock(stdout="3: wlan0mon: <...>\n", returncode=0)
            return MagicMock(stdout="", returncode=0)

        with patch.object(self.mod, "run", side_effect=fake_run), \
             patch.object(self.mod.shutil, "which", return_value=None), \
             patch("time.sleep"):
            result = self.mod.start_monitor("wlan1")
            self.assertFalse(result)
            self.assertTrue(any("CRACK-201" in d for d in self.mod.DIAGNOSTICS))

    def test_start_monitor_failure_reverts_via_stop_monitor(self):
        def fake_run(cmd, timeout=None, capture=True):
            if "info" in cmd:
                return MagicMock(stdout="type managed\n", returncode=0)
            return MagicMock(stdout="", returncode=0)

        with patch.object(self.mod, "run", side_effect=fake_run), \
             patch.object(self.mod.shutil, "which", return_value=None), \
             patch.object(self.mod, "stop_monitor") as mock_stop, \
             patch("time.sleep"):
            result = self.mod.start_monitor("wlan1")
            self.assertFalse(result)
            mock_stop.assert_called_once_with("wlan1")

    def test_crack_201_message_no_longer_mentions_interface_constant(self):
        def fake_run(cmd, timeout=None, capture=True):
            if "info" in cmd:
                return MagicMock(stdout="type managed\n", returncode=0)
            return MagicMock(stdout="", returncode=0)

        with patch.object(self.mod, "run", side_effect=fake_run), \
             patch.object(self.mod.shutil, "which", return_value=None), \
             patch("time.sleep"):
            self.mod.start_monitor("wlan1")
            crack_201_msgs = [d for d in self.mod.DIAGNOSTICS if "CRACK-201" in d]
            self.assertTrue(crack_201_msgs)
            self.assertNotIn("INTERFACE", crack_201_msgs[0])
            self.assertNotIn("wrong interface", crack_201_msgs[0].lower())


class BurnCrackerStopMonitorTests(unittest.TestCase):
    def setUp(self):
        self.mod = load("burncracker")
        self.mod.monitor_active = True

    def test_restore_sequence_with_nmcli(self):
        calls = []

        def fake_run(cmd, timeout=None, capture=True):
            calls.append(cmd)
            return MagicMock(stdout="", returncode=0)

        with patch.object(self.mod, "run", side_effect=fake_run), \
             patch.object(self.mod.shutil, "which", return_value="/usr/bin/nmcli"), \
             patch("time.sleep"):
            self.mod.stop_monitor("wlan1")
            self.assertFalse(self.mod.monitor_active)
            self.assertTrue(any("ip link set wlan1 down" in c for c in calls))
            self.assertTrue(any("iw dev wlan1 set type managed" in c for c in calls))
            self.assertTrue(any("ip link set wlan1 up" in c for c in calls))
            self.assertTrue(any("nmcli device set wlan1 managed yes" in c for c in calls))

    def test_restore_sequence_without_nmcli(self):
        calls = []

        def fake_run(cmd, timeout=None, capture=True):
            calls.append(cmd)
            return MagicMock(stdout="", returncode=0)

        with patch.object(self.mod, "run", side_effect=fake_run), \
             patch.object(self.mod.shutil, "which", return_value=None), \
             patch("time.sleep"):
            self.mod.stop_monitor("wlan1")
            self.assertFalse(self.mod.monitor_active)
            self.assertFalse(any("nmcli" in c for c in calls))


class BurnCrackerScopeRegressionTests(unittest.TestCase):
    """Guards against ever reintroducing the old system-wide
    airmon-ng/NetworkManager disruption this whole feature was built to
    avoid — the entire point of dedicating a second adapter is that other
    interfaces (e.g. the one keeping you online) are never touched."""

    def setUp(self):
        self.mod = load("burncracker")
        self.mod.DIAGNOSTICS.clear()

    def _run_full_cycle(self, nmcli_present):
        calls = []

        def fake_run(cmd, timeout=None, capture=True):
            calls.append(cmd)
            if isinstance(cmd, str) and "info" in cmd:
                return MagicMock(stdout="type monitor\n", returncode=0)
            return MagicMock(stdout="", returncode=0)

        which_path = "/usr/bin/nmcli" if nmcli_present else None
        with patch.object(self.mod, "run", side_effect=fake_run), \
             patch.object(self.mod.shutil, "which", return_value=which_path), \
             patch("time.sleep"):
            self.mod.start_monitor("wlan1")
            self.mod.stop_monitor("wlan1")
        return calls

    def test_never_calls_airmon_ng_check_kill(self):
        for nmcli_present in (True, False):
            calls = self._run_full_cycle(nmcli_present)
            self.assertFalse(any("airmon-ng check kill" in c for c in calls))

    def test_never_calls_airmon_ng_start_or_stop(self):
        for nmcli_present in (True, False):
            calls = self._run_full_cycle(nmcli_present)
            self.assertFalse(any("airmon-ng start" in c for c in calls))
            self.assertFalse(any("airmon-ng stop" in c for c in calls))

    def test_never_touches_networkmanager_or_wpa_supplicant_unscoped(self):
        for nmcli_present in (True, False):
            calls = self._run_full_cycle(nmcli_present)
            self.assertFalse(any("systemctl stop NetworkManager" in c for c in calls))
            self.assertFalse(any("systemctl start NetworkManager" in c for c in calls))
            self.assertFalse(any("killall wpa_supplicant" in c for c in calls))
            self.assertFalse(any("pkill" in c and "wpa_supplicant" in c for c in calls))

    def test_every_nmcli_call_includes_explicit_iface(self):
        calls = self._run_full_cycle(nmcli_present=True)
        nmcli_calls = [c for c in calls if "nmcli" in c]
        self.assertTrue(nmcli_calls)
        for c in nmcli_calls:
            self.assertIn("wlan1", c)


class BurnCrackerIfacePropagationTests(unittest.TestCase):
    def setUp(self):
        self.mod = load("burncracker")

    def test_scan_networks_passes_iface_to_airodump(self):
        captured = {}

        def fake_popen(args, **kwargs):
            captured["args"] = args
            return MagicMock()

        with patch("subprocess.Popen", side_effect=fake_popen), \
             patch("time.sleep"), \
             patch("os.path.exists", return_value=False):
            self.mod.scan_networks("wlxDEADBEEF")
        self.assertIn("wlxDEADBEEF", captured["args"])

    def test_get_stations_passes_iface_to_airodump(self):
        captured = {}

        def fake_popen(args, **kwargs):
            captured["args"] = args
            return MagicMock()

        target = {"channel": "6", "bssid": "AA:BB:CC:DD:EE:FF", "essid": "t"}
        with patch("subprocess.Popen", side_effect=fake_popen), \
             patch("time.sleep"), \
             patch("os.makedirs"), \
             patch.object(self.mod, "run", return_value=MagicMock()):
            self.mod.get_stations(target, "wlxDEADBEEF")
        self.assertIn("wlxDEADBEEF", captured["args"])

    def test_hasattr_mon_iface_and_interface_are_gone(self):
        self.assertFalse(hasattr(self.mod, "MON_IFACE"))
        self.assertFalse(hasattr(self.mod, "INTERFACE"))


class BurnCrackerCleanupSignatureTests(unittest.TestCase):
    def setUp(self):
        self.mod = load("burncracker")

    def test_cleanup_restores_selected_interface_when_active(self):
        self.mod.monitor_active = True
        self.mod.SELECTED_IFACE = "wlan1"
        with patch.object(self.mod, "stop_monitor") as mock_stop, \
             patch("sys.exit"):
            self.mod.cleanup()
            mock_stop.assert_called_once_with("wlan1")

    def test_cleanup_is_noop_restore_when_not_active(self):
        self.mod.monitor_active = False
        self.mod.SELECTED_IFACE = "wlan1"
        with patch.object(self.mod, "stop_monitor") as mock_stop, \
             patch("sys.exit"):
            self.mod.cleanup()
            mock_stop.assert_not_called()

    def test_cleanup_accepts_signal_handler_positional_args(self):
        self.mod.monitor_active = False
        with patch("sys.exit"):
            self.mod.cleanup(2, None)  # matches real signal.signal(SIGINT, cleanup) invocation


if __name__ == "__main__":
    unittest.main()
