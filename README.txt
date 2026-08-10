================================================================================
  BURN SUITE v1.0
  Automated Network Penetration Testing Toolkit
  Built for Kali Linux
================================================================================

  LEGAL NOTICE
  ------------
  This toolkit is intended for authorized security testing ONLY.
  Only use these tools on networks and devices you own or have explicit
  written permission to test. Unauthorized use is a federal crime under
  the Computer Fraud and Abuse Act (CFAA) and equivalent laws worldwide.
  The authors assume no liability for misuse.

================================================================================
  TOOLS INCLUDED
================================================================================

  burnscanner.py  —  Automated network vulnerability scanner
                      Discovers hosts, scans ports, queries CVE databases,
                      runs Nmap vuln scripts, optionally attempts Metasploit
                      exploits, and generates a readable .txt report.

  burncracker.py  —  Automated WiFi handshake capture and password cracker
                      Scans for nearby networks, lets you pick a target,
                      captures a WPA2 handshake via deauth, and cracks it
                      using aircrack-ng (CPU) or hashcat (GPU + rules).

  burnrecon.py    —  Automated OSINT reconnaissance tool
                      Pulls DNS records, WHOIS data, subdomains, IP
                      geolocation, Shodan intelligence, HTTP headers,
                      email format patterns, and open ports for any
                      domain or IP target. Generates a readable .txt report.

  burnweb.py      —  Automated web application recon & weakness scanner
                      Fingerprints the tech stack, checks for exposed
                      files (.git, .env, backups), fuzzes for hidden
                      directories, runs nikto and a TLS/cipher check,
                      and flags missing security headers. PASSIVE BY
                      DEFAULT — active exploitation (sqlmap) requires a
                      separate, explicit typed confirmation at the end
                      of the scan. Generates a readable .txt report.

  burnreport.py   —  Cross-tool report combiner
                      Doesn't scan anything itself. Reads the existing
                      reports in burn_report/, lets you pick several,
                      and merges their findings and diagnostics into
                      one summarized report tagged by source tool.

  All reports are saved to:  burn_suite/burn_report/

================================================================================
  SUPPORTED PLATFORMS
================================================================================

  Primary target:  Kali Linux / Parrot OS (Debian-family). This is where
                    the suite is plug-and-play — the expected tools and file
                    paths (e.g. /usr/share/wordlists/rockyou.txt) match.

  Other Debian/Ubuntu:  Works via install.sh. rockyou.txt may not be
                    pre-installed at that path; the wordlist picker lets you
                    point to any list, so it's not fatal.

  Fedora / Arch / openSUSE / Alpine:  install.sh now auto-detects your
                    package manager (dnf / pacman / zypper / apk) and installs
                    what it can, best-effort. Some packages (hcxtools,
                    hcxdumptool, ieee-data) may live in a separate repo (AUR,
                    COPR, …) or under a different name — those are skipped, not
                    fatal, and the affected features degrade gracefully.

  Any Linux:        burncracker.py itself is pure Python standard library (no
                    pip packages). It will RUN anywhere with Python 3; whether
                    it's fully FUNCTIONAL depends on the wireless tools and a
                    monitor-mode-capable adapter being present.

  After install, always confirm what's actually available on your system:

       python3 ./burncracker.py --check

  This reports every required and optional dependency as present or missing,
  so you know exactly where you stand regardless of distro.

================================================================================
  REQUIREMENTS
================================================================================

  Operating System:  Kali/Parrot (primary); other distros best-effort — see
                     SUPPORTED PLATFORMS above.
  Python:            Python 3.x (pre-installed on Kali)

  The following tools must be installed. Most are pre-installed on Kali.
  Run install.sh, or the setup commands below, if anything is missing.

  burnscanner.py
  --------------
  - nmap            (pre-installed)
  - metasploit      (pre-installed)
  - python3-requests

    Install:  sudo apt install python3-requests

  burncracker.py
  --------------
  - airodump-ng     (pre-installed)
  - aireplay-ng     (pre-installed)
  - aircrack-ng     (pre-installed)
  - iw              (pre-installed — enumerates adapters, switches monitor mode)
  - hashcat         (optional, for GPU cracking)
  - hcxtools        (optional, for hashcat capture conversion)
  - ieee-data       (optional — OUI database so the connected-device list
                    shows each client's hardware vendor; falls back to
                    nmap's prefix file or "unknown vendor" if absent)
  - NetworkManager / nmcli
                    (optional — used to cleanly release just the
                    selected adapter; skipped gracefully if absent)

    Install:  sudo apt install hashcat hcxtools ieee-data

  NOTE: burncracker.py requires a physical wireless card with monitor
  mode support. It will NOT work inside a VM unless a USB WiFi adapter
  is passed through directly to the VM. Recommended adapters:
  Alfa AWUS036ACH or AWUS036ACM (~$40, plug and play on Kali).

  burncracker.py no longer uses airmon-ng. It lists every wireless
  interface on the system and lets you pick one each run — ideal for
  dedicating a USB adapter to this tool while your main/built-in card
  stays connected to whatever network you're already on. See USAGE
  below.

  burnrecon.py
  ------------
  - whois           (may need install)
  - dnsutils        (may need install)
  - nmap            (needed for --active/--aggressive port scans)
  - python3-requests
  - python3-cryptography  (optional — full TLS cert parsing on invalid
                           certs; degrades gracefully if absent)

    Install:  sudo apt install whois dnsutils nmap python3-requests python3-cryptography

  burnweb.py
  ----------
  - nikto            (pre-installed)
  - gobuster         (pre-installed)
  - sslscan          (may need install)
  - sqlmap           (pre-installed — only used if you explicitly
                      confirm the active-exploitation step)
  - python3-requests

    Install:  sudo apt install sslscan python3-requests

  NOTE: burnweb.py works with just python3-requests installed — nikto,
  gobuster, sslscan, and sqlmap are each checked for individually and
  skipped gracefully (with an install hint) if missing.

  burnreport.py
  -------------
  No external tools required — pure Python standard library. It only
  reads .txt reports already written by the other four tools.

================================================================================
  SETUP
================================================================================

  1. Place all scripts (and the man/ and tests/ folders, if you want
     manual pages and the regression test suite) in your burn_suite folder:

       ~/burn_suite/
       ├── burnscanner.py
       ├── burncracker.py
       ├── burnrecon.py
       ├── burnweb.py
       ├── burnreport.py
       ├── install.sh
       ├── README.txt
       ├── ERROR_CODES.txt
       ├── man/            (optional — manual pages, see MANUAL PAGES below)
       └── tests/           (optional — regression test suite, see TESTING below)

  2. Install dependencies:

       sudo apt update
       sudo apt install whois dnsutils aircrack-ng hashcat hcxtools ieee-data sslscan python3-requests

  3. Configure optional API keys (see CONFIGURATION below).

  4. Run any tool:

       sudo python3 ./burnscanner.py
       sudo python3 ./burncracker.py
            python3 ./burnrecon.py      (does not require root)
            python3 ./burnweb.py        (does not require root)
            python3 ./burnreport.py     (does not require root)

     Or run "sudo ./install.sh" once to register short commands
     (burnscanner, burncracker, burnrecon, burnweb, burnreport) and install
     the manual pages — see below.

================================================================================
  CONFIGURATION
================================================================================

  SHODAN API KEY (burnrecon.py)
  --------------------------------
  Shodan provides intelligence on internet-facing devices including open
  ports, known vulnerabilities, and OS fingerprints.

  To enable Shodan lookups:
  1. Create a free account at https://shodan.io
  2. Copy your API key from your account dashboard
  3. Create your own key file next to burnrecon.py by copying the
     template, then paste YOUR key into it (no quotes, just the key):
         cp shodan_api.txt.example shodan_api.txt
         # then edit shodan_api.txt and replace the placeholder

  burnrecon.py reads the key from shodan_api.txt automatically at
  startup. If the file is missing or empty, Shodan lookups are skipped.
  shodan_api.txt is git-ignored so your personal key is never shared or
  committed — each user must supply their own.

  Free Shodan accounts have 100 query credits per month which is
  sufficient for home lab and learning purposes.

  OPTIONAL: Hunter.io and HaveIBeenPwned keys use the exact same pattern:
      cp hunter_api.txt.example hunter_api.txt   # then paste your key
      cp hibp_api.txt.example   hibp_api.txt     # then paste your key
  Both are git-ignored; if absent, those OSINT lookups are skipped.

  PASSIVE vs ACTIVE (burnrecon.py)
  --------------------------------
  burnrecon is PASSIVE by default: it only queries third-party OSINT
  sources and never sends packets to the target's own infrastructure.

      python3 ./burnrecon.py example.com                 # passive (default)
      python3 ./burnrecon.py example.com --active -o both# +direct probes, txt+json
      python3 ./burnrecon.py example.com --aggressive    # +brute-force, full scan
      python3 ./burnrecon.py -f targets.txt --active     # batch mode

  --active adds direct probing (HTTP/TLS grab, CORS test, zone-transfer
  attempt, subdomain-takeover checks, web-metadata fetch, quick port scan).
  --aggressive adds DNS subdomain brute-force and a full top-1000 scripted
  port scan (implies --active). Only use --active/--aggressive within the
  scope of your authorization. Run  burnrecon --help  for all options.

  WORDLIST (burncracker.py)
  ------------------------
  burncracker.py lets you pick a wordlist interactively at crack time —
  after a handshake is captured and you've chosen a method, not at
  startup (so you're never asked unless there's actually something to
  crack). No code edit needed. It scans /usr/share/wordlists for
  installed lists (.txt/.lst, including .gz), shows them with sizes,
  offers rockyou.txt (~14 million passwords) as the recommended default,
  and also accepts a custom path you type in. A chosen gzipped list is
  decompressed automatically (the original .gz is kept). All three
  methods run a dictionary attack, so the prompt applies to hashcat too.

  To change the default offered, or the directory that's scanned, edit
  the constants near the top of burncracker.py:

       WORDLIST     = "/usr/share/wordlists/rockyou.txt"
       WORDLIST_DIR = "/usr/share/wordlists"

  Recommended larger wordlists:
  - SecLists:     sudo apt install seclists
                  Located at: /usr/share/seclists/
  - CrackStation: Free download at https://crackstation.net (1.5 billion entries)

  HASHCAT RULES (burncracker.py)
  ------------------------------
  When selecting GPU + rules cracking (option 3), burncracker.py
  automatically looks for rule files in:

       /usr/share/hashcat/rules/

  For best coverage download OneRuleToRuleThemAll:
  https://github.com/NotSoSecure/password_cracking_rules

================================================================================
  USAGE
================================================================================

  BURN SCANNER
  ------------
  sudo python3 ./burnscanner.py

  1. Enter target IP or network range when prompted
     Examples:  192.168.1.0/24   |   192.168.1.50   |   192.168.1.1-50
  2. Tool discovers live hosts, scans ports, queries CVE database
  3. Nmap vuln scripts run automatically against each host
  4. If vulnerabilities are found, you are asked before any exploit attempt
  5. .txt report saved to burn_report/

  BURN CRACK
  ----------
  sudo python3 ./burncracker.py

  Verify dependencies first (no root needed):

       python3 ./burncracker.py --check

  This preflight reports each required tool (airodump-ng, aireplay-ng,
  aircrack-ng, iw) and optional one (hashcat, hcxtools, OUI database) as
  present or missing, and exits 2 if anything required is absent. The
  same preflight runs automatically at the start of every normal run, so
  a missing tool aborts cleanly before any prompts rather than failing
  partway through. (This is a runtime dependency check — not the unit
  test suite, which lives in tests/ and is for development.)

  1. Tool lists every wireless interface on the system (via iw dev),
     each with a driver-name hint — pick the one to dedicate to this
     run (e.g. a USB adapter). Every other interface, including
     whatever's keeping you online, is never touched.
  2. Monitor mode starts automatically on the selected interface only
  3. Scans all channels and lists nearby networks (the DEVICES column
     is a scan-only hint — "—" means none seen in the quick scan, not
     confirmed empty)
  4. Enter the number of your target network. The tool checks its
     security and only proceeds if it's actually attackable (see WPA3
     below) — open, Enterprise, and WPA3-only targets are declined with
     an explanation
  5. Choose a capture method (if hcxdumptool is installed):
       - PMKID    — clientless: request it straight from the AP, no
                    client and no deauth needed (quieter)
       - Handshake — deauth a client to force a 4-way handshake
     For the handshake method, connected devices are listed with their
     hardware vendor (via OUI lookup) so you can spot the IoT device to
     target; a randomized MAC is flagged as a likely phone
  6. (Handshake) Choose whether to send a deauth to force a handshake.
     A single-device deauth is targeted (unicast) at that one client
     only — no broadcast frames — to stay as covert as possible
  7. Once a hash is captured, choose cracking method:
       1 — Aircrack-ng (CPU, works everywhere, slower)
       2 — Hashcat GPU (fast, requires compatible GPU)
       3 — Hashcat GPU + rules (best coverage, mutates wordlist)
     Then pick the wordlist (see WORDLIST above) — asked only now, once
     you've committed to cracking. Cracking output streams live with an
     elapsed-time heartbeat, and Ctrl+C stops the cracker cleanly
     instead of orphaning it
  8. Results saved to burn_report/; selected interface restored to
     normal mode automatically

  Only the interface you pick is ever touched — no more airmon-ng
  "check kill", which used to disconnect every wireless connection on
  the machine. If burncracker.py crashes mid-run and you need to
  restore an interface manually:

       sudo ip link set <iface> down
       sudo iw dev <iface> set type managed
       sudo ip link set <iface> up
       sudo nmcli device set <iface> managed yes

  WPA3 — what is and isn't attackable
  -----------------------------------
  This tool does an OFFLINE dictionary attack: capture a WPA2-PSK
  handshake (or a PMKID) and try passphrases against it at GPU speed.

  WPA3-Personal replaces PSK with SAE, a handshake designed specifically
  to defeat offline dictionary attacks — capturing it gives you nothing
  to test guesses against, and there's no hashcat mode for it. So a
  WPA3-ONLY network is not crackable this way, and no hardware changes
  that (a laptop and a datacenter are equally stuck). AES/CCMP is just
  the cipher; SAE is the barrier. The tool detects this and declines
  (CRACK-403) instead of wasting your time.

  The practical exception is WPA3 TRANSITION mode (mixed WPA2/WPA3 for
  compatibility): a client connecting over WPA2 still yields a crackable
  handshake, so those targets proceed via the WPA2 path. Enterprise
  (802.1X) has no PSK to attack and is declined (CRACK-404).

  PMKID (clientless capture)
  --------------------------
  If hcxdumptool is installed, the capture step offers a PMKID option:
  it pulls the PMKID straight from the AP (no client, no deauth), which
  is quieter and works even when nobody's connected. The PMKID is
  cracked through the same path as a handshake (hashcat mode 22000
  handles both). hcxdumptool's CLI is version-specific — these flags
  target the 6.3.x line.

  BURN RECON
  ----------
  python3 ./burnrecon.py

  1. Enter a domain, IP, or company name when prompted
     Examples:  example.com   |   192.168.1.1
  2. Tool automatically runs all recon modules
  3. .txt report saved to burn_report/

  BURN WEB
  --------
  python3 ./burnweb.py

  1. Enter a target URL or domain when prompted
     Examples:  https://example.com   |   example.com
  2. Tool automatically runs all PASSIVE checks: fingerprinting, robots.txt/
     sitemap, exposed-file checks, directory fuzzing, nikto, TLS check
  3. At the end, if parameterized URLs/forms were found, you get a BIG
     warning and are asked to type an exact confirmation phrase before
     ANY active exploitation (sqlmap) runs. Press Enter to skip it —
     nothing exploitative runs unless you type the phrase AND then
     confirm a specific target a second time.
  4. .txt report saved to burn_report/ either way

  ONLY type the confirmation phrase if the site owner has given you
  explicit written permission to actively exploit the target.

  BURN REPORT
  -----------
  python3 ./burnreport.py

  1. Lists every report currently in burn_report/, newest first, with
     its source tool, parsed target, and timestamp
  2. Enter comma-separated report numbers to combine, or "all"
  3. Writes a combined .txt report merging every selected report's
     findings and diagnostics, each tagged with its source tool and
     sorted by severity

  Doesn't scan anything and doesn't require a target — it only reads
  reports that already exist. burncracker.py reports (WiFi results)
  are included for their diagnostics but don't have a findings list to
  merge in, since a crack attempt is a single pass/fail result rather
  than a list of findings.

================================================================================
  REPORTS
================================================================================

  All reports are saved to the burn_report/ folder inside burn_suite/.
  Reports are timestamped so they never overwrite each other. All reports
  are plain, readable .txt files — no browser needed.

  Report types:
    burnscan_YYYYMMDD_HHMMSS.txt      —  Burn Scanner results
    burncracker_YYYYMMDD_HHMMSS.txt   —  Burn Crack results
    burnrecon_YYYYMMDD_HHMMSS.txt     —  Burn Recon results (.json with -o json/both)
    burnweb_YYYYMMDD_HHMMSS.txt       —  Burn Web results
    burnreport_YYYYMMDD_HHMMSS.txt    —  Burn Report combined results

  View a report:
    cat burn_report/filename.txt

  Navigate to your reports folder:
    cd ~/burn_suite/burn_report
    ls

================================================================================
  DIAGNOSTICS & ERROR CODES
================================================================================

  Every tool logs a short code (e.g. SCAN-401, CRACK-302, RECON-203,
  WEB-406) to the console whenever a check fails, gets skipped, or comes
  back empty — and every report ends with a DIAGNOSTICS section listing
  every code that fired during that run.

  This matters because "no vulnerabilities found" and "we couldn't check
  for vulnerabilities" are NOT the same thing, and a report that doesn't
  distinguish them can quietly overstate how secure a target is. Each
  code is tagged as either a real negative result (the check ran and
  found nothing — a HARDENED finding worth reporting) or inconclusive
  (the check couldn't complete — missing tool, timeout, rate limit,
  connectivity issue — and should not be read as a security conclusion
  either way).

  Full reference: see ERROR_CODES.txt in this folder for what every code
  means, grouped by tool. If a report's only findings are HARDENED codes,
  treat it as real. If INCONCLUSIVE or ENV codes show up, re-run once the
  underlying issue is fixed before trusting that section.

================================================================================
  MANUAL PAGES
================================================================================

  Each tool has a full man(1) page in the man/ folder, same as any
  system command (e.g. "man nmap"). After running "sudo ./install.sh",
  they're installed system-wide and work directly:

    man burnsuite      — overview of the whole toolkit (section 7)
    man burnscanner
    man burncracker
    man burnrecon
    man burnweb
    man burnreport

  install.sh copies man/*.1 to /usr/local/share/man/man1/ and
  man/*.7 to /usr/local/share/man/man7/, then runs "mandb" so they're
  searchable immediately. This step is optional — install.sh skips it
  gracefully (with a note) if the man/ folder isn't present, and every
  other part of the suite works exactly the same without it.

  To read a page without installing anything:

    man ./man/burnscanner.1
    groff -man -Tutf8 ./man/burnsuite.7 | less

================================================================================
  TESTING
================================================================================

  A persisted regression test suite lives in tests/ (Python's stdlib
  unittest — no extra dependencies to install). It covers the
  diagnostics system for all five tools, including the cases that are
  easy to get subtly wrong: a tool timing out must never be reported
  the same way as that tool running to completion and finding nothing
  clean, a failed crack must never be reported as "password resists
  this wordlist," and so on.

  Run the whole suite:

    python3 -m unittest discover -s tests -p "test_*.py"

  Or use the wrapper script from anywhere in the suite folder:

    ./tests/run_tests.sh

  The tests/ folder is optional — like man/, it isn't required for any
  tool to run. It's there so a future change to one of the scripts can
  be checked against this whole set of "false negative" scenarios in
  seconds instead of by hand.

================================================================================
  TIPS & NOTES
================================================================================

  - Always run burnscanner.py and burncracker.py with sudo
  - burnrecon.py, burnweb.py, and burnreport.py do NOT require sudo
  - burncracker.py will not work in a VM without a USB WiFi adapter passthrough
  - burncracker.py picks its wireless adapter interactively each run (no
    config edit needed) — great for dedicating a USB adapter (e.g. an
    Alfa AWUS036ACH/ACM) to WiFi work while your main card stays online.
    If your adapter doesn't show up in the list, check "iw dev" yourself
    to confirm the system sees it.
  - Shodan free tier is limited to 100 queries/month — use sparingly
  - rockyou.txt may be gzipped on fresh installs — burncracker.py handles
    decompression automatically
  - burnweb.py NEVER runs sqlmap automatically — it always requires typing
    an exact confirmation phrase first, even if candidate URLs are found
  - CVE lookups in burnscanner.py are cached per product+version for the
    life of a scan, so the same software showing up on multiple hosts/
    ports doesn't repeat the NVD rate-limit wait
  - burnweb.py's exposed-file and fallback directory-fuzz checks run
    several requests concurrently (MAX_WORKERS, default 8) for speed
  - Run "sudo apt update && sudo apt upgrade -y" regularly to keep
    Kali tools current
  - On some Kali installs, sudo's secure_path excludes /usr/local/bin
    (a hardening default, not a bug). If "sudo burnscanner" or
    "sudo burncracker" says "command not found" even after a successful
    install, use the full path instead:
      sudo python3 /path/to/burnsuite/burnscanner.py
      sudo python3 /path/to/burnsuite/burncracker.py
    install.sh detects this and prints a note if it applies to your
    system. burnrecon.py/burnweb.py/burnreport.py aren't affected since
    they don't need sudo.

================================================================================
  FOLDER STRUCTURE
================================================================================

  burn_suite/
  ├── README.txt         This file
  ├── ERROR_CODES.txt    Reference for every diagnostic code the tools log
  ├── install.sh         Dependency installer, command + man page registration
  ├── burnscanner.py     Network vulnerability scanner
  ├── burncracker.py     WiFi handshake cracker
  ├── burnrecon.py       OSINT reconnaissance tool
  ├── burnweb.py         Web application recon & weakness scanner
  ├── burnreport.py      Cross-tool report combiner
  ├── shodan_api.txt     Your Shodan API key (optional, read by burnrecon.py)
  ├── man/               Manual pages (optional — see MANUAL PAGES above)
  │   ├── burnsuite.7
  │   ├── burnscanner.1
  │   ├── burncracker.1
  │   ├── burnrecon.1
  │   ├── burnweb.1
  │   └── burnreport.1
  ├── tests/             Regression test suite (optional — see TESTING above)
  │   ├── run_tests.sh
  │   └── test_*.py
  └── burn_report/       All generated reports (auto-created)
      ├── burnscan_*.txt
      ├── burncracker_*.txt
      ├── burnrecon_*.txt
      ├── burnweb_*.txt
      └── burnreport_*.txt

================================================================================
  FOR AUTHORIZED USE ONLY
================================================================================
