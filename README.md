# Burn Suite

A small collection of standalone Python security tools for **authorized** reconnaissance, scanning, and reporting on Linux (built and tested on Kali/Parrot).

> ⚠️ **FOR AUTHORIZED TESTING ONLY.** Only use these tools against systems, domains, and networks that you own or have **explicit written permission** to test. Unauthorized scanning, cracking, or exploitation is illegal in most jurisdictions. You are solely responsible for how you use this software. It is provided with **no warranty** (see [LICENSE](LICENSE)).

Each tool is a self-contained script — you can copy any one of them out and run it on its own.

## Tools

| Command | Script | What it does |
|---|---|---|
| `burnrecon` | `burnrecon.py` | Passive-by-default OSINT recon (DNS, WHOIS, subdomains, TLS, email auth, Shodan, and more). `--active` / `--aggressive` add direct probing. |
| `burnscanner` | `burnscanner.py` | Automated network vulnerability scanner. |
| `burnweb` | `burnweb.py` | Web-app recon & weakness scanner (passive/discovery by default). |
| `burncracker` | `burncracker.py` | WiFi handshake capture & password cracking. |
| `burnreport` | `burnreport.py` | Combines the other tools' reports into one summary. |

## Requirements

- Python 3
- `sudo apt install whois dnsutils nmap` (plus `nikto gobuster sslscan` for `burnweb`, and `aircrack-ng hashcat` for `burncracker`)
- `pip3 install requests cryptography` (`cryptography` is optional — it enables full TLS certificate parsing)

The installer handles these for you.

## Install

```bash
git clone https://github.com/<your-username>/burn-suite.git
cd burn-suite
sudo ./install.sh
```

`install.sh` installs dependencies, registers the commands in `/usr/local/bin`, installs the man pages, and clears any previous install first (so re-running it is safe and fully overrides an older copy). You can also just run any tool directly without installing: `python3 ./burnrecon.py`.

## Usage

```bash
# Passive OSINT (default — no packets to the target's own infrastructure)
burnrecon example.com

# Add active probing (HTTP/TLS grab, port scan, zone transfer, takeover checks)
burnrecon example.com --active -o both      # writes both .txt and .json

# Add loud techniques (DNS brute-force, full port scan)
burnrecon example.com --aggressive

# Full help
burnrecon --help
```

Reports are written to `burn_report/`. See the man pages (`man burnrecon`) or [README.txt](README.txt) for the complete manual and the full option list for every tool.

## API keys (optional)

`burnrecon` can use Shodan, Hunter.io, and HaveIBeenPwned if you supply keys. Each is optional and skipped gracefully if absent. Copy the template and paste in your own key:

```bash
cp shodan_api.txt.example shodan_api.txt   # then edit and paste your key
cp hunter_api.txt.example hunter_api.txt
cp hibp_api.txt.example   hibp_api.txt
```

These key files are git-ignored — **never commit your keys.**

## Tests

```bash
python3 -m unittest discover -s tests -p "test_*.py"
```

## Diagnostics

Every skip, failure, or empty result is logged as a `*-NNN` code in the report's DIAGNOSTICS section. See [ERROR_CODES.txt](ERROR_CODES.txt) for what each code means.

## License

GNU General Public License v3.0 or later — see [LICENSE](LICENSE). This is free software: you're welcome to use, study, modify, and redistribute it under the terms of the GPL.
