#!/bin/bash

# ================================================================
#  BURN SUITE — Install Script
#  Run once to register all Burn Suite tools as system commands
#  Usage: sudo ./install.sh
# ================================================================

# Must run as root
if [ "$EUID" -ne 0 ]; then
    echo ""
    echo "  [!] Please run as root: sudo ./install.sh"
    echo ""
    exit 1
fi

echo ""
echo "  ██████╗ ██╗   ██╗██████╗ ███╗   ██╗"
echo "  ██╔══██╗██║   ██║██╔══██╗████╗  ██║"
echo "  ██████╔╝██║   ██║██████╔╝██╔██╗ ██║"
echo "  ██╔══██╗██║   ██║██╔══██╗██║╚██╗██║"
echo "  ██████╔╝╚██████╔╝██║  ██║██║ ╚████║"
echo "  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝"
echo ""
echo "  BURN SUITE v1.0 — Installer"
echo "  =============================="
echo ""

# Get the directory this script lives in
SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "  [*] Burn Suite directory: $SUITE_DIR"
echo ""

# ----------------------------------------------------------------
# CHECK SCRIPTS EXIST
# ----------------------------------------------------------------
MISSING=0
for script in burnscanner.py burncracker.py burnrecon.py burnweb.py burnreport.py; do
    if [ ! -f "$SUITE_DIR/$script" ]; then
        echo "  [!] Missing: $script — make sure all tools are in the same folder as this installer."
        MISSING=1
    fi
done

if [ "$MISSING" -eq 1 ]; then
    echo ""
    echo "  [!] Install aborted. Fix missing files and try again."
    echo ""
    exit 1
fi

# ----------------------------------------------------------------
# INSTALL DEPENDENCIES  (multi-distro, best-effort)
# ----------------------------------------------------------------
# Debian/Kali is the primary target, but detect other package managers too.
# Packages are installed ONE AT A TIME so a name that doesn't exist on a
# given distro (e.g. ieee-data outside Debian) is skipped, not fatal — the
# tool's own preflight (python3 ./burncracker.py --check) is the real gate.
echo "  [*] Installing dependencies..."
echo ""

# Detect a supported package manager (apt-get preferred over apt for scripts).
PM=""
for c in apt-get dnf pacman zypper apk; do
    command -v "$c" >/dev/null 2>&1 && { PM="$c"; break; }
done

# Per-manager: a human label, the DB-refresh command, the install command,
# and the package list (names differ across distros).
case "$PM" in
    apt-get) PM_LABEL="apt (Debian/Ubuntu/Kali/Parrot)"
             UPDATE=(apt-get update -qq); INSTALL=(apt-get install -y)
             PKGS=(iw whois dnsutils nmap aircrack-ng hashcat hcxtools hcxdumptool ieee-data sslscan python3-requests python3-cryptography) ;;
    dnf)     PM_LABEL="dnf (Fedora/RHEL)"
             UPDATE=(true); INSTALL=(dnf install -y)
             PKGS=(iw whois bind-utils nmap aircrack-ng hashcat hcxtools hcxdumptool sslscan python3-requests python3-cryptography) ;;
    pacman)  PM_LABEL="pacman (Arch) — hcxtools/hcxdumptool may be AUR-only"
             UPDATE=(pacman -Sy --noconfirm); INSTALL=(pacman -S --needed --noconfirm)
             PKGS=(iw whois bind nmap aircrack-ng hashcat sslscan python-requests python-cryptography) ;;
    zypper)  PM_LABEL="zypper (openSUSE)"
             UPDATE=(true); INSTALL=(zypper --non-interactive install)
             PKGS=(iw whois bind-utils nmap aircrack-ng hashcat hcxtools hcxdumptool sslscan python3-requests python3-cryptography) ;;
    apk)     PM_LABEL="apk (Alpine)"
             UPDATE=(apk update); INSTALL=(apk add)
             PKGS=(iw whois bind-tools nmap aircrack-ng hashcat sslscan py3-requests py3-cryptography) ;;
esac

if [ -z "$PM" ]; then
    echo "  [!] No supported package manager found (apt/dnf/pacman/zypper/apk)."
    echo "  [!] Install the dependencies manually, then verify with:"
    echo "         python3 ./burncracker.py --check"
    echo ""
    echo "      Required : aircrack-ng, iw"
    echo "      Optional : hashcat, hcxtools, hcxdumptool, ieee-data (OUI database)"
    echo "      Suite    : whois, dnsutils/bind-utils, nmap, sslscan, python3-requests, python3-cryptography"
    echo ""
else
    echo "  [*] Detected $PM_LABEL"
    "${UPDATE[@]}" >/dev/null 2>&1
    ok=0; skipped=""
    for pkg in "${PKGS[@]}"; do
        if "${INSTALL[@]}" "$pkg" >/dev/null 2>&1; then
            ok=$((ok + 1))
        else
            skipped="$skipped $pkg"
        fi
    done
    echo "  [+] Installed $ok/${#PKGS[@]} packages."
    if [ -n "$skipped" ]; then
        echo "  [~] Not available via this package manager (skipped):$skipped"
        echo "  [~] They may live in a separate repo (AUR/COPR/…) or be named"
        echo "  [~] differently. The tool degrades gracefully — confirm what's"
        echo "  [~] actually present with: python3 ./burncracker.py --check"
    fi
    echo ""
fi

# ----------------------------------------------------------------
# MAKE SCRIPTS EXECUTABLE
# ----------------------------------------------------------------
echo "  [*] Setting permissions..."
chmod +x "$SUITE_DIR/burnscanner.py"
chmod +x "$SUITE_DIR/burncracker.py"
chmod +x "$SUITE_DIR/burnrecon.py"
chmod +x "$SUITE_DIR/burnweb.py"
chmod +x "$SUITE_DIR/burnreport.py"
echo "  [+] Permissions set."
echo ""

# ----------------------------------------------------------------
# CLEAN UP ANY PRIOR INSTALL
# Makes a re-run fully idempotent: removes command symlinks (including
# older/renamed names), stale suite man pages, and bytecode caches left
# by earlier installs — so moving the suite between machines with
# different versions can't leave conflicting leftovers behind.
# ----------------------------------------------------------------
echo "  [*] Clearing any previous Burn Suite install..."

# Every command name the suite has EVER registered (current + legacy).
# Add old names here if you ever rename a command again.
LEGACY_CMDS=(burnscanner burncracker burnrecon burnweb burnreport burnscan burncrack)
for cmd in "${LEGACY_CMDS[@]}"; do
    old="/usr/local/bin/$cmd"
    if [ -L "$old" ]; then
        rm -f "$old" && echo "  [+] Removed old command: $cmd"
    elif [ -e "$old" ]; then
        # A real file (not our symlink) — don't clobber something we didn't create.
        echo "  [!] $old exists but is not a symlink — leaving it untouched."
    fi
done

# Suite man pages (stable names) — remove so any renamed/dropped page can't linger.
for m in burnscanner.1 burncracker.1 burnrecon.1 burnweb.1 burnreport.1; do
    rm -f "/usr/local/share/man/man1/$m" 2>/dev/null
done
rm -f "/usr/local/share/man/man7/burnsuite.7" 2>/dev/null

# Bytecode caches — stale .pyc from a different Python/version can be confusing.
find "$SUITE_DIR" -type d -name "__pycache__" -prune -exec rm -rf {} + 2>/dev/null

echo "  [+] Previous install cleared."
echo ""

# ----------------------------------------------------------------
# CREATE SYMLINKS IN /usr/local/bin
# ----------------------------------------------------------------
echo "  [*] Registering system commands..."

declare -A TOOLS=(
    ["burnscanner"]="burnscanner.py"
    ["burncracker"]="burncracker.py"
    ["burnrecon"]="burnrecon.py"
    ["burnweb"]="burnweb.py"
    ["burnreport"]="burnreport.py"
)

for cmd in "${!TOOLS[@]}"; do
    script="${TOOLS[$cmd]}"
    target="/usr/local/bin/$cmd"

    if ln -sf "$SUITE_DIR/$script" "$target" 2>/dev/null; then
        echo "  [+] Registered: $cmd -> $SUITE_DIR/$script"
    else
        echo "  [!] Failed to register: $cmd -> $target (path may be a non-symlink file you don't own)"
    fi
done

echo ""

# ----------------------------------------------------------------
# INSTALL MAN PAGES
# ----------------------------------------------------------------
if [ -d "$SUITE_DIR/man" ]; then
    echo "  [*] Installing man pages..."
    mkdir -p /usr/local/share/man/man1 /usr/local/share/man/man7
    cp "$SUITE_DIR/man/"*.1 /usr/local/share/man/man1/ 2>/dev/null
    cp "$SUITE_DIR/man/"*.7 /usr/local/share/man/man7/ 2>/dev/null
    if command -v mandb > /dev/null 2>&1; then
        mandb -q > /dev/null 2>&1
    fi
    MAN_INSTALLED=1
    echo "  [+] Man pages installed."
else
    MAN_INSTALLED=0
    echo "  [~] man/ folder not found — skipping man page installation (optional)."
fi

echo ""

# ----------------------------------------------------------------
# CREATE BURN REPORT DIRECTORY
# ----------------------------------------------------------------
REPORT_DIR="$SUITE_DIR/burn_report"
if [ ! -d "$REPORT_DIR" ]; then
    mkdir -p "$REPORT_DIR"
    echo "  [+] Created report directory: $REPORT_DIR"
else
    echo "  [+] Report directory already exists: $REPORT_DIR"
fi

echo ""

# ----------------------------------------------------------------
# VERIFY
# ----------------------------------------------------------------
# Checks the symlink itself exists, NOT "command -v" / PATH lookup. Some
# distros' sudo (Kali included) sets a secure_path for the sudo'd process
# that excludes /usr/local/bin, which would make every command -v check
# here fail even though registration above succeeded perfectly — this
# verify step should only judge whether install.sh did ITS OWN job, not
# whether the current shell's PATH happens to be able to find the result.
echo "  [*] Verifying installation..."
echo ""
ALL_OK=1
for cmd in burnscanner burncracker burnrecon burnweb burnreport; do
    if [ -e "/usr/local/bin/$cmd" ]; then
        echo "  [+] $cmd — OK"
    else
        echo "  [!] $cmd — FAILED"
        ALL_OK=0
    fi
done

echo ""

# Separately: warn if /usr/local/bin won't actually be reachable when the
# user types these commands, since that's a real (if different) problem.
if [[ ":$PATH:" != *":/usr/local/bin:"* ]]; then
    echo "  [~] NOTE: /usr/local/bin is not in PATH under sudo on this system."
    echo "  [~] This is common on Kali — sudo's secure_path intentionally"
    echo "  [~] excludes /usr/local/*. The commands above were still"
    echo "  [~] installed correctly, but 'sudo burnscanner' / 'sudo burncracker'"
    echo "  [~] will say \"command not found\". Use the full path instead:"
    echo "  [~]   sudo python3 $SUITE_DIR/burnscanner.py"
    echo "  [~]   sudo python3 $SUITE_DIR/burncracker.py"
    echo "  [~] (burnrecon/burnweb/burnreport don't need sudo, so plain"
    echo "  [~]  'burnrecon' etc. is unaffected by this.)"
    echo ""
fi

if [ "$ALL_OK" -eq 1 ]; then
    echo "  =============================="
    echo "  [+] BURN SUITE INSTALLED"
    echo "  =============================="
    echo ""
    echo "  Available commands:"
    echo ""
    echo "    sudo burnscanner —  Network vulnerability scanner"
    echo "    sudo burncracker —  WiFi handshake cracker"
    echo "         burnrecon   —  OSINT reconnaissance tool"
    echo "         burnweb     —  Web application recon & weakness scanner"
    echo "         burnreport  —  Cross-tool report combiner"
    echo ""
    if [ "$MAN_INSTALLED" -eq 1 ]; then
        echo "  Manual pages installed — try: man burnsuite"
        echo ""
    fi
    echo "  Reports saved to: $REPORT_DIR"
    echo ""
else
    echo "  [!] One or more commands are missing from /usr/local/bin."
    echo "  [!] Check the 'Registering system commands' output above for"
    echo "  [!] the specific failure, then try running the script again."
    echo ""
fi
