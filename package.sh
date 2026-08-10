#!/bin/bash
# ================================================================
#  BURN SUITE — Clean Packager
#  Builds a shippable .tar.gz of the suite WITHOUT your personal
#  secrets or generated junk. Use this instead of a raw zip/tar/cp,
#  which would bundle shodan_api.txt (your API key) along with it.
#
#  Usage: ./package.sh   (writes ../burnsuite_<date>.tar.gz)
# ================================================================
set -euo pipefail

SUITE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAME="$(basename "$SUITE_DIR")"
OUT="$(dirname "$SUITE_DIR")/burnsuite_$(date +%Y%m%d_%H%M%S).tar.gz"

# Things that must never ship.
EXCLUDES=(
    "shodan_api.txt"          # personal API keys
    "hunter_api.txt"
    "hibp_api.txt"
    "__pycache__"
    "*.pyc"
    "burn_report"             # generated scan reports (target data)
    ".git"
    ".claude"                 # Claude Code local settings — not part of the suite
    "System Volume Information"
)

tar_args=()
for e in "${EXCLUDES[@]}"; do
    tar_args+=(--exclude="$e")
done

# Archive from the parent so paths are prefixed with the folder name.
tar -czf "$OUT" "${tar_args[@]}" -C "$(dirname "$SUITE_DIR")" "$NAME"

# Safety net: fail loudly if a real key file slipped into the archive.
# (the *.example placeholder templates are fine — they carry no real key.)
if tar -tzf "$OUT" | grep -qE "(^|/)(shodan|hunter|hibp)_api\.txt$"; then
    echo "[!] ABORT: an API key file ended up in the archive — deleting it." >&2
    rm -f "$OUT"
    exit 1
fi

echo "[+] Clean package built: $OUT"
echo "[~] Excluded: your API key, reports, caches, and .git"
echo "[~] Recipients copy shodan_api.txt.example -> shodan_api.txt and add their own key."
