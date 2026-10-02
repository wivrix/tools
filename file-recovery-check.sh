#!/usr/bin/env bash

# file-recovery-check.sh
# Filesystem-level storage remanence check for Linux VPS instances.
#
# IMPORTANT:
# This checks the filesystem/device visible INSIDE the VPS.
# It cannot prove or disprove residual data on the hosting provider's
# underlying physical storage.
#
# For a real cross-tenant test:
#   1. Write a unique canary to VPS A.
#   2. Destroy/release VPS A.
#   3. Provision VPS B.
#   4. Run this scanner on VPS B.
#   5. Search specifically for the canary.

set -uo pipefail

VERSION="3.1"

WORKDIR="$(mktemp -d /tmp/file-recovery-check.XXXXXX)"
REPORT="/tmp/file-recovery-check-$(date +%Y%m%d-%H%M%S).txt"

MAX_FINDINGS=500
MAX_INTERESTING=500

cleanup() {
    rm -rf "$WORKDIR"
}

trap cleanup EXIT

line() {
    printf '%*s\n' 72 '' | tr ' ' '='
}

section() {
    echo
    line
    echo "$1"
    line
}

human_size() {
    local bytes="$1"

    if command -v numfmt >/dev/null 2>&1; then
        numfmt --to=iec --suffix=B "$bytes"
    else
        echo "${bytes} bytes"
    fi
}

fail() {
    echo
    echo "[ERROR] $1"
    echo
    exit 1
}

# ----------------------------------------------------------------------
# Basic checks
# ----------------------------------------------------------------------

if [ "$(id -u)" -ne 0 ]; then
    fail "This script must be run as root."
fi

if [ ! -f /etc/os-release ]; then
    fail "Cannot determine Linux distribution."
fi

# shellcheck disable=SC1091
. /etc/os-release

echo
line
echo "       FILE RECOVERY / STORAGE REMANENCE CHECK"
echo "                         v$VERSION"
line
echo
echo "Host       : $(hostname)"
echo "Date       : $(date)"
echo "Kernel     : $(uname -r)"
echo "OS         : ${PRETTY_NAME:-Unknown}"
echo "Report     : $REPORT"

# ----------------------------------------------------------------------
# Dependencies
# ----------------------------------------------------------------------

section "[1] Checking dependencies"

install_sleuthkit() {
    case "${ID:-}" in
        ubuntu|debian)
            echo "[INFO] Installing Sleuth Kit using apt..."

            if ! apt-get update -qq; then
                return 1
            fi

            apt-get install -y -qq sleuthkit
            ;;

        fedora|rhel|centos|rocky|almalinux)
            if command -v dnf >/dev/null 2>&1; then
                echo "[INFO] Installing Sleuth Kit using dnf..."
                dnf install -y sleuthkit

            elif command -v yum >/dev/null 2>&1; then
                echo "[INFO] Installing Sleuth Kit using yum..."
                yum install -y sleuthkit

            else
                return 1
            fi
            ;;

        arch)
            echo "[INFO] Installing Sleuth Kit using pacman..."
            pacman -Sy --noconfirm sleuthkit
            ;;

        *)
            echo "[ERROR] Automatic Sleuth Kit installation is not supported for:"
            echo "        ${PRETTY_NAME:-${ID:-unknown}}"
            return 1
            ;;
    esac
}

if ! command -v blkls >/dev/null 2>&1 ||
   ! command -v fls >/dev/null 2>&1; then

    echo "[INFO] Sleuth Kit is not installed."
    echo "[INFO] Attempting automatic installation..."

    if ! install_sleuthkit; then
        fail "Could not install Sleuth Kit automatically."
    fi
fi

REQUIRED_COMMANDS="
blkls
fls
lsblk
findmnt
df
strings
grep
awk
sed
sort
wc
mktemp
"

for cmd in $REQUIRED_COMMANDS; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        fail "Required command not found: $cmd"
    fi
done

echo "[OK] Required dependencies are available."

# ----------------------------------------------------------------------
# Storage / filesystem detection
# ----------------------------------------------------------------------

section "[2] Detecting root filesystem"

ROOT_SOURCE="$(findmnt -n -o SOURCE / 2>/dev/null || true)"
ROOT_FSTYPE="$(findmnt -n -o FSTYPE / 2>/dev/null || true)"

if [ -z "$ROOT_SOURCE" ]; then
    fail "Could not determine the root filesystem source."
fi

echo "Root source : $ROOT_SOURCE"
echo "Filesystem  : ${ROOT_FSTYPE:-unknown}"

echo
echo "Block devices:"

lsblk \
    -e7 \
    -o NAME,PATH,SIZE,TYPE,FSTYPE,MOUNTPOINTS \
    2>/dev/null || true

# ----------------------------------------------------------------------
# Validate filesystem source
# ----------------------------------------------------------------------

case "$ROOT_SOURCE" in
    /dev/*)
        ;;
    *)
        echo
        echo "[WARNING] Root filesystem source is not a block device:"
        echo "          $ROOT_SOURCE"
        echo
        echo "This commonly happens with containers/overlay filesystems."
        echo "A block-level unallocated-space scan cannot be performed."
        echo
        echo "[RESULT] BLOCK-LEVEL SCAN NOT POSSIBLE"
        echo
        echo "Report: $REPORT"

        {
            echo "FILE RECOVERY / STORAGE REMANENCE CHECK"
            echo "Version: $VERSION"
            echo "Date: $(date)"
            echo "Host: $(hostname)"
            echo "Kernel: $(uname -r)"
            echo "OS: ${PRETTY_NAME:-Unknown}"
            echo
            echo "Root source: $ROOT_SOURCE"
            echo "Filesystem: ${ROOT_FSTYPE:-unknown}"
            echo
            echo "Result: Block-level scan not possible."
            echo "Reason: Root source is not a block device."
        } > "$REPORT"

        exit 0
        ;;
esac

# ----------------------------------------------------------------------
# Filesystem information
# ----------------------------------------------------------------------

case "$ROOT_FSTYPE" in
    ext2|ext3|ext4)
        echo "[OK] EXT filesystem detected."
        ;;

    xfs)
        echo "[WARNING] XFS detected."
        echo "[WARNING] Deleted-file analysis may be limited."
        ;;

    btrfs)
        echo "[WARNING] Btrfs detected."
        echo "[WARNING] Copy-on-write/snapshots can affect interpretation."
        ;;

    zfs)
        echo "[WARNING] ZFS detected."
        echo "[WARNING] This scanner is not designed for ZFS internals."
        ;;

    *)
        echo "[WARNING] Filesystem '$ROOT_FSTYPE' may not be fully supported."
        ;;
esac

# ----------------------------------------------------------------------
# Current filesystem usage
# ----------------------------------------------------------------------

section "[3] Current filesystem usage"

df -h "$ROOT_SOURCE" 2>/dev/null || df -h /

# ----------------------------------------------------------------------
# Deleted files still held open
# ----------------------------------------------------------------------

section "[4] Deleted files still held open"

if command -v lsof >/dev/null 2>&1; then

    DELETED_OPEN="$(lsof +L1 2>/dev/null || true)"

    if [ -n "$DELETED_OPEN" ]; then
        echo "$DELETED_OPEN"
    else
        echo "None detected."
    fi

else
    echo "[INFO] lsof is not installed."
    echo "[INFO] Skipping deleted-open-file check."
fi

# ----------------------------------------------------------------------
# Deleted filesystem entries
#
# fls:
#   -r = recursive
#   -d = deleted entries
#   -l = long format
#
# We consume the complete output but save only the first MAX_FINDINGS
# entries so a large filesystem does not create a huge report.
# ----------------------------------------------------------------------

section "[5] Deleted filesystem entries"

DELETED_FILE="$WORKDIR/deleted.txt"
DELETED_ERROR="$WORKDIR/fls-error.txt"
DELETED_COUNT=0

if fls -r -d -l "$ROOT_SOURCE" 2>"$DELETED_ERROR" |
    awk -v max="$MAX_FINDINGS" -v out="$DELETED_FILE" '
        {
            count++

            if (count <= max)
                print $0 > out
        }

        END {
            print count
        }
    ' > "$WORKDIR/deleted-count.txt"; then

    DELETED_COUNT="$(cat "$WORKDIR/deleted-count.txt" 2>/dev/null || echo 0)"
else
    echo "[WARNING] fls could not complete successfully."
    DELETED_COUNT=0
fi

case "$DELETED_COUNT" in
    ''|*[!0-9]*)
        DELETED_COUNT=0
        ;;
esac

if [ "$DELETED_COUNT" -gt 0 ]; then

    echo "Deleted filesystem entries detected: $DELETED_COUNT"

    if [ "$DELETED_COUNT" -gt "$MAX_FINDINGS" ]; then
        echo "(Only the first $MAX_FINDINGS are shown.)"
    fi

    echo
    cat "$DELETED_FILE" 2>/dev/null || true

else
    echo "No deleted filesystem entries were reported."
fi

if [ -s "$DELETED_ERROR" ]; then
    echo
    echo "[INFO] fls reported:"
    cat "$DELETED_ERROR"
fi

# ----------------------------------------------------------------------
# Unallocated filesystem data
#
# blkls outputs unallocated filesystem data to stdout.
#
# IMPORTANT:
# We NEVER redirect this stream into a large file.
# ----------------------------------------------------------------------

section "[6] Measuring unallocated filesystem data"

BLKLS_ERROR="$WORKDIR/blkls-error.txt"

echo "Device: $ROOT_SOURCE"
echo
echo "[INFO] Reading unallocated filesystem data..."
echo "[INFO] No unallocated-data image will be created."
echo "[INFO] This is a read-only operation."
echo

UNALLOC_SIZE="$(
    blkls "$ROOT_SOURCE" 2>"$BLKLS_ERROR" |
    wc -c
)"

if [ -z "$UNALLOC_SIZE" ]; then
    UNALLOC_SIZE=0
fi

case "$UNALLOC_SIZE" in
    ''|*[!0-9]*)
        UNALLOC_SIZE=0
        ;;
esac

if [ -s "$BLKLS_ERROR" ]; then
    echo "[WARNING] blkls reported:"
    cat "$BLKLS_ERROR"
    echo
fi

echo "Unallocated data stream: $(human_size "$UNALLOC_SIZE")"

if [ "$UNALLOC_SIZE" -eq 0 ]; then
    echo
    echo "[INFO] No unallocated filesystem data was exposed."
fi

# ----------------------------------------------------------------------
# Readable strings
#
# blkls is streamed directly into strings.
# Only the first MAX_FINDINGS strings are stored.
# The counter still counts all strings processed.
# ----------------------------------------------------------------------

section "[7] Searching readable strings"

STRINGS_FILE="$WORKDIR/strings.txt"
STRING_COUNT=0

if blkls "$ROOT_SOURCE" 2>/dev/null |
    strings -a -t d -n 6 2>/dev/null |
    awk -v max="$MAX_FINDINGS" -v out="$STRINGS_FILE" '
        {
            count++

            if (count <= max)
                print $0 > out
        }

        END {
            print count
        }
    ' > "$WORKDIR/string-count.txt"; then

    STRING_COUNT="$(cat "$WORKDIR/string-count.txt" 2>/dev/null || echo 0)"
else
    echo "[WARNING] The unallocated-data string scan did not complete cleanly."
    STRING_COUNT=0
fi

case "$STRING_COUNT" in
    ''|*[!0-9]*)
        STRING_COUNT=0
        ;;
esac

echo "Readable string records processed: $STRING_COUNT"

if [ "$STRING_COUNT" -gt "$MAX_FINDINGS" ]; then
    echo "(Only the first $MAX_FINDINGS are retained for further analysis.)"
fi

# ----------------------------------------------------------------------
# Filename-like strings
# ----------------------------------------------------------------------

section "[8] Searching filename-like remnants"

FILENAME_FILE="$WORKDIR/filenames.txt"

grep -Eai \
'(^|[[:space:]/])[A-Za-z0-9._@+/-]+\.(txt|log|conf|cfg|ini|json|xml|yaml|yml|csv|sql|db|sqlite|sqlite3|jpg|jpeg|png|gif|webp|bmp|pdf|doc|docx|xls|xlsx|ppt|pptx|zip|tar|gz|tgz|bz2|xz|7z|rar|php|html|htm|js|ts|jsx|tsx|py|rb|go|java|c|cpp|h|hpp|sh|bash|env|key|pem|crt|cer|bak|old|tmp)([^A-Za-z0-9._-]|$)' \
"$STRINGS_FILE" 2>/dev/null |
sed -E 's/^[[:space:]]*[0-9]+:[[:space:]]*//' |
sort -u |
head -n "$MAX_FINDINGS" > "$FILENAME_FILE" || true

FILENAME_COUNT="$(wc -l < "$FILENAME_FILE" 2>/dev/null || echo 0)"

case "$FILENAME_COUNT" in
    ''|*[!0-9]*)
        FILENAME_COUNT=0
        ;;
esac

if [ "$FILENAME_COUNT" -gt 0 ]; then

    echo "Filename-like candidates retained: $FILENAME_COUNT"

    if [ "$FILENAME_COUNT" -ge "$MAX_FINDINGS" ]; then
        echo "(Output capped at $MAX_FINDINGS.)"
    fi

    echo
    cat "$FILENAME_FILE"

else
    echo "No obvious filename-like remnants found."
fi

# ----------------------------------------------------------------------
# Interesting text
# ----------------------------------------------------------------------

section "[9] Searching interesting text"

INTERESTING_FILE="$WORKDIR/interesting.txt"

grep -Eai \
'(password|passwd|secret|api[_-]?key|authorization|bearer|private[_-]?key|database|mysql|postgres|mongodb|redis|BEGIN [A-Z ]+ KEY|/home/|/root/|/var/www/|/etc/|/opt/|/srv/|\.ssh/|docker|kubernetes)' \
"$STRINGS_FILE" 2>/dev/null |
sort -u |
head -n "$MAX_INTERESTING" > "$INTERESTING_FILE" || true

INTERESTING_COUNT="$(wc -l < "$INTERESTING_FILE" 2>/dev/null || echo 0)"

case "$INTERESTING_COUNT" in
    ''|*[!0-9]*)
        INTERESTING_COUNT=0
        ;;
esac

if [ "$INTERESTING_COUNT" -gt 0 ]; then

    echo "Interesting-text candidates retained: $INTERESTING_COUNT"

    if [ "$INTERESTING_COUNT" -ge "$MAX_INTERESTING" ]; then
        echo "(Output capped at $MAX_INTERESTING.)"
    fi

    echo
    cat "$INTERESTING_FILE"

else
    echo "No obvious interesting-text remnants found."
fi

# ----------------------------------------------------------------------
# Final result
# ----------------------------------------------------------------------

section "[10] Result"

echo "Root source              : $ROOT_SOURCE"
echo "Filesystem               : ${ROOT_FSTYPE:-unknown}"
echo "Unallocated data         : $(human_size "$UNALLOC_SIZE")"
echo "Deleted entries          : $DELETED_COUNT"
echo "Readable string records  : $STRING_COUNT"
echo "Filename candidates      : $FILENAME_COUNT"
echo "Interesting text         : $INTERESTING_COUNT"
echo

if [ "$DELETED_COUNT" -gt 0 ] ||
   [ "$FILENAME_COUNT" -gt 0 ] ||
   [ "$INTERESTING_COUNT" -gt 0 ]; then

    echo "RESULT: POTENTIAL RESIDUAL DATA DETECTED"
    echo
    echo "The filesystem exposed deleted entries and/or"
    echo "readable data in unallocated filesystem space."
    echo
    echo "This is NOT proof of cross-tenant data leakage."

else

    echo "RESULT: NO OBVIOUS RECOVERABLE REMNANTS DETECTED"
    echo
    echo "No obvious deleted entries or useful readable strings"
    echo "were identified by this filesystem-level scan."
fi

echo
echo "LIMITATIONS:"
echo
echo "1. This scanner only sees storage exposed to this VPS."
echo "2. It cannot inspect provider-side physical storage."
echo "3. It cannot identify the previous owner of residual data."
echo "4. A clean result does not prove physical secure erasure."
echo "5. A positive result does not prove cross-tenant leakage."
echo "6. Live filesystem analysis can produce incomplete/inconsistent results."
echo
echo "For a true cross-tenant test:"
echo "  VPS A -> write unique canary -> destroy VPS A"
echo "  VPS B -> search for exact canary"
echo
echo "Report: $REPORT"

# ----------------------------------------------------------------------
# Save concise report
# ----------------------------------------------------------------------

{
    echo "FILE RECOVERY / STORAGE REMANENCE CHECK"
    echo "Version: $VERSION"
    echo "Date: $(date)"
    echo "Host: $(hostname)"
    echo "Kernel: $(uname -r)"
    echo "OS: ${PRETTY_NAME:-Unknown}"
    echo
    echo "Root source: $ROOT_SOURCE"
    echo "Filesystem: ${ROOT_FSTYPE:-unknown}"
    echo
    echo "Unallocated data: $UNALLOC_SIZE bytes"
    echo "Deleted entries: $DELETED_COUNT"
    echo "Readable string records: $STRING_COUNT"
    echo "Filename candidates retained: $FILENAME_COUNT"
    echo "Interesting text candidates retained: $INTERESTING_COUNT"
    echo
    if [ "$DELETED_COUNT" -gt 0 ] ||
       [ "$FILENAME_COUNT" -gt 0 ] ||
       [ "$INTERESTING_COUNT" -gt 0 ]; then

        echo "Result: Potential residual data detected."

    else

        echo "Result: No obvious recoverable remnants detected."
    fi

    echo
    echo "This is a filesystem-level test."
    echo "It does not establish previous ownership or cross-tenant leakage."

} > "$REPORT"

echo
line
echo "Scan complete."
echo "Report saved to:"
echo "$REPORT"
line
