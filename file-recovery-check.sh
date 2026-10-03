#!/usr/bin/env bash

# file-recovery-check.sh
# General Linux deleted-file and storage recovery check.

set -uo pipefail

VERSION="4.1"
MAX_FINDINGS=500
MAX_INTERESTING=500

WORKDIR="$(mktemp -d /tmp/file-recovery-check.XXXXXX)"
REPORT="/tmp/file-recovery-check-$(date +%Y%m%d-%H%M%S).txt"

ROOT_SOURCE=""
ROOT_FSTYPE=""
SCAN_SOURCE=""
SCAN_FSTYPE=""

DELETED_COUNT=0
STRING_COUNT=0
FILENAME_COUNT=0
INTERESTING_COUNT=0
UNALLOC_SIZE=0

cleanup() {
    rm -rf "$WORKDIR"
}

trap cleanup EXIT

separator() {
    printf '%*s\n' 72 '' | tr ' ' '='
}

section() {
    echo
    separator
    echo "$1"
    separator
}

human_size() {
    if command -v numfmt >/dev/null 2>&1; then
        numfmt --to=iec --suffix=B "$1"
    else
        echo "$1 bytes"
    fi
}

error_exit() {
    echo
    echo "[ERROR] $1"
    exit 1
}

# ----------------------------------------------------------------------
# Basic checks
# ----------------------------------------------------------------------

if [ "$(id -u)" -ne 0 ]; then
    error_exit "Run this script as root."
fi

if [ ! -r /etc/os-release ]; then
    error_exit "Cannot read /etc/os-release."
fi

# shellcheck disable=SC1091
. /etc/os-release

echo
separator
echo "             FILE RECOVERY CHECK"
echo "                     v$VERSION"
separator
echo
echo "Host       : $(hostname)"
echo "Date       : $(date)"
echo "Kernel     : $(uname -r)"
echo "OS         : ${PRETTY_NAME:-Unknown}"
echo "Report     : $REPORT"

# ----------------------------------------------------------------------
# Dependency installation
# ----------------------------------------------------------------------

section "[1] Checking dependencies"

install_sleuthkit() {
    case "${ID:-}" in

        ubuntu|debian)
            echo "[INFO] Installing Sleuth Kit..."
            apt-get update -qq || return 1
            apt-get install -y -qq sleuthkit
            ;;

        fedora|rhel|centos|rocky|almalinux)
            if command -v dnf >/dev/null 2>&1; then
                echo "[INFO] Installing Sleuth Kit..."
                dnf install -y sleuthkit
            elif command -v yum >/dev/null 2>&1; then
                echo "[INFO] Installing Sleuth Kit..."
                yum install -y sleuthkit
            else
                return 1
            fi
            ;;

        arch)
            echo "[INFO] Installing Sleuth Kit..."
            pacman -Sy --noconfirm sleuthkit
            ;;

        *)
            echo "[ERROR] Automatic Sleuth Kit installation is not supported."
            return 1
            ;;
    esac
}

if ! command -v fls >/dev/null 2>&1 ||
   ! command -v blkls >/dev/null 2>&1; then

    echo "[INFO] Sleuth Kit is not installed."
    echo "[INFO] Attempting automatic installation..."

    if ! install_sleuthkit; then
        error_exit "Could not install Sleuth Kit."
    fi
fi

REQUIRED_COMMANDS="
fls
blkls
findmnt
lsblk
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
        error_exit "Required command not found: $cmd"
    fi
done

echo "[OK] Required commands are available."

# ----------------------------------------------------------------------
# Detect root filesystem
# ----------------------------------------------------------------------

section "[2] Detecting root filesystem"

ROOT_SOURCE="$(findmnt -n -o SOURCE / 2>/dev/null || true)"
ROOT_FSTYPE="$(findmnt -n -o FSTYPE / 2>/dev/null || true)"

if [ -z "$ROOT_SOURCE" ]; then
    error_exit "Could not determine the root filesystem."
fi

echo "Root source : $ROOT_SOURCE"
echo "Filesystem  : ${ROOT_FSTYPE:-unknown}"

echo
echo "Block devices:"
lsblk -e7 -o NAME,PATH,SIZE,TYPE,FSTYPE,MOUNTPOINTS 2>/dev/null || true

# ----------------------------------------------------------------------
# Deleted-open-file check
#
# This works independently of the root filesystem type.
# ----------------------------------------------------------------------

section "[3] Deleted files still held open"

DELETED_OPEN="$WORKDIR/deleted-open.txt"

if command -v lsof >/dev/null 2>&1; then
    lsof +L1 2>/dev/null > "$DELETED_OPEN" || true

    if [ -s "$DELETED_OPEN" ]; then
        cat "$DELETED_OPEN"
    else
        echo "None detected."
    fi
else
    echo "[INFO] lsof is not installed."
    echo "[INFO] Skipping this check."
fi

# ----------------------------------------------------------------------
# Determine filesystem that can actually be analyzed.
# ----------------------------------------------------------------------

section "[4] Determining analysis filesystem"

if [ "$ROOT_FSTYPE" = "overlay" ]; then

    echo "[INFO] Root filesystem is overlayfs."
    echo "[INFO] Inspecting overlay mount information."

    OVERLAY_OPTIONS="$(findmnt -n -o OPTIONS / 2>/dev/null || true)"

    UPPER_DIR=""
    LOWER_DIR=""

    # Extract upperdir without embedding shell variables inside awk.
    UPPER_DIR="$(
        printf '%s\n' "$OVERLAY_OPTIONS" |
        tr ',' '\n' |
        sed -n 's/^upperdir=//p' |
        head -n 1
    )"

    LOWER_DIR="$(
        printf '%s\n' "$OVERLAY_OPTIONS" |
        tr ',' '\n' |
        sed -n 's/^lowerdir=//p' |
        head -n 1
    )"

    if [ -n "$UPPER_DIR" ]; then
        echo "Upper directory : $UPPER_DIR"
    else
        echo "Upper directory : not exposed"
    fi

    if [ -n "$LOWER_DIR" ]; then
        echo "Lower directory : $LOWER_DIR"
    else
        echo "Lower directory : not exposed"
    fi

    if [ -n "$UPPER_DIR" ] && [ -d "$UPPER_DIR" ]; then

        UPPER_SOURCE="$(
            findmnt -n -T "$UPPER_DIR" -o SOURCE 2>/dev/null || true
        )"

        UPPER_FSTYPE="$(
            findmnt -n -T "$UPPER_DIR" -o FSTYPE 2>/dev/null || true
        )"

        echo
        echo "Upper source     : ${UPPER_SOURCE:-unknown}"
        echo "Upper filesystem : ${UPPER_FSTYPE:-unknown}"

        if [ -n "$UPPER_SOURCE" ] && [ -b "$UPPER_SOURCE" ]; then
            SCAN_SOURCE="$UPPER_SOURCE"
            SCAN_FSTYPE="$UPPER_FSTYPE"

            echo
            echo "[OK] Accessible block device found for overlay upper layer."
        else
            echo
            echo "[INFO] Overlay upper layer does not expose a directly"
            echo "       accessible block device."
        fi

    else
        echo
        echo "[INFO] Overlay upper directory is not accessible."
    fi

else

    if [ -b "$ROOT_SOURCE" ]; then
        SCAN_SOURCE="$ROOT_SOURCE"
        SCAN_FSTYPE="$ROOT_FSTYPE"
    fi

fi

if [ -n "$SCAN_SOURCE" ]; then
    echo
    echo "Analysis source     : $SCAN_SOURCE"
    echo "Analysis filesystem : ${SCAN_FSTYPE:-unknown}"
else
    echo
    echo "Analysis source     : none"
    echo "Analysis filesystem : unavailable"
fi

# ----------------------------------------------------------------------
# Current disk usage
# ----------------------------------------------------------------------

section "[5] Current filesystem usage"

df -h / 2>/dev/null || true

if [ -n "$SCAN_SOURCE" ]; then
    echo
    df -h "$SCAN_SOURCE" 2>/dev/null || true
fi

# ----------------------------------------------------------------------
# Deleted filesystem entries
# ----------------------------------------------------------------------

section "[6] Deleted filesystem entries"

DELETED_FILE="$WORKDIR/deleted.txt"
DELETED_ERROR="$WORKDIR/fls-error.txt"

if [ -n "$SCAN_SOURCE" ]; then

    fls -r -d -l "$SCAN_SOURCE" 2>"$DELETED_ERROR" |
    awk -v max="$MAX_FINDINGS" -v output="$DELETED_FILE" '
        {
            total++

            if (total <= max) {
                print > output
            }
        }

        END {
            print total
        }
    ' > "$WORKDIR/deleted-count.txt"

    DELETED_COUNT="$(cat "$WORKDIR/deleted-count.txt" 2>/dev/null || echo 0)"

    case "$DELETED_COUNT" in
        ''|*[!0-9]*)
            DELETED_COUNT=0
            ;;
    esac

    if [ "$DELETED_COUNT" -gt 0 ]; then

        echo "Deleted entries detected: $DELETED_COUNT"

        if [ "$DELETED_COUNT" -gt "$MAX_FINDINGS" ]; then
            echo "Only the first $MAX_FINDINGS are displayed."
        fi

        echo
        cat "$DELETED_FILE" 2>/dev/null || true

    else
        echo "No deleted filesystem entries were reported."
    fi

    if [ -s "$DELETED_ERROR" ]; then
        echo
        echo "[INFO] fls messages:"
        cat "$DELETED_ERROR"
    fi

else
    echo "Skipped: no directly accessible filesystem device."
fi

# ----------------------------------------------------------------------
# Unallocated filesystem data
# ----------------------------------------------------------------------

section "[7] Measuring unallocated filesystem data"

BLKLS_ERROR="$WORKDIR/blkls-error.txt"

if [ -n "$SCAN_SOURCE" ]; then

    echo "[INFO] Streaming unallocated filesystem data."
    echo "[INFO] No recovery image will be created."

    UNALLOC_SIZE="$(
        blkls "$SCAN_SOURCE" 2>"$BLKLS_ERROR" |
        wc -c
    )"

    case "$UNALLOC_SIZE" in
        ''|*[!0-9]*)
            UNALLOC_SIZE=0
            ;;
    esac

    echo
    echo "Unallocated data: $(human_size "$UNALLOC_SIZE")"

    if [ -s "$BLKLS_ERROR" ]; then
        echo
        echo "[INFO] blkls messages:"
        cat "$BLKLS_ERROR"
    fi

else
    echo "Skipped: no directly accessible filesystem device."
fi

# ----------------------------------------------------------------------
# Readable strings
# ----------------------------------------------------------------------

section "[8] Searching readable strings"

STRINGS_FILE="$WORKDIR/strings.txt"

if [ -n "$SCAN_SOURCE" ]; then

    blkls "$SCAN_SOURCE" 2>/dev/null |
    strings -a -t d -n 6 2>/dev/null |
    awk -v max="$MAX_FINDINGS" -v output="$STRINGS_FILE" '
        {
            total++

            if (total <= max) {
                print > output
            }
        }

        END {
            print total
        }
    ' > "$WORKDIR/string-count.txt"

    STRING_COUNT="$(cat "$WORKDIR/string-count.txt" 2>/dev/null || echo 0)"

    case "$STRING_COUNT" in
        ''|*[!0-9]*)
            STRING_COUNT=0
            ;;
    esac

    echo "Readable string records processed: $STRING_COUNT"

    if [ "$STRING_COUNT" -gt "$MAX_FINDINGS" ]; then
        echo "Only the first $MAX_FINDINGS are retained."
    fi

else
    echo "Skipped: no directly accessible filesystem device."
fi

# ----------------------------------------------------------------------
# Filename-like remnants
# ----------------------------------------------------------------------

section "[9] Searching filename-like remnants"

FILENAME_FILE="$WORKDIR/filenames.txt"

if [ -s "$STRINGS_FILE" ]; then

    grep -Eai \
    '(^|[[:space:]/])[A-Za-z0-9._@+/-]+\.(txt|log|conf|cfg|ini|json|xml|yaml|yml|csv|sql|db|sqlite|sqlite3|jpg|jpeg|png|gif|webp|bmp|pdf|doc|docx|xls|xlsx|ppt|pptx|zip|tar|gz|tgz|bz2|xz|7z|rar|php|html|htm|js|ts|jsx|tsx|py|rb|go|java|c|cpp|h|hpp|sh|bash|env|key|pem|crt|cer|bak|old|tmp)([^A-Za-z0-9._-]|$)' \
    "$STRINGS_FILE" 2>/dev/null |
    sed -E 's/^[[:space:]]*[0-9]+:[[:space:]]*//' |
    sort -u |
    head -n "$MAX_FINDINGS" > "$FILENAME_FILE" || true

else
    : > "$FILENAME_FILE"
fi

FILENAME_COUNT="$(wc -l < "$FILENAME_FILE" 2>/dev/null || echo 0)"

case "$FILENAME_COUNT" in
    ''|*[!0-9]*)
        FILENAME_COUNT=0
        ;;
esac

if [ "$FILENAME_COUNT" -gt 0 ]; then
    echo "Filename-like candidates retained: $FILENAME_COUNT"
    echo
    cat "$FILENAME_FILE"
else
    echo "No obvious filename-like remnants found."
fi

# ----------------------------------------------------------------------
# Interesting strings
# ----------------------------------------------------------------------

section "[10] Searching interesting text"

INTERESTING_FILE="$WORKDIR/interesting.txt"

if [ -s "$STRINGS_FILE" ]; then

    grep -Eai \
    '(password|passwd|secret|api[_-]?key|authorization|bearer|private[_-]?key|database|mysql|postgres|mongodb|redis|BEGIN [A-Z ]+ KEY|/home/|/root/|/var/www/|/etc/|/opt/|/srv/|\.ssh/|docker|kubernetes)' \
    "$STRINGS_FILE" 2>/dev/null |
    sort -u |
    head -n "$MAX_INTERESTING" > "$INTERESTING_FILE" || true

else
    : > "$INTERESTING_FILE"
fi

INTERESTING_COUNT="$(wc -l < "$INTERESTING_FILE" 2>/dev/null || echo 0)"

case "$INTERESTING_COUNT" in
    ''|*[!0-9]*)
        INTERESTING_COUNT=0
        ;;
esac

if [ "$INTERESTING_COUNT" -gt 0 ]; then
    echo "Interesting-text candidates retained: $INTERESTING_COUNT"
    echo
    cat "$INTERESTING_FILE"
else
    echo "No obvious interesting-text remnants found."
fi

# ----------------------------------------------------------------------
# Result
# ----------------------------------------------------------------------

section "[11] Result"

echo "Root source              : $ROOT_SOURCE"
echo "Root filesystem          : ${ROOT_FSTYPE:-unknown}"
echo "Analysis source          : ${SCAN_SOURCE:-none}"
echo "Analysis filesystem      : ${SCAN_FSTYPE:-unknown}"
echo "Unallocated data         : $(human_size "$UNALLOC_SIZE")"
echo "Deleted entries          : $DELETED_COUNT"
echo "Readable string records  : $STRING_COUNT"
echo "Filename candidates      : $FILENAME_COUNT"
echo "Interesting text         : $INTERESTING_COUNT"
echo

if [ "$DELETED_COUNT" -gt 0 ] ||
   [ "$FILENAME_COUNT" -gt 0 ] ||
   [ "$INTERESTING_COUNT" -gt 0 ]; then

    echo "RESULT: POTENTIAL RECOVERABLE REMNANTS DETECTED"

elif [ -n "$SCAN_SOURCE" ]; then

    echo "RESULT: NO OBVIOUS RECOVERABLE REMNANTS DETECTED"

else

    echo "RESULT: FILESYSTEM-LEVEL ANALYSIS NOT AVAILABLE"

    if [ "$ROOT_FSTYPE" = "overlay" ]; then
        echo "The root filesystem is overlayfs and no directly accessible"
        echo "backing filesystem device was available."
    else
        echo "No directly accessible filesystem device was available."
    fi
fi

echo
echo "NOTES:"
echo
echo "1. Results depend on the filesystem and storage layer available."
echo "2. Deleted entries may be stale or already reallocated."
echo "3. Readable strings are candidates, not complete recovered files."
echo "4. Live filesystem analysis can produce incomplete results."
echo "5. Overlay filesystems can hide their underlying storage layer."

# ----------------------------------------------------------------------
# Save report
# ----------------------------------------------------------------------

{
    echo "FILE RECOVERY CHECK"
    echo "Version: $VERSION"
    echo "Date: $(date)"
    echo "Host: $(hostname)"
    echo "Kernel: $(uname -r)"
    echo "OS: ${PRETTY_NAME:-Unknown}"
    echo
    echo "Root source: $ROOT_SOURCE"
    echo "Root filesystem: ${ROOT_FSTYPE:-unknown}"
    echo "Analysis source: ${SCAN_SOURCE:-none}"
    echo "Analysis filesystem: ${SCAN_FSTYPE:-unknown}"
    echo
    echo "Unallocated data: $UNALLOC_SIZE bytes"
    echo "Deleted entries: $DELETED_COUNT"
    echo "Readable string records: $STRING_COUNT"
    echo "Filename candidates: $FILENAME_COUNT"
    echo "Interesting text candidates: $INTERESTING_COUNT"
    echo
    if [ "$DELETED_COUNT" -gt 0 ] ||
       [ "$FILENAME_COUNT" -gt 0 ] ||
       [ "$INTERESTING_COUNT" -gt 0 ]; then
        echo "Result: Potential recoverable remnants detected."
    elif [ -n "$SCAN_SOURCE" ]; then
        echo "Result: No obvious recoverable remnants detected."
    else
        echo "Result: Filesystem-level analysis not available."
    fi
} > "$REPORT"

echo
separator
echo "Scan complete."
echo "Report: $REPORT"
separator
