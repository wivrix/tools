#!/usr/bin/env bash

# file-recovery-check.sh
# General Linux deleted-file and storage recovery check.
#
# This tool performs filesystem-level checks on storage that is
# accessible from the current system.
#
# For overlay filesystems, the overlay mount itself is not a normal
# filesystem device. The script therefore:
#   - checks deleted-but-open files
#   - identifies overlay upper/lower directories when available
#   - checks the overlay upper directory when accessible
#   - attempts backing-filesystem analysis when its block device
#     can be safely identified
#
# No recovery image is created by this script.

set -uo pipefail

VERSION="4.0"

WORKDIR="$(mktemp -d /tmp/file-recovery-check.XXXXXX)"
REPORT="/tmp/file-recovery-check-$(date +%Y%m%d-%H%M%S).txt"

MAX_FINDINGS=500
MAX_INTERESTING=500

ROOT_SOURCE=""
ROOT_FSTYPE=""
SCAN_SOURCE=""
SCAN_FSTYPE=""
SCAN_REASON=""

DELETED_COUNT=0
STRING_COUNT=0
FILENAME_COUNT=0
INTERESTING_COUNT=0
UNALLOC_SIZE=0

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
echo "             FILE RECOVERY CHECK"
echo "                     v$VERSION"
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
# Root filesystem detection
# ----------------------------------------------------------------------

section "[2] Detecting filesystem"

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
# Deleted files still held open
#
# This check is independent of the filesystem type and therefore also
# works when the root filesystem is overlay.
# ----------------------------------------------------------------------

section "[3] Deleted files still held open"

DELETED_OPEN_FILE="$WORKDIR/deleted-open.txt"

if command -v lsof >/dev/null 2>&1; then

    lsof +L1 2>/dev/null > "$DELETED_OPEN_FILE" || true

    if [ -s "$DELETED_OPEN_FILE" ]; then
        cat "$DELETED_OPEN_FILE"
    else
        echo "None detected."
    fi

else
    echo "[INFO] lsof is not installed."
    echo "[INFO] Skipping deleted-open-file check."
fi

# ----------------------------------------------------------------------
# Overlay detection
# ----------------------------------------------------------------------

if [ "$ROOT_FSTYPE" = "overlay" ]; then

    section "[4] Overlay filesystem"

    echo "[INFO] The root filesystem is overlayfs."
    echo "[INFO] The overlay mount itself is not scanned as a block filesystem."

    OVERLAY_OPTIONS="$(
        findmnt -n -o OPTIONS / 2>/dev/null || true
    )"

    UPPER_DIR=""
    LOWER_DIRS=""

    case ",$OVERLAY_OPTIONS," in
        *,upperdir=*,*)
            UPPER_DIR="$(
                printf '%s\n' "$OVERLAY_OPTIONS" |
                sed -n 's/.*,\?upperdir=\([^,]*\).*/\1/p' |
                head -n 1
            )"
            ;;
    esac

    case ",$OVERLAY_OPTIONS," in
        *,lowerdir=*,*)
            LOWER_DIRS="$(
                printf '%s\n' "$OVERLAY_OPTIONS" |
                sed -n 's/.*,\?lowerdir=\([^,]*\).*/\1/p' |
                head -n 1
            )"
            ;;
    esac

    if [ -n "$UPPER_DIR" ]; then
        echo "Upper directory: $UPPER_DIR"
    else
        echo "Upper directory: not exposed"
    fi

    if [ -n "$LOWER_DIRS" ]; then
        echo "Lower directory: $LOWER_DIRS"
    else
        echo "Lower directory: not exposed"
    fi

    # --------------------------------------------------------------
    # Inspect the upper directory when accessible.
    #
    # This can show the actual files currently present in the upper
    # layer, but cannot recover blocks that have already been deleted
    # from that filesystem.
    # --------------------------------------------------------------

    if [ -n "$UPPER_DIR" ] && [ -d "$UPPER_DIR" ]; then

        echo
        echo "[INFO] Overlay upper directory is accessible."

        UPPER_MOUNT_SOURCE="$(
            findmnt -n -T "$UPPER_DIR" -o SOURCE 2>/dev/null || true
        )"

        UPPER_MOUNT_FSTYPE="$(
            findmnt -n -T "$UPPER_DIR" -o FSTYPE 2>/dev/null || true
        )"

        echo "Upper backing source : ${UPPER_MOUNT_SOURCE:-unknown}"
        echo "Upper filesystem     : ${UPPER_MOUNT_FSTYPE:-unknown}"

        if [ -n "$UPPER_MOUNT_SOURCE" ] &&
           [ -b "$UPPER_MOUNT_SOURCE" ]; then

            SCAN_SOURCE="$UPPER_MOUNT_SOURCE"
            SCAN_FSTYPE="$UPPER_MOUNT_FSTYPE"
            SCAN_REASON="overlay upper directory backing device"

            echo
            echo "[OK] A block device backing the overlay upper directory was found."
            echo "[INFO] Filesystem-level recovery analysis can be attempted."

        else
            echo
            echo "[INFO] The overlay upper directory does not expose a"
            echo "       directly accessible block device."
            echo "[INFO] Deleted filesystem entries cannot be analyzed"
            echo "       directly from the overlay mount."
        fi

    else
        echo
        echo "[INFO] Overlay upper directory is not accessible."
    fi

else

    # ------------------------------------------------------------------
    # Normal block-backed filesystem
    # ------------------------------------------------------------------

    case "$ROOT_SOURCE" in
        /dev/*)
            if [ -b "$ROOT_SOURCE" ]; then
                SCAN_SOURCE="$ROOT_SOURCE"
                SCAN_FSTYPE="$ROOT_FSTYPE"
                SCAN_REASON="root filesystem"
            fi
            ;;
    esac

fi

# ----------------------------------------------------------------------
# Filesystem information
# ----------------------------------------------------------------------

section "[5] Filesystem analysis target"

if [ -n "$SCAN_SOURCE" ]; then

    echo "Scan source : $SCAN_SOURCE"
    echo "Filesystem  : ${SCAN_FSTYPE:-unknown}"
    echo "Reason      : $SCAN_REASON"

    case "$SCAN_FSTYPE" in
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
            echo "[WARNING] This tool is not designed for ZFS internals."
            ;;

        *)
            echo "[WARNING] Filesystem '$SCAN_FSTYPE' may not be fully supported."
            ;;
    esac

else

    echo "No directly accessible block filesystem was identified."
    echo
    echo "Filesystem-level deleted-entry and unallocated-space analysis"
    echo "will be skipped."
    echo
    echo "Other applicable checks will continue."

fi

# ----------------------------------------------------------------------
# Current filesystem usage
# ----------------------------------------------------------------------

section "[6] Current filesystem usage"

df -h / 2>/dev/null || true

if [ -n "$SCAN_SOURCE" ]; then
    echo
    df -h "$SCAN_SOURCE" 2>/dev/null || true
fi

# ----------------------------------------------------------------------
# Deleted filesystem entries
#
# fls:
#   -r = recursive
#   -d = deleted entries
#   -l = long format
#
# Sleuth Kit can expose deleted names and orphan metadata, but deleted
# entries must be interpreted carefully.
# ----------------------------------------------------------------------

section "[7] Deleted filesystem entries"

DELETED_FILE="$WORKDIR/deleted.txt"
DELETED_ERROR="$WORKDIR/fls-error.txt"

if [ -n "$SCAN_SOURCE" ]; then

    if fls -r -d -l "$SCAN_SOURCE" 2>"$DELETED_ERROR" |
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

        DELETED_COUNT="$(
            cat "$WORKDIR/deleted-count.txt" 2>/dev/null || echo 0
        )"

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

else

    echo "Skipped: no directly accessible block filesystem."

fi

# ----------------------------------------------------------------------
# Unallocated filesystem data
#
# blkls streams unallocated filesystem data.
# Nothing is written to a large recovery image.
# ----------------------------------------------------------------------

section "[8] Measuring unallocated filesystem data"

BLKLS_ERROR="$WORKDIR/blkls-error.txt"

if [ -n "$SCAN_SOURCE" ]; then

    echo "Device: $SCAN_SOURCE"
    echo
    echo "[INFO] Reading unallocated filesystem data..."
    echo "[INFO] No recovery image will be created."
    echo

    UNALLOC_SIZE="$(
        blkls "$SCAN_SOURCE" 2>"$BLKLS_ERROR" |
        wc -c
    )"

    case "$UNALLOC_SIZE" in
        ''|*[!0-9]*)
            UNALLOC_SIZE=0
            ;;
    esac

    echo "Unallocated data stream: $(human_size "$UNALLOC_SIZE")"

    if [ -s "$BLKLS_ERROR" ]; then
        echo
        echo "[WARNING] blkls reported:"
        cat "$BLKLS_ERROR"
    fi

else

    echo "Skipped: no directly accessible block filesystem."

fi

# ----------------------------------------------------------------------
# Readable strings from unallocated space
# ----------------------------------------------------------------------

section "[9] Searching readable strings"

STRINGS_FILE="$WORKDIR/strings.txt"

if [ -n "$SCAN_SOURCE" ]; then

    if blkls "$SCAN_SOURCE" 2>/dev/null |
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

        STRING_COUNT="$(
            cat "$WORKDIR/string-count.txt" 2>/dev/null || echo 0
        )"

    else

        echo "[WARNING] Unallocated string scan did not complete cleanly."
        STRING_COUNT=0
    fi

    case "$STRING_COUNT" in
        ''|*[!0-9]*)
            STRING_COUNT=0
            ;;
    esac

    echo "Readable string records processed: $STRING_COUNT"

    if [ "$STRING_COUNT" -gt "$MAX_FINDINGS" ]; then
        echo "(Only the first $MAX_FINDINGS are retained.)"
    fi

else

    echo "Skipped: no directly accessible block filesystem."

fi

# ----------------------------------------------------------------------
# Filename-like strings
# ----------------------------------------------------------------------

section "[10] Searching filename-like remnants"

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

section "[11] Searching interesting text"

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

section "[12] Result"

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
    echo
    echo "Deleted filesystem entries and/or readable data"
    echo "were identified during the available checks."

elif [ -n "$SCAN_SOURCE" ]; then

    echo "RESULT: NO OBVIOUS RECOVERABLE REMNANTS DETECTED"
    echo
    echo "No obvious deleted entries or useful readable strings"
    echo "were identified during the filesystem-level checks."

else

    echo "RESULT: FILESYSTEM-LEVEL RECOVERY CHECK NOT AVAILABLE"
    echo
    echo "No directly accessible block filesystem was available"
    echo "for deleted-entry and unallocated-space analysis."
    echo "Other applicable checks were completed."

fi

echo
echo "NOTES:"
echo
echo "1. Results depend on the filesystem and storage layer being analyzed."
echo "2. Deleted filesystem entries may be stale or already reallocated."
echo "3. Readable strings in unallocated space are candidates, not proof"
echo "   of a complete recoverable file."
echo "4. Live filesystem analysis can produce incomplete or inconsistent results."
echo "5. Overlay filesystems may hide the underlying storage layer."
echo "6. An overlay mount cannot itself be analyzed as a normal disk filesystem."

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
    echo "Analysis reason: ${SCAN_REASON:-none}"
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

        echo "Result: Potential recoverable remnants detected."

    elif [ -n "$SCAN_SOURCE" ]; then

        echo "Result: No obvious recoverable remnants detected."

    else

        echo "Result: Filesystem-level recovery check not available."

    fi

    echo
    echo "This report contains filesystem-level recovery results."
} > "$REP
