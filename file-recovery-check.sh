#!/usr/bin/env bash

# ============================================================
# File Recovery / Storage Remanence Check
# Version: 3.0
#
# Purpose:
#   Detect deleted-file metadata and recoverable-looking
#   remnants in filesystem unallocated space.
#
# IMPORTANT:
#   A finding does NOT prove that the data belonged to a
#   previous VPS/customer.
#
#   This tool performs READ-ONLY analysis.
# ============================================================

set -uo pipefail

VERSION="3.0"
MAX_FINDINGS=500
REPORT="/tmp/file-recovery-check-$(date +%Y%m%d-%H%M%S).txt"
WORKDIR="$(mktemp -d /tmp/file-recovery-check.XXXXXX)"

cleanup() {
    rm -rf "$WORKDIR"
}

trap cleanup EXIT

print_line() {
    printf '%*s\n' 72 '' | tr ' ' '='
}

section() {
    echo
    print_line
    echo "$1"
    print_line
}

human_size() {
    if command -v numfmt >/dev/null 2>&1; then
        numfmt --to=iec --suffix=B "$1" 2>/dev/null
    else
        echo "${1} bytes"
    fi
}

fail() {
    echo
    echo "[ERROR] $1"
    exit 1
}

# ------------------------------------------------------------
# Root check
# ------------------------------------------------------------

if [ "$(id -u)" -ne 0 ]; then
    fail "This script must be run as root."
fi

# ------------------------------------------------------------
# OS detection
# ------------------------------------------------------------

if [ ! -f /etc/os-release ]; then
    fail "Cannot determine the Linux distribution."
fi

# shellcheck disable=SC1091
. /etc/os-release

# ------------------------------------------------------------
# Header
# ------------------------------------------------------------

print_line
echo "       FILE RECOVERY / STORAGE REMANENCE CHECK"
echo "                         v$VERSION"
print_line

echo
echo "Host       : $(hostname)"
echo "Date       : $(date)"
echo "Kernel     : $(uname -r)"
echo "OS         : ${PRETTY_NAME:-Unknown}"
echo "Report     : $REPORT"

# ------------------------------------------------------------
# Dependency installation
# ------------------------------------------------------------

section "[1] Checking dependencies"

install_sleuthkit() {
    case "${ID:-}" in
        ubuntu|debian)
            echo "[INFO] Installing Sleuth Kit..."
            apt-get update -qq &&
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sleuthkit
            ;;

        fedora|rhel|centos|rocky|almalinux)
            echo "[INFO] Installing Sleuth Kit..."

            if command -v dnf >/dev/null 2>&1; then
                dnf install -y sleuthkit
            elif command -v yum >/dev/null 2>&1; then
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
            echo "[ERROR] Unsupported distribution: ${ID:-unknown}"
            return 1
            ;;
    esac
}

if ! command -v blkls >/dev/null 2>&1 ||
   ! command -v fls >/dev/null 2>&1; then

    install_sleuthkit || fail "Could not install Sleuth Kit."
fi

REQUIRED_COMMANDS=(
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
    uniq
    wc
    stat
)

for cmd in "${REQUIRED_COMMANDS[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        fail "Required command not found: $cmd"
    fi
done

echo "[OK] All required commands are available."

# ------------------------------------------------------------
# Block devices
# ------------------------------------------------------------

section "[2] Block devices"

lsblk -e7 -o NAME,PATH,SIZE,TYPE,FSTYPE,MOUNTPOINTS

# ------------------------------------------------------------
# Root filesystem
# ------------------------------------------------------------

ROOT_SOURCE="$(findmnt -n -o SOURCE / 2>/dev/null || true)"
ROOT_FSTYPE="$(findmnt -n -o FSTYPE / 2>/dev/null || true)"

if [ -z "$ROOT_SOURCE" ]; then
    fail "Could not determine the root filesystem."
fi

echo
echo "Root device : $ROOT_SOURCE"
echo "Filesystem   : ${ROOT_FSTYPE:-unknown}"

case "$ROOT_FSTYPE" in
    ext2|ext3|ext4)
        echo "[OK] EXT filesystem detected."
        ;;

    xfs)
        echo "[WARNING] XFS detected."
        echo "[WARNING] Deleted-file metadata may be limited."
        ;;

    btrfs)
        echo "[WARNING] Btrfs detected."
        echo "[WARNING] Copy-on-write/snapshots affect interpretation."
        ;;

    zfs)
        echo "[WARNING] ZFS detected."
        echo "[WARNING] This scanner does not analyze ZFS internals."
        ;;

    *)
        echo "[WARNING] Filesystem '$ROOT_FSTYPE' may have limited support."
        ;;
esac

# ------------------------------------------------------------
# Filesystem usage
# ------------------------------------------------------------

section "[3] Current filesystem usage"

df -h "$ROOT_SOURCE"

# ------------------------------------------------------------
# Deleted but open files
# ------------------------------------------------------------

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
    echo "[INFO] This check is skipped."
fi

# ------------------------------------------------------------
# Deleted filesystem entries
# ------------------------------------------------------------

section "[5] Deleted filesystem entries"

DELETED_FILE="$WORKDIR/deleted-files.txt"
FLS_ERROR="$WORKDIR/fls-error.txt"

echo "[INFO] Searching filesystem metadata for deleted entries..."
echo

if fls -r -d -l "$ROOT_SOURCE" > "$DELETED_FILE" 2>"$FLS_ERROR"; then

    DELETED_COUNT="$(wc -l < "$DELETED_FILE" | tr -d ' ')"

    if [ "$DELETED_COUNT" -gt 0 ]; then
        echo "Deleted entries found: $DELETED_COUNT"
        echo
        head -n "$MAX_FINDINGS" "$DELETED_FILE"

        if [ "$DELETED_COUNT" -gt "$MAX_FINDINGS" ]; then
            echo
            echo "... output limited to $MAX_FINDINGS entries."
        fi
    else
        echo "No deleted filesystem entries reported by fls."
    fi

else

    echo "[WARNING] fls could not analyze the filesystem."

    if [ -s "$FLS_ERROR" ]; then
        cat "$FLS_ERROR"
    fi

    DELETED_COUNT=0
fi

# ------------------------------------------------------------
# Unallocated-space size
# ------------------------------------------------------------

section "[6] Unallocated filesystem data"

UNALLOC_SIZE_FILE="$WORKDIR/unallocated-size.txt"

echo "[INFO] Measuring unallocated filesystem data."
echo "[INFO] No unallocated data is saved to disk."

# blkls writes binary data to stdout.
# wc counts the bytes while the data is streamed.
#
# IMPORTANT:
# This is a filesystem-level measurement, not physical
# cloud-storage capacity.

if blkls "$ROOT_SOURCE" 2>"$WORKDIR/blkls-size-error.txt" |
   wc -c > "$UNALLOC_SIZE_FILE"; then

    UNALLOC_SIZE="$(cat "$UNALLOC_SIZE_FILE" | tr -d '[:space:]')"

    if [ -z "$UNALLOC_SIZE" ]; then
        UNALLOC_SIZE=0
    fi

    echo "Unallocated data exposed by filesystem:"
    echo "  $(human_size "$UNALLOC_SIZE")"

else

    echo "[WARNING] Could not measure unallocated data."

    if [ -s "$WORKDIR/blkls-size-error.txt" ]; then
        cat "$WORKDIR/blkls-size-error.txt"
    fi

    UNALLOC_SIZE=0
fi

# ------------------------------------------------------------
# String / filename analysis
# ------------------------------------------------------------

section "[7] Searching unallocated space for readable remnants"

STRING_FINDINGS="$WORKDIR/string-findings.txt"
INTERESTING_FINDINGS="$WORKDIR/interesting-findings.txt"

: > "$STRING_FINDINGS"
: > "$INTERESTING_FINDINGS"

echo "[INFO] Streaming unallocated data through strings."
echo "[INFO] No complete unallocated image is stored."

# The awk process consumes the entire stream, but only saves
# a limited number of interesting matches.

if blkls "$ROOT_SOURCE" 2>"$WORKDIR/blkls-strings-error.txt" |
   strings -a -n 6 |
   awk -v max="$MAX_FINDINGS" '
   BEGIN {
       total=0
       files=0
       interesting=0
   }

   {
       total++

       line=$0

       if (
           line ~ /(^|[\/[:space:]])[^[:space:]]+\.(txt|log|conf|cfg|ini|json|xml|yaml|yml|csv|sql|db|sqlite|sqlite3|jpg|jpeg|png|gif|web
