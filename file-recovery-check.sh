#!/usr/bin/env bash

set -uo pipefail

VERSION="2.0"
REPORT="/tmp/file-recovery-check-$(date +%Y%m%d-%H%M%S).txt"
WORKDIR="$(mktemp -d /tmp/file-recovery-check.XXXXXX)"

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
    if command -v numfmt >/dev/null 2>&1; then
        numfmt --to=iec --suffix=B "$1"
    else
        echo "${1} bytes"
    fi
}

if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] This script must be run as root."
    exit 1
fi

if [ -f /etc/os-release ]; then
    . /etc/os-release
else
    echo "[ERROR] Cannot determine operating system."
    exit 1
fi

clear 2>/dev/null || true

line
echo "       FILE RECOVERY / STORAGE REMANENCE CHECK"
echo "                      v$VERSION"
line

echo
echo "Host       : $(hostname)"
echo "Date       : $(date)"
echo "Kernel     : $(uname -r)"
echo "OS         : ${PRETTY_NAME:-Unknown}"
echo "Report     : $REPORT"

section "[1] Checking dependencies"

install_sleuthkit() {
    case "${ID:-}" in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y -qq sleuthkit
            ;;
        fedora|rhel|centos|rocky|almalinux)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y sleuthkit
            else
                yum install -y sleuthkit
            fi
            ;;
        arch)
            pacman -Sy --noconfirm sleuthkit
            ;;
        *)
            echo "[ERROR] Automatic installation is not supported for: ${ID:-unknown}"
            return 1
            ;;
    esac
}

if ! command -v blkls >/dev/null 2>&1; then
    echo "[INFO] Sleuth Kit is not installed."
    echo "[INFO] Installing Sleuth Kit..."
    install_sleuthkit || {
        echo "[ERROR] Failed to install Sleuth Kit."
        exit 1
    }
fi

REQUIRED_COMMANDS=(
    blkls
    lsblk
    findmnt
    df
    strings
    grep
    awk
    sed
    stat
)

for cmd in "${REQUIRED_COMMANDS[@]}"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "[ERROR] Required command not found: $cmd"
        exit 1
    fi
done

echo "[OK] Required dependencies are available."

section "[2] Block devices"

lsblk -e7 -o NAME,PATH,SIZE,TYPE,FSTYPE,MOUNTPOINTS

ROOT_SOURCE="$(findmnt -n -o SOURCE / 2>/dev/null || true)"
ROOT_FSTYPE="$(findmnt -n -o FSTYPE / 2>/dev/null || true)"

if [ -z "$ROOT_SOURCE" ]; then
    echo "[ERROR] Could not determine root filesystem."
    exit 1
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
        echo "[WARNING] Deleted-data analysis may be limited."
        ;;
    btrfs)
        echo "[WARNING] Btrfs detected."
        echo "[WARNING] Copy-on-write and snapshots can affect results."
        ;;
    zfs)
        echo "[WARNING] ZFS detected."
        echo "[WARNING] This scanner is not designed for ZFS internals."
        ;;
    *)
        echo "[WARNING] Filesystem '$ROOT_FSTYPE' may not be fully supported."
        ;;
esac

section "[3] Current filesystem usage"

df -h "$ROOT_SOURCE"

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

section "[5] Scanning unallocated filesystem space"

UNALLOC="$WORKDIR/unallocated.bin"
BLKLS_ERROR="$WORKDIR/blkls-error.txt"

echo "Device: $ROOT_SOURCE"
echo
echo "[INFO] Reading unallocated filesystem blocks..."
echo "[INFO] This operation is read-only."
echo

if blkls "$ROOT_SOURCE" > "$UNALLOC" 2>"$BLKLS_ERROR"; then
    UNALLOC_SIZE="$(stat -c '%s' "$UNALLOC" 2>/dev/null || echo 0)"

    echo "[OK] Unallocated data stream created."
    echo "Size: $(human_size "$UNALLOC_SIZE")"
else
    echo "[ERROR] blkls could not analyze $ROOT_SOURCE."

    if [ -s "$BLKLS_ERROR" ]; then
        echo
        cat "$BLKLS_ERROR"
    fi

    echo
    echo "The filesystem or storage layout may not be supported."
    exit 1
fi

if [ "$UNALLOC_SIZE" -eq 0 ]; then
    echo
    echo "[RESULT] No unallocated data was exposed."
    echo
    echo "This does not prove that the underlying physical storage"
    echo "contains no residual data."
    exit 0
fi

section "[6] Searching readable strings"

STRINGS_FILE="$WORKDIR/strings.txt"

strings -a -t d -n 6 "$UNALLOC" > "$STRINGS_FILE" 2>/dev/null || true

STRING_COUNT="$(wc -l < "$STRINGS_FILE" 2>/dev/null || echo 0)"

echo "Readable strings found: $STRING_COUNT"

section "[7] Searching filename candidates"

FILENAME_FILE="$WORKDIR/filenames.txt"

grep -Eai \
'(^|[/[:space:]])[A-Za-z0-9._@/-]+\.(txt|log|conf|cfg|ini|json|xml|yaml|yml|csv|sql|db|sqlite|sqlite3|jpg|jpeg|png|gif|webp|bmp|pdf|doc|docx|xls|xlsx|ppt|pptx|zip|tar|gz|tgz|bz2|7z|rar|php|html|htm|js|ts|jsx|tsx|py|rb|go|java|c|cpp|h|hpp|sh|bash|env|key|pem|crt|cer|bak|old|tmp)([^A-Za-z0-9._-]|$)' \
"$STRINGS_FILE" |
sed -E 's/^[[:space:]]*[0-9]+:[[:space:]]*//' |
sort -u |
head -1000 > "$FILENAME_FILE"

FILENAME_COUNT="$(wc -l < "$FILENAME_FILE" 2>/dev/null || echo 0)"

if [ "$FILENAME_COUNT" -gt 0 ]; then
    echo "Candidates found: $FILENAME_COUNT"
    echo
    cat "$FILENAME_FILE"
else
    echo "No obvious filename candidates found."
fi

section "[8] Searching file signatures"

count_signature() {
    local name="$1"
    local pattern="$2"
    local count

    count="$(grep -aob "$pattern" "$UNALLOC" 2>/dev/null | wc -l || echo 0)"
    printf "%-12s %s\n" "$name:" "$count"
}

count_signature "PDF" '%PDF-'
count_signature "ZIP" 'PK'
count_signature "GZIP" $'\x1f\x8b'
count_signature "PNG" 'PNG'
count_signature "JPEG" $'\xff\xd8\xff'
count_signature "GIF" 'GIF8'
count_signature "SQLite" 'SQLite format 3'
count_signature "ELF" $'\x7fELF'

section "[9] Searching interesting text"

INTERESTING_FILE="$WORKDIR/interesting.txt"

grep -Eai \
'(password|passwd|secret|api[_-]?key|authorization|bearer|private[_-]?key|database|mysql|postgres|mongodb|redis|BEGIN [A-Z ]+ KEY|/home/|/root/|/var/www/|/etc/|/opt/|/srv/|\.ssh/|docker|kubernetes)' \
"$STRINGS_FILE" |
sort -u |
head -1000 > "$INTERESTING_FILE"

INTERESTING_COUNT="$(wc -l < "$INTERESTING_FILE" 2>/dev/null || echo 0)"

if [ "$INTERESTING_COUNT" -gt 0 ]; then
    echo "Candidates found: $INTERESTING_COUNT"
    echo
    cat "$INTERESTING_FILE"
else
    echo "No obvious interesting text candidates found."
fi

section "[10] Summary"

echo "Root device              : $ROOT_SOURCE"
echo "Filesystem               : ${ROOT_FSTYPE:-unknown}"
echo "Unallocated data         : $(human_size "$UNALLOC_SIZE")"
echo "Readable strings         : $STRING_COUNT"
echo "Filename candidates      : $FILENAME_COUNT"
echo "Interesting text         : $INTERESTING_COUNT"

section "[11] Result"

if [ "$FILENAME_COUNT" -gt 0 ] || [ "$INTERESTING_COUNT" -gt 0 ]; then
    echo "POTENTIAL RESIDUAL DATA DETECTED"
    echo
    echo "File-like or readable remnants were found in"
    echo "unallocated filesystem space."
else
    echo "NO OBVIOUS FILE REMNANTS DETECTED"
fi

echo
echo "IMPORTANT:"
echo
echo "This scanner cannot determine who previously owned"
echo "the recovered data."
echo
echo "A positive result does not prove cross-tenant leakage."
echo "A clean result does not prove secure physical erasure."
echo
echo "For a cross-tenant test, use a unique canary string"
echo "on VPS A, destroy VPS A, create VPS B, and search"
echo "VPS B for the exact same canary."

{
    echo "FILE RECOVERY / STORAGE REMANENCE CHECK"
    echo "Version: $VERSION"
    echo "Date: $(date)"
    echo "Host: $(hostname)"
    echo "Root device: $ROOT_SOURCE"
    echo "Filesystem: $ROOT_FSTYPE"
    echo
    echo "Unallocated data: $UNALLOC_SIZE bytes"
    echo "Readable strings: $STRING_COUNT"
    echo "Filename candidates: $FILENAME_COUNT"
    echo "Interesting text candidates: $INTERESTING_COUNT"
    echo
    if [ "$FILENAME_COUNT" -gt 0 ] || [ "$INTERESTING_COUNT" -gt 0 ]; then
        echo "Result: Potential residual data detected."
    else
        echo "Result: No obvious file remnants detected."
    fi
} > "$REPORT"

echo
line
echo "Report saved to:"
echo "$REPORT"
line
echo
echo "Scan complete."
