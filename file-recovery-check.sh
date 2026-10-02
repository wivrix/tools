#!/usr/bin/env bash

set -u

VERSION="1.0"

# ------------------------------------------------------------
# Deleted Data / Filesystem Remanence Scanner
#
# READ-ONLY:
#   - Does not delete files
#   - Does not modify filesystem data
#   - Scans unallocated filesystem blocks where supported
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/USERNAME/REPO/main/scan.sh | sudo bash
# ------------------------------------------------------------

REPORT="/tmp/deleted-data-scan-$(date +%Y%m%d-%H%M%S).txt"
TMPDIR="$(mktemp -d)"

cleanup() {
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

# ------------------------------------------------------------
# Formatting
# ------------------------------------------------------------

line() {
    printf '%*s\n' 70 '' | tr ' ' '='
}

section() {
    echo
    line
    echo "  $1"
    line
}

info() {
    echo "[+] $1"
}

warn() {
    echo "[!] $1"
}

error() {
    echo "[-] $1"
}

# ------------------------------------------------------------
# Root check
# ------------------------------------------------------------

if [ "$(id -u)" -ne 0 ]; then
    error "Please run as root."
    exit 1
fi

# ------------------------------------------------------------
# OS detection
# ------------------------------------------------------------

if [ -f /etc/os-release ]; then
    . /etc/os-release
else
    error "Cannot determine Linux distribution."
    exit 1
fi

echo
line
echo "        Deleted Data / Remanence Scanner v$VERSION"
line

echo
info "Operating system : ${PRETTY_NAME:-unknown}"
info "Kernel            : $(uname -r)"
info "Hostname          : $(hostname)"
info "Date              : $(date)"
info "Report            : $REPORT"

# ------------------------------------------------------------
# Install dependencies
# ------------------------------------------------------------

section "Checking dependencies"

install_packages() {

    case "${ID:-}" in

        ubuntu|debian)
            apt-get update -qq
            apt-get install -y -qq sleuthkit util-linux file binutils
            ;;

        fedora)
            dnf install -y sleuthkit util-linux file binutils
            ;;

        centos|rhel|rocky|almalinux)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y sleuthkit util-linux file binutils
            else
                yum install -y sleuthkit util-linux file binutils
            fi
            ;;

        arch)
            pacman -Sy --noconfirm sleuthkit util-linux file binutils
            ;;

        *)
            warn "Unsupported distribution: ${ID:-unknown}"
            warn "Please install Sleuth Kit manually."
            ;;
    esac
}

if ! command -v blkls >/dev/null 2>&1; then
    warn "Sleuth Kit is not installed."
    install_packages
fi

if ! command -v blkls >/dev/null 2>&1; then
    error "blkls is still unavailable."
    error "Cannot perform filesystem unallocated-space analysis."
    exit 1
fi

command -v strings >/dev/null 2>&1 || {
    error "strings command is unavailable."
    exit 1
}

command -v lsblk >/dev/null 2>&1 || {
    error "lsblk command is unavailable."
    exit 1
}

info "Dependencies OK"

# ------------------------------------------------------------
# Disk information
# ------------------------------------------------------------

section "Detected block devices"

lsblk -o NAME,PATH,SIZE,TYPE,FSTYPE,MOUNTPOINTS

# ------------------------------------------------------------
# Find root filesystem
# ------------------------------------------------------------

ROOT_SOURCE="$(findmnt -n -o SOURCE / 2>/dev/null || true)"

if [ -z "$ROOT_SOURCE" ]; then
    error "Could not determine root filesystem."
    exit 1
fi

echo
info "Root filesystem : $ROOT_SOURCE"

# Handle mapper devices and normal partitions
SCAN_DEV="$ROOT_SOURCE"

if [[ "$SCAN_DEV" == /dev/mapper/* ]]; then
    warn "Root filesystem is a device-mapper volume."
    warn "Filesystem-level scanning will be attempted."
fi

# ------------------------------------------------------------
# Filesystem information
# ------------------------------------------------------------

section "Filesystem information"

findmnt /
echo
df -h /

FSTYPE="$(lsblk -no FSTYPE "$SCAN_DEV" 2>/dev/null | head -n1)"

if [ -z "$FSTYPE" ]; then
    FSTYPE="$(blkid -o value -s TYPE "$SCAN_DEV" 2>/dev/null || true)"
fi

info "Filesystem type: ${FSTYPE:-unknown}"

# ------------------------------------------------------------
# Deleted-open files
# ------------------------------------------------------------

section "Deleted files still held open"

if command -v lsof >/dev/null 2>&1; then

    OPEN_DELETED="$(lsof +L1 2>/dev/null || true)"

    if [ -n "$OPEN_DELETED" ]; then
        echo "$OPEN_DELETED"
    else
        echo "No deleted-but-open files detected."
    fi

else
    warn "lsof not installed; skipping open-deleted-file check."
fi

# ------------------------------------------------------------
# Calculate filesystem usage
# ------------------------------------------------------------

section "Filesystem space analysis"

DF_USED="$(df -B1 "$SCAN_DEV" | awk 'NR==2 {print $3}')"
DF_AVAIL="$(df -B1 "$SCAN_DEV" | awk 'NR==2 {print $4}')"
DF_TOTAL="$(df -B1 "$SCAN_DEV" | awk 'NR==2 {print $2}')"

echo "Filesystem total : $DF_TOTAL bytes"
echo "Filesystem used  : $DF_USED bytes"
echo "Filesystem free  : $DF_AVAIL bytes"

# ------------------------------------------------------------
# Scan unallocated space
# ------------------------------------------------------------

section "Scanning unallocated filesystem space"

UNALLOC="$TMPDIR/unallocated.bin"

info "Extracting unallocated blocks..."
info "This can take time on large disks."

if blkls "$SCAN_DEV" > "$UNALLOC" 2>/dev/null; then

    UNALLOC_SIZE="$(stat -c%s "$UNALLOC" 2>/dev/null || echo 0)"

    echo
    info "Unallocated data exposed by filesystem: $UNALLOC_SIZE bytes"

else

    warn "blkls could not analyze $SCAN_DEV."
    warn "This filesystem may not be supported or may be a virtual/device-mapper layout."
    UNALLOC_SIZE=0
fi

# ------------------------------------------------------------
# File signatures
# ------------------------------------------------------------

if [ "$UNALLOC_SIZE" -gt 0 ]; then

    section "Detected file signatures"

    file "$UNALLOC" 2>/dev/null | head -100

    echo
    info "Searching for common binary signatures..."

    # JPEG
    JPEG_COUNT="$(grep -aob $'\xFF\xD8\xFF' "$UNALLOC" 2>/dev/null | wc -l || true)"

    # PDF
    PDF_COUNT="$(grep -aob '％PDF-' "$UNALLOC" 2>/dev/null | wc -l || true)"

    # ZIP
    ZIP_COUNT="$(grep -aob 'PK\x03\x04' "$UNALLOC" 2>/dev/null | wc -l || true)"

    # PNG
    PNG_COUNT="$(grep -aob $'\x89PNG' "$UNALLOC" 2>/dev/null | wc -l || true)"

    # GZIP
    GZIP_COUNT="$(grep -aob $'\x1F\x8B' "$UNALLOC" 2>/dev/null | wc -l || true)"

    echo "JPEG signatures : $JPEG_COUNT"
    echo "PDF signatures  : $PDF_COUNT"
    echo "ZIP signatures  : $ZIP_COUNT"
    echo "PNG signatures  : $PNG_COUNT"
    echo "GZIP signatures : $GZIP_COUNT"

fi

# ------------------------------------------------------------
# Filename / path strings
# ------------------------------------------------------------

if [ "$UNALLOC_SIZE" -gt 0 ]; then

    section "Recoverable-looking filenames and paths"

    STRINGS_FILE="$TMPDIR/strings.txt"

    strings -a -n 5 "$UNALLOC" > "$STRINGS_FILE" 2>/dev/null || true

    grep -Eai \
        '(^|/)[A-Za-z0-9._-]+\.(txt|log|conf|cfg|ini|json|xml|yaml|yml|csv|sql|db|sqlite|sqlite3|jpg|jpeg|png|gif|webp|bmp|pdf|doc|docx|xls|xlsx|ppt|pptx|zip|tar|gz|tgz|bz2|7z|rar|php|html|htm|js|ts|jsx|tsx|py|rb|go|java|c|cpp|h|hpp|sh|bash|env|key|pem|crt|cer|bak|old|tmp)$' \
        "$STRINGS_FILE" |
        sort -u |
        head -1000

fi

# ------------------------------------------------------------
# Interesting text fragments
# ------------------------------------------------------------

if [ "$UNALLOC_SIZE" -gt 0 ]; then

    section "Interesting recovered text fragments"

    grep -Eai \
        '(password|passwd|secret|token|api[_-]?key|authorization|bearer|private[_-]?key|database|mysql|postgres|mongodb|redis|ssh|BEGIN [A-Z ]+ KEY)' \
        "$STRINGS_FILE" |
        sort -u |
        head -500

fi

# ------------------------------------------------------------
# Common filesystem artifacts
# ------------------------------------------------------------

if [ "$UNALLOC_SIZE" -gt 0 ]; then

    section "Filesystem / application artifacts"

    grep -Eai \
        '(\/home\/|\/root\/|\/var\/www\/|\/etc\/|\/tmp\/|\/opt\/|\/srv\/|\.git\/|node_modules\/|\.ssh\/|docker|kubernetes)' \
        "$STRINGS_FILE" |
        sort -u |
        head -1000

fi

# ------------------------------------------------------------
# Recoverability summary
# ------------------------------------------------------------

section "Summary"

echo "Filesystem       : $SCAN_DEV"
echo "Filesystem type  : ${FSTYPE:-unknown}"
echo "Unallocated data : $UNALLOC_SIZE bytes"

echo

if [ "$UNALLOC_SIZE" -gt 0 ]; then

    echo "RESULT: Unallocated blocks containing residual data are accessible"
    echo
    echo "This indicates that data fragments exist in filesystem-unallocated"
    echo "space. It does NOT prove that the data belongs to a previous"
    echo "cloud/VPS customer."

else

    echo "RESULT: No accessible unallocated data was detected."
    echo
    echo "This does NOT prove that physical storage contains no residual data."
    echo "The provider may use virtualization, encryption, thin provisioning,"
    echo "snapshots, or storage-layer isolation."
fi

echo
echo "IMPORTANT:"
echo "This scanner cannot determine previous ownership of recovered data."
echo "Only a known canary/marker written before destroying a test VM can"
echo "reliably establish that your old data survived VM reallocation."

# ------------------------------------------------------------
# Save report
# ------------------------------------------------------------

{
    echo "Deleted Data / Remanence Scanner"
    echo "Version: $VERSION"
    echo "Date: $(date)"
    echo
    echo "Device: $SCAN_DEV"
    echo "Filesystem: ${FSTYPE:-unknown}"
    echo "Unallocated bytes: $UNALLOC_SIZE"
} > "$REPORT"

echo
line
echo "Report metadata saved to:"
echo "$REPORT"
line
echo
