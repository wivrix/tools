#!/usr/bin/env bash

# file-recovery-check.sh
# General Linux storage/remanence analysis.
#
# v5.0
#
# Features:
#   - Enumerates visible block devices and partitions
#   - Identifies filesystem types
#   - Analyzes mounted filesystems
#   - Analyzes accessible unmounted filesystem devices read-only
#   - Handles overlayfs when its backing filesystem is accessible
#   - Checks deleted-open files with lsof
#   - Checks deleted filesystem entries with Sleuth Kit
#   - Measures unallocated filesystem data
#   - Extracts printable strings from unallocated space
#   - Searches filename-like and interesting-text candidates
#   - Checks swap separately
#   - Keeps findings associated with the source device
#   - Does not mount or modify unmounted filesystems

set -uo pipefail

VERSION="5.0"

MAX_FINDINGS=500
MAX_INTERESTING=500
MAX_STRING_BYTES=$((256 * 1024 * 1024))

WORKDIR="$(mktemp -d /tmp/file-recovery-check.XXXXXX)"
REPORT="/tmp/file-recovery-check-$(date +%Y%m%d-%H%M%S).txt"

trap 'rm -rf "$WORKDIR"' EXIT

separator() {
    printf '%*s\n' 76 '' | tr ' ' '='
}

section() {
    echo
    separator
    echo "$1"
    separator
}

human_size() {
    if command -v numfmt >/dev/null 2>&1; then
        numfmt --to=iec --suffix=B "$1" 2>/dev/null || echo "$1 bytes"
    else
        echo "$1 bytes"
    fi
}

safe_number() {
    case "${1:-}" in
        ''|*[!0-9]*) echo 0 ;;
        *) echo "$1" ;;
    esac
}

error_exit() {
    echo
    echo "[ERROR] $1"
    exit 1
}

# ----------------------------------------------------------------------
# Root / OS checks
# ----------------------------------------------------------------------

if [ "$(id -u)" -ne 0 ]; then
    error_exit "Run this script as root, for example: sudo bash file-recovery-check.sh"
fi

if [ ! -r /etc/os-release ]; then
    error_exit "Cannot read /etc/os-release."
fi

# shellcheck disable=SC1091
. /etc/os-release

echo
separator
echo "              FILE RECOVERY CHECK"
echo "                      v$VERSION"
separator
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

install_packages() {
    case "${ID:-}" in
        ubuntu|debian)
            apt-get update -qq || return 1
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@"
            ;;
        fedora|rhel|centos|rocky|almalinux)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y "$@"
            elif command -v yum >/dev/null 2>&1; then
                yum install -y "$@"
            else
                return 1
            fi
            ;;
        arch)
            pacman -Sy --noconfirm "$@"
            ;;
        *)
            return 1
            ;;
    esac
}

MISSING_PACKAGES=""

command -v fls >/dev/null 2>&1 || MISSING_PACKAGES="$MISSING_PACKAGES sleuthkit"
command -v blkls >/dev/null 2>&1 || MISSING_PACKAGES="$MISSING_PACKAGES sleuthkit"
command -v lsof >/dev/null 2>&1 || MISSING_PACKAGES="$MISSING_PACKAGES lsof"
command -v lsblk >/dev/null 2>&1 || MISSING_PACKAGES="$MISSING_PACKAGES util-linux"
command -v findmnt >/dev/null 2>&1 || MISSING_PACKAGES="$MISSING_PACKAGES util-linux"

if [ -n "$MISSING_PACKAGES" ]; then
    echo "[INFO] Missing packages:$MISSING_PACKAGES"
    echo "[INFO] Attempting automatic installation..."

    # shellcheck disable=SC2086
    if ! install_packages $MISSING_PACKAGES; then
        echo "[WARN] Automatic package installation failed."
        echo "[WARN] Continuing with available commands."
    fi
fi

REQUIRED_COMMANDS="
lsblk
findmnt
blkid
df
strings
grep
awk
sed
sort
wc
head
tail
mktemp
"

for cmd in $REQUIRED_COMMANDS; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        error_exit "Required command not found: $cmd"
    fi
done

echo "[OK] Core commands are available."

if command -v fls >/dev/null 2>&1 && command -v blkls >/dev/null 2>&1; then
    HAVE_SLEUTHKIT=1
    echo "[OK] Sleuth Kit available."
else
    HAVE_SLEUTHKIT=0
    echo "[WARN] Sleuth Kit unavailable."
fi

if command -v lsof >/dev/null 2>&1; then
    HAVE_LSOF=1
else
    HAVE_LSOF=0
    echo "[WARN] lsof unavailable."
fi

# ----------------------------------------------------------------------
# Root filesystem
# ----------------------------------------------------------------------

section "[2] Root filesystem"

ROOT_SOURCE="$(findmnt -n -o SOURCE / 2>/dev/null || true)"
ROOT_FSTYPE="$(findmnt -n -o FSTYPE / 2>/dev/null || true)"

echo "Root source : ${ROOT_SOURCE:-unknown}"
echo "Filesystem  : ${ROOT_FSTYPE:-unknown}"

# ----------------------------------------------------------------------
# Block device inventory
# ----------------------------------------------------------------------

section "[3] Complete storage inventory"

lsblk -e7 -o \
NAME,PATH,SIZE,TYPE,FSTYPE,LABEL,UUID,MOUNTPOINTS,RO \
2>/dev/null || true

echo
echo "[INFO] Raw block devices visible to this environment:"
echo

BLOCK_LIST="$WORKDIR/block-devices.txt"

lsblk -nrpo NAME,TYPE 2>/dev/null |
awk '$2 == "disk" || $2 == "part" {print $1}' |
sort -u > "$BLOCK_LIST"

if [ -s "$BLOCK_LIST" ]; then
    cat "$BLOCK_LIST"
else
    echo "No block devices reported."
fi

# ----------------------------------------------------------------------
# Deleted-open files
# ----------------------------------------------------------------------

section "[4] Deleted files still held open"

DELETED_OPEN="$WORKDIR/deleted-open.txt"

if [ "$HAVE_LSOF" -eq 1 ]; then

    lsof +L1 2>/dev/null > "$DELETED_OPEN" || true

    if [ -s "$DELETED_OPEN" ]; then
        cat "$DELETED_OPEN"
    else
        echo "None detected."
    fi

else
    echo "Skipped: lsof is unavailable."
fi

# ----------------------------------------------------------------------
# Overlay filesystem
# ----------------------------------------------------------------------

section "[5] Overlay filesystem analysis"

OVERLAY_SOURCE=""

if [ "$ROOT_FSTYPE" = "overlay" ]; then

    echo "[INFO] Root is overlayfs."

    OVERLAY_OPTIONS="$(findmnt -n -o OPTIONS / 2>/dev/null || true)"

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

    echo "Upper directory : ${UPPER_DIR:-not exposed}"
    echo "Lower directory : ${LOWER_DIR:-not exposed}"

    if [ -n "$UPPER_DIR" ] && [ -d "$UPPER_DIR" ]; then

        echo
        echo "[INFO] Overlay upper directory is accessible."

        UPPER_SOURCE="$(
            findmnt -n -T "$UPPER_DIR" -o SOURCE 2>/dev/null || true
        )"

        UPPER_FSTYPE="$(
            findmnt -n -T "$UPPER_DIR" -o FSTYPE 2>/dev/null || true
        )"

        echo "Upper source     : ${UPPER_SOURCE:-unknown}"
        echo "Upper filesystem : ${UPPER_FSTYPE:-unknown}"

        if [ -n "$UPPER_SOURCE" ] &&
           [ -b "$UPPER_SOURCE" ] &&
           [ "$UPPER_FSTYPE" != "overlay" ]; then

            OVERLAY_SOURCE="$UPPER_SOURCE"

            echo "[OK] Overlay backing block device: $OVERLAY_SOURCE"

        else
            echo "[INFO] Overlay upper backing device is not directly accessible."
        fi

    else
        echo "[INFO] Overlay upper directory is not accessible."
    fi

else
    echo "Root filesystem is not overlayfs."
fi

# ----------------------------------------------------------------------
# Mounted filesystem inventory
# ----------------------------------------------------------------------

section "[6] Mounted filesystem inventory"

MOUNTS_FILE="$WORKDIR/mounts.txt"

findmnt -rn -o TARGET,SOURCE,FSTYPE |
while IFS= read -r line; do
    target="$(printf '%s\n' "$line" | awk '{print $1}')"
    source="$(printf '%s\n' "$line" | awk '{print $2}')"
    fstype="$(printf '%s\n' "$line" | awk '{print $3}')"

    case "$fstype" in
        proc|sysfs|devtmpfs|devpts|tmpfs|cgroup|cgroup2|overlay|squashfs)
            continue
            ;;
    esac

    printf '%s|%s|%s\n' "$target" "$source" "$fstype"
done > "$MOUNTS_FILE"

if [ -s "$MOUNTS_FILE" ]; then
    while IFS='|' read -r target source fstype; do
        printf '%-35s %-25s %s\n' "$target" "$source" "$fstype"
    done < "$MOUNTS_FILE"
else
    echo "No directly analyzable mounted filesystems found."
fi

# ----------------------------------------------------------------------
# Build analysis target list
#
# TARGET format:
# source|filesystem|mountpoint|type
# ----------------------------------------------------------------------

TARGETS="$WORKDIR/targets.txt"
: > "$TARGETS"

# Mounted real filesystems.
if [ -s "$MOUNTS_FILE" ]; then

    while IFS='|' read -r target source fstype; do

        if [ -b "$source" ]; then
            printf '%s|%s|%s|mounted\n' \
                "$source" "$fstype" "$target" >> "$TARGETS"
        fi

    done < "$MOUNTS_FILE"

fi

# Overlay upper backing filesystem.
if [ -n "$OVERLAY_SOURCE" ]; then

    OVERLAY_FSTYPE="$(
        findmnt -n -T "$UPPER_DIR" -o FSTYPE 2>/dev/null || true
    )"

    printf '%s|%s|%s|overlay-upper\n' \
        "$OVERLAY_SOURCE" \
        "${OVERLAY_FSTYPE:-unknown}" \
        "$UPPER_DIR" >> "$TARGETS"

fi

# Unmounted block devices / partitions.
#
# We intentionally only select partitions/filesystems that blkid
# identifies. Whole disks are not sent directly to fls/blkls here.

UNMOUNTED="$WORKDIR/unmounted.txt"

while IFS= read -r dev; do

    [ -b "$dev" ] || continue

    fstype="$(blkid -o value -s TYPE "$dev" 2>/dev/null || true)"

    [ -n "$fstype" ] || continue

    case "$fstype" in
        swap)
            continue
            ;;
        iso9660|udf)
            # Read-only filesystems can still contain useful data,
            # but deleted-file recovery generally isn't applicable.
            continue
            ;;
        *)
            ;;
    esac

    mounted="$(findmnt -n -S "$dev" -o TARGET 2>/dev/null || true)"

    if [ -z "$mounted" ]; then
        printf '%s|%s|unmounted|unmounted\n' \
            "$dev" "$fstype" >> "$UNMOUNTED"
    fi

done < "$BLOCK_LIST"

if [ -s "$UNMOUNTED" ]; then
    cat "$UNMOUNTED" >> "$TARGETS"
fi

# Remove duplicate target sources.
sort -t'|' -k1,1 -u "$TARGETS" -o "$TARGETS"

# ----------------------------------------------------------------------
# Swap inventory
# ----------------------------------------------------------------------

section "[7] Swap storage"

SWAP_FILE="$WORKDIR/swap.txt"

if [ -r /proc/swaps ]; then
    cat /proc/swaps

    awk 'NR > 1 && $1 != "" {print $1}' /proc/swaps > "$SWAP_FILE"

    if [ -s "$SWAP_FILE" ]; then
        echo
        echo "[INFO] Active swap devices/files detected."
        echo "[INFO] Swap is not analyzed with filesystem recovery tools."
    fi
else
    echo "Swap information unavailable."
fi

# ----------------------------------------------------------------------
# Analysis functions
# ----------------------------------------------------------------------

analyze_target() {

    local source="$1"
    local fstype="$2"
    local mountpoint="$3"
    local target_type="$4"

    local safe_name
    safe_name="$(printf '%s' "$source" | sed 's#[^A-Za-z0-9._-]#_#g')"

    local dir="$WORKDIR/$safe_name"

    mkdir -p "$dir"

    local deleted_file="$dir/deleted.txt"
    local deleted_error="$dir/deleted-error.txt"

    local strings_file="$dir/strings.txt"
    local string_error="$dir/strings-error.txt"

    local filenames_file="$dir/filenames.txt"
    local interesting_file="$dir/interesting.txt"

    local deleted_count=0
    local string_count=0
    local filename_count=0
    local interesting_count=0
    local unalloc_size=0

    echo
    separator
    echo "ANALYZING STORAGE"
    separator

    echo "Source      : $source"
    echo "Filesystem  : $fstype"
    echo "Mountpoint  : $mountpoint"
    echo "Target type : $target_type"

    if [ ! -b "$source" ]; then
        echo
        echo "[SKIP] Source is no longer an accessible block device."
        return
    fi

    # --------------------------------------------------------------
    # Basic device information
    # --------------------------------------------------------------

    echo
    echo "Device information:"
    lsblk -no NAME,SIZE,RO,FSTYPE,MOUNTPOINTS "$source" 2>/dev/null || true

    # --------------------------------------------------------------
    # Deleted entries
    # --------------------------------------------------------------

    if [ "$HAVE_SLEUTHKIT" -eq 1 ]; then

        echo
        echo "[1] Deleted filesystem entries"

        fls -r -d -l "$source" \
            2>"$deleted_error" |
        awk -v max="$MAX_FINDINGS" -v output="$deleted_file" '
            {
                total++

                if (total <= max) {
                    print > output
                }
            }

            END {
                print total
            }
        ' > "$dir/deleted-count"

        deleted_count="$(safe_number "$(cat "$dir/deleted-count" 2>/dev/null || echo 0)")"

        echo "Deleted entries: $deleted_count"

        if [ "$deleted_count" -gt 0 ]; then

            if [ "$deleted_count" -gt "$MAX_FINDINGS" ]; then
                echo "Only first $MAX_FINDINGS retained."
            fi

            echo
            cat "$deleted_file" 2>/dev/null || true
        fi

        if [ -s "$deleted_error" ]; then
            echo
            echo "[INFO] fls messages:"
            cat "$deleted_error"
        fi

    else

        echo
        echo "[1] Deleted filesystem entries"
        echo "Skipped: Sleuth Kit unavailable."

    fi

    # --------------------------------------------------------------
    # Unallocated space
    # --------------------------------------------------------------

    if [ "$HAVE_SLEUTHKIT" -eq 1 ]; then

        echo
        echo "[2] Unallocated filesystem data"

        blkls "$source" \
            2>"$dir/blkls-error" |
        head -c "$MAX_STRING_BYTES" > "$dir/unallocated-sample"

        # Obtain total size separately.
        unalloc_size="$(
            blkls "$source" 2>/dev/null |
            wc -c
        )"

        unalloc_size="$(safe_number "$unalloc_size")"

        echo "Unallocated data: $(human_size "$unalloc_size")"

        if [ -s "$dir/blkls-error" ]; then
            echo
            echo "[INFO] blkls messages:"
            cat "$dir/blkls-error"
        fi

    else

        echo
        echo "[2] Unallocated filesystem data"
        echo "Skipped: Sleuth Kit unavailable."

    fi

    # --------------------------------------------------------------
    # Printable strings
    # --------------------------------------------------------------

    if [ "$HAVE_SLEUTHKIT" -eq 1 ]; then

        echo
        echo "[3] Printable strings from unallocated data"

        if [ -s "$dir/unallocated-sample" ]; then

            strings -a -t d -n 6 "$dir/unallocated-sample" \
                2>"$string_error" |
            awk -v max="$MAX_FINDINGS" -v output="$strings_file" '
                {
                    total++

                    if (total <= max) {
                        print > output
                    }
                }

                END {
                    print total
                }
            ' > "$dir/string-count"

            string_count="$(safe_number "$(cat "$dir/string-count" 2>/dev/null || echo 0)")"

        else
            string_count=0
            : > "$strings_file"
        fi

        echo "Readable string records: $string_count"

    else

        echo
        echo "[3] Printable strings"
        echo "Skipped: Sleuth Kit unavailable."

    fi

    # --------------------------------------------------------------
    # Filename-like remnants
    # --------------------------------------------------------------

    echo
    echo "[4] Filename-like remnants"

    : > "$filenames_file"

    if [ -s "$strings_file" ]; then

        grep -Eai \
        '(^|[[:space:]/])[A-Za-z0-9._@+/-]+\.(txt|log|conf|cfg|ini|json|xml|yaml|yml|csv|sql|db|sqlite|sqlite3|jpg|jpeg|png|gif|webp|bmp|pdf|doc|docx|xls|xlsx|ppt|pptx|zip|tar|gz|tgz|bz2|xz|7z|rar|php|html|htm|js|ts|jsx|tsx|py|rb|go|java|c|cpp|h|hpp|sh|bash|env|key|pem|crt|cer|bak|old|tmp)([^A-Za-z0-9._-]|$)' \
        "$strings_file" 2>/dev/null |
        sed -E 's/^[[:space:]]*[0-9]+:[[:space:]]*//' |
        sort -u |
        head -n "$MAX_FINDINGS" > "$filenames_file" || true

    fi

    filename_count="$(safe_number "$(wc -l < "$filenames_file" 2>/dev/null || echo 0)")"

    echo "Filename candidates: $filename_count"

    if [ "$filename_count" -gt 0 ]; then
        cat "$filenames_file"
    fi

    # --------------------------------------------------------------
    # Interesting text
    # --------------------------------------------------------------

    echo
    echo "[5] Interesting text"

    : > "$interesting_file"

    if [ -s "$strings_file" ]; then

        grep -Eai \
        '(password|passwd|secret|api[_-]?key|authorization|bearer|private[_-]?key|database|mysql|postgres|mongodb|redis|BEGIN [A-Z ]+ KEY|/home/|/root/|/var/www/|/etc/|/opt/|/srv/|\.ssh/|docker|kubernetes)' \
        "$strings_file" 2>/dev/null |
        sort -u |
        head -n "$MAX_INTERESTING" > "$interesting_file" || true

    fi

    interesting_count="$(safe_number "$(wc -l < "$interesting_file" 2>/dev/null || echo 0)")"

    echo "Interesting-text candidates: $interesting_count"

    if [ "$interesting_count" -gt 0 ]; then
        cat "$interesting_file"
    fi

    # --------------------------------------------------------------
    # Per-device result
    # --------------------------------------------------------------

    echo
    echo "[6] Storage result"

    echo "Source                  : $source"
    echo "Filesystem              : $fstype"
    echo "Mountpoint              : $mountpoint"
    echo "Unallocated data        : $(human_size "$unalloc_size")"
    echo "Deleted entries         : $deleted_count"
    echo "Readable strings        : $string_count"
    echo "Filename candidates     : $filename_count"
    echo "Interesting text        : $interesting_count"

    if [ "$deleted_count" -gt 0 ] ||
       [ "$filename_count" -gt 0 ] ||
       [ "$interesting_count" -gt 0 ]; then

        echo
        echo "RESULT: POTENTIAL REMNANTS DETECTED"

    else

        echo
        echo "RESULT: NO OBVIOUS REMNANTS DETECTED"

    fi

    # --------------------------------------------------------------
    # Save per-device report
    # --------------------------------------------------------------

    {
        echo "SOURCE: $source"
        echo "FILESYSTEM: $fstype"
        echo "MOUNTPOINT: $mountpoint"
        echo "TARGET TYPE: $target_type"
        echo "UNALLOCATED BYTES: $unalloc_size"
        echo "DELETED ENTRIES: $deleted_count"
        echo "READABLE STRINGS: $string_count"
        echo "FILENAME CANDIDATES: $filename_count"
        echo "INTERESTING TEXT: $interesting_count"
        echo

        if [ "$deleted_count" -gt 0 ] ||
           [ "$filename_count" -gt 0 ] ||
           [ "$interesting_count" -gt 0 ]; then
            echo "RESULT: POTENTIAL REMNANTS DETECTED"
        else
            echo "RESULT: NO OBVIOUS REMNANTS DETECTED"
        fi

        echo
        echo "--- DELETED ENTRIES ---"
        cat "$deleted_file" 2>/dev/null || true

        echo
        echo "--- FILENAME CANDIDATES ---"
        cat "$filenames_file" 2>/dev/null || true

        echo
        echo "--- INTERESTING TEXT ---"
        cat "$interesting_file" 2>/dev/null || true

    } > "$dir/report.txt"

    # Global result record.
    printf '%s|%s|%s|%s|%s|%s|%s|%s\n' \
        "$source" \
        "$fstype" \
        "$mountpoint" \
        "$target_type" \
        "$unalloc_size" \
        "$deleted_count" \
        "$filename_count" \
        "$interesting_count" \
        >> "$WORKDIR/results.txt"
}

# ----------------------------------------------------------------------
# Analyze every target
# ----------------------------------------------------------------------

section "[8] Storage analysis"

: > "$WORKDIR/results.txt"

if [ ! -s "$TARGETS" ]; then

    echo "No filesystem targets are available for analysis."

else

    TARGET_COUNT="$(wc -l < "$TARGETS")"
    echo "Analysis targets: $TARGET_COUNT"
    echo

    while IFS='|' read -r source fstype mountpoint target_type; do

        [ -n "$source" ] || continue

        analyze_target \
            "$source" \
            "$fstype" \
            "$mountpoint" \
            "$target_type"

    done < "$TARGETS"

fi

# ----------------------------------------------------------------------
# Final storage summary
# ----------------------------------------------------------------------

section "[9] Final storage summary"

if [ -s "$WORKDIR/results.txt" ]; then

    printf '%-16s %-12s %-12s %-12s %-12s\n' \
        "SOURCE" "FILESYSTEM" "UNALLOCATED" "DELETED" "INTERESTING"

    echo "-----------------------------------------------------------------------"

    while IFS='|' read -r source fstype mountpoint target_type unalloc deleted filenames interesting; do

        printf '%-16s %-12s %-12s %-12s %-12s\n' \
            "$source" \
            "$fstype" \
            "$(human_size "$unalloc")" \
            "$deleted" \
            "$interesting"

    done < "$WORKDIR/results.txt"

else

    echo "No filesystem analysis results."

fi

# ----------------------------------------------------------------------
# Final assessment
# ----------------------------------------------------------------------

section "[10] Overall result"

TOTAL_DELETED=0
TOTAL_FILENAMES=0
TOTAL_INTERESTING=0
TARGET_COUNT=0

if [ -s "$WORKDIR/results.txt" ]; then

    while IFS='|' read -r source fstype mountpoint target_type unalloc deleted filenames interesting; do

        TARGET_COUNT=$((TARGET_COUNT + 1))
        TOTAL_DELETED=$((TOTAL_DELETED + deleted))
        TOTAL_FILENAMES=$((TOTAL_FILENAMES + filenames))
        TOTAL_INTERESTING=$((TOTAL_INTERESTING + interesting))

    done < "$WORKDIR/results.txt"

fi

echo "Filesystem targets analyzed : $TARGET_COUNT"
echo "Deleted entries             : $TOTAL_DELETED"
echo "Filename candidates         : $TOTAL_FILENAMES"
echo "Interesting-text candidates : $TOTAL_INTERESTING"

echo

if [ "$TARGET_COUNT" -eq 0 ]; then

    echo "RESULT: NO FILESYSTEM ANALYSIS AVAILABLE"

elif [ "$TOTAL_DELETED" -gt 0 ] ||
     [ "$TOTAL_FILENAMES" -gt 0 ] ||
     [ "$TOTAL_INTERESTING" -gt 0 ]; then

    echo "RESULT: POTENTIAL RECOVERABLE REMNANTS DETECTED"

else

    echo "RESULT: NO OBVIOUS RECOVERABLE REMNANTS DETECTED"

fi

echo
echo "IMPORTANT LIMITATIONS:"
echo
echo "1. Only storage actually exposed to this environment is analyzed."
echo "2. Visibility of a block device does not prove ownership or isolation failure."
echo "3. Generic strings are not proof that data belonged to another environment."
echo "4. Deleted entries may be stale, unrelated, or already reallocated."
echo "5. Overlayfs may hide its backing filesystem."
echo "6. Unmounted filesystems are inspected without mounting or modifying them."
echo "7. Swap is identified separately and is not interpreted as a normal filesystem."
echo "8. Absence of recovered data does not prove secure erasure."
echo "9. A unique controlled canary is stronger evidence than generic strings."
echo "10. Results should be correlated with the storage/device allocation model."

# ----------------------------------------------------------------------
# Full report
# ----------------------------------------------------------------------

section "[11] Saving report"

{
    echo "FILE RECOVERY CHECK"
    echo "Version: $VERSION"
    echo "Date: $(date)"
    echo "Host: $(hostname)"
    echo "Kernel: $(uname -r)"
    echo "OS: ${PRETTY_NAME:-Unknown}"
    echo

    echo "ROOT SOURCE: ${ROOT_SOURCE:-unknown}"
    echo "ROOT FILESYSTEM: ${ROOT_FSTYPE:-unknown}"
    echo

    echo "=== STORAGE INVENTORY ==="
    lsblk -e7 -o \
        NAME,PATH,SIZE,TYPE,FSTYPE,LABEL,UUID,MOUNTPOINTS,RO \
        2>/dev/null || true

    echo
    echo "=== ANALYSIS RESULTS ==="

    if [ -s "$WORKDIR/results.txt" ]; then
        cat "$WORKDIR/results.txt"
    else
        echo "No filesystem results."
    fi

    echo
    echo "=== OVERALL ==="
    echo "Filesystem targets analyzed: $TARGET_COUNT"
    echo "Deleted entries: $TOTAL_DELETED"
    echo "Filename candidates: $TOTAL_FILENAMES"
    echo "Interesting-text candidates: $TOTAL_INTERESTING"

    echo
    echo "=== NOTES ==="
    echo "Only storage actually exposed to this environment was considered."
    echo "No unmounted filesystem was mounted or modified."
    echo "Generic remnants are not proof of data ownership."
    echo "Controlled canary evidence provides stronger attribution."

} > "$REPORT"

echo "Report saved:"
echo "$REPORT"

echo
separator
echo "Scan complete."
separator
