#!/usr/bin/env bash

# ============================================================
# FILE RECOVERY CHECK v5.3
#
# Read-only storage/remnant analysis
#
# Usage:
#   sudo bash file-recovery-check.sh
#
# Full raw scan:
#   sudo bash file-recovery-check.sh --full-raw
#
# IMPORTANT:
#   This script never mounts or writes to discovered block
#   devices/filesystems.
# ============================================================

set -u
set -o pipefail

VERSION="5.3"
FULL_RAW=0

for arg in "$@"; do
    case "$arg" in
        --full-raw)
            FULL_RAW=1
            ;;
        -h|--help)
            cat <<'EOF'

FILE RECOVERY CHECK v5.3

Usage:
  sudo bash file-recovery-check.sh
  sudo bash file-recovery-check.sh --full-raw

Default:
  - complete visible block-device inventory
  - filesystem signature probing
  - mounted filesystem discovery
  - unmounted partition discovery
  - LVM logical-volume discovery when available
  - overlayfs inspection
  - deleted-open inspection
  - Sleuth Kit filesystem analysis
  - bounded raw-device sampling

--full-raw:
  Fully scan unknown/raw devices.

WARNING:
  Full raw scans can take a very long time on multi-TB devices.

EOF
            exit 0
            ;;
        *)
            echo "Unknown option: $arg"
            exit 1
            ;;
    esac
done


# ============================================================
# WORK AREA
# ============================================================

WORKDIR="/tmp/file-recovery-check-$$"
mkdir -p "$WORKDIR"

DEVICES_FILE="$WORKDIR/devices.txt"
TARGETS_FILE="$WORKDIR/targets.txt"
MOUNTS_FILE="$WORKDIR/mounts.txt"

FINDINGS_FILE="$WORKDIR/findings.txt"
RAW_FINDINGS_FILE="$WORKDIR/raw-findings.txt"
ERROR_FILE="$WORKDIR/errors.txt"

touch \
    "$DEVICES_FILE" \
    "$TARGETS_FILE" \
    "$MOUNTS_FILE" \
    "$FINDINGS_FILE" \
    "$RAW_FINDINGS_FILE" \
    "$ERROR_FILE"

ANALYZED_TARGETS=0
UNKNOWN_TARGETS=0
RAW_TARGETS=0

DELETED_DISK_OBJECTS=0
DELETED_MEMORY_OBJECTS=0

TEXT_CANDIDATES=0
RAW_CANDIDATES=0

cleanup() {
    rm -rf "$WORKDIR"
}

trap cleanup EXIT INT TERM


# ============================================================
# OUTPUT
# ============================================================

if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    BLUE='\033[0;34m'
    CYAN='\033[0;36m'
    RESET='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    CYAN=''
    RESET=''
fi

info() {
    printf "${BLUE}[INFO]${RESET} %s\n" "$*"
}

start_msg() {
    printf "${CYAN}[START]${RESET} %s\n" "$*"
}

done_msg() {
    printf "${GREEN}[DONE]${RESET} %s\n" "$*"
}

ok() {
    printf "${GREEN}[OK]${RESET} %s\n" "$*"
}

warn() {
    printf "${YELLOW}[WARN]${RESET} %s\n" "$*"
}

err() {
    printf "${RED}[ERROR]${RESET} %s\n" "$*" >&2
}

section() {
    printf "\n${CYAN}============================================================${RESET}\n"
    printf "${CYAN}%s${RESET}\n" "$*"
    printf "${CYAN}============================================================${RESET}\n"
}


# ============================================================
# ROOT
# ============================================================

if [ "$(id -u)" -ne 0 ]; then
    err "Run this script with sudo/root."
    exit 1
fi


# ============================================================
# HEADER
# ============================================================

section "FILE RECOVERY CHECK"

printf "Version : %s\n" "$VERSION"
printf "Host    : %s\n" "$(hostname 2>/dev/null || echo unknown)"
printf "Kernel  : %s\n" "$(uname -r 2>/dev/null || echo unknown)"

if [ -f /etc/os-release ]; then
    . /etc/os-release
    printf "OS      : %s\n" "${PRETTY_NAME:-unknown}"
fi

printf "Started : %s\n" "$(date)"

if [ "$FULL_RAW" -eq 1 ]; then
    warn "FULL RAW MODE ENABLED"
fi


# ============================================================
# DEPENDENCIES
# ============================================================

install_missing() {

    local missing=()

    command -v lsof >/dev/null 2>&1 || missing+=("lsof")
    command -v fls >/dev/null 2>&1 || missing+=("sleuthkit")
    command -v blkls >/dev/null 2>&1 || missing+=("sleuthkit")

    if [ "${#missing[@]}" -eq 0 ]; then
        ok "Core analysis commands are available."
        return
    fi

    info "Missing packages: ${missing[*]}"

    if command -v apt-get >/dev/null 2>&1; then

        info "Attempting automatic installation..."

        export DEBIAN_FRONTEND=noninteractive

        if apt-get update -qq >>"$ERROR_FILE" 2>&1 &&
           apt-get install -y "${missing[@]}" >>"$ERROR_FILE" 2>&1; then

            ok "Required packages installed."

        else

            warn "Automatic installation failed."
            warn "See $ERROR_FILE"

        fi

    else

        warn "apt-get unavailable."

    fi
}

install_missing


# ============================================================
# SLEUTH KIT
# ============================================================

if command -v fls >/dev/null 2>&1 &&
   command -v blkls >/dev/null 2>&1; then

    SLEUTHKIT=1
    ok "Sleuth Kit available."

else

    SLEUTHKIT=0
    warn "Sleuth Kit unavailable."

fi


# ============================================================
# ROOT FILESYSTEM
# ============================================================

section "ROOT FILESYSTEM"

ROOT_SOURCE="$(findmnt -n -o SOURCE / 2>/dev/null || true)"
ROOT_FSTYPE="$(findmnt -n -o FSTYPE / 2>/dev/null || true)"

printf "Root source : %s\n" "${ROOT_SOURCE:-unknown}"
printf "Filesystem  : %s\n" "${ROOT_FSTYPE:-unknown}"


# ============================================================
# HELPERS
# ============================================================

normalize_source() {

    local s="$1"

    case "$s" in
        /dev/*\[*\])
            printf '%s\n' "${s%%[*}"
            ;;
        *)
            printf '%s\n' "$s"
            ;;
    esac
}


device_size_bytes() {

    local dev="$1"

    blockdev --getsize64 "$dev" 2>/dev/null || echo 0
}


human_size() {

    local bytes="${1:-0}"

    awk -v b="$bytes" '
    BEGIN {
        if (b >= 1099511627776)
            printf "%.2f TiB", b/1099511627776;
        else if (b >= 1073741824)
            printf "%.2f GiB", b/1073741824;
        else if (b >= 1048576)
            printf "%.2f MiB", b/1048576;
        else if (b >= 1024)
            printf "%.2f KiB", b/1024;
        else
            printf "%d B", b;
    }'
}


safe_name() {
    printf '%s' "$1" | tr '/: ' '___'
}


# ============================================================
# COMPLETE BLOCK DEVICE DISCOVERY
# ============================================================

section "BLOCK DEVICE INVENTORY"

: > "$DEVICES_FILE"

if command -v lsblk >/dev/null 2>&1; then

    lsblk \
        -e 7 \
        -o NAME,PATH,SIZE,TYPE,FSTYPE,LABEL,UUID,MOUNTPOINTS,RO \
        2>/dev/null || true

    echo
    info "Collecting all visible block devices and partitions..."

    # IMPORTANT:
    # Do NOT use lsblk -d here.
    # -d means "top-level devices only" and hides partitions.

    lsblk \
        -r \
        -n \
        -e 7 \
        -o PATH,TYPE \
        2>/dev/null |
    awk '
        $2=="disk" ||
        $2=="part" ||
        $2=="lvm" ||
        $2=="crypt" {
            print $1
        }
    ' |
    sort -u >> "$DEVICES_FILE"

fi


# Also inspect common device names directly.
# This catches devices that lsblk may not list normally.

for pattern in \
    "/dev/vd[a-z]" \
    "/dev/vd[a-z][0-9]*" \
    "/dev/sd[a-z]" \
    "/dev/sd[a-z][0-9]*" \
    "/dev/xvd[a-z]" \
    "/dev/xvd[a-z][0-9]*" \
    "/dev/nvme*n*" \
    "/dev/nvme*n*p*" \
    "/dev/mmcblk*" \
    "/dev/mmcblk*p*"
do

    for d in $pattern; do

        if [ -b "$d" ]; then
            printf '%s\n' "$d" >> "$DEVICES_FILE"
        fi

    done

done


# Device-mapper nodes.
if [ -d /dev/mapper ]; then

    for d in /dev/mapper/*; do

        if [ -b "$d" ]; then
            printf '%s\n' "$d" >> "$DEVICES_FILE"
        fi

    done

fi


sort -u "$DEVICES_FILE" -o "$DEVICES_FILE"

printf "\nVisible block devices:\n"

cat "$DEVICES_FILE"

DEVICE_COUNT="$(grep -c '^/dev/' "$DEVICES_FILE" 2>/dev/null || echo 0)"

printf "\nTotal block devices discovered: %s\n" "$DEVICE_COUNT"


if [ "$DEVICE_COUNT" -eq 0 ]; then

    err "No block devices were discovered."
    err "This is a discovery failure, not evidence that storage is clean."

fi


# ============================================================
# DELETED-OPEN FILES
# ============================================================

section "DELETED OPEN FILES"

if command -v lsof >/dev/null 2>&1; then

    start_msg "Checking deleted-open objects..."

    LSOF_OUT="$WORKDIR/lsof.txt"

    lsof +L1 2>/dev/null > "$LSOF_OUT" || true

    if [ -s "$LSOF_OUT" ]; then

        cat "$LSOF_OUT"

        # Examine DEVICE column.
        #
        # DEVICE 0,1 is normally memory-backed / virtual.
        # Do not treat it as persistent disk storage.

        while IFS= read -r line; do

            [ -n "$line" ] || continue

            device_field="$(printf '%s\n' "$line" | awk '{print $5}')"

            case "$device_field" in

                0,1|0,0)
                    DELETED_MEMORY_OBJECTS=$(
                        printf '%s' "$DELETED_MEMORY_OBJECTS" |
                        awk '{print $1+1}'
                    )
                    ;;

                *)
                    DELETED_DISK_OBJECTS=$(
                        printf '%s' "$DELETED_DISK_OBJECTS" |
                        awk '{print $1+1}'
                    )
                    ;;

            esac

        done < <(tail -n +2 "$LSOF_OUT")

        printf "\nMemory/virtual deleted objects : %s\n" \
            "$DELETED_MEMORY_OBJECTS"

        printf "Potential disk-backed objects   : %s\n" \
            "$DELETED_DISK_OBJECTS"

        if [ "$DELETED_DISK_OBJECTS" -gt 0 ]; then
            warn "Disk-backed deleted-open objects require review."
        else
            ok "No disk-backed deleted-open objects detected."
        fi

    else

        ok "No deleted-open objects detected."

    fi

else

    warn "lsof unavailable."

fi


# ============================================================
# OVERLAY
# ============================================================

section "OVERLAYFS"

if [ "$ROOT_FSTYPE" = "overlay" ]; then

    info "Root filesystem is overlayfs."

    OVERLAY_OPTIONS="$(
        findmnt -n -t overlay -o OPTIONS / 2>/dev/null || true
    )"

    UPPER="$(
        printf '%s\n' "$OVERLAY_OPTIONS" |
        tr ',' '\n' |
        sed -n 's/^upperdir=//p' |
        head -n 1
    )"

    LOWER="$(
        printf '%s\n' "$OVERLAY_OPTIONS" |
        tr ',' '\n' |
        sed -n 's/^lowerdir=//p' |
        head -n 1
    )"

    printf "Upper directory : %s\n" "${UPPER:-not exposed}"
    printf "Lower directory : %s\n" "${LOWER:-not exposed}"

    if [ -n "${UPPER:-}" ] && [ -d "$UPPER" ]; then

        ok "Overlay upper directory is accessible."

        info "Checking overlay whiteouts..."

        find "$UPPER" \
            -xdev \
            \( -name '.wh.*' -o -name '.wh..wh..opq' \) \
            -print 2>/dev/null |
            head -n 200 || true

    else

        warn "Overlay upper directory is not accessible."

    fi

else

    info "Root filesystem is not overlayfs."

fi


# ============================================================
# MOUNT INVENTORY
# ============================================================

section "MOUNTED FILESYSTEM INVENTORY"

: > "$MOUNTS_FILE"

findmnt -rn -o TARGET,SOURCE,FSTYPE 2>/dev/null |
while IFS= read -r line; do

    target="$(printf '%s\n' "$line" | awk '{print $1}')"
    raw_source="$(printf '%s\n' "$line" | awk '{print $2}')"
    fstype="$(printf '%s\n' "$line" | awk '{print $3}')"

    source="$(normalize_source "$raw_source")"

    [ -n "$target" ] || continue
    [ -n "$source" ] || continue

    printf '%s|%s|%s\n' \
        "$target" \
        "$source" \
        "$fstype"

done > "$MOUNTS_FILE"

cat "$MOUNTS_FILE"


# ============================================================
# FILESYSTEM PROBE
# ============================================================

probe_type() {

    local dev="$1"
    local out=""
    local type=""

    [ -b "$dev" ] || {
        echo "NOT_BLOCK_DEVICE"
        return
    }

    # Fast blkid probe.
    out="$(blkid -p -o export "$dev" 2>/dev/null || true)"

    type="$(
        printf '%s\n' "$out" |
        sed -n 's/^TYPE=//p' |
        head -n 1
    )"

    if [ -n "$type" ]; then
        printf '%s\n' "$type"
        return
    fi

    # file fallback.
    out="$(file -sL "$dev" 2>/dev/null || true)"

    case "$out" in

        *"SGI XFS filesystem"*|*"XFS filesystem"*)
            echo "xfs"
            ;;

        *"ext4 filesystem"*)
            echo "ext4"
            ;;

        *"ext3 filesystem"*)
            echo "ext3"
            ;;

        *"ext2 filesystem"*)
            echo "ext2"
            ;;

        *"LVM2_member"*)
            echo "LVM2_member"
            ;;

        *"crypto_LUKS"*)
            echo "crypto_LUKS"
            ;;

        *"swap"*)
            echo "swap"
            ;;

        *)
            echo "UNKNOWN"
            ;;

    esac
}


# ============================================================
# TARGET MANAGEMENT
# ============================================================

add_target() {

    local dev="$1"
    local type="$2"
    local fstype="$3"
    local source="$4"

    [ -n "$dev" ] || return
    [ -b "$dev" ] || return

    printf '%s|%s|%s|%s\n' \
        "$dev" \
        "$type" \
        "$fstype" \
        "$source" >> "$TARGETS_FILE"
}


# ============================================================
# ADD EVERY BLOCK DEVICE
# ============================================================

section "STORAGE DISCOVERY"

: > "$TARGETS_FILE"

start_msg "Probing every visible block device..."

while IFS= read -r dev; do

    [ -n "$dev" ] || continue
    [ -b "$dev" ] || continue

    printf "[PROBE] %-30s " "$dev"

    fstype="$(probe_type "$dev")"

    printf "%s\n" "$fstype"

    case "$fstype" in

        swap)
            add_target "$dev" "swap" "$fstype" "block-device"
            ;;

        LVM2_member)
            add_target "$dev" "lvm-pv" "$fstype" "block-device"
            ;;

        crypto_LUKS)
            add_target "$dev" "encrypted" "$fstype" "block-device"
            ;;

        UNKNOWN)
            add_target "$dev" "unknown" "$fstype" "block-device"
            ;;

        *)
            add_target "$dev" "filesystem" "$fstype" "block-device"
            ;;

    esac

done < "$DEVICES_FILE"

done_msg "Block-device probing complete."


# ============================================================
# MOUNTED DEVICE SOURCES
# ============================================================

start_msg "Adding mounted block-device sources..."

while IFS='|' read -r target source fstype; do

    source="$(normalize_source "$source")"

    if [ -b "$source" ]; then

        detected="$(probe_type "$source")"

        if [ "$detected" != "UNKNOWN" ]; then
            fstype="$detected"
        fi

        add_target \
            "$source" \
            "mounted" \
            "$fstype" \
            "$target"

    fi

done < "$MOUNTS_FILE"

done_msg "Mounted storage discovery complete."


# ============================================================
# LVM
# ============================================================

section "LVM DISCOVERY"

if command -v lvs >/dev/null 2>&1; then

    LVM_COUNT=0

    while IFS='|' read -r lv vg attr size path; do

        [ -n "$path" ] || continue
        [ -b "$path" ] || continue

        LVM_COUNT=$((LVM_COUNT + 1))

        fstype="$(probe_type "$path")"

        add_target \
            "$path" \
            "lvm" \
            "$fstype" \
            "LVM:$vg"

    done < <(
        lvs \
            --noheadings \
            --separator='|' \
            -o lv_name,vg_name,lv_attr,lv_size,lv_path \
            2>/dev/null |
        sed 's/^ *//;s/ *$//'
    )

    printf "LVM logical volumes: %s\n" "$LVM_COUNT"

else

    info "lvs command unavailable; using device-mapper discovery."

    if [ -d /dev/mapper ]; then

        for dev in /dev/mapper/*; do

            [ -b "$dev" ] || continue

            # Skip control node.
            [ "$(basename "$dev")" = "control" ] && continue

            fstype="$(probe_type "$dev")"

            add_target \
                "$dev" \
                "device-mapper" \
                "$fstype" \
                "/dev/mapper"

        done

    fi

fi


# ============================================================
# ACTIVE SWAP
# ============================================================

section "SWAP"

if [ -r /proc/swaps ]; then

    cat /proc/swaps

    while read -r filename type size used priority; do

        [ "$filename" = "Filename" ] && continue
        [ -n "${filename:-}" ] || continue

        if [ -b "$filename" ]; then

            add_target \
                "$filename" \
                "swap" \
                "swap" \
                "active-swap"

        fi

    done < /proc/swaps

fi


# ============================================================
# DEDUPLICATE
# ============================================================

sort -t'|' -k1,1 -u "$TARGETS_FILE" -o "$TARGETS_FILE"


# ============================================================
# TARGET LIST
# ============================================================

section "DISCOVERED STORAGE TARGETS"

printf "%-38s %-16s %-18s %s\n" \
    "DEVICE" \
    "TYPE" \
    "FILESYSTEM" \
    "SOURCE"

printf "%-38s %-16s %-18s %s\n" \
    "--------------------------------------" \
    "----------------" \
    "------------------" \
    "----------------"

while IFS='|' read -r dev type fstype source; do

    size="$(device_size_bytes "$dev")"

    printf "%-38s %-16s %-18s %s (%s)\n" \
        "$dev" \
        "$type" \
        "$fstype" \
        "$source" \
        "$(human_size "$size")"

done < "$TARGETS_FILE"

TARGET_COUNT="$(
    grep -c '^/dev/' "$TARGETS_FILE" 2>/dev/null || echo 0
)"

printf "\nTotal analysis targets: %s\n" "$TARGET_COUNT"

if [ "$TARGET_COUNT" -eq 0 ]; then

    err "DISCOVERY ERROR: zero storage targets were created."
    err "The script will not report this environment as clean."

fi


# ============================================================
# INTERESTING STRING EXTRACTION
# ============================================================

extract_candidates() {

    local input="$1"
    local output="$2"

    [ -f "$input" ] || return 0

    strings -a -n 8 "$input" 2>/dev/null |
    grep -Ei \
        'password|passwd|username|authorization|bearer |api[_-]?key|secret|private[_-]?key|access[_-]?token|refresh[_-]?token|database|mysql|postgres|mongodb|redis|ssh-rsa|BEGIN .*PRIVATE KEY|AWS_ACCESS_KEY|AWS_SECRET|github[_-]?token|credit.?card' |
    sed 's/^[[:space:]]*//' |
    head -n 500 > "$output" || true
}


# ============================================================
# FILESYSTEM ANALYSIS
# ============================================================

analyze_filesystem() {

    local dev="$1"
    local type="$2"
    local fstype="$3"
    local source="$4"

    section "ANALYZING $dev"

    printf "Device     : %s\n" "$dev"
    printf "Type       : %s\n" "$type"
    printf "Filesystem : %s\n" "$fstype"
    printf "Source     : %s\n" "$source"
    printf "Size       : %s\n" \
        "$(human_size "$(device_size_bytes "$dev")")"


    case "$fstype" in

        ext2|ext3|ext4|xfs|ntfs|fat|vfat|exfat|hfs|hfsplus|ufs)

            if [ "$SLEUTHKIT" -eq 0 ]; then

                warn "$dev: Sleuth Kit unavailable."
                UNKNOWN_TARGETS=$((UNKNOWN_TARGETS + 1))
                return

            fi

            ANALYZED_TARGETS=$((ANALYZED_TARGETS + 1))

            base="$(safe_name "$dev")"

            FLS_OUT="$WORKDIR/fls-$base.txt"
            BLKLS_OUT="$WORKDIR/blkls-$base.bin"
            STRINGS_OUT="$WORKDIR/strings-$base.txt"


            # ------------------------------------------------
            # Deleted entries
            # ------------------------------------------------

            start_msg "$dev: deleted filesystem entries"

            if fls -r -d -p "$dev" \
                > "$FLS_OUT" \
                2>>"$ERROR_FILE"; then

                count="$(
                    grep -c . "$FLS_OUT" 2>/dev/null || echo 0
                )"

                if [ "$count" -gt 0 ]; then

                    warn "$dev: deleted entries = $count"

                    {
                        echo
                        echo "DEVICE: $dev"
                        echo "FILESYSTEM: $fstype"
                        echo "DELETED ENTRIES:"
                        head -n 500 "$FLS_OUT"
                    } >> "$FINDINGS_FILE"

                else

                    ok "$dev: no deleted entries reported."

                fi

            else

                warn "$dev: fls failed."

            fi

            done_msg "$dev: deleted-entry analysis complete."


            # ------------------------------------------------
            # Unallocated space
            # ------------------------------------------------

            start_msg "$dev: unallocated filesystem space"

            if blkls "$dev" > "$BLKLS_OUT" 2>>"$ERROR_FILE"; then

                unalloc_size="$(
                    stat -c '%s' "$BLKLS_OUT" 2>/dev/null || echo 0
                )"

                printf "Unallocated stream: %s\n" \
                    "$(human_size "$unalloc_size")"

                if [ "$unalloc_size" -gt 0 ]; then

                    extract_candidates \
                        "$BLKLS_OUT" \
                        "$STRINGS_OUT"

                    count="$(
                        wc -l < "$STRINGS_OUT" |
                        tr -d ' '
                    )"

                    if [ "${count:-0}" -gt 0 ]; then

                        warn "$dev: potential interesting strings = $count"

                        {
                            echo
                            echo "DEVICE: $dev"
                            echo "FILESYSTEM: $fstype"
                            echo "POTENTIAL STRINGS:"
                            cat "$STRINGS_OUT"
                        } >> "$FINDINGS_FILE"

                        TEXT_CANDIDATES=$(
                            awk -v a="$TEXT_CANDIDATES" \
                                -v b="$count" \
                                'BEGIN {print a+b}'
                        )

                    else

                        ok "$dev: no configured interesting strings."

                    fi

                else

                    info "$dev: no unallocated data returned."

                fi

            else

                warn "$dev: blkls failed."

            fi

            rm -f "$BLKLS_OUT"

            done_msg "$dev: unallocated-space analysis complete."

            ;;


        swap)

            info "$dev: swap detected."
            info "Swap is not treated as a normal filesystem."

            RAW_TARGETS=$((RAW_TARGETS + 1))

            ;;


        LVM2_member)

            info "$dev: LVM physical volume."
            info "Physical volume itself is not a normal filesystem."

            UNKNOWN_TARGETS=$((UNKNOWN_TARGETS + 1))

            ;;


        crypto_LUKS)

            warn "$dev: encrypted LUKS storage."

            UNKNOWN_TARGETS=$((UNKNOWN_TARGETS + 1))

            ;;


        UNKNOWN|"")

            warn "$dev: unknown filesystem signature."

            UNKNOWN_TARGETS=$((UNKNOWN_TARGETS + 1))

            ;;


        *)

            warn "$dev: unsupported filesystem: $fstype"

            UNKNOWN_TARGETS=$((UNKNOWN_TARGETS + 1))

            ;;

    esac
}


# ============================================================
# RAW ANALYSIS
# ============================================================

analyze_raw() {

    local dev="$1"
    local type="$2"
    local fstype="$3"
    local source="$4"

    section "RAW / UNKNOWN: $dev"

    printf "Device    : %s\n" "$dev"
    printf "Type      : %s\n" "$type"
    printf "Signature : %s\n" "$fstype"
    printf "Source    : %s\n" "$source"

    size="$(device_size_bytes "$dev")"

    printf "Size      : %s\n" "$(human_size "$size")"

    RAW_TARGETS=$((RAW_TARGETS + 1))

    base="$(safe_name "$dev")"

    SAMPLE="$WORKDIR/sample-$base.bin"
    END_SAMPLE="$WORKDIR/end-$base.bin"
    OUTPUT="$WORKDIR/rawstrings-$base.txt"

    SAMPLE_SIZE=$((64 * 1024 * 1024))


    # --------------------------------------------------------
    # FULL RAW
    # --------------------------------------------------------

    if [ "$FULL_RAW" -eq 1 ]; then

        warn "$dev: FULL RAW SCAN"
        start_msg "$dev: full raw scan"

        if dd \
            if="$dev" \
            bs=16M \
            iflag=fullblock \
            status=progress \
            2>"$WORKDIR/dd-$base.log" |
            strings -a -n 8 |
            grep -Ei \
                'password|passwd|authorization|bearer |api[_-]?key|secret|private[_-]?key|access[_-]?token|refresh[_-]?token|database|mysql|postgres|mongodb|redis|ssh-rsa|BEGIN .*PRIVATE KEY|AWS_ACCESS_KEY|AWS_SECRET|github[_-]?token' |
            head -n 1000 > "$OUTPUT"; then

            count="$(
                wc -l < "$OUTPUT" |
                tr -d ' '
            )"

            if [ "$count" -gt 0 ]; then

                warn "$dev: raw candidates = $count"

                {
                    echo
                    echo "DEVICE: $dev"
                    echo "TYPE: $type"
                    echo "SIGNATURE: $fstype"
                    echo "RAW CANDIDATES:"
                    cat "$OUTPUT"
                } >> "$RAW_FINDINGS_FILE"

                RAW_CANDIDATES=$(
                    awk -v a="$RAW_CANDIDATES" \
                        -v b="$count" \
                        'BEGIN {print a+b}'
                )

            else

                ok "$dev: no configured raw candidates."

            fi

        else

            warn "$dev: raw scan failed."

        fi

        done_msg "$dev: full raw scan complete."

        return
    fi


    # --------------------------------------------------------
    # BOUNDED RAW SAMPLE
    # --------------------------------------------------------

    info "$dev: bounded raw sample"
    info "Beginning: 64 MiB"
    info "End:       64 MiB"

    rm -f "$SAMPLE" "$END_SAMPLE"


    # Beginning

    start_msg "$dev: reading beginning"

    if dd \
        if="$dev" \
        of="$SAMPLE" \
        bs=1M \
        count=64 \
        iflag=fullblock \
        status=progress \
        2>"$WORKDIR/dd-start-$base.log"; then

        done_msg "$dev: beginning read complete."

    else

        warn "$dev: beginning read failed."

    fi


    # End

    if [ "$size" -gt "$SAMPLE_SIZE" ]; then

        skip_mb=$(
            awk -v size="$size" -v sample="$SAMPLE_SIZE" \
                'BEGIN {printf "%d", (size-sample)/1048576}'
        )

        start_msg "$dev: reading end"

        if dd \
            if="$dev" \
            of="$END_SAMPLE" \
            bs=1M \
            skip="$skip_mb" \
            count=64 \
            iflag=fullblock \
            status=progress \
            2>"$WORKDIR/dd-end-$base.log"; then

            done_msg "$dev: end read complete."

        else

            warn "$dev: end read failed."

        fi

    fi


    # Analyze

    cat "$SAMPLE" "$END_SAMPLE" 2>/dev/null |
    strings -a -n 8 |
    grep -Ei \
        'password|passwd|username|authorization|bearer |api[_-]?key|secret|private[_-]?key|access[_-]?token|refresh[_-]?token|database|mysql|postgres|mongodb|redis|ssh-rsa|BEGIN .*PRIVATE KEY|AWS_ACCESS_KEY|AWS_SECRET|github[_-]?token|credit.?card' |
    sed 's/^[[:space:]]*//' |
    head -n 500 > "$OUTPUT" || true

    count="$(
        wc -l < "$OUTPUT" 2>/dev/null |
        tr -d ' '
    )"

    if [ "${count:-0}" -gt 0 ]; then

        warn "$dev: potential raw candidates = $count"

        {
            echo
            echo "DEVICE: $dev"
            echo "TYPE: $type"
            echo "SIGNATURE: $fstype"
            echo "BOUNDED RAW SAMPLE:"
            cat "$OUTPUT"
        } >> "$RAW_FINDINGS_FILE"

        RAW_CANDIDATES=$(
            awk -v a="$RAW_CANDIDATES" \
                -v b="$count" \
                'BEGIN {print a+b}'
        )

    else

        ok "$dev: no configured candidates in bounded sample."

    fi

    rm -f "$SAMPLE" "$END_SAMPLE"

    done_msg "$dev: bounded raw analysis complete."
}


# ============================================================
# RUN ANALYSIS
# ============================================================

section "STORAGE ANALYSIS"

while IFS='|' read -r dev type fstype source; do

    [ -n "$dev" ] || continue

    case "$fstype" in

        UNKNOWN|"")
            analyze_raw \
                "$dev" \
                "$type" \
                "$fstype" \
                "$source"
            ;;

        *)
            analyze_filesystem \
                "$dev" \
                "$type" \
                "$fstype" \
                "$source"
            ;;

    esac

done < "$TARGETS_FILE"


# ============================================================
# FINDINGS
# ============================================================

section "FILESYSTEM FINDINGS"

if [ -s "$FINDINGS_FILE" ]; then
    cat "$FINDINGS_FILE"
else
    ok "No filesystem findings."
fi


section "RAW STORAGE FINDINGS"

if [ -s "$RAW_FINDINGS_FILE" ]; then
    cat "$RAW_FINDINGS_FILE"
else
    ok "No raw-storage findings."
fi


# ============================================================
# RESULTS
# ============================================================

section "RESULTS"

printf "Analysis targets             : %s\n" "$TARGET_COUNT"
printf "Filesystems analyzed        : %s\n" "$ANALYZED_TARGETS"
printf "Unknown/unanalyzable        : %s\n" "$UNKNOWN_TARGETS"
printf "Raw targets inspected       : %s\n" "$RAW_TARGETS"
printf "Disk-backed deleted objects : %s\n" "$DELETED_DISK_OBJECTS"
printf "Memory-backed deleted objs  : %s\n" "$DELETED_MEMORY_OBJECTS"
printf "Interesting-text candidates : %s\n" "$TEXT_CANDIDATES"
printf "Raw-data candidates         : %s\n" "$RAW_CANDIDATES"


# ============================================================
# FINAL STATUS
# ============================================================

section "FINAL STATUS"

if [ "$TARGET_COUNT" -eq 0 ]; then

    err "RESULT: STORAGE DISCOVERY FAILED"
    echo
    echo "No block-device/filesystem targets were created."
    echo "This result must not be interpreted as clean storage."

elif [ "$TEXT_CANDIDATES" -gt 0 ] ||
     [ "$RAW_CANDIDATES" -gt 0 ] ||
     [ "$DELETED_DISK_OBJECTS" -gt 0 ]; then

    warn "RESULT: POTENTIAL STORAGE REMNANTS DETECTED"

    echo
    echo "Review the evidence above."
    echo "Generic strings are not proof of another environment's data."
    echo "Controlled unique canary evidence is substantially stronger."

elif [ "$UNKNOWN_TARGETS" -gt 0 ]; then

    warn "RESULT: STORAGE PRESENT BUT NOT FULLY ANALYZABLE"

    echo
    echo "One or more exposed storage targets could not be fully analyzed."
    echo "This must not be reported as proof that storage is clean."

else

    ok "RESULT: ANALYZED STORAGE - NO CONFIGURED REMNANTS DETECTED"

    echo
    echo "The analyzed storage did not produce configured findings."
    echo "This does not prove physical storage sanitization."

fi


# ============================================================
# INTERPRETATION
# ============================================================

section "INTERPRETATION"

cat <<'EOF'

This tool performs read-only analysis of storage exposed to the
current environment.

Important:

- A visible block device is not itself proof of a vulnerability.

- A deleted filename is not necessarily recoverable file content.

- Generic strings in raw/unallocated storage do not prove that
  the data came from another environment.

- A unique controlled canary is stronger evidence.

For controlled remanence testing, preserve:

  * exact canary value
  * creation timestamp
  * release/destruction timestamp
  * new environment creation timestamp
  * exact device/path/offset
  * recovered evidence
  * hashes where applicable

"No findings" does not prove that every underlying physical byte
was sanitized.

Virtualization, snapshots, copy-on-write, RAID, encryption,
network storage and inaccessible storage layers may prevent
complete inspection from inside the environment.

This tool does not attempt to bypass encryption or obtain keys.

EOF


# ============================================================
# FINAL TARGET SUMMARY
# ============================================================

section "TARGET SUMMARY"

printf "%-38s %-16s %-18s %s\n" \
    "DEVICE" \
    "TYPE" \
    "FILESYSTEM" \
    "SOURCE"

while IFS='|' read -r dev type fstype source; do

    printf "%-38s %-16s %-18s %s\n" \
        "$dev" \
        "$type" \
        "$fstype" \
        "$source"

done < "$TARGETS_FILE"

echo
echo "Completed: $(date)"

exit 0
