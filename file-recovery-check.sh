#!/usr/bin/env bash

# ============================================================
# FILE RECOVERY CHECK v5.2
#
# Read-only storage/remnant analysis
#
# Usage:
#   sudo bash file-recovery-check.sh
#
# Full raw scan:
#   sudo bash file-recovery-check.sh --full-raw
#
# This script:
#   - inventories exposed block devices
#   - detects mounted/unmounted filesystems
#   - handles findmnt subvolume/subpath sources
#   - discovers LVM logical volumes
#   - analyzes supported filesystems with Sleuth Kit
#   - checks deleted filesystem entries
#   - checks unallocated filesystem space
#   - analyzes overlayfs visibility
#   - identifies swap/encrypted/LVM devices
#   - samples unknown/raw devices safely
#
# IMPORTANT:
#   No filesystem is mounted.
#   No block device is modified.
# ============================================================

set -u
set -o pipefail

VERSION="5.2"

FULL_RAW=0

for arg in "$@"; do
    case "$arg" in
        --full-raw)
            FULL_RAW=1
            ;;
        -h|--help)
            cat <<'EOF'

FILE RECOVERY CHECK v5.2

Usage:
  sudo bash file-recovery-check.sh
  sudo bash file-recovery-check.sh --full-raw

Default:
  - filesystem analysis
  - deleted-entry analysis
  - unallocated-space analysis
  - overlayfs inspection
  - LVM discovery
  - bounded raw-device sampling

--full-raw:
  Fully scan unknown/raw devices.

WARNING:
  Full raw scanning can take a very long time on multi-TB devices.

The script does not mount or modify discovered storage.

EOF
            exit 0
            ;;
        *)
            echo "Unknown option: $arg"
            echo "Use --help for usage."
            exit 1
            ;;
    esac
done


# ============================================================
# GLOBALS
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

TOTAL_TARGETS=0
ANALYZED_TARGETS=0
UNKNOWN_TARGETS=0
RAW_TARGETS=0

DELETED_ENTRIES=0
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
# ROOT CHECK
# ============================================================

if [ "$(id -u)" -ne 0 ]; then
    err "Run with sudo/root."
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
    warn "Unknown devices may require a very long time."
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
        ok "Required analysis commands are available."
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
            warn "See: $ERROR_FILE"
        fi

    else
        warn "apt-get is unavailable."
    fi
}

install_missing


# ============================================================
# COMMAND CHECK
# ============================================================

for cmd in \
    lsblk \
    findmnt \
    blkid \
    file \
    strings \
    dd \
    awk \
    sed \
    grep \
    sort \
    uniq \
    stat \
    blockdev
do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        warn "Missing command: $cmd"
    fi
done

if command -v fls >/dev/null 2>&1 &&
   command -v blkls >/dev/null 2>&1; then

    SLEUTHKIT=1
    ok "Sleuth Kit available."

else

    SLEUTHKIT=0
    warn "Sleuth Kit unavailable."

fi


# ============================================================
# ROOT
# ============================================================

section "ROOT FILESYSTEM"

ROOT_SOURCE="$(findmnt -n -o SOURCE / 2>/dev/null || true)"
ROOT_FSTYPE="$(findmnt -n -o FSTYPE / 2>/dev/null || true)"

printf "Root source : %s\n" "${ROOT_SOURCE:-unknown}"
printf "Filesystem  : %s\n" "${ROOT_FSTYPE:-unknown}"


# ============================================================
# NORMALIZE FINDMNT SOURCE
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


# ============================================================
# DEVICE HELPERS
# ============================================================

device_is_block() {
    [ -b "$1" ]
}


device_size_bytes() {

    local dev="$1"

    if command -v blockdev >/dev/null 2>&1; then
        blockdev --getsize64 "$dev" 2>/dev/null || echo 0
    else
        echo 0
    fi
}


human_size() {

    local bytes="${1:-0}"

    awk -v b="$bytes" '
    BEGIN {
        if (b >= 1099511627776)
            printf "%.2f TiB", b/1099511627776
        else if (b >= 1073741824)
            printf "%.2f GiB", b/1073741824
        else if (b >= 1048576)
            printf "%.2f MiB", b/1048576
        else if (b >= 1024)
            printf "%.2f KiB", b/1024
        else
            printf "%d B", b
    }'
}


safe_name() {
    printf '%s' "$1" | tr '/: ' '___'
}


# ============================================================
# BLOCK INVENTORY
# ============================================================

section "BLOCK DEVICE INVENTORY"

if command -v lsblk >/dev/null 2>&1; then

    lsblk \
        -e 7 \
        -o NAME,PATH,SIZE,TYPE,FSTYPE,LABEL,UUID,MOUNTPOINTS,RO \
        2>/dev/null || true

    echo

    info "Collecting visible block devices..."

    lsblk -dn -e 7 -o PATH,TYPE 2>/dev/null |
    awk '
        $2=="disk" ||
        $2=="part" ||
        $2=="lvm" ||
        $2=="crypt" {
            print $1
        }
    ' |
    sort -u |
    tee "$DEVICES_FILE"

else

    warn "lsblk unavailable."

fi


# Add common device names if visible but missing from lsblk.

for d in \
    /dev/vd[a-z] \
    /dev/sd[a-z] \
    /dev/xvd[a-z] \
    /dev/nvme*n* \
    /dev/mmcblk*
do
    if [ -b "$d" ]; then
        printf '%s\n' "$d" >> "$DEVICES_FILE"
    fi
done

sort -u "$DEVICES_FILE" -o "$DEVICES_FILE"


# ============================================================
# DELETED OPEN FILES
# ============================================================

section "DELETED OPEN FILES"

if command -v lsof >/dev/null 2>&1; then

    start_msg "Checking deleted-open files..."

    LSOF_OUT="$WORKDIR/lsof.txt"

    lsof +L1 2>/dev/null > "$LSOF_OUT" || true

    if [ -s "$LSOF_OUT" ]; then

        cat "$LSOF_OUT"

        DELETED_ENTRIES="$(tail -n +2 "$LSOF_OUT" |
            wc -l |
            tr -d ' ')"

        warn "Deleted-open objects: $DELETED_ENTRIES"
        warn "These may be memory-backed and are not automatically disk remnants."

    else

        ok "No deleted-open files detected."

    fi

    done_msg "Deleted-open check complete."

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
        warn "Overlay storage cannot be considered fully analyzed."

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

    # Fast signature probe.
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

    # file(1) fallback.
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
# DISCOVER MOUNTED STORAGE
# ============================================================

section "STORAGE DISCOVERY"

: > "$TARGETS_FILE"

while IFS='|' read -r target source fstype; do

    [ -n "$source" ] || continue

    source="$(normalize_source "$source")"

    if [ -b "$source" ]; then

        detected="$(probe_type "$source")"

        [ "$detected" != "UNKNOWN" ] &&
            fstype="$detected"

        case "$fstype" in

            swap)
                add_target "$source" "swap" "$fstype" "$target"
                ;;

            LVM2_member)
                add_target "$source" "lvm-pv" "$fstype" "$target"
                ;;

            crypto_LUKS)
                add_target "$source" "encrypted" "$fstype" "$target"
                ;;

            *)
                add_target "$source" "mounted" "$fstype" "$target"
                ;;

        esac

    fi

done < "$MOUNTS_FILE"


# ============================================================
# DISCOVER BLOCK DEVICES
# ============================================================

while IFS= read -r dev; do

    [ -n "$dev" ] || continue
    [ -b "$dev" ] || continue

    fstype="$(probe_type "$dev")"

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

    if [ "$LVM_COUNT" -gt 0 ]; then
        ok "LVM logical volumes discovered: $LVM_COUNT"
    else
        info "No active LVM logical volumes discovered."
    fi

else

    info "lvs command unavailable."

fi


# ============================================================
# ACTIVE SWAP
# ============================================================

section "SWAP"

if [ -r /proc/swaps ]; then
    cat /proc/swaps
fi

if [ -r /proc/swaps ]; then

    while read -r filename type size used priority; do

        [ "$filename" = "Filename" ] && continue
        [ -n "${filename:-}" ] || continue

        if [ -b "$filename" ]; then
            add_target "$filename" "swap" "swap" "active-swap"
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

printf "%-38s %-12s %-18s %s\n" \
    "DEVICE" \
    "TYPE" \
    "FILESYSTEM" \
    "SOURCE"

printf "%-38s %-12s %-18s %s\n" \
    "--------------------------------------" \
    "------------" \
    "------------------" \
    "----------------"

while IFS='|' read -r dev type fstype source; do

    size="$(device_size_bytes "$dev")"

    printf "%-38s %-12s %-18s %s (%s)\n" \
        "$dev" \
        "$type" \
        "$fstype" \
        "$source" \
        "$(human_size "$size")"

done < "$TARGETS_FILE"


# ============================================================
# STRING EXTRACTION
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

    TOTAL_TARGETS=$((TOTAL_TARGETS + 1))

    section "FILESYSTEM ANALYSIS: $dev"

    printf "Device     : %s\n" "$dev"
    printf "Type       : %s\n" "$type"
    printf "Filesystem : %s\n" "$fstype"
    printf "Source     : %s\n" "$source"

    size="$(device_size_bytes "$dev")"

    printf "Size       : %s\n" "$(human_size "$size")"

    case "$fstype" in

        ext2|ext3|ext4|xfs|ntfs|fat|vfat|exfat|hfs|hfsplus|ufs)

            if [ "$SLEUTHKIT" -eq 0 ]; then

                warn "Sleuth Kit unavailable."
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

            start_msg "$dev: deleted-entry analysis"

            if fls -r -d -p "$dev" \
                > "$FLS_OUT" \
                2>>"$ERROR_FILE"; then

                deleted_count="$(
                    grep -c . "$FLS_OUT" 2>/dev/null || echo 0
                )"

                if [ "$deleted_count" -gt 0 ]; then

                    warn "Deleted filesystem entries: $deleted_count"

                    {
                        echo
                        echo "DEVICE: $dev"
                        echo "FILESYSTEM: $fstype"
                        echo "DELETED ENTRIES:"
                        head -n 500 "$FLS_OUT"
                    } >> "$FINDINGS_FILE"

                    DELETED_ENTRIES=$(
                        printf '%s' "$DELETED_ENTRIES" |
                        awk -v x="$deleted_count" '{print $1+x}'
                    )

                else

                    ok "$dev: no deleted filesystem entries reported."

                fi

            else

                warn "$dev: fls analysis failed."

            fi

            done_msg "$dev: deleted-entry analysis complete."


            # ------------------------------------------------
            # Unallocated space
            # ------------------------------------------------

            start_msg "$dev: unallocated-space analysis"

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

                    candidate_count="$(
                        wc -l < "$STRINGS_OUT" |
                        tr -d ' '
                    )"

                    if [ "${candidate_count:-0}" -gt 0 ]; then

                        warn "Potential interesting strings: $candidate_count"

                        {
                            echo
                            echo "DEVICE: $dev"
                            echo "FILESYSTEM: $fstype"
                            echo "POTENTIAL STRINGS FROM UNALLOCATED SPACE:"
                            cat "$STRINGS_OUT"
                        } >> "$FINDINGS_FILE"

                        TEXT_CANDIDATES=$(
                            printf '%s' "$TEXT_CANDIDATES" |
                            awk -v x="$candidate_count" '{print $1+x}'
                        )

                    else

                        ok "$dev: no configured interesting strings found."

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
            info "Swap is not analyzed as a normal filesystem."

            RAW_TARGETS=$((RAW_TARGETS + 1))

            ;;


        LVM2_member)

            info "$dev: LVM physical volume detected."
            info "Analyzing active logical volumes instead."

            UNKNOWN_TARGETS=$((UNKNOWN_TARGETS + 1))

            ;;


        crypto_LUKS)

            warn "$dev: encrypted storage detected."
            warn "Contents cannot be analyzed without the appropriate mapping."

            UNKNOWN_TARGETS=$((UNKNOWN_TARGETS + 1))

            ;;


        UNKNOWN|"")

            warn "$dev: filesystem type unknown."

            UNKNOWN_TARGETS=$((UNKNOWN_TARGETS + 1))

            ;;


        *)

            warn "$dev: unsupported filesystem type: $fstype"

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

    section "RAW / UNKNOWN ANALYSIS: $dev"

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
        warn "Size: $(human_size "$size")"

        start_msg "$dev: starting full raw scan"

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

                warn "$dev: raw candidates: $count"

                {
                    echo
                    echo "DEVICE: $dev"
                    echo "TYPE: $type"
                    echo "SIGNATURE: $fstype"
                    echo "RAW CANDIDATES:"
                    cat "$OUTPUT"
                } >> "$RAW_FINDINGS_FILE"

                RAW_CANDIDATES=$(
                    printf '%s' "$RAW_CANDIDATES" |
                    awk -v x="$count" '{print $1+x}'
                )

            else

                ok "$dev: no configured raw candidates."

            fi

        else

            warn "$dev: full raw scan failed."

        fi

        done_msg "$dev: full raw scan complete."

        return
    fi


    # --------------------------------------------------------
    # BOUNDED SAMPLE
    #
    # Efficient reads:
    # 64 MiB from beginning
    # 64 MiB from end
    #
    # No bs=1.
    # --------------------------------------------------------

    info "$dev: bounded raw sample"
    info "Reading 64 MiB from beginning..."

    rm -f "$SAMPLE" "$END_SAMPLE"

    if dd \
        if="$dev" \
        of="$SAMPLE" \
        bs=1M \
        count=64 \
        iflag=fullblock \
        status=progress \
        2>"$WORKDIR/dd-start-$base.log"; then

        done_msg "$dev: beginning sample complete."

    else

        warn "$dev: beginning sample failed."

    fi


    # --------------------------------------------------------
    # End sample
    # --------------------------------------------------------

    if [ "$size" -gt "$SAMPLE_SIZE" ]; then

        offset=$((size - SAMPLE_SIZE))

        info "$dev: reading 64 MiB from end..."

        # Efficient seek:
        # seek in 1 MiB blocks rather than bs=1.
        skip_mb=$((offset / 1048576))

        if dd \
            if="$dev" \
            of="$END_SAMPLE" \
            bs=1M \
            skip="$skip_mb" \
            count=64 \
            iflag=fullblock \
            status=progress \
            2>"$WORKDIR/dd-end-$base.log"; then

            done_msg "$dev: end sample complete."

        else

            warn "$dev: end sample failed."

        fi

    else

        info "$dev: device smaller than 64 MiB; end sample skipped."

    fi


    # --------------------------------------------------------
    # Analyze samples
    # --------------------------------------------------------

    cat "$SAMPLE" "$END_SAMPLE" \
        2>/dev/null |
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

        warn "$dev: potential raw-data candidates: $count"

        {
            echo
            echo "DEVICE: $dev"
            echo "TYPE: $type"
            echo "SIGNATURE: $fstype"
            echo "BOUNDED RAW SAMPLE:"
            cat "$OUTPUT"
        } >> "$RAW_FINDINGS_FILE"

        RAW_CANDIDATES=$(
            printf '%s' "$RAW_CANDIDATES" |
            awk -v x="$count" '{print $1+x}'
        )

    else

        ok "$dev: no configured candidates in bounded sample."

    fi

    rm -f "$SAMPLE" "$END_SAMPLE"

    done_msg "$dev: bounded raw analysis complete."
}


# ============================================================
# PROCESS TARGETS
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

printf "Filesystem targets analyzed : %s\n" "$ANALYZED_TARGETS"
printf "Unknown/unanalyzable        : %s\n" "$UNKNOWN_TARGETS"
printf "Raw targets inspected       : %s\n" "$RAW_TARGETS"
printf "Deleted entries             : %s\n" "$DELETED_ENTRIES"
printf "Interesting-text candidates : %s\n" "$TEXT_CANDIDATES"
printf "Raw-data candidates         : %s\n" "$RAW_CANDIDATES"


# ============================================================
# FINAL STATUS
# ============================================================

section "FINAL STATUS"

if [ "$TEXT_CANDIDATES" -gt 0 ] ||
   [ "$RAW_CANDIDATES" -gt 0 ] ||
   [ "$DELETED_ENTRIES" -gt 0 ]; then

    warn "RESULT: POTENTIAL REMNANTS DETECTED"

    echo
    echo "Review the evidence above."
    echo
    echo "Generic strings are not proof of another environment's data."
    echo "A unique controlled canary provides substantially stronger evidence."

elif [ "$UNKNOWN_TARGETS" -gt 0 ]; then

    warn "RESULT: STORAGE PRESENT BUT NOT FULLY ANALYZABLE"

    echo
    echo "One or more storage targets were exposed but could not be"
    echo "fully analyzed."
    echo
    echo "Do not interpret this result as proof that the storage is clean."

elif [ "$ANALYZED_TARGETS" -eq 0 ]; then

    warn "RESULT: NO FILESYSTEM ANALYSIS AVAILABLE"

else

    ok "RESULT: ANALYZED STORAGE - NO OBVIOUS REMNANTS DETECTED"

    echo
    echo "No configured remnants were found in the analyzed areas."
    echo "This does not prove that every underlying physical byte is clean."

fi


# ============================================================
# INTERPRETATION
# ============================================================

section "INTERPRETATION"

cat <<'EOF'

This is a read-only storage analysis.

The following distinctions are important:

- A visible block device is not itself proof of a vulnerability.

- A deleted filename is not necessarily recoverable file content.

- Generic strings in unallocated/raw storage do not prove that the
  data originated from another environment.

- A unique controlled canary is stronger evidence.

- If a controlled canary created in one environment is later
  recoverable from storage exposed to another environment, preserve:

    * exact canary value
    * creation timestamp
    * release/destruction timestamp
    * new environment creation timestamp
    * exact device/offset/path
    * recovered evidence
    * hashes where applicable

- "No findings" does not prove physical storage sanitization.

- Virtualization, snapshots, copy-on-write, RAID, encryption,
  network storage, and inaccessible storage layers can prevent
  complete inspection from inside an environment.

- The script does not attempt to bypass encryption or obtain keys.

EOF


# ============================================================
# TARGET SUMMARY
# ============================================================

section "TARGET SUMMARY"

printf "%-38s %-12s %-18s %s\n" \
    "DEVICE" \
    "TYPE" \
    "FILESYSTEM" \
    "SOURCE"

while IFS='|' read -r dev type fstype source; do

    printf "%-38s %-12s %-18s %s\n" \
        "$dev" \
        "$type" \
        "$fstype" \
        "$source"

done < "$TARGETS_FILE"

echo
echo "Completed: $(date)"

exit 0
