#!/usr/bin/env bash

# ============================================================
# FILE RECOVERY CHECK v5.1
# Read-only storage/remnant analysis
#
# Designed to inspect storage actually exposed to this
# environment:
#   - mounted filesystems
#   - unmounted partitions
#   - LVM logical volumes
#   - overlayfs
#   - swap
#   - unknown/raw devices
#   - deleted-open files
#
# IMPORTANT:
#   This script NEVER mounts or writes to discovered storage.
#
# Usage:
#   sudo bash file-recovery-check.sh
#
# Optional:
#   sudo bash file-recovery-check.sh --full-raw
#
# --full-raw:
#   Perform a complete raw scan of unknown/raw devices.
#   This can be extremely slow on multi-TB devices.
# ============================================================

set -u
set -o pipefail

VERSION="5.1"

FULL_RAW=0

for arg in "$@"; do
    case "$arg" in
        --full-raw)
            FULL_RAW=1
            ;;
        -h|--help)
            cat <<EOF

FILE RECOVERY CHECK v${VERSION}

Usage:
  sudo bash file-recovery-check.sh
  sudo bash file-recovery-check.sh --full-raw

Options:
  --full-raw
      Fully scan unknown/raw devices for printable strings.
      WARNING: multi-TB devices can take a very long time.

The default mode performs:
  - block device inventory
  - filesystem probing
  - mounted filesystem analysis
  - unmounted filesystem analysis
  - LVM discovery
  - overlayfs analysis
  - deleted-open file detection
  - swap inventory
  - bounded raw-device scanning

No storage is mounted or modified.

EOF
            exit 0
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

touch "$DEVICES_FILE"
touch "$TARGETS_FILE"
touch "$MOUNTS_FILE"
touch "$FINDINGS_FILE"
touch "$RAW_FINDINGS_FILE"
touch "$ERROR_FILE"

TOTAL_TARGETS=0
ANALYZED_TARGETS=0
UNKNOWN_TARGETS=0
RAW_TARGETS=0
DELETED_ENTRIES=0
FILENAME_CANDIDATES=0
TEXT_CANDIDATES=0
RAW_CANDIDATES=0

cleanup() {
    rm -rf "$WORKDIR"
}

trap cleanup EXIT


# ============================================================
# COLORS
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
# REQUIRE ROOT
# ============================================================

if [ "$(id -u)" -ne 0 ]; then
    err "Run this script with sudo/root."
    exit 1
fi


# ============================================================
# BASIC COMMANDS
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
    warn "Unknown devices may require very long reads."
fi


# ============================================================
# DEPENDENCY INSTALLATION
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
            warn "Automatic package installation failed."
            warn "See: $ERROR_FILE"
        fi
    else
        warn "apt-get is not available."
    fi
}

install_missing


# ============================================================
# COMMAND AVAILABILITY
# ============================================================

for cmd in lsblk findmnt blkid file awk sed grep sort uniq strings dd; do
    if command -v "$cmd" >/dev/null 2>&1; then
        :
    else
        warn "Missing command: $cmd"
    fi
done

if command -v fls >/dev/null 2>&1 && command -v blkls >/dev/null 2>&1; then
    SLEUTHKIT=1
    ok "Sleuth Kit available."
else
    SLEUTHKIT=0
    warn "Sleuth Kit is unavailable. Filesystem deleted-entry analysis will be limited."
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
# SOURCE NORMALIZATION
# ============================================================
#
# findmnt can return:
#
#   /dev/vdb[/storage/abc]
#
# instead of:
#
#   /dev/vdb
#
# This function removes the subpath.
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
# DEVICE TYPE
# ============================================================

device_is_block() {
    local d="$1"

    [ -b "$d" ]
}


# ============================================================
# GET SIZE
# ============================================================

device_size_bytes() {
    local d="$1"

    if command -v blockdev >/dev/null 2>&1; then
        blockdev --getsize64 "$d" 2>/dev/null || echo 0
    else
        echo 0
    fi
}


human_size() {
    local bytes="${1:-0}"

    awk -v b="$bytes" '
    function human(x) {
        if (x >= 1099511627776)
            return sprintf("%.2f TiB", x/1099511627776)
        if (x >= 1073741824)
            return sprintf("%.2f GiB", x/1073741824)
        if (x >= 1048576)
            return sprintf("%.2f MiB", x/1048576)
        if (x >= 1024)
            return sprintf("%.2f KiB", x/1024)
        return sprintf("%d B", x)
    }
    BEGIN { print human(b) }
    '
}


# ============================================================
# BLOCK DEVICE INVENTORY
# ============================================================

section "BLOCK DEVICE INVENTORY"

if command -v lsblk >/dev/null 2>&1; then

    lsblk -e 7 -o NAME,PATH,SIZE,TYPE,FSTYPE,LABEL,UUID,MOUNTPOINTS,RO \
        2>/dev/null || true

    echo

    info "Raw block devices visible to this environment:"

    lsblk -dn -e 7 -o PATH,TYPE 2>/dev/null |
    awk '$2=="disk" || $2=="part" || $2=="lvm" || $2=="crypt" {
        print $1
    }' |
    sort -u |
    tee "$DEVICES_FILE"

else
    warn "lsblk unavailable."
fi


# ============================================================
# ADD DEVICES FROM /DEV
# ============================================================

# Some devices can be exposed but absent from normal lsblk output.

for d in /dev/vd[a-z] /dev/sd[a-z] /dev/xvd[a-z] /dev/nvme*n* /dev/mmcblk*; do
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

    LSOF_OUT="$WORKDIR/lsof.txt"

    lsof +L1 2>/dev/null > "$LSOF_OUT" || true

    if [ -s "$LSOF_OUT" ]; then
        cat "$LSOF_OUT"

        DELETED_ENTRIES="$(tail -n +2 "$LSOF_OUT" | wc -l | tr -d ' ')"

        warn "Deleted-open objects detected: $DELETED_ENTRIES"
        warn "These do NOT automatically represent recoverable disk data."
    else
        ok "No deleted-open files detected."
    fi

else
    warn "lsof unavailable."
fi


# ============================================================
# OVERLAYFS
# ============================================================

section "OVERLAYFS ANALYSIS"

if [ "$ROOT_FSTYPE" = "overlay" ]; then

    info "Root filesystem is overlayfs."

    OVERLAY_INFO="$WORKDIR/overlay.txt"

    findmnt -n -t overlay -o TARGET,SOURCE,OPTIONS 2>/dev/null |
        tee "$OVERLAY_INFO" || true

    UPPER="$(findmnt -n -t overlay -o OPTIONS / 2>/dev/null |
        tr ',' '\n' |
        sed -n 's/^upperdir=//p' |
        head -n 1)"

    LOWER="$(findmnt -n -t overlay -o OPTIONS / 2>/dev/null |
        tr ',' '\n' |
        sed -n 's/^lowerdir=//p' |
        head -n 1)"

    printf "Upper directory : %s\n" "${UPPER:-not exposed}"
    printf "Lower directory : %s\n" "${LOWER:-not exposed}"

    if [ -n "${UPPER:-}" ] && [ -d "$UPPER" ]; then
        ok "Overlay upper directory is accessible."

        info "Scanning overlay upper directory for deleted/whiteout indicators..."

        find "$UPPER" -xdev \
            \( -name '.wh.*' -o -name '.wh..wh..opq' \) \
            -print 2>/dev/null |
            head -n 200 || true

    else
        warn "Overlay upper directory is not accessible."
        warn "The overlay filesystem itself cannot be treated as fully analyzed."
    fi

else
    info "Root filesystem is not overlayfs."
fi


# ============================================================
# MOUNTED FILESYSTEM INVENTORY
# ============================================================

section "MOUNTED FILESYSTEMS"

findmnt -rn -o TARGET,SOURCE,FSTYPE 2>/dev/null |
while IFS= read -r line; do

    target="$(printf '%s\n' "$line" | awk '{print $1}')"
    source_raw="$(printf '%s\n' "$line" | awk '{print $2}')"
    fstype="$(printf '%s\n' "$line" | awk '{print $3}')"

    source="$(normalize_source "$source_raw")"

    [ -n "$target" ] || continue
    [ -n "$source" ] || continue

    printf '%s|%s|%s\n' "$target" "$source" "$fstype"

done > "$MOUNTS_FILE"

cat "$MOUNTS_FILE"


# ============================================================
# PROBE FILESYSTEM
# ============================================================

probe_device() {
    local dev="$1"

    local blkid_out=""
    local file_out=""

    if ! [ -b "$dev" ]; then
        echo "NOT_BLOCK_DEVICE"
        return
    fi

    blkid_out="$(blkid -p "$dev" 2>/dev/null || true)"

    if [ -n "$blkid_out" ]; then
        printf '%s\n' "$blkid_out"
        return
    fi

    file_out="$(file -sL "$dev" 2>/dev/null || true)"

    if [ -n "$file_out" ]; then
        printf '%s\n' "$file_out"
    else
        echo "UNKNOWN"
    fi
}


get_fstype() {
    local dev="$1"

    local out=""
    local type=""

    out="$(blkid -p -o export "$dev" 2>/dev/null || true)"

    type="$(printf '%s\n' "$out" |
        sed -n 's/^TYPE=//p' |
        head -n 1)"

    if [ -n "$type" ]; then
        printf '%s\n' "$type"
        return
    fi

    # Fallback: inspect file(1) output.
    out="$(file -sL "$dev" 2>/dev/null || true)"

    case "$out" in
        *"SGI XFS filesystem"*) echo "xfs" ;;
        *"XFS filesystem"*) echo "xfs" ;;
        *"Linux rev 1.0 ext4 filesystem"*) echo "ext4" ;;
        *"Linux rev 1.0 ext3 filesystem"*) echo "ext3" ;;
        *"Linux rev 1.0 ext2 filesystem"*) echo "ext2" ;;
        *"LVM2_member"*) echo "LVM2_member" ;;
        *"crypto_LUKS"*) echo "crypto_LUKS" ;;
        *"swap"*) echo "swap" ;;
        *) echo "" ;;
    esac
}


# ============================================================
# BUILD STORAGE TARGET LIST
# ============================================================

section "STORAGE DISCOVERY"

: > "$TARGETS_FILE"

add_target() {
    local dev="$1"
    local type="$2"
    local fstype="$3"
    local source="$4"

    [ -n "$dev" ] || return

    if ! [ -b "$dev" ]; then
        return
    fi

    printf '%s|%s|%s|%s\n' \
        "$dev" "$type" "$fstype" "$source" >> "$TARGETS_FILE"
}


# ------------------------------------------------------------
# 1. Mounted filesystem sources
# ------------------------------------------------------------

while IFS='|' read -r target source fstype; do

    [ -n "$source" ] || continue

    source="$(normalize_source "$source")"

    if device_is_block "$source"; then

        probed="$(get_fstype "$source")"

        if [ -n "$probed" ]; then
            fstype="$probed"
        fi

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


# ------------------------------------------------------------
# 2. Block devices / partitions
# ------------------------------------------------------------

while IFS= read -r dev; do

    [ -n "$dev" ] || continue

    [ -b "$dev" ] || continue

    fstype="$(get_fstype "$dev")"

    case "$fstype" in
        swap)
            add_target "$dev" "swap" "$fstype" "lsblk"
            ;;

        LVM2_member)
            add_target "$dev" "lvm-pv" "$fstype" "lsblk"
            ;;

        crypto_LUKS)
            add_target "$dev" "encrypted" "$fstype" "lsblk"
            ;;

        "")
            add_target "$dev" "unknown" "UNKNOWN" "lsblk"
            ;;

        *)
            add_target "$dev" "filesystem" "$fstype" "lsblk"
            ;;
    esac

done < "$DEVICES_FILE"


# ============================================================
# LVM DISCOVERY
# ============================================================

section "LVM DISCOVERY"

if command -v lvs >/dev/null 2>&1; then

    LVM_FOUND=0

    while IFS='|' read -r lv vg attr size path; do

        [ -n "$path" ] || continue
        [ -b "$path" ] || continue

        LVM_FOUND=1

        fstype="$(get_fstype "$path")"

        if [ -z "$fstype" ]; then
            fstype="UNKNOWN"
        fi

        add_target "$path" "lvm" "$fstype" "LVM:${vg}"

    done < <(
        lvs --noheadings --separator='|' \
            -o lv_name,vg_name,lv_attr,lv_size,lv_path \
            2>/dev/null |
        sed 's/^ *//;s/ *$//'
    )

    if [ "$LVM_FOUND" -eq 1 ]; then
        ok "Active LVM logical volumes discovered."
    else
        info "No active LVM logical volumes discovered."
    fi

else
    info "lvs command unavailable."
fi


# ============================================================
# SWAP DISCOVERY
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
# DEDUPLICATE TARGETS
# ============================================================

sort -t'|' -k1,1 -u "$TARGETS_FILE" -o "$TARGETS_FILE"


# ============================================================
# SHOW PROBED TARGETS
# ============================================================

section "DISCOVERED STORAGE TARGETS"

printf "%-38s %-12s %-18s %s\n" \
    "DEVICE" "TYPE" "FILESYSTEM" "SOURCE"

printf "%-38s %-12s %-18s %s\n" \
    "--------------------------------------" \
    "------------" \
    "------------------" \
    "----------------"

while IFS='|' read -r dev type fstype source; do

    size="$(device_size_bytes "$dev")"
    hsize="$(human_size "$size")"

    printf "%-38s %-12s %-18s %s (%s)\n" \
        "$dev" "$type" "$fstype" "$source" "$hsize"

done < "$TARGETS_FILE"


# ============================================================
# SAFE STRING FILTER
# ============================================================

extract_candidates() {

    local input="$1"
    local output="$2"

    [ -f "$input" ] || return 0

    strings -a -n 8 "$input" 2>/dev/null |
    grep -Ei \
        '(^|[^a-zA-Z0-9])(
        password|
        passwd|
        username|
        authorization|
        bearer |
        api[_-]?key|
        secret|
        private[_-]?key|
        access[_-]?token|
        refresh[_-]?token|
        database|
        mysql|
        postgres|
        mongodb|
        redis|
        ssh-rsa|
        BEGIN .*PRIVATE KEY|
        AWS_ACCESS_KEY|
        AWS_SECRET|
        github[_-]?token|
        credit.?card
        )' |
    sed 's/^[[:space:]]*//' |
    head -n 500 > "$output" || true
}


# ============================================================
# FILESYSTEM ANALYSIS
# ============================================================

analyze_filesystem() {

    local dev="$1"
    local fstype="$2"
    local type="$3"
    local source="$4"

    TOTAL_TARGETS=$((TOTAL_TARGETS + 1))

    section "ANALYZING: $dev"

    printf "Device      : %s\n" "$dev"
    printf "Type        : %s\n" "$type"
    printf "Filesystem  : %s\n" "$fstype"
    printf "Source      : %s\n" "$source"

    size="$(device_size_bytes "$dev")"
    printf "Size        : %s\n" "$(human_size "$size")"

    case "$fstype" in

        ext2|ext3|ext4|xfs|ntfs|fat|vfat|exfat|hfs|hfsplus|ufs)

            if [ "$SLEUTHKIT" -eq 0 ]; then
                warn "Sleuth Kit unavailable; cannot perform filesystem deleted-entry analysis."
                UNKNOWN_TARGETS=$((UNKNOWN_TARGETS + 1))
                return
            fi

            ANALYZED_TARGETS=$((ANALYZED_TARGETS + 1))

            local fls_out="$WORKDIR/fls-$(basename "$dev" | tr '/' '_').txt"
            local blkls_out="$WORKDIR/blkls-$(basename "$dev" | tr '/' '_').bin"
            local strings_out="$WORKDIR/strings-$(basename "$dev" | tr '/' '_').txt"

            info "Running filesystem metadata/deleted-entry analysis..."

            if fls -r -d -p "$dev" > "$fls_out" 2>>"$ERROR_FILE"; then

                deleted_count="$(grep -c . "$fls_out" 2>/dev/null || echo 0)"

                if [ "$deleted_count" -gt 0 ]; then
                    warn "Deleted filesystem entries: $deleted_count"

                    {
                        echo
                        echo "DEVICE: $dev"
                        echo "FILESYSTEM: $fstype"
                        echo "DELETED ENTRIES:"
                        head -n 500 "$fls_out"
                    } >> "$FINDINGS_FILE"

                    DELETED_ENTRIES=$((DELETED_ENTRIES + deleted_count))
                else
                    ok "No deleted filesystem entries reported."
                fi

            else
                warn "fls could not analyze $dev."
            fi


            # ------------------------------------------------
            # Unallocated space extraction
            # ------------------------------------------------

            info "Analyzing filesystem unallocated space..."

            if blkls "$dev" > "$blkls_out" 2>>"$ERROR_FILE"; then

                file_size="$(stat -c '%s' "$blkls_out" 2>/dev/null || echo 0)"

                printf "Unallocated stream : %s\n" \
                    "$(human_size "$file_size")"

                if [ "$file_size" -gt 0 ]; then

                    extract_candidates "$blkls_out" "$strings_out"

                    candidate_count="$(wc -l < "$strings_out" 2>/dev/null | tr -d ' ')"

                    if [ "${candidate_count:-0}" -gt 0 ]; then

                        warn "Potential interesting strings: $candidate_count"

                        {
                            echo
                            echo "DEVICE: $dev"
                            echo "FILESYSTEM: $fstype"
                            echo "POTENTIAL STRINGS FROM UNALLOCATED SPACE:"
                            cat "$strings_out"
                        } >> "$FINDINGS_FILE"

                        TEXT_CANDIDATES=$((TEXT_CANDIDATES + candidate_count))

                    else
                        ok "No configured interesting strings found."
                    fi

                else
                    info "No unallocated data stream returned."
                fi

                # Remove potentially huge temporary file.
                rm -f "$blkls_out"

            else
                warn "blkls failed for $dev."
            fi

            ;;

        swap)
            info "Swap detected."
            info "Swap is not a normal filesystem and is not passed to fls/blkls."

            RAW_TARGETS=$((RAW_TARGETS + 1))

            ;;

        LVM2_member)
            info "LVM physical volume detected."
            info "Physical volume metadata is not itself a filesystem."

            UNKNOWN_TARGETS=$((UNKNOWN_TARGETS + 1))

            ;;

        crypto_LUKS)
            warn "Encrypted LUKS device detected."
            warn "Contents cannot be analyzed without the appropriate mapping/key."

            UNKNOWN_TARGETS=$((UNKNOWN_TARGETS + 1))

            ;;

        UNKNOWN|"")
            warn "Filesystem type is unknown."
            UNKNOWN_TARGETS=$((UNKNOWN_TARGETS + 1))
            ;;

        *)
            warn "Filesystem type '$fstype' is not supported by this analysis path."
            UNKNOWN_TARGETS=$((UNKNOWN_TARGETS + 1))
            ;;

    esac
}


# ============================================================
# RAW / UNKNOWN ANALYSIS
# ============================================================

analyze_raw() {

    local dev="$1"
    local fstype="$2"
    local type="$3"
    local source="$4"

    section "RAW / UNKNOWN ANALYSIS: $dev"

    printf "Device      : %s\n" "$dev"
    printf "Type        : %s\n" "$type"
    printf "Signature   : %s\n" "$fstype"
    printf "Source      : %s\n" "$source"

    size="$(device_size_bytes "$dev")"

    printf "Size        : %s\n" "$(human_size "$size")"

    RAW_TARGETS=$((RAW_TARGETS + 1))

    if [ "$FULL_RAW" -eq 1 ]; then

        warn "Full raw scan enabled."

        output="$WORKDIR/raw-$(basename "$dev" | tr '/' '_').txt"

        info "Reading complete raw device. This may take a long time..."

        # Read-only operation.
        #
        # strings sees the raw byte stream and writes only to
        # our temporary output file.

        if dd if="$dev" \
            bs=16M \
            iflag=fullblock \
            status=progress \
            2>"$WORKDIR/dd-$(basename "$dev" | tr '/' '_').log" |
            strings -a -n 8 |
            grep -Ei \
                'password|passwd|authorization|bearer |api[_-]?key|secret|private[_-]?key|access[_-]?token|refresh[_-]?token|database|mysql|postgres|mongodb|redis|ssh-rsa|BEGIN .*PRIVATE KEY|AWS_ACCESS_KEY|AWS_SECRET|github[_-]?token' |
            head -n 1000 > "$output"; then

            count="$(wc -l < "$output" | tr -d ' ')"

            if [ "$count" -gt 0 ]; then

                warn "Potential raw-data candidates: $count"

                {
                    echo
                    echo "DEVICE: $dev"
                    echo "TYPE: $type"
                    echo "SIGNATURE: $fstype"
                    echo "POTENTIAL RAW DATA:"
                    cat "$output"
                } >> "$RAW_FINDINGS_FILE"

                RAW_CANDIDATES=$((RAW_CANDIDATES + count))

            else
                ok "No configured interesting strings found."
            fi

        else
            warn "Raw scan failed for $dev."
        fi

        return
    fi


    # --------------------------------------------------------
    # Default bounded scan
    #
    # Scan beginning + end only.
    # This prevents accidentally reading many TB by default.
    # --------------------------------------------------------

    SAMPLE_SIZE=$((64 * 1024 * 1024))

    info "Performing bounded raw sample."
    info "Sample size: 64 MiB from beginning + 64 MiB from end."

    sample="$WORKDIR/sample-$(basename "$dev" | tr '/' '_').bin"
    output="$WORKDIR/rawstrings-$(basename "$dev" | tr '/' '_').txt"

    :

    # Beginning
    dd if="$dev" \
        bs=1M \
        count=64 \
        iflag=fullblock \
        of="$sample" \
        status=none \
        2>>"$ERROR_FILE" || true

    # End
    if [ "$size" -gt "$SAMPLE_SIZE" ]; then

        offset=$((size - SAMPLE_SIZE))

        dd if="$dev" \
            bs=1 \
            skip="$offset" \
            count="$SAMPLE_SIZE" \
            iflag=fullblock \
            of="$WORKDIR/end-$(basename "$dev" | tr '/' '_').bin" \
            status=none \
            2>>"$ERROR_FILE" || true

        cat "$WORKDIR/end-$(basename "$dev" | tr '/' '_').bin" >> "$sample" 2>/dev/null || true
    fi

    extract_candidates "$sample" "$output"

    count="$(wc -l < "$output" 2>/dev/null | tr -d ' ' || echo 0)"

    if [ "${count:-0}" -gt 0 ]; then

        warn "Potential raw-data candidates in bounded sample: $count"

        {
            echo
            echo "DEVICE: $dev"
            echo "TYPE: $type"
            echo "SIGNATURE: $fstype"
            echo "BOUNDED RAW SAMPLE:"
            cat "$output"
        } >> "$RAW_FINDINGS_FILE"

        RAW_CANDIDATES=$((RAW_CANDIDATES + count))

    else
        ok "No configured interesting strings found in bounded sample."
    fi

    rm -f "$sample"
    rm -f "$WORKDIR/end-$(basename "$dev" | tr '/' '_').bin"
}


# ============================================================
# PROCESS ALL TARGETS
# ============================================================

section "FILESYSTEM / STORAGE ANALYSIS"

while IFS='|' read -r dev type fstype source; do

    [ -n "$dev" ] || continue

    # Do not analyze the same physical target twice.
    case "$fstype" in
        UNKNOWN|"")
            analyze_raw "$dev" "$fstype" "$type" "$source"
            ;;

        LVM2_member|crypto_LUKS)
            analyze_filesystem "$dev" "$fstype" "$type" "$source"
            ;;

        swap)
            analyze_filesystem "$dev" "$fstype" "$type" "$source"
            ;;

        *)
            analyze_filesystem "$dev" "$fstype" "$type" "$source"
            ;;
    esac

done < "$TARGETS_FILE"


# ============================================================
# RESULTS
# ============================================================

section "RESULTS"

printf "Filesystem targets analyzed : %s\n" "$ANALYZED_TARGETS"
printf "Unknown/unanalyzable targets: %s\n" "$UNKNOWN_TARGETS"
printf "Raw targets inspected       : %s\n" "$RAW_TARGETS"
printf "Deleted entries             : %s\n" "$DELETED_ENTRIES"
printf "Filename candidates         : %s\n" "$FILENAME_CANDIDATES"
printf "Interesting-text candidates : %s\n" "$TEXT_CANDIDATES"
printf "Raw-data candidates         : %s\n" "$RAW_CANDIDATES"


# ============================================================
# FINDINGS
# ============================================================

if [ -s "$FINDINGS_FILE" ]; then

    section "FILESYSTEM FINDINGS"

    cat "$FINDINGS_FILE"

else

    ok "No filesystem findings were generated."
fi


if [ -s "$RAW_FINDINGS_FILE" ]; then

    section "RAW STORAGE FINDINGS"

    cat "$RAW_FINDINGS_FILE"

else

    ok "No raw-storage findings were generated."
fi


# ============================================================
# FINAL CLASSIFICATION
# ============================================================

section "FINAL STATUS"

if [ "$TEXT_CANDIDATES" -gt 0 ] ||
   [ "$RAW_CANDIDATES" -gt 0 ] ||
   [ "$DELETED_ENTRIES" -gt 0 ]; then

    warn "RESULT: POTENTIAL REMNANTS DETECTED"

    echo
    echo "Review the findings above."
    echo "A generic string or deleted filesystem entry is not by itself"
    echo "proof that the data belonged to another environment."
    echo "Controlled unique canary data provides substantially stronger evidence."

elif [ "$UNKNOWN_TARGETS" -gt 0 ]; then

    warn "RESULT: STORAGE PRESENT BUT NOT FULLY ANALYZABLE"

    echo
    echo "One or more exposed storage targets could not be analyzed"
    echo "as a recognized filesystem."
    echo "The environment must NOT be described as clean."

elif [ "$ANALYZED_TARGETS" -eq 0 ]; then

    warn "RESULT: NO FILESYSTEM ANALYSIS AVAILABLE"

else

    ok "RESULT: ANALYZED STORAGE - NO OBVIOUS REMNANTS DETECTED"

    echo
    echo "This means the analyzed filesystem areas did not produce"
    echo "findings matching the configured detection rules."
    echo "It does not prove that every byte of underlying storage is clean."
fi


# ============================================================
# IMPORTANT INTERPRETATION
# ============================================================

section "INTERPRETATION"

cat <<'EOF'

This tool performs read-only analysis of storage exposed to the
current environment.

Important distinctions:

1. A visible block device is not itself proof of a security issue.

2. A deleted filesystem entry is not necessarily recoverable content.

3. Generic strings found in unallocated/raw storage are not proof
   of another environment's data.

4. A controlled unique canary is stronger evidence.

5. If a unique canary created in one controlled environment remains
   recoverable from storage later exposed to a different environment,
   preserve:
     - exact canary value
     - creation timestamp
     - destruction/release timestamp
     - new environment creation timestamp
     - exact device/path where it was recovered
     - raw evidence/hash where possible

6. "No findings" does not mean the underlying physical storage is
   proven clean, especially where storage layers are hidden behind
   virtualization, encryption, RAID, snapshots, copy-on-write,
   network storage, or inaccessible overlay layers.

7. This script does not attempt to bypass encryption or obtain
   credentials/keys.

EOF


# ============================================================
# ENVIRONMENT SUMMARY
# ============================================================

section "EXPOSED STORAGE SUMMARY"

printf "Root filesystem : %s\n" "${ROOT_FSTYPE:-unknown}"
printf "Root source     : %s\n" "${ROOT_SOURCE:-unknown}"

echo
echo "Targets analyzed:"
cat "$TARGETS_FILE" 2>/dev/null || true

echo
echo "Analysis completed: $(date)"

exit 0
