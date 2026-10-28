#!/usr/bin/env bash
# Read-only: pull the Windows MachineGuid out of a Windows installation.
#
# Mounts every NTFS partition read-only, locates the Windows SOFTWARE registry
# hive, and reads HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid directly
# with tools/scan_hive.py (no hivex / chntpw needed).  Nothing is written to
# the Windows volumes; the output is a small text file that
# tools/hwkey_probe.py can consume with --guid-file.
#
# Usage:
#   sudo bash tools/find_windows_guid.sh [OUTFILE]
#
# Default OUTFILE: /tmp/opencode/windows-machine-guid.reg

set -uo pipefail

OUT="${1:-/tmp/opencode/windows-machine-guid.reg}"
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
scan="$script_dir/scan_hive.py"

die() { echo "ERROR: $*" >&2; exit 2; }

[ "$(id -u)" -eq 0 ] || die "run with sudo"
command -v lsblk >/dev/null 2>&1 || die "lsblk not found (util-linux)"
command -v python3 >/dev/null 2>&1 || die "python3 not found"
[ -f "$scan" ] || die "missing $scan"

mkdir -p "$(dirname "$OUT")" || die "cannot create $(dirname "$OUT")"
mkdir -p /tmp/opencode || die "cannot create /tmp/opencode"

work=$(mktemp -d /tmp/opencode/winhive.XXXXXX) || die "mktemp failed"

declare -a mounts=()
cleanup() {
    for m in "${mounts[@]:-}"; do
        [ -n "$m" ] && umount "$m" 2>/dev/null
    done
    rm -rf "$work"
}
trap cleanup EXIT INT TERM

mapfile -t parts < <(lsblk -rno NAME,FSTYPE | awk '$2 ~ /^ntfs/ {print "/dev/" $1}')
if [ "${#parts[@]}" -eq 0 ]; then
    die "no NTFS partition found (BitLocker-encrypted volume?)"
fi

: > "$OUT"
found=0

for dev in "${parts[@]}"; do
    mnt="$work/$(basename "$dev")"
    mkdir -p "$mnt"

    if ! mount -t ntfs3 -o ro "$dev" "$mnt" 2>/dev/null; then
        if ! mount -t ntfs-3g -o ro "$dev" "$mnt" 2>/dev/null; then
            echo "-- $dev: cannot mount read-only (BitLocker / hibernated / dirty)"
            rmdir "$mnt" 2>/dev/null
            continue
        fi
    fi
    mounts+=("$mnt")

    hive=$(find "$mnt" -maxdepth 5 \
                -ipath '*/Windows/System32/config/SOFTWARE' \
                -print -quit 2>/dev/null)
    if [ -z "$hive" ]; then
        echo "-- $dev: mounted, no Windows SOFTWARE hive"
        continue
    fi
    echo "-- $dev: $hive"

    if python3 "$scan" "$hive" --name MachineGuid --out "$OUT"; then
        found=1
    else
        rc=$?
        if [ "$rc" -eq 2 ]; then
            echo "   hive could not be parsed (unexpected format?)"
        else
            echo "   no MachineGuid value in this hive"
        fi
    fi
done

guids=$(sed -n 's/^MachineGuid=//p' "$OUT" 2>/dev/null | sort -u)
if [ -z "$guids" ]; then
    rm -f "$OUT"
    echo
    echo "No MachineGuid could be read."
    echo "Options:"
    echo "  * boot Windows once and run (cmd):"
    echo "      reg query HKLM\\SOFTWARE\\Microsoft\\Cryptography /v MachineGuid"
    echo "    then boot Linux and run:"
    echo "      sudo python3 $script_dir/hwkey_probe.py --machine-guid <GUID>"
    echo "  * if the volume is BitLocker-encrypted, unlock it in Windows first"
    echo "    (or use 'dislocker', which needs the recovery key)."
    exit 1
fi

chmod 600 "$OUT"
echo
echo "MachineGuid:"
echo "$guids" | sed 's/^/  /'
echo
echo "Wrote $OUT"
echo "Now run:"
echo "  sudo python3 $script_dir/hwkey_probe.py --guid-file $OUT"
