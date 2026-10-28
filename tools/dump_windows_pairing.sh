#!/usr/bin/env bash
# Read-only: dump the Windows registry values that may hold the pairing key.
#
# The Synaptics UMDF driver keeps its per-device state in the device registry
# key (HKLM\SYSTEM\...\Enum\USB\VID_06CB&PID_00BB\...\Device Parameters):
# values "PairingData", "PairingContext" and "UnpairingContext".  The firmware
# extension id ("fwextId") lives under HKLM\SOFTWARE\Validity.
#
# One of those values may be the 32-byte host key (GWK) that Windows used when
# it paired this sensor.  If it is, tools/hwkey_probe.py can try it and the
# existing Windows Hello pairing can be reused without a wipe.
#
# This script only mounts the Windows volumes read-only and reads the hive
# files with tools/scan_hive.py.  It never writes to them.
#
# Usage:
#   sudo bash tools/dump_windows_pairing.sh [--name NAME]... [OUTFILE]
#
# --name NAME adds a registry value from the survey (a name we did not guess)
# to the dump; repeatable.  Its size and, when printable, its text are shown,
# and its bytes are handed to hwkey_probe as another candidate.
#
# Default OUTFILE: /tmp/opencode/windows-pairing.txt
# Feed it to:
#   sudo python3 tools/hwkey_probe.py --raw-file /tmp/opencode/windows-pairing.txt

set -uo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
scan="$script_dir/scan_hive.py"

die() { echo "ERROR: $*" >&2; exit 2; }

OUT=""
EXTRA=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        --name)
            [ "$#" -ge 2 ] || die "--name needs a value"
            EXTRA+=("$2"); shift 2 ;;
        --name=*)
            EXTRA+=("${1#*=}"); shift ;;
        -h|--help)
            sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*)
            die "unknown option $1 (try --help)" ;;
        *)
            [ -z "$OUT" ] || die "only one OUTFILE may be given"
            OUT="$1"; shift ;;
    esac
done

OUT="${OUT:-/tmp/opencode/windows-pairing.txt}"
NAMES="${OUT%.txt}-names.txt"

VALUES=(PairingData PairingContext UnpairingContext fwextId MachineGuid)
# Extras may repeat a default name; keep the list unique so the hive is
# scanned once per value.
for extra in "${EXTRA[@]:-}"; do
    [ -n "$extra" ] || continue
    skip=""
    for known in "${VALUES[@]}"; do
        [ "$extra" = "$known" ] && skip=1
    done
    [ -n "$skip" ] || VALUES+=("$extra")
done
# Name survey: catches a key stored under a name we did not guess.
SURVEY_RE='(?i)pair|gwk|fwext|validity|synaptics|hostkey|host_key'

# stdin: "Name=hex" lines from scan_hive.py; prints size and printable text.
# scan_hive writes REG_SZ/REG_EXPAND_SZ values as decoded text and everything
# else as hex, so both forms are handled here.
# The program is kept in a variable because a heredoc would steal stdin from
# the pipe that feeds this function.
SHOW_VALUES_PY=$(cat <<'PY'
import sys

rows = []          # (name, rendered, count), first-seen order
index = {}         # rendered line -> position in rows


def render(name, value):
    try:
        raw = bytes.fromhex(value.strip())
    except ValueError:
        # A decoded string value, e.g. MachineGuid or a device path.
        return '   %-16s %4d chars  "%s"' % (name, len(value), value), 'chars:"%s"' % value
    text = ''
    for encoding in ('utf-16-le', 'ascii'):
        try:
            decoded = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        if decoded and all(32 <= ord(ch) < 127 for ch in decoded):
            text = decoded
            break
    suffix = '  "%s"' % text if text else ''
    return ('   %-16s %4d bytes%s' % (name, len(raw), suffix),
            'bytes:"%s"' % raw.hex())


for line in sys.stdin:
    line = line.strip()
    if not line or '=' not in line:
        continue
    name, value = line.split('=', 1)
    rendered, key = render(name.strip(), value)
    position = index.get(key)
    if position is None:
        index[key] = len(rows)
        rows.append([rendered, 1])
    else:
        rows[position][1] += 1

# One REG_SZ can appear in hundreds of keys ("HID\VID_06CB&PID_*" does);
# show it once with a multiplicity instead of flooding the terminal.
for rendered, count in rows:
    if count > 1:
        rendered += '  (x%d)' % count
    print(rendered)
PY
)

show_values() { python3 -c "$SHOW_VALUES_PY"; }

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
trap cleanup EXIT
trap 'exit 130' INT TERM

mapfile -t parts < <(lsblk -rno NAME,FSTYPE | awk '$2 ~ /^ntfs/ {print "/dev/" $1}')
if [ "${#parts[@]}" -eq 0 ]; then
    die "no NTFS partition found (BitLocker-encrypted volume?)"
fi

: > "$OUT"
: > "$NAMES"
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

    hives=$(find "$mnt" -maxdepth 5 \
                 \( -ipath '*/Windows/System32/config/SYSTEM' \
                    -o -ipath '*/Windows/System32/config/SOFTWARE' \) \
                 ! -ipath '*/Windows.old/*' \
                 -print 2>/dev/null)
    if [ -z "$hives" ]; then
        echo "-- $dev: mounted, no Windows registry hives"
        continue
    fi

    while IFS= read -r hive; do
        [ -n "$hive" ] || continue
        echo "-- $dev: $hive"
        # One pass per hive: scan_hive accepts repeated --name.
        args=()
        for name in "${VALUES[@]}"; do
            args+=(--name "$name")
        done
        before=$(wc -l < "$OUT")
        if python3 "$scan" "$hive" "${args[@]}" --out "$OUT" >/dev/null 2>&1; then
            tail -n +"$((before + 1))" "$OUT" | show_values
            found=1
        fi

        survey=$(mktemp "$work/names.XXXXXX") || continue
        if python3 "$scan" "$hive" --list-names "$SURVEY_RE" > "$survey" 2>/dev/null; then
            echo "   name survey:"
            sed "s/^/     /" "$survey"
            echo "-- $hive" >> "$NAMES"
            cat "$survey" >> "$NAMES"
        fi
        rm -f "$survey"
    done <<< "$hives"
done

if [ "$found" -eq 0 ]; then
    rm -f "$OUT"
    echo
    echo "No pairing-related registry value could be read."
    echo "Options:"
    echo "  * Windows may be hibernated (fast startup) -> boot it, shut down"
    echo "    fully, then retry."
    echo "  * if the volume is BitLocker-encrypted, unlock it in Windows first."
    echo "  * from Windows, export the values with (cmd as admin):"
    echo "      reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB\\VID_06CB&PID_00BB\" /s /v PairingData"
    echo "      reg query \"HKLM\\SOFTWARE\\Validity\" /s"
    exit 1
fi

if [ -s "$NAMES" ]; then
    chmod 600 "$NAMES"
else
    rm -f "$NAMES"
fi

chmod 600 "$OUT"
echo
echo "Wrote $OUT"
[ -f "$NAMES" ] && echo "Name survey: $NAMES"
echo "Now run:"
echo "  sudo python3 $script_dir/hwkey_probe.py --raw-file $OUT"
echo
echo "If no match is found, look at the name survey: a driver value with a"
echo "different name might hold the key.  Re-run with that name to add it:"
echo "  sudo bash $script_dir/dump_windows_pairing.sh --name <Name> $OUT"
echo "  sudo python3 $script_dir/hwkey_probe.py --raw-file $OUT"
