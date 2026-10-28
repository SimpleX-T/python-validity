#!/usr/bin/env python3
"""Try to recover the host key that encrypts the sensor's pairing blob.

Why
---
When this sensor was paired by Windows Hello, Windows generated a P-256
keypair and stored only the *encrypted* private key on the sensor (flash
partition 1, cert-store block 0x0004).  The encryption/HMAC key is derived
from a host secret:

    psk_enc = PRF(password_hardcoded, b'GWK' + hw_key)
    psk_val = PRF(psk_enc, b'GWK_SIGN' + gwk_sign_hardcoded)

``python-validity`` uses ``hw_key = product_name + '\\0' + product_serial +
'\\0'`` (ASCII).  ``tools/checkpair.py`` proved that Windows used something
else on this machine.  If we can find the secret Windows used, we can reuse
the existing pairing: no wipe, Windows Hello keeps working, Linux works too.

This tool is **read-only and offline**.  It takes the cert-store backup,
computes the HMAC of block 0x0004 for a large set of candidate ``hw_key``
values, and reports the first one that verifies.  No sensor access, no
writes.

Candidate sources
-----------------
* every readable ``/sys/class/dmi/id/*`` value (name, serial, UUID, board,
  chassis, BIOS ...), in ASCII and UTF-16LE, with and without NUL terminators;
* GUIDs passed with ``--machine-guid`` / found in ``--guid-file`` /
  ``--part4`` (Windows registry exports, partition-4 dumps), including the
  Windows little-endian raw layout;
* free-form values with ``--value`` (e.g. a hostname);
* raw binary blobs with ``--raw-hex`` / ``--raw-file`` -- e.g. the
  ``PairingData`` value dumped from the Windows device registry, including
  32-byte windows at every offset inside a larger blob;
* all sensible concatenations of the above.

A match is a 256-bit HMAC - false positives are not a concern.

Usage
-----
    sudo python3 tools/hwkey_probe.py
    sudo python3 tools/hwkey_probe.py --machine-guid 12345678-1234-...-...
    sudo python3 tools/hwkey_probe.py --guid-file /tmp/cryptography.reg
    sudo python3 tools/hwkey_probe.py --raw-file /tmp/opencode/windows-pairing.txt
    sudo python3 tools/hwkey_probe.py --read-part4        # needs the sensor
    sudo python3 tools/hwkey_probe.py --part4 backups/00bb-part4-*.bin

Getting the Windows device-registry pairing values (read-only)
--------------------------------------------------------------
    sudo bash tools/dump_windows_pairing.sh
    sudo python3 tools/hwkey_probe.py --raw-file /tmp/opencode/windows-pairing.txt

Getting the Windows MachineGuid (read-only, Windows not needed)
---------------------------------------------------------------
    sudo bash tools/find_windows_guid.sh
    sudo python3 tools/hwkey_probe.py --guid-file /tmp/opencode/windows-machine-guid.reg

The script mounts every NTFS partition read-only, reads
HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid straight out of the
SOFTWARE hive with tools/scan_hive.py (no hivex / chntpw needed), and umounts
again.  If the volume cannot be mounted (BitLocker, hibernated Windows), boot
Windows once and run:

    reg query HKLM\\SOFTWARE\\Microsoft\\Cryptography /v MachineGuid

then pass the value with ``--machine-guid``.

Exit codes: 0 match found, 1 no match, 2 precondition missing.
"""

import argparse
import hashlib
import hmac
import json
import os
import re
import sys
import time
from pathlib import Path
from struct import unpack

REPO = Path(__file__).resolve().parent.parent
PROJECT = REPO
sys.path.insert(0, str(REPO))

from validitysensor.tls import gwk_sign_hardcoded, password_hardcoded, prf  # noqa: E402

GUID_PATTERN = r'[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}'
GUID_TEXT_RE = re.compile(GUID_PATTERN)
GUID_BYTES_RE = re.compile(GUID_PATTERN.encode())
PRINTABLE_RE = re.compile(rb'[ -~]{6,64}')

DMI_FILES = (
    'product_name', 'product_serial', 'product_uuid', 'product_sku',
    'product_family', 'product_version',
    'sys_vendor', 'board_name', 'board_serial', 'board_vendor',
    'board_version', 'board_asset_tag',
    'chassis_serial', 'chassis_vendor', 'chassis_version',
    'bios_vendor', 'bios_version', 'bios_date',
)

# Seeds/labels tried in front of hw_key.  The first one is what
# python-validity uses; the others are cheap to test.
GWK_LABELS = (b'GWK', b'GWK\0', b'GWK\0\0')


# --------------------------------------------------------------------------
# cert-store handling
# --------------------------------------------------------------------------

def parse_blocks(certstore: bytes):
    walk = certstore
    blocks = {}
    while len(walk) >= 0x24:
        hdr, walk = walk[:4], walk[4:]
        hs, walk = walk[:0x20], walk[0x20:]
        block_id, size = unpack('<HH', hdr)
        if block_id == 0xFFFF:
            break
        body, walk = walk[:size], walk[size:]
        if hashlib.sha256(body).digest() != hs:
            raise RuntimeError('block 0x%04x has a bad SHA256' % block_id)
        blocks[block_id] = body
    return blocks


def split_pairing_blob(body: bytes):
    if not body or body[0] != 2:
        raise RuntimeError('unexpected private-key prefix %r'
                           % (body[:1],))
    c, mac = body[1:-0x20], body[-0x20:]
    return c, mac


def mac_for(hw_key: bytes, label: bytes, c: bytes) -> bytes:
    psk_enc = prf(password_hardcoded, label + hw_key, 0x20)
    psk_val = prf(psk_enc, b'GWK_SIGN' + gwk_sign_hardcoded, 0x20)
    return hmac.new(psk_val, c, hashlib.sha256).digest()


# --------------------------------------------------------------------------
# candidate generation
# --------------------------------------------------------------------------

def read_dmi_values():
    values = {}
    for name in DMI_FILES:
        try:
            text = Path('/sys/class/dmi/id/' + name).read_text().strip('\0\r\n\t ')
        except OSError:
            continue
        if text and not text.startswith('<'):
            values[name] = text
    return values


def guid_variants(guid: str):
    """All plausible byte encodings of one GUID string."""
    g = guid.strip().strip('{}')
    if not GUID_TEXT_RE.fullmatch(g):
        return []
    out = []
    for f in {g.lower(), g.upper()}:
        for s in (f, '{%s}' % f):
            out.append(('ascii:%s' % s, s.encode()))
            out.append(('ascii-nul:%s' % s, s.encode() + b'\0'))
            out.append(('utf16:%s' % s, s.encode('utf-16le')))
            out.append(('utf16-nul:%s' % s, s.encode('utf-16le') + b'\0\0'))
    raw = bytes.fromhex(g.replace('-', ''))
    le = raw[0:4][::-1] + raw[4:6][::-1] + raw[6:8][::-1] + raw[8:]
    out.append(('raw-be:%s' % g, raw))
    out.append(('raw-le:%s' % g, le))
    out.append(('raw-le-nul:%s' % g, le + b'\0'))
    # "hex without dashes" is a common registry/UEFI representation
    compact = g.replace('-', '')
    for f in {compact.lower(), compact.upper()}:
        out.append(('compact:%s' % f, f.encode()))
        out.append(('compact-nul:%s' % f, f.encode() + b'\0'))
        out.append(('compact-utf16:%s' % f, f.encode('utf-16le')))
        out.append(('compact-utf16-nul:%s' % f, f.encode('utf-16le') + b'\0\0'))
    return out


def text_variants(label: str, text: str):
    out = []
    for enc in ('ascii', 'utf-16le'):
        try:
            raw = text.encode(enc)
        except UnicodeEncodeError:
            continue
        suffix = b'\0' if enc == 'ascii' else b'\0\0'
        out.append(('%s[%s]' % (label, enc), raw))
        out.append(('%s[%s]+nul' % (label, enc), raw + suffix))
    return out


def raw_variants(label: str, blob: bytes):
    """Plausible hw_key views of a raw registry blob.

    The GWK is 32 bytes.  A registry value may hold it bare, or wrapped in a
    small header (type/size), so also try every 32-byte window.  Digests and
    NUL-stripped forms are cheap extra shots.
    """
    out = []
    if not blob:
        return out
    if len(blob) <= 4096:
        out.append((label, blob))
    if len(blob) > 32:
        out.append(('%s first32' % label, blob[:32]))
        out.append(('%s last32' % label, blob[-32:]))
        # A registry blob holding the key is small.  For very large values,
        # scan the start and the end instead of every offset.
        if len(blob) <= 0x10000:
            offsets = range(0, len(blob) - 32 + 1)
        else:
            offsets = list(range(0, 0x10000)) + \
                list(range(len(blob) - 0x1000, len(blob) - 32 + 1))
        for offset in offsets:
            out.append(('%s window@%#x' % (label, offset),
                        blob[offset:offset + 32]))
    stripped = blob.rstrip(b'\0')
    if stripped and stripped != blob:
        out.append(('%s strip-nul' % label, stripped))
    seen = set()
    unique = []
    for desc, key in out:
        if key not in seen:
            seen.add(key)
            unique.append((desc, key))
    return unique


def build_candidates(dmi: dict, guids, explicit_values, scanned_values,
                     raw_values=()):
    """Return list of (description, hw_key bytes), de-duplicated.

    ``explicit_values`` come from ``--value`` (trusted, combined freely);
    ``scanned_values`` come from a partition dump (noisy, only combined with
    the DMI core); ``raw_values`` are (label, bytes) pairs from ``--raw-hex``
    / ``--raw-file`` (trusted, like ``--value``).
    """
    singles = []  # (desc, key)
    for name, text in sorted(dmi.items()):
        variants = text_variants('dmi.%s=%r' % (name, text), text)
        singles += variants
        if name in ('product_name', 'product_serial', 'product_uuid'):
            # Windows might normalise case; cheap to test for the core fields
            for desc, key in variants:
                if '[ascii' in desc:
                    singles.append((desc + ' lower', key.lower()))
                    singles.append((desc + ' upper', key.upper()))
        if name in ('product_name', 'product_serial'):
            # SMBIOS strings are sometimes space padded to a fixed width
            for width in (32, 64):
                if len(text) < width:
                    padded = text.ljust(width).encode('ascii', 'ignore')
                    singles.append(('dmi.%s padded%d' % (name, width), padded))
                    singles.append(('dmi.%s padded%d+nul' % (name, width),
                                    padded + b'\0'))
    for guid in guids:
        singles += guid_variants(guid)
    for i, value in enumerate(explicit_values):
        singles += text_variants('value[%d]=%r' % (i, value), value)
    for i, value in enumerate(scanned_values):
        singles += text_variants('scan[%d]=%r' % (i, value), value)
    raw_atoms = []
    for label, blob in raw_values:
        if not blob:
            continue
        variants = raw_variants(label, blob)
        singles += variants
        raw_atoms += variants

    # de-duplicate by bytes, keep the first (most descriptive) label
    seen = set()
    atoms = []
    for desc, key in singles:
        if key and key not in seen:
            seen.add(key)
            atoms.append((desc, key))

    # The Windows driver may hash the identifier before using it as the GWK
    # input; test the common digests as standalone candidates.
    hashed = []
    for desc, key in atoms:
        hashed.append(('sha256(%s)' % desc, hashlib.sha256(key).digest()))
        hashed.append(('sha1(%s)' % desc, hashlib.sha1(key).digest()))
        hashed.append(('md5(%s)' % desc, hashlib.md5(key).digest()))

    candidates = list(atoms) + hashed

    # Atoms built from --value / partition-4 strings are noisy; pair them
    # with the DMI core but not with each other.
    core = [(d, k) for d, k in atoms
            if any(('dmi.%s=' % n) in d for n in
                   ('product_name', 'product_serial', 'product_uuid'))
            or d.startswith('guid')]
    explicit = [(d, k) for d, k in atoms if d.startswith('value[')]
    scanned = [(d, k) for d, k in atoms if d.startswith('scan[')]

    separators = (b'', b'\0', b'\0\0')

    # Raw blobs expand to hundreds of windows; combining all of them with the
    # DMI core would multiply that by ~100 for almost no gain.  The key is
    # expected to be a self-contained 32-byte value, so only combine the
    # leading candidates of each blob.
    raw_combine = [item for item in raw_atoms if len(item[1]) <= 128][:24]

    def combine(list_a, list_b):
        for desc_a, key_a in list_a:
            for desc_b, key_b in list_b:
                for sep in separators:
                    candidates.append(('%s + %r + %s'
                                       % (desc_a, sep, desc_b),
                                       key_a + sep + key_b))

    combine(core, core)
    combine(explicit, core)
    combine(core, explicit)
    combine(explicit, explicit)
    combine(scanned, core)
    combine(raw_combine, core)
    combine(core, raw_combine)
    combine(raw_combine, explicit)

    # 3-part combinations, plain ASCII forms only, from a small primary set
    primary = []
    for name in ('product_name', 'product_serial', 'product_uuid'):
        if name in dmi:
            primary.append(('dmi.%s' % name, dmi[name].encode('ascii',
                                                             'ignore')))
    for guid in guids[:8]:
        primary.append(('guid:%s' % guid, guid.strip('{}').lower().encode()))
    for i, value in enumerate(explicit_values[:8]):
        primary.append(('value[%d]' % i, value.encode('ascii', 'ignore')))

    for desc_a, key_a in primary:
        for desc_b, key_b in primary:
            for desc_c, key_c in primary:
                candidates.append(('%s\\0%s\\0%s' % (desc_a, desc_b, desc_c),
                                   key_a + b'\0' + key_b + b'\0' + key_c))

    return candidates


# --------------------------------------------------------------------------
# scanning helpers
# --------------------------------------------------------------------------

ID_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{5,63}$')


def guid_strings_in(data: bytes):
    """Text GUIDs (ASCII or UTF-16LE); raw fallback only if nothing textual."""
    found = []
    for match in GUID_BYTES_RE.finditer(data):
        found.append(match.group().decode('ascii'))
    try:
        wide = data.decode('utf-16le', errors='ignore')
    except Exception:  # noqa: BLE001
        wide = ''
    for match in GUID_TEXT_RE.finditer(wide):
        found.append(match.group())

    if not found:
        # Windows GUIDs can also be stored as a raw 16-byte little-endian
        # struct.  This scan is noisy, so only use it as a fallback and
        # keep the first few hits.
        for i in range(0, max(0, len(data) - 16)):
            chunk = data[i:i + 16]
            if chunk == b'\0' * 16 or chunk == b'\xff' * 16:
                continue
            if chunk[6] >> 4 != 4:  # version 4 GUIDs dominate in practice
                continue
            raw = (chunk[0:4][::-1] + chunk[4:6][::-1]
                   + chunk[6:8][::-1] + chunk[8:])
            found.append('%s-%s-%s-%s-%s' % (
                raw[0:4].hex(), raw[4:6].hex(), raw[6:8].hex(),
                raw[8:10].hex(), raw[10:16].hex()))
            if len(found) >= 24:
                break

    out = []
    seen = set()
    for g in found:
        g = g.strip().lower()
        if g not in seen:
            seen.add(g)
            out.append(g)
    return out


def strings_in(data: bytes, limit=60):
    out = []
    seen = set()
    for match in PRINTABLE_RE.finditer(data):
        text = match.group().decode('ascii').strip()
        if text in seen or not ID_RE.match(text):
            continue
        seen.add(text)
        out.append(text)
        if len(out) >= limit:
            break
    return out


def scan_dump(data: bytes):
    guids = guid_strings_in(data)
    strings = strings_in(data)
    return guids, strings


# --------------------------------------------------------------------------
# hardware: read partition 4 (read-only)
# --------------------------------------------------------------------------

def read_part4():
    import usb.core as ucore

    import checkpair  # same directory
    from validitysensor.flash import get_flash_info, read_flash
    from validitysensor.sensor import RebootException, reboot
    from validitysensor.usb import usb

    dev = ucore.find(idVendor=checkpair.VID, idProduct=checkpair.PID)
    if dev is None:
        print('ERROR: 06cb:00bb not found', file=sys.stderr)
        return None

    serial = (dev.serial_number or 'unknown').replace('/', '_')
    print('== read partition 4 (read-only)')
    usb.open_dev(dev)
    try:
        checkpair.init_sequence()
        info = get_flash_info()
        part = next((p for p in info.partitions if p.id == 4), None)
        if part is None:
            print('ERROR: no partition 4 on this sensor', file=sys.stderr)
            return None
        print('    partition 4: offset 0x%x size 0x%x access 0x%02x'
              % (part.offset, part.size, part.access_lvl))
        data = b''
        while len(data) < part.size:
            chunk_size = min(0x1000, part.size - len(data))
            try:
                chunk = read_flash(4, len(data), chunk_size)
            except Exception as error:  # noqa: BLE001
                print('    stopped after %d bytes: %s' % (len(data), error))
                break
            if not chunk:
                break
            data += chunk
        if not data:
            print('ERROR: partition 4 is not readable without TLS',
                  file=sys.stderr)
            return None
        outdir = PROJECT / 'backups'
        outdir.mkdir(parents=True, exist_ok=True)
        path = outdir / ('00bb-part4-%s-%s.bin'
                         % (serial, time.strftime('%Y%m%d-%H%M%S')))
        path.write_bytes(data)
        os.chmod(path, 0o600)
        print('    saved %d bytes to %s' % (len(data), path))
        return data
    finally:
        try:
            reboot()
        except RebootException:
            pass
        except Exception as error:  # noqa: BLE001
            print('    reboot failed (usually harmless): %s' % error)
        usb.dev = None


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def newest_certstore():
    files = sorted((PROJECT / 'backups').glob('00bb-certstore-*.bin'),
                   key=lambda p: p.stat().st_mtime)
    return files[-1] if files else None


HEX_RE = re.compile(r'^[0-9A-Fa-f]+$')
GUID_ONLY_RE = re.compile(r'^\{?' + GUID_PATTERN + r'\}?$')
# Longer decoded strings are descriptions, not keys; skipping them keeps the
# candidate count sane when a dump contains driver prose.
TEXT_CANDIDATE_MAX = 256


def load_raw_blobs(hex_values, paths):
    """Build (label, bytes) candidates from --raw-hex / --raw-file.

    Files may be raw binary or the text output of tools/dump_windows_pairing.sh
    / scan_hive.py ("Name=hex").  Trailing "(type N)" annotations are ignored.
    """
    blobs = []
    for i, value in enumerate(hex_values):
        compact = ''.join(value.split())
        if len(compact) % 2 or not HEX_RE.fullmatch(compact):
            print('WARNING: --raw-hex[%d] is not valid hex, ignored' % i,
                  file=sys.stderr)
            continue
        blobs.append(('raw-hex[%d]' % i, bytes.fromhex(compact)))

    for path in paths:
        try:
            text = path.read_text(errors='strict')
        except (OSError, UnicodeDecodeError):
            try:
                data = path.read_bytes()
            except OSError as error:
                print('WARNING: cannot read %s: %s' % (path, error),
                      file=sys.stderr)
                continue
            blobs.append(('raw-file[%s]' % path.name, data))
            continue
        found = False
        for line in text.splitlines():
            line = line.strip()
            if '=' not in line:
                continue
            name, value = line.split('=', 1)
            name = name.strip()
            # scan_hive's stdout form appends "  (type N)"; --out does not.
            value = re.sub(r'\s+\(type \d+\)$', '', value.strip())
            compact = ''.join(value.split())
            if GUID_ONLY_RE.match(compact):
                # scan_hive decodes REG_SZ, so MachineGuid arrives as text.
                guid = compact.strip('{}').lower()
                blobs.append(('%s=%s ascii' % (name, path.name), guid.encode()))
                blobs.append(('%s=%s utf16le' % (name, path.name),
                              guid.encode('utf-16le')))
                found = True
                continue
            if len(compact) % 2 == 0 and HEX_RE.fullmatch(compact):
                blobs.append(('%s=%s' % (name, path.name),
                              bytes.fromhex(compact)))
                found = True
                continue
            # Any other decoded string value (device path, serial, ...) is a
            # candidate too: a hw_key is just bytes.
            if 0 < len(value) <= TEXT_CANDIDATE_MAX:
                blobs.append(('%s=%s ascii' % (name, path.name),
                              value.encode()))
                blobs.append(('%s=%s utf16le' % (name, path.name),
                              value.encode('utf-16le')))
                found = True
        if not found:
            try:
                blobs.append(('raw-file[%s]' % path.name, path.read_bytes()))
            except OSError as error:
                print('WARNING: cannot read %s: %s' % (path, error),
                      file=sys.stderr)
    return blobs


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description='Offline search for the host key that protects the '
                    "sensor's stored pairing.")
    parser.add_argument('--certstore', type=Path,
                        help='cert-store backup (default: newest in backups/)')
    parser.add_argument('--machine-guid', action='append', default=[],
                        metavar='GUID', help='candidate Windows MachineGuid '
                                             '(repeatable)')
    parser.add_argument('--guid-file', type=Path, action='append', default=[],
                        help='file to scan for GUIDs (registry export, etc.)')
    parser.add_argument('--part4', type=Path,
                        help='partition-4 dump to scan for GUIDs/strings')
    parser.add_argument('--value', action='append', default=[],
                        metavar='TEXT', help='extra candidate value, e.g. '
                                             'hostname or sensor serial')
    parser.add_argument('--raw-hex', action='append', default=[],
                        metavar='HEX', help='raw binary candidate (hex), '
                                            'e.g. a PairingData value')
    parser.add_argument('--raw-file', type=Path, action='append', default=[],
                        help='raw binary file or "Name=hex" registry dump '
                             'to scan for 32-byte key candidates')
    parser.add_argument('--read-part4', action='store_true',
                        help='read flash partition 4 from the sensor first '
                             '(read-only, needs root)')
    args = parser.parse_args(argv)

    certstore_path = args.certstore or newest_certstore()
    if certstore_path is None:
        print('ERROR: no cert-store backup found; pass --certstore',
              file=sys.stderr)
        return 2
    try:
        certstore = certstore_path.read_bytes()
    except OSError as error:
        print('ERROR: cannot read %s: %s\n'
              '       the backup is 0600 root -- run with sudo.'
              % (certstore_path, error), file=sys.stderr)
        return 2

    blocks = parse_blocks(certstore)
    if 4 not in blocks:
        print('ERROR: cert-store has no pairing block 0x0004 (NO_PAIRING)',
              file=sys.stderr)
        return 1
    c, mac = split_pairing_blob(blocks[4])
    print('== cert-store %s' % certstore_path)
    print('   pairing blob: %d bytes ciphertext, %d-byte HMAC'
          % (len(c), len(mac)))

    guids = []
    for guid in args.machine_guid:
        guids.append(guid)
    for path in args.guid_file:
        try:
            data = path.read_bytes()
        except OSError as error:
            print('WARNING: cannot read %s: %s' % (path, error),
                  file=sys.stderr)
            continue
        found = guid_strings_in(data)
        print('   %s: %d GUID(s)' % (path, len(found)))
        guids += found

    explicit = list(args.value)
    raw_blobs = load_raw_blobs(args.raw_hex, args.raw_file)
    scanned = []
    if args.read_part4:
        if os.geteuid() != 0:
            print('ERROR: --read-part4 needs root', file=sys.stderr)
            return 2
        data = read_part4()
        if data is None:
            return 1
        found_guids, found_strings = scan_dump(data)
        print('   partition 4: %d GUID(s), %d string(s)'
              % (len(found_guids), len(found_strings)))
        guids += found_guids
        scanned += found_strings
    elif args.part4 is not None:
        data = args.part4.read_bytes()
        found_guids, found_strings = scan_dump(data)
        print('   %s: %d GUID(s), %d string(s)'
              % (args.part4, len(found_guids), len(found_strings)))
        guids += found_guids
        scanned += found_strings

    if not guids:
        print('   (no GUID text candidates -- MachineGuid not supplied; '
              'raw blobs are still tried)')

    dmi = read_dmi_values()
    print('== candidates')
    print('   DMI values: %d, GUIDs: %d, --value: %d, raw blobs: %d, scanned: %d'
          % (len(dmi), len(set(g.lower() for g in guids)), len(explicit),
             len(raw_blobs), len(scanned)))
    candidates = build_candidates(dmi, guids, explicit, scanned, raw_blobs)

    # de-duplicate again: combinations often collide
    unique = []
    seen_keys = set()
    for desc, key in candidates:
        if key in seen_keys:
            continue
        seen_keys.add(key)
        unique.append((desc, key))
    candidates = unique
    print('   derived hw_key candidates: %d' % len(candidates))

    print('== HMAC check')
    match = None
    for label in GWK_LABELS:
        for desc, key in candidates:
            if hmac.compare_digest(mac_for(key, label, c), mac):
                match = (desc, key, label)
                break
        if match is not None:
            break

    if match is not None:
        desc, key, label = match
        print()
        print('MATCH FOUND')
        print('  hw_key  (%d bytes): %s' % (len(key), key.hex()))
        print('  as text           : %r' % key)
        print('  derived from      : %s' % desc)
        print('  GWK label         : %r' % label)
        print()
        print('  Next step: feed this key to the driver instead of the')
        print('  DMI default, then re-run tools/checkpair.py.  If it says')
        print('  ALREADY_PAIRED, no wipe is needed and Windows Hello')
        print('  keeps working.')
        report = {'stamp': time.strftime('%Y%m%d-%H%M%S'),
                  'certstore': str(certstore_path),
                  'result': 'MATCH', 'hw_key_hex': key.hex(),
                  'description': desc, 'gwk_label': label.hex(),
                  'candidates': len(candidates),
                  'guids': sorted(set(guids)),
                  'dmi': dmi}
        outdir = PROJECT / 'backups'
        path = outdir / ('00bb-hwkey-%s.json' % report['stamp'])
        try:
            path.write_text(json.dumps(report, indent=2) + '\n')
            os.chmod(path, 0o600)
            print('  report: %s' % path)
        except OSError as error:
            print('  (could not write report: %s)' % error)
        return 0

    print()
    print('NO MATCH')
    print('  None of the %d candidates reproduces the pairing HMAC.'
          % len(candidates))
    print('  Likely causes:')
    print('    * the secret is not machine-readable (TPM-sealed), or')
    print('    * it uses data we have not supplied yet.')
    print('  Try, in this order:')
    print('    1. dump the Windows registry pairing values (read-only):')
    print('         sudo bash tools/dump_windows_pairing.sh')
    print('         sudo python3 tools/hwkey_probe.py --raw-file /tmp/opencode/windows-pairing.txt')
    print('    2. export the Windows MachineGuid and pass --guid-file')
    print('    3. read partition 4 (may contain the host key record):')
    print('         sudo python3 tools/hwkey_probe.py --read-part4')
    print('    4. pass any extra identifiers with --value (hostname, sensor')
    print('       serial, Windows product ID ...)')
    print('  If all of that fails, the pairing cannot be reused; the wipe in')
    print('  tools/flash00bb.py is then the only option.')
    return 1


if __name__ == '__main__':
    sys.exit(main())
