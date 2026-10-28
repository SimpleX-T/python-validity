#!/usr/bin/env python3
"""Read registry values straight out of a Windows hive file (read-only).

Used by ``tools/find_windows_guid.sh`` to get ``MachineGuid`` without needing
``hivex`` / ``chntpw``.  Parses the regf container directly:

* base block ("regf"), then hbins ("hbin") with size-prefixed cells;
* value cells ("vk") carry a name (ASCII or UTF-16LE, see the compressed-name
  flag), a data type, and either inline data (<= 4 bytes, high bit of the size
  set) or an offset into the hive.

Values larger than ~16 KiB use "db" big-data cells; these are reassembled by
following the indirect block and concatenating 0x3FD8-byte segments (verified
against python-registry's large-data fixture).

Only reads the file; never writes to it.  Large hives are mapped with mmap,
so scanning a multi-hundred-MB SOFTWARE hive does not load it into RAM.

Usage:
    python3 tools/scan_hive.py SOFTWARE --name MachineGuid
    python3 tools/scan_hive.py SOFTWARE --name MachineGuid --out guid.txt
    python3 tools/scan_hive.py SYSTEM --name PairingData --name fwextId
    python3 tools/scan_hive.py SYSTEM --list-names '(?i)pair|gwk'   # survey

``--list-names`` prints every value name matching a regular expression together
with its type and size; it does not dump data.  Use it to find the name under
which a driver stores a key, then fetch it with ``--name``.

Exit codes: 0 value found, 1 not found, 2 unreadable / not a hive.
"""

import argparse
import mmap
import re
import struct
import sys
from pathlib import Path

REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_MULTI_SZ = 7


def iter_cells(data: bytes):
    """Yield (cell_file_offset, cell_payload) for every allocated cell."""
    if len(data) < 0x1000 or data[:4] != b'regf':
        raise ValueError('not a registry hive (missing regf signature)')

    pos = 0x1000
    while pos + 0x20 <= len(data):
        if data[pos:pos + 4] != b'hbin':
            # tolerate trailing garbage, but stop silently
            return
        bin_size = struct.unpack_from('<I', data, pos + 0x08)[0]
        if bin_size < 0x20 or pos + bin_size > len(data):
            return
        cell = pos + 0x20
        end = pos + bin_size
        while cell + 4 <= end:
            raw_size = struct.unpack_from('<i', data, cell)[0]
            size = abs(raw_size)
            if size < 4 or cell + size > end:
                break
            if raw_size < 0:  # allocated
                yield cell, data[cell + 4:cell + size]
            cell += size
        pos += bin_size


def parse_vk(payload: bytes):
    """Parse a vk cell payload -> dict or None."""
    if len(payload) < 0x14 or payload[:2] != b'vk':
        return None
    name_len, data_size, data_off, data_type, flags = struct.unpack_from(
        '<HIIIH', payload, 2)
    if name_len > len(payload) - 0x14:
        return None
    raw_name = payload[0x14:0x14 + name_len]
    if flags & 0x0001:  # VALUE_COMP_NAME: name is stored as single-byte ASCII
        name = raw_name.decode('latin-1')
    else:
        name = raw_name.decode('utf-16le', errors='replace')
    return {
        'name': name,
        'data_size': data_size,
        'data_offset': data_off,
        'type': data_type,
        'flags': flags,
    }


def read_big_data(data: bytes, list_offset: int, total_size: int) -> bytes:
    """Reassemble a "db" big-data value.

    Layout (as implemented by Windows and python-registry): the db cell holds
    an offset to an indirect cell whose payload is an array of dword offsets;
    each referenced cell contributes at most 0x3FD8 bytes of data.
    """
    list_abs = 0x1000 + list_offset
    if list_abs + 4 > len(data):
        return b''
    cell_size = struct.unpack_from('<i', data, list_abs)[0]
    if cell_size >= 0:
        return b''
    list_body = data[list_abs + 4:list_abs + abs(cell_size)]

    out = bytearray()
    remaining = total_size
    index = 0
    while remaining > 0:
        if (index + 1) * 4 > len(list_body):
            break
        segment_offset = struct.unpack_from('<I', list_body, index * 4)[0]
        chunk_size = min(0x3FD8, remaining)
        segment_abs = 0x1000 + segment_offset
        if segment_abs + 4 > len(data):
            break
        segment_cell = struct.unpack_from('<i', data, segment_abs)[0]
        if segment_cell >= 0:
            break
        chunk_size = min(chunk_size, abs(segment_cell) - 4)
        out += data[segment_abs + 4:segment_abs + 4 + chunk_size]
        remaining -= chunk_size
        index += 1
    return bytes(out)


def read_value_data(data: bytes, vk: dict) -> bytes:
    size = vk['data_size']
    if size & 0x80000000:  # inline, stored in the offset field itself
        return struct.pack('<I', vk['data_offset'])[:size & 0x7FFFFFFF]
    if size == 0:
        return b''
    absolute = 0x1000 + vk['data_offset']
    if absolute + 4 > len(data):
        return b''
    cell_size = struct.unpack_from('<i', data, absolute)[0]
    if cell_size >= 0:
        return b''
    body_start = absolute + 4
    if size > 0x3FD8 and data[body_start:body_start + 2] == b'db':
        list_offset = struct.unpack_from('<I', data, body_start + 4)[0]
        return read_big_data(data, list_offset, size)
    return data[body_start:absolute + abs(cell_size)][:size]


def decode_value(vk: dict, raw: bytes):
    if vk['type'] in (REG_SZ, REG_EXPAND_SZ):
        text = raw.decode('utf-16le', errors='replace')
        return text.split('\0', 1)[0]
    if vk['type'] == REG_MULTI_SZ:
        text = raw.decode('utf-16le', errors='replace')
        return [part for part in text.split('\0') if part]
    if vk['type'] == REG_DWORD:
        return struct.unpack('<I', raw[:4].ljust(4, b'\0'))[0]
    return raw


def find_many_values(data: bytes, names):
    """Return {name: [(vk, value, raw), ...]} for several value names.

    One pass over the cells, so dumping a set of values from a big hive stays
    cheap.  Lookup is case-insensitive, like the registry.
    """
    lookup = {}
    for name in names:
        lookup.setdefault(name.lower(), name)
    found = {name: [] for name in names}
    for _, payload in iter_cells(data):
        vk = parse_vk(payload)
        if vk is None:
            continue
        name = lookup.get(vk['name'].lower())
        if name is None:
            continue
        raw = read_value_data(data, vk)
        entry = (vk, decode_value(vk, raw), raw)
        for candidate in names:
            if candidate.lower() == name.lower():
                found[candidate].append(entry)
    return found


def find_values(data: bytes, name: str):
    return find_many_values(data, [name])[name]


def list_value_names(data: bytes, pattern: str):
    """Names (and type/size) of all values matching a regular expression.

    Values can be stored anywhere in the hive and scan_hive has no key-path
    information, so this is a name survey: useful to discover how a driver
    names the value that holds a key.
    """
    regex = re.compile(pattern)
    seen = {}
    for _, payload in iter_cells(data):
        vk = parse_vk(payload)
        if vk is None or not regex.search(vk['name']):
            continue
        size = vk['data_size'] & 0x7FFFFFFF
        seen.setdefault(vk['name'], set()).add((vk['type'], size))
    return [(name, sorted(shapes))
            for name, shapes in sorted(seen.items(),
                                       key=lambda item: item[0].lower())]


def list_names(data: bytes, pattern: str, hive) -> int:
    try:
        names = list_value_names(data, pattern)
    except re.error as error:
        print('ERROR: bad --list-names regex: %s' % error, file=sys.stderr)
        return 2
    if not names:
        print('no value name matches %r in %s' % (pattern, hive),
              file=sys.stderr)
        return 1
    for name, shapes in names:
        rendered = ', '.join('type %d, %d bytes' % (kind, size)
                             for kind, size in shapes)
        print('%-48s %s' % (name, rendered))
    print('%d matching value name(s) in %s' % (len(names), hive))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description='Read a value from a Windows registry hive without '
                    'any external tools.')
    parser.add_argument('hive', type=Path)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--name', action='append',
                       help='value name, e.g. MachineGuid (repeatable)')
    group.add_argument('--list-names', metavar='REGEX',
                       help='list value names matching REGEX (case-sensitive '
                            'Python regex; use (?i) for insensitive)')
    parser.add_argument('--out', type=Path,
                        help='append "name=value" lines to this file')
    args = parser.parse_args(argv)

    try:
        handle = args.hive.open('rb')
    except OSError as error:
        print('ERROR: cannot read %s: %s' % (args.hive, error),
              file=sys.stderr)
        return 2

    with handle:
        # The SOFTWARE hive can be several hundred MB.  Map it instead of
        # reading it into memory; the parser only uses slicing and
        # struct.unpack_from, both of which work on mmap objects.
        try:
            data = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
        except (ValueError, OSError):
            try:
                data = handle.read()
            except OSError as error:
                print('ERROR: cannot read %s: %s' % (args.hive, error),
                      file=sys.stderr)
                return 2
        try:
            if args.list_names is not None:
                return list_names(data, args.list_names, args.hive)
            values = find_many_values(data, args.name)
        except ValueError as error:
            print('ERROR: %s' % error, file=sys.stderr)
            return 2
        finally:
            if isinstance(data, mmap.mmap):
                data.close()

    lines = []
    for name in args.name:
        for vk, value, raw in values[name]:
            if isinstance(value, bytes):
                text = value.hex()
            elif isinstance(value, list):
                text = ';'.join(value)
            else:
                text = str(value)
            print('%s = %s  (type %d)' % (name, text, vk['type']))
            lines.append('%s=%s' % (name, text))

    if not lines:
        print('no value named %s in %s'
              % (', '.join(repr(n) for n in args.name), args.hive),
              file=sys.stderr)
        return 1

    if args.out is not None:
        try:
            with args.out.open('a', encoding='utf-8') as fh:
                for line in lines:
                    fh.write(line + '\n')
            print('appended to %s' % args.out)
        except OSError as error:
            print('WARNING: cannot write %s: %s' % (args.out, error),
                  file=sys.stderr)

    return 0


if __name__ == '__main__':
    sys.exit(main())
