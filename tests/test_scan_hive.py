import importlib.util
import io
import struct
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent / 'tools'


def load_scan_hive():
    spec = importlib.util.spec_from_file_location(
        'scan_hive', TOOLS / 'scan_hive.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scan_hive = load_scan_hive()

REG_SZ = 1
REG_BINARY = 3
REG_DWORD = 4


def align8(size):
    return (size + 7) & ~7


class HiveBuilder:
    """Minimal but structurally valid regf/hbin writer for tests.

    Offsets in the registry are relative to the start of the hive-bins area
    (i.e. 0x1000 in the file), which is what ``scan_hive`` assumes.
    """

    def __init__(self):
        self.bins = bytearray()
        self.cells = []

    def _alloc(self, payload, allocated=True):
        size = align8(len(payload) + 4)
        offset = 0x20 + len(self.bins)
        sign = -size if allocated else size
        self.bins += struct.pack('<i', sign)
        self.bins += payload
        self.bins += b'\0' * (size - 4 - len(payload))
        self.cells.append((offset, allocated))
        return offset

    def add_data(self, data):
        return self._alloc(data)

    def add_value(self, name, data_type, data, compressed=True,
                  inline=False, allocated=True):
        if isinstance(name, str):
            key = name.encode('latin-1') if compressed else \
                name.encode('utf-16le')
        else:
            key = name
        if inline:
            data_size = 0x80000000 | len(data)
            data_offset = struct.unpack('<I', data[:4].ljust(4, b'\0'))[0]
        else:
            data_offset = self.add_data(data)
            data_size = len(data)
        payload = b'vk' + struct.pack(
            '<HIIIHH', len(key), data_size, data_offset, data_type,
            0x0001 if compressed else 0x0000, 0)
        payload += key
        self._alloc(payload, allocated=allocated)

    def add_free(self, payload):
        self._alloc(payload, allocated=False)

    def add_big_value(self, name, data, compressed=True):
        """Add a value that uses the "db" big-data cell layout."""
        segments = []
        rest = memoryview(data)
        while len(rest):
            chunk, rest = rest[:0x3FD8], rest[0x3FD8:]
            segments.append(self.add_data(bytes(chunk)))
        list_offset = self._alloc(
            b''.join(struct.pack('<I', offset) for offset in segments))
        db_offset = self._alloc(
            b'db' + struct.pack('<HI', len(segments), list_offset) + b'\0' * 4)
        key = name.encode('latin-1') if compressed else name.encode('utf-16le')
        payload = b'vk' + struct.pack(
            '<HIIIHH', len(key), len(data), db_offset, REG_BINARY,
            0x0001 if compressed else 0x0000, 0)
        payload += key
        self._alloc(payload)

    def build(self):
        # root key cell (never inspected, but keeps the hive realistic)
        root = b'nk' + struct.pack('<H', 0x2C) + b'\0' * (0x4C - 4) + b'ROOT'
        root_off = self._alloc(root)

        bins_size = align8(len(self.bins) + 0x20)
        header = b'hbin' + struct.pack('<II', 0, bins_size) + b'\0' * 0x14
        bins = header + self.bins + b'\0' * (bins_size - 0x20 - len(self.bins))

        base = bytearray(0x1000)
        base[0:4] = b'regf'
        struct.pack_into('<IIQ', base, 4, 1, 1, 0)
        struct.pack_into('<IIII', base, 0x14, 1, 5, 0, 1)
        struct.pack_into('<II', base, 0x24, root_off, len(bins))
        return bytes(base) + bytes(bins)


GUID = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'


def guid_hive(guid=GUID, extra_values=True, free_decoy=False):
    hive = HiveBuilder()
    hive.add_value('MachineGuid', REG_SZ,
                   guid.encode('utf-16le') + b'\0\0')
    if extra_values:
        hive.add_value('MachineGuidBackup', REG_SZ,
                       b'11111111-2222-3333-4444-555555555555\0\0')
        hive.add_value('VolatileName', REG_SZ,
                       'not-a-guid\0'.encode('utf-16le'), compressed=False)
        hive.add_value('DwordValue', REG_DWORD, b'\x78\x56\x34\x12',
                       inline=True)
        hive.add_value('BinaryValue', REG_BINARY, bytes(range(40)))
    if free_decoy:
        # deleted value cell: looks like a vk, must be ignored
        decoy = b'vk' + struct.pack(
            '<HIIIHH', 11, 0x80000000 | 4, 0x41424344, REG_SZ, 1, 0)
        decoy += b'MachineGuid'
        hive.add_free(decoy)
    return hive.build()


class ScanHiveTests(unittest.TestCase):
    def test_finds_machine_guid(self):
        values = scan_hive.find_values(guid_hive(), 'MachineGuid')
        self.assertEqual([value for _, value, _ in values], [GUID])

    def test_lookup_is_case_insensitive(self):
        self.assertEqual(
            scan_hive.find_values(guid_hive(), 'machineguid')[0][1], GUID)

    def test_compressed_and_wide_names_are_distinct(self):
        data = guid_hive()
        self.assertEqual(scan_hive.find_values(data, 'VolatileName')[0][1],
                         'not-a-guid')
        self.assertEqual(scan_hive.find_values(data, 'MachineGuid')[0][1],
                         GUID)

    def test_name_is_not_matched_by_prefix(self):
        self.assertEqual(scan_hive.find_values(guid_hive(), 'MachineGui'), [])

    def test_inline_dword_is_decoded(self):
        values = scan_hive.find_values(guid_hive(), 'DwordValue')
        self.assertEqual(values[0][1], 0x12345678)

    def test_binary_value_is_returned_raw(self):
        values = scan_hive.find_values(guid_hive(), 'BinaryValue')
        self.assertEqual(values[0][1], bytes(range(40)))

    def test_free_cell_is_ignored(self):
        values = scan_hive.find_values(guid_hive(free_decoy=True),
                                       'MachineGuid')
        self.assertEqual(len(values), 1)
        self.assertEqual(values[0][1], GUID)

    def test_missing_value_returns_empty(self):
        self.assertEqual(scan_hive.find_values(guid_hive(), 'Nope'), [])

    def test_find_many_values_single_pass(self):
        data = guid_hive()
        found = scan_hive.find_many_values(
            data, ['MachineGuid', 'BinaryValue', 'Missing'])
        self.assertEqual(found['MachineGuid'][0][1], GUID)
        self.assertEqual(found['BinaryValue'][0][1], bytes(range(40)))
        self.assertEqual(found['Missing'], [])
        self.assertNotIn('MachineGuidBackup', found)

    def test_find_many_values_case_variants_do_not_duplicate(self):
        found = scan_hive.find_many_values(
            guid_hive(), ['MachineGuid', 'machineguid'])
        self.assertEqual(len(found['MachineGuid']), 1)
        self.assertEqual(len(found['machineguid']), 1)

    def test_rejects_non_hive(self):
        with self.assertRaises(ValueError):
            list(scan_hive.iter_cells(b'\0' * 0x2000))
        with self.assertRaises(ValueError):
            scan_hive.find_values(b'not a hive', 'MachineGuid')

    def test_stops_cleanly_on_trailing_garbage(self):
        data = guid_hive() + b'JUNKJUNKJUNK'
        self.assertEqual(scan_hive.find_values(data, 'MachineGuid')[0][1],
                         GUID)

    def test_large_hive_with_multiple_bins(self):
        hive = HiveBuilder()
        payload = bytes(range(256)) * 40  # 10 KiB forces extra hbin space
        hive.add_value('Padding', REG_BINARY, payload)
        hive.add_value('MachineGuid', REG_SZ,
                       GUID.encode('utf-16le') + b'\0\0')
        values = scan_hive.find_values(hive.build(), 'MachineGuid')
        self.assertEqual(values[0][1], GUID)

    def test_big_data_value_is_reassembled(self):
        payload = bytes(range(256)) * 160  # 40 KiB -> three db segments
        hive = HiveBuilder()
        hive.add_big_value('ProductPolicy', payload)
        hive.add_value('MachineGuid', REG_SZ,
                       GUID.encode('utf-16le') + b'\0\0')
        data = hive.build()
        values = scan_hive.find_values(data, 'ProductPolicy')
        self.assertEqual(values[0][1], payload)
        self.assertEqual(scan_hive.find_values(data, 'MachineGuid')[0][1],
                         GUID)

    def test_big_data_value_not_confused_with_db_header(self):
        hive = HiveBuilder()
        hive.add_value('SmallBinary', REG_BINARY, b'db\x00\x00\0\0\0\0\0\0')
        values = scan_hive.find_values(hive.build(), 'SmallBinary')
        self.assertEqual(values[0][1], b'db\x00\x00\0\0\0\0\0\0')

    def test_list_value_names_matches_regex(self):
        names = scan_hive.list_value_names(guid_hive(), '(?i)value')
        self.assertEqual([name for name, _ in names],
                         ['BinaryValue', 'DwordValue'])
        shapes = dict(names)
        self.assertIn((REG_BINARY, 40), shapes['BinaryValue'])

    def test_list_value_names_no_match(self):
        self.assertEqual(scan_hive.list_value_names(guid_hive(), 'zzz'), [])

    def test_cli_list_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            hive = Path(tmp) / 'SYSTEM'
            hive.write_bytes(guid_hive())
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = scan_hive.main([str(hive), '--list-names', '(?i)machine'])
            self.assertEqual(rc, 0)
            self.assertIn('MachineGuid', buf.getvalue())
            self.assertIn('MachineGuidBackup', buf.getvalue())

    def test_cli_list_names_no_match_exits_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            hive = Path(tmp) / 'SYSTEM'
            hive.write_bytes(guid_hive())
            with redirect_stdout(io.StringIO()), \
                    redirect_stderr(io.StringIO()):
                self.assertEqual(
                    scan_hive.main([str(hive), '--list-names', 'zzz']), 1)

    def test_cli_writes_value_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            hive = Path(tmp) / 'SOFTWARE'
            hive.write_bytes(guid_hive())
            out = Path(tmp) / 'guid.txt'
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = scan_hive.main(
                    [str(hive), '--name', 'MachineGuid', '--out', str(out)])
            self.assertEqual(rc, 0)
            self.assertIn(GUID, buf.getvalue())
            self.assertIn('MachineGuid=' + GUID, out.read_text())

    def test_cli_accepts_repeated_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            hive = Path(tmp) / 'SYSTEM'
            hive.write_bytes(guid_hive())
            out = Path(tmp) / 'values.txt'
            with redirect_stdout(io.StringIO()):
                rc = scan_hive.main(
                    [str(hive), '--name', 'MachineGuid',
                     '--name', 'BinaryValue',
                     '--name', 'Missing', '--out', str(out)])
            self.assertEqual(rc, 0)
            text = out.read_text()
            self.assertIn('MachineGuid=' + GUID, text)
            self.assertIn('BinaryValue=' + bytes(range(40)).hex(), text)
            self.assertNotIn('Missing=', text)

    def test_cli_missing_value_exits_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            hive = Path(tmp) / 'SOFTWARE'
            hive.write_bytes(guid_hive())
            with redirect_stdout(io.StringIO()), \
                    redirect_stderr(io.StringIO()):
                self.assertEqual(
                    scan_hive.main([str(hive), '--name', 'Missing']), 1)

    def test_cli_unreadable_file_exits_2(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(
                scan_hive.main(['/nonexistent/SOFTWARE', '--name',
                                'MachineGuid']), 2)


if __name__ == '__main__':
    unittest.main()
