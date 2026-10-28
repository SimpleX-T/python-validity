import importlib.util
import io
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent / 'tools'


def load_hwkey_probe():
    spec = importlib.util.spec_from_file_location(
        'hwkey_probe', TOOLS / 'hwkey_probe.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hwkey_probe = load_hwkey_probe()


class RawVariantsTests(unittest.TestCase):
    def keys(self, label, blob):
        return [key for _, key in hwkey_probe.raw_variants(label, blob)]

    def test_exact_32_byte_blob_is_a_candidate(self):
        blob = bytes(range(32))
        variants = hwkey_probe.raw_variants('PairingData', blob)
        self.assertEqual(variants[0], ('PairingData', blob))

    def test_windows_expose_every_offset(self):
        blob = b'\x01\x02\x03\x04' + bytes(range(32)) + b'\xaa'
        keys = self.keys('x', blob)
        self.assertIn(blob[4:36], keys)
        self.assertIn(blob[:32], keys)
        self.assertIn(blob[-32:], keys)
        # every 32-byte window inside the blob is covered
        for offset in range(0, len(blob) - 32 + 1):
            self.assertIn(blob[offset:offset + 32], keys)

    def test_duplicates_are_removed(self):
        blob = b'\0' * 96
        keys = self.keys('zero', blob)
        self.assertEqual(len(keys), len(set(keys)))

    def test_large_blob_is_not_used_whole(self):
        blob = b'\x11' * 8192
        keys = self.keys('big', blob)
        self.assertNotIn(blob, keys)
        self.assertIn(blob[:32], keys)

    def test_huge_blob_is_scanned_only_at_the_edges(self):
        blob = bytearray(204800)
        blob[0x100:0x120] = bytes(range(32))
        blob[-0x800:-0x800 + 32] = bytes(range(32, 64))
        blob[0x20000:0x20020] = b'\xf0' * 32
        variants = hwkey_probe.raw_variants('huge', bytes(blob))
        self.assertLess(len(variants), 0x10000 + 0x1000 + 10)
        keys = [key for _, key in variants]
        self.assertIn(bytes(blob[:32]), keys)
        self.assertIn(bytes(blob[-32:]), keys)
        self.assertIn(bytes(blob[0x100:0x120]), keys)          # near the start
        self.assertIn(bytes(blob[-0x800:-0x800 + 32]), keys)   # near the end
        self.assertNotIn(b'\xf0' * 32, keys)                   # middle skipped

    def test_trailing_nul_stripped_form_is_added(self):
        blob = b'Laptop\0SERIAL\0'
        self.assertIn(b'Laptop\0SERIAL', self.keys('dmi', blob))

    def test_empty_blob_yields_nothing(self):
        self.assertEqual(hwkey_probe.raw_variants('empty', b''), [])


class LoadRawBlobsTests(unittest.TestCase):
    def test_raw_hex_is_decoded(self):
        blobs = hwkey_probe.load_raw_blobs(['0011aaff', '00 11 aa ff'], [])
        self.assertEqual([label for label, _ in blobs],
                         ['raw-hex[0]', 'raw-hex[1]'])
        self.assertEqual(blobs[0][1], b'\x00\x11\xaa\xff')

    def test_invalid_hex_is_warned_about_and_skipped(self):
        err = io.StringIO()
        with redirect_stderr(err):
            blobs = hwkey_probe.load_raw_blobs(['xyz', 'abc'], [])
        self.assertEqual(blobs, [])
        self.assertIn('not valid hex', err.getvalue())

    def test_name_equals_hex_dump_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'windows-pairing.txt'
            path.write_text(
                'PairingData=deadbeef\n'
                'PairingContext = 00010203  (type 3)\n'
                'not a value line\n',
                encoding='utf-8')
            blobs = hwkey_probe.load_raw_blobs([], [path])
        labels = [label for label, _ in blobs]
        self.assertIn('PairingData=windows-pairing.txt', labels)
        self.assertIn('PairingContext=windows-pairing.txt', labels)
        self.assertIn(b'\xde\xad\xbe\xef',
                      [blob for label, blob in blobs if 'PairingData' in label])

    def test_guid_text_is_accepted_as_ascii_and_utf16(self):
        guid = '0123abcd-4567-89ef-0123-456789abcdef'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'windows-pairing.txt'
            path.write_text('MachineGuid=%s\n' % guid, encoding='utf-8')
            blobs = hwkey_probe.load_raw_blobs([], [path])
        blobs = dict(blobs)
        self.assertEqual(blobs['MachineGuid=windows-pairing.txt ascii'],
                         guid.encode())
        self.assertEqual(blobs['MachineGuid=windows-pairing.txt utf16le'],
                         guid.encode('utf-16le'))

    def test_plain_string_value_is_accepted_as_ascii_and_utf16(self):
        # scan_hive decodes REG_SZ, so a device path arrives as plain text.
        device = 'USB\\VID_06CB&PID_00BB\\0123456789AB'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'windows-pairing.txt'
            path.write_text('Synaptics_01=%s  (type 1)\n' % device,
                            encoding='utf-8')
            blobs = hwkey_probe.load_raw_blobs([], [path])
        blobs = dict(blobs)
        self.assertEqual(blobs['Synaptics_01=windows-pairing.txt ascii'],
                         device.encode())
        self.assertEqual(blobs['Synaptics_01=windows-pairing.txt utf16le'],
                         device.encode('utf-16le'))

    def test_overlong_string_value_is_not_a_candidate(self):
        prose = 'x' * (hwkey_probe.TEXT_CANDIDATE_MAX + 1)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'windows-pairing.txt'
            path.write_text('Description=%s\n' % prose, encoding='utf-8')
            blobs = hwkey_probe.load_raw_blobs([], [path])
        # No ascii/utf16 pairs for the prose; only the whole-file fallback.
        self.assertEqual([label for label, _ in blobs],
                         ['raw-file[windows-pairing.txt]'])

    def test_binary_file_is_read_whole(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'pairing.bin'
            path.write_bytes(b'\x00\xff\xfe\x80')
            blobs = hwkey_probe.load_raw_blobs([], [path])
        self.assertEqual(blobs, [('raw-file[pairing.bin]', b'\x00\xff\xfe\x80')])

    def test_text_file_without_hex_pairs_is_read_whole(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'notes.txt'
            path.write_text('nothing useful here\n', encoding='utf-8')
            blobs = hwkey_probe.load_raw_blobs([], [path])
        self.assertEqual(blobs,
                         [('raw-file[notes.txt]', b'nothing useful here\n')])

    def test_missing_file_is_warned_about(self):
        err = io.StringIO()
        with redirect_stderr(err):
            blobs = hwkey_probe.load_raw_blobs(
                [], [Path('/nonexistent/pairing.bin')])
        self.assertEqual(blobs, [])
        self.assertIn('cannot read', err.getvalue())


class BuildCandidatesTests(unittest.TestCase):
    DMI = {'product_name': 'Laptop', 'product_serial': 'SERIAL'}

    def build(self, **kwargs):
        return hwkey_probe.build_candidates(
            dict(self.DMI), [], kwargs.get('explicit', []),
            kwargs.get('scanned', []), kwargs.get('raw', []))

    def test_default_hw_key_layout_is_a_candidate(self):
        keys = [key for _, key in self.build()]
        self.assertIn(b'Laptop\0SERIAL\0', keys)

    def test_raw_blob_is_a_candidate(self):
        blob = bytes(range(48))
        keys = [key for _, key in self.build(raw=[('PairingData', blob)])]
        self.assertIn(blob, keys)
        self.assertIn(blob[8:40], keys)

    def test_raw_blob_combinations_are_bounded(self):
        blob = bytes(range(64))
        candidates = self.build(raw=[('PairingData', blob)])
        self.assertLess(len(candidates), 5000)


if __name__ == '__main__':
    unittest.main()
