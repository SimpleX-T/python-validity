import hashlib
import unittest
from unittest.mock import patch


class CleanSlateBootstrapTests(unittest.TestCase):
    def test_d51_reset_blob_matches_windows_factory_capture(self):
        from validitysensor.blobs_d51 import reset_blob

        self.assertEqual(len(reset_blob), 11973)
        self.assertEqual(
            hashlib.sha256(reset_blob).hexdigest(),
            '7f379b1648326f031753d2d0a974bae75bc59a95f847b9c6478a124f32b3c17a',
        )

    def test_transport_init_precedes_flash_initialisation(self):
        from validitysensor import init

        calls = []
        with patch.object(init, 'init_data_dir'), \
                patch.object(init.usb, 'send_init',
                             side_effect=lambda: calls.append('transport')), \
                patch.object(init, 'init_flash',
                             side_effect=lambda: calls.append('flash')), \
                patch.object(init, 'read_tls_flash', return_value=b''), \
                patch.object(init.tls, 'parse_tls_flash'), \
                patch.object(init.tls, 'open'), \
                patch.object(init, 'upload_fwext'), \
                patch.object(init.sensor, 'open'), \
                patch.object(init, 'init_db'), \
                patch.object(init.atexit, 'register'):
            init.open_common()

        self.assertEqual(calls, ['transport', 'flash'])

    def test_d51_reset_preflight_matches_windows_capture(self):
        from validitysensor import init_flash

        calls = []
        with patch.object(init_flash, 'write_hw_reg32',
                          side_effect=lambda address, value:
                          calls.append(('write', address, value))), \
                patch.object(init_flash, 'read_hw_reg32',
                             side_effect=lambda address:
                             calls.append(('read', address)) or 3), \
                patch.object(init_flash, 'identify_sensor',
                             side_effect=lambda:
                             calls.append(('identify',))), \
                patch.object(init_flash, 'call_cleanups',
                             side_effect=lambda:
                             calls.append(('cleanup',))):
            init_flash.prepare_clean_slate_reset()

        self.assertEqual(calls, [
            ('write', 0x8000205c, 7),
            ('read', 0x80002080),
            ('identify',),
            ('cleanup',),
        ])


if __name__ == '__main__':
    unittest.main()
