import os
import unittest
from unittest.mock import patch

from validitysensor.tls import (Tls, gwk_sign_hardcoded, password_hardcoded,
                                prf)


def expected_key(hw_key: bytes) -> bytes:
    return prf(password_hardcoded, b'GWK' + hw_key, 0x20)


class HostKeyOverrideTests(unittest.TestCase):
    def make_tls(self):
        # usb is only used for commands, not for key derivation
        return Tls(None)

    def test_default_uses_dmi_strings_with_nul_terminators(self):
        tls = self.make_tls()
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop('PYTHON_VALIDITY_HW_KEY', None)
            tls.set_hwkey('Laptop', 'SERIAL')
        self.assertEqual(tls.psk_encryption_key,
                         expected_key(b'Laptop\0SERIAL\0'))

    def test_validation_key_uses_the_encryption_key(self):
        tls = self.make_tls()
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop('PYTHON_VALIDITY_HW_KEY', None)
            tls.set_hwkey('Laptop', 'SERIAL')
        self.assertEqual(
            tls.psk_validation_key,
            prf(tls.psk_encryption_key,
                b'GWK_SIGN' + gwk_sign_hardcoded, 0x20))

    def test_env_override_is_used_as_raw_bytes(self):
        tls = self.make_tls()
        with patch.dict(os.environ,
                        {'PYTHON_VALIDITY_HW_KEY': b'abc'.hex()}):
            tls.set_hwkey('Laptop', 'SERIAL')
        self.assertEqual(tls.psk_encryption_key,
                         expected_key(b'abc'))

    def test_env_override_wins_over_dmi(self):
        tls = self.make_tls()
        with patch.dict(os.environ,
                        {'PYTHON_VALIDITY_HW_KEY': b'other'.hex()}):
            tls.set_hwkey('Laptop', 'SERIAL')
        self.assertNotEqual(tls.psk_encryption_key,
                            expected_key(b'Laptop\0SERIAL\0'))


if __name__ == '__main__':
    unittest.main()
