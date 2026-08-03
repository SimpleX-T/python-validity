import unittest
from unittest.mock import patch

from validitysensor.sensor import FingerNotMatchedException, sensor


class MatchInterruptTests(unittest.TestCase):
    def assert_no_match_interrupt(self, sensor_type, interrupt):
        original_type = getattr(sensor, 'real_device_type', None)
        sensor.real_device_type = sensor_type
        try:
            with patch('validitysensor.sensor.tls.app', return_value=b'\x00\x00'), \
                    patch('validitysensor.sensor.usb.wait_int',
                          return_value=bytes([interrupt, 0, 1, 0])):
                with self.assertRaises(FingerNotMatchedException):
                    sensor.match_finger()
        finally:
            sensor.real_device_type = original_type

    def test_d51_uses_interrupt_5_for_no_template(self):
        self.assert_no_match_interrupt(0xd51, 5)

    def test_969_uses_interrupt_4_for_no_template(self):
        self.assert_no_match_interrupt(0x969, 4)


if __name__ == '__main__':
    unittest.main()
