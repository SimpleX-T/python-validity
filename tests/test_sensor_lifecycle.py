import unittest
from unittest.mock import patch

from validitysensor.sensor import sensor
from validitysensor.usb import CancelledException


class SensorLifecycleTests(unittest.TestCase):
    @patch('validitysensor.sensor.glow_end_scan')
    @patch('validitysensor.sensor.glow_start_scan')
    def test_identify_always_ends_scan_after_success(self, glow_start, glow_end):
        expected = (12, 3, b'hash')
        with patch.object(sensor, 'capture'), \
                patch.object(sensor, 'match_finger', return_value=expected):
            self.assertEqual(sensor.identify(lambda error: None), expected)

        glow_start.assert_called_once_with()
        glow_end.assert_called_once_with()

    @patch('validitysensor.sensor.glow_end_scan')
    @patch('validitysensor.sensor.glow_start_scan')
    def test_identify_always_ends_scan_after_cancel(self, glow_start, glow_end):
        with patch.object(sensor, 'capture', side_effect=CancelledException):
            with self.assertRaises(CancelledException):
                sensor.identify(lambda error: None)

        glow_start.assert_called_once_with()
        glow_end.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()
