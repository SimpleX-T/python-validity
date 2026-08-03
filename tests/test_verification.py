import unittest

from validitysensor.sensor import FingerNotMatchedException
from validitysensor.verification import identify_with_retries


class VerificationRetryTests(unittest.TestCase):
    def test_false_negative_can_recover_on_later_physical_scan(self):
        outcomes = [FingerNotMatchedException(), (7, 3, b'hash')]
        retries = []

        def identify(_update_cb):
            outcome = outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

        result = identify_with_retries(
            identify, lambda error: None, lambda *args: retries.append(args))

        self.assertEqual(result, (7, 3, b'hash'))
        self.assertEqual(retries, [(1, 3)])

    def test_stops_after_exactly_three_clean_no_matches(self):
        calls = []
        retries = []

        def identify(_update_cb):
            calls.append(1)
            raise FingerNotMatchedException()

        with self.assertRaises(FingerNotMatchedException):
            identify_with_retries(
                identify, lambda error: None,
                lambda *args: retries.append(args), max_attempts=3)

        self.assertEqual(len(calls), 3)
        self.assertEqual(retries, [(1, 3), (2, 3)])

    def test_does_not_retry_unrelated_sensor_failure(self):
        calls = []

        def identify(_update_cb):
            calls.append(1)
            raise RuntimeError('transport failed')

        with self.assertRaises(RuntimeError):
            identify_with_retries(
                identify, lambda error: None, lambda *args: None)

        self.assertEqual(len(calls), 1)


if __name__ == '__main__':
    unittest.main()
