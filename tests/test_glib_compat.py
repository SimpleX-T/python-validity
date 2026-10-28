import sys
import types
import unittest
from unittest import mock

from validitysensor.glib_compat import unix_signal_add


def fake_gi(glib, glib_unix=None, require_error=None):
    """Build the sys.modules entries that ``from gi.repository import ...`` hits."""
    repository = types.SimpleNamespace(GLib=glib)
    if glib_unix is not None:
        repository.GLibUnix = glib_unix

    def require_version(*args):
        if require_error is not None:
            raise require_error

    gi = types.SimpleNamespace(repository=repository, require_version=require_version)
    modules = {'gi': gi, 'gi.repository': repository}
    if glib_unix is not None:
        modules['gi.repository.GLibUnix'] = glib_unix
    return modules


class UnixSignalAddTests(unittest.TestCase):
    def test_prefers_glib_unix_signal_add(self):
        sentinel = object()
        glib = types.SimpleNamespace(unix_signal_add=sentinel)

        with mock.patch.dict(sys.modules, fake_gi(glib)):
            self.assertIs(unix_signal_add(), sentinel)

    def test_falls_back_to_glibunix_signal_add(self):
        sentinel = object()
        glib = types.SimpleNamespace()
        glib_unix = types.SimpleNamespace(signal_add=sentinel)

        with mock.patch.dict(sys.modules, fake_gi(glib, glib_unix)):
            self.assertIs(unix_signal_add(), sentinel)

    def test_signal_add_full_is_wrapped_with_user_data(self):
        calls = []
        glib = types.SimpleNamespace()
        glib_unix = types.SimpleNamespace(
            signal_add_full=lambda *args: calls.append(args) or 42)

        with mock.patch.dict(sys.modules, fake_gi(glib, glib_unix)):
            add = unix_signal_add()
            result = add(1, 2, 'handler', 'user-data')

        self.assertEqual(result, 42)
        self.assertEqual(calls, [(1, 2, 'handler', 'user-data')])

    def test_missing_binding_is_an_explicit_error(self):
        glib = types.SimpleNamespace()

        with mock.patch.dict(sys.modules, fake_gi(glib)):
            with self.assertRaises(RuntimeError):
                unix_signal_add()

    def test_require_version_failure_is_not_fatal(self):
        glib = types.SimpleNamespace()
        modules = fake_gi(glib, require_error=ValueError('namespace unavailable'))

        with mock.patch.dict(sys.modules, modules):
            with self.assertRaises(RuntimeError):
                unix_signal_add()


if __name__ == '__main__':
    unittest.main()
