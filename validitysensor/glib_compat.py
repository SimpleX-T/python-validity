"""Compatibility helpers for PyGObject API differences."""


def unix_signal_add():
    """Return ``g_unix_signal_add`` with a 4-argument handler signature.

    PyGObject exposes the function under different names depending on the
    distribution and version:

    * ``GLib.unix_signal_add`` -- the traditional override, present on most
      builds and the one to prefer;
    * ``GLibUnix.signal_add`` -- some split-namespace builds;
    * ``GLibUnix.signal_add_full`` -- what PyGObject 3.48 ships; it takes the
      same ``user_data`` argument, so it can be wrapped directly.

    Every variant is called as ``add(priority, signum, callback, user_data)``.
    """
    from gi.repository import GLib

    if hasattr(GLib, 'unix_signal_add'):
        return GLib.unix_signal_add

    try:
        import gi
        gi.require_version('GLibUnix', '2.0')
        from gi.repository import GLibUnix
    except (ImportError, ValueError):
        GLibUnix = None

    if GLibUnix is not None and hasattr(GLibUnix, 'signal_add'):
        return GLibUnix.signal_add
    if GLibUnix is not None and hasattr(GLibUnix, 'signal_add_full'):
        def add(priority, signum, callback, user_data):
            return GLibUnix.signal_add_full(priority, signum, callback, user_data)

        return add
    raise RuntimeError('No g_unix_signal_add binding is available')
