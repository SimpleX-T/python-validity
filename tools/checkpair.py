#!/usr/bin/env python3
"""Read-only: is this 06cb:00bb sensor already paired to THIS machine?

Background
----------
The sensor keeps exactly one ECDH/TLS pairing.  Its cert-store (flash
partition 1) holds the private key, encrypted with a key derived from this
host's DMI strings (``product_name`` + ``product_serial``) -- see
``validitysensor/tls.py``.  ``handle_priv()`` verifies that blob with an HMAC
before it is used.

That gives a definitive, **non-destructive** test:

* HMAC verifies  -> the pairing already belongs to this machine.  No wipe is
  needed; just install the driver and enroll.
* HMAC mismatch  -> the pairing belongs to another host (Windows Hello).  The
  only way to Linux support is the re-provisioning in ``flash00bb.py``.
* no block 0x0004 -> the sensor is unprovisioned (clean slate); provision it.

Results: ``ALREADY_PAIRED`` / ``LOCAL_KEY_OK`` (paired),
``PAIRED_TO_OTHER_HOST``, ``NO_PAIRING``, ``CERTSTORE_CORRUPT``, ``CERTSTORE_UNREADABLE``,
``TLS_REJECTED``, ``PARSE_ERROR``.  Exit code 0 only for the first two.

What this sends (hardware mode)
-------------------------------
1. the standard init sequence (``01``, ``19``, ``43 02``, init blob) -- the
   same bytes the python-validity daemon sends on every start;
2. ``40 01`` reads of flash partition 1 (cert-store), twice: it is saved and
   analysed;
3. a TLS 1.2 handshake (``44`` client hello / key exchange / finished) and, if
   it succeeds, one encrypted ``3e`` (flash info) + ``75`` (identity) read;
4. ``05 02 00`` reboot, the normal daemon exit path.

Nothing is written, erased or re-paired.  No ``4f``, no ``50``, no reset blob.

Offline mode
------------
``--certstore PATH`` skips the USB device entirely and analyses a previously
saved cert-store backup (e.g. the one written by ``probe00bb.py``).  Useful as
a dry run before touching hardware, and it needs no sensor access -- only
read permission on the file (root, since the backup is 0600).

Run:
    sudo python3 tools/checkpair.py
    sudo python3 tools/checkpair.py --certstore backups/00bb-certstore-*.bin
"""

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path
from struct import unpack

REPO = Path(__file__).resolve().parent.parent
PROJECT = REPO
sys.path.insert(0, str(REPO))

from validitysensor import blobs  # noqa: E402
from validitysensor.tls import tls  # noqa: E402

VID, PID = 0x06CB, 0x00BB


def status_of(rsp: bytes) -> int:
    return unpack('<H', rsp[:2])[0] if len(rsp) >= 2 else -1


def send(label: str, data: bytes) -> bytes:
    from validitysensor.usb import usb

    rsp = usb.cmd(data)
    print('    %-24s -> status 0x%04x (%d bytes)'
          % (label, status_of(rsp), len(rsp)))
    return rsp


def init_sequence():
    """Exactly what the daemon sends on start (usb.send_init())."""
    if status_of(send('rom info (01)', b'\x01')) != 0:
        raise RuntimeError('ROM info rejected')
    if status_of(send('19', b'\x19')) != 0:
        raise RuntimeError('19 rejected')
    fw = send('fwext info (43 02)', b'\x43\x02')
    if status_of(send('init blob', blobs.init_hardcoded())) != 0:
        raise RuntimeError('init blob rejected')
    if status_of(fw) != 0:
        send('init blob (clean slate)', blobs.init_hardcoded_clean_slate())
    return fw


def analyze_certstore(certstore: bytes, report: dict) -> bool:
    """Print the block table and verify the private-key HMAC.

    Returns True if the blob is bound to this machine's DMI key.  Sets
    ``report['result']`` on failure, returns False.
    """
    report['certstore_sha256'] = hashlib.sha256(certstore).hexdigest()
    print('    %d bytes, sha256 %s'
          % (len(certstore), report['certstore_sha256']))

    walk = certstore
    seen = set()
    while len(walk) >= 0x24:
        hdr, walk = walk[:4], walk[4:]
        hs, walk = walk[:0x20], walk[0x20:]
        block_id, size = unpack('<HH', hdr)
        if block_id == 0xFFFF:
            break
        body, walk = walk[:size], walk[size:]
        seen.add(block_id)
        ok = hashlib.sha256(body).digest() == hs
        report['blocks'].append({'id': block_id, 'size': size, 'sha256_ok': ok})
        print('    block 0x%04x  %5d bytes  sha256 %s'
              % (block_id, size, 'ok' if ok else 'MISMATCH'))

    if 4 not in seen:
        report['result'] = 'NO_PAIRING'
        print()
        print('RESULT: NO_PAIRING')
        print('  The cert-store has no private-key block (0x0004): this sensor')
        print('  is unprovisioned / clean slate.  Provision it with:')
        print('      sudo python3 tools/flash00bb.py --phase all')
        return False

    try:
        tls.reset()
        tls.parse_tls_flash(certstore)
    except Exception as error:  # noqa: BLE001
        message = str(error)
        if 'Signature verification failed' in message:
            report['result'] = 'PAIRED_TO_OTHER_HOST'
            print()
            print('RESULT: PAIRED_TO_OTHER_HOST')
            print('  The cert-store is intact, but its private-key blob is')
            print('  bound to a different host key (Windows Hello / another')
            print('  install).  Linux support needs the re-provisioning step:')
            print('      sudo python3 tools/flash00bb.py --phase all')
        elif 'hash mismatch' in message:
            report['result'] = 'CERTSTORE_CORRUPT'
            print()
            print('RESULT: CERTSTORE_CORRUPT: %s' % message)
        else:
            report['result'] = 'PARSE_ERROR'
            print()
            print('RESULT: PARSE_ERROR: %r' % error)
        return False

    report['result'] = 'LOCAL_KEY_OK'
    print("    private-key blob verified against the configured host key")
    return True


def read_host_identity():
    values = {}
    for name in ('product_name', 'product_serial'):
        try:
            values[name] = Path('/sys/class/dmi/id/' + name).read_text().strip()
        except OSError as error:
            raise RuntimeError('%s is unreadable (%s) -- run with sudo'
                               % (name, error))
    return values['product_name'], values['product_serial']


def describe_host(product_name: str, product_serial: str):
    print('    DMI product_name   %s' % product_name)
    print('    DMI product_serial %s' % product_serial)


def apply_host_key():
    """Force the TLS keys from the real DMI values (or the env override).

    ``Tls.__init__`` silently falls back to ``VirtualBox`` / ``0`` when
    ``product_serial`` cannot be read (i.e. as non-root).  That would make
    the HMAC test meaningless, so re-derive explicitly and abort instead.

    ``PYTHON_VALIDITY_HW_KEY`` (hex, raw bytes) takes precedence; it is the
    key recovered by ``tools/hwkey_probe.py`` for a pairing that Windows
    created with something other than the DMI default.
    """
    product_name, product_serial = read_host_identity()
    tls.set_hwkey(product_name=product_name, serial_number=product_serial)
    describe_host(product_name, product_serial)
    override = os.environ.get('PYTHON_VALIDITY_HW_KEY', '').strip()
    if override:
        print('    host key override  PYTHON_VALIDITY_HW_KEY (%d bytes)'
              % (len(override) // 2))
    return product_name, product_serial


def write_report(outdir: Path, name: str, report: dict) -> Path | None:
    path = outdir / name
    try:
        path.write_text(json.dumps(report, indent=2) + '\n')
        os.chmod(path, 0o600)
    except OSError as error:
        print('\ncould not write report %s: %s' % (path, error),
              file=sys.stderr)
        return None
    print('\nreport: %s' % path)
    return path


def run_offline(certstore_path: Path) -> int:
    report = {'mode': 'offline', 'certstore': str(certstore_path),
              'stamp': time.strftime('%Y%m%d-%H%M%S'),
              'result': None, 'certstore_sha256': None, 'blocks': []}

    print('== host key derivation')
    try:
        apply_host_key()
    except RuntimeError as error:
        print('ERROR: %s' % error, file=sys.stderr)
        return 2

    print('== cert-store %s' % certstore_path)
    try:
        certstore = certstore_path.read_bytes()
    except OSError as error:
        print('ERROR: cannot read %s: %s' % (certstore_path, error),
              file=sys.stderr)
        print('       the probe wrote it 0600, so run this with sudo.',
              file=sys.stderr)
        return 2

    outdir = PROJECT / 'backups'
    outdir.mkdir(parents=True, exist_ok=True)

    print('== blocks + HMAC')
    paired = analyze_certstore(certstore, report)
    if paired:
        print()
        print('RESULT: LOCAL_KEY_OK')
        print('  The private-key blob in this backup belongs to THIS machine.')
        print('  If the live sensor still holds the same cert-store, no wipe')
        print('  is needed.  Confirm with:  sudo python3 tools/checkpair.py')
    write_report(outdir, '00bb-checkpair-offline-%s.json' % report['stamp'],
                 report)
    return 0 if paired else 1


def run_hardware() -> int:
    import usb.core as ucore

    from validitysensor.flash import get_flash_info, read_flash
    from validitysensor.sensor import (RebootException, identify_sensor,
                                       reboot)
    from validitysensor.usb import usb

    dev = ucore.find(idVendor=VID, idProduct=PID)
    if dev is None:
        print('ERROR: 06cb:00bb not found on the USB bus.', file=sys.stderr)
        return 2

    serial = (dev.serial_number or 'unknown').replace('/', '_')
    stamp = time.strftime('%Y%m%d-%H%M%S')
    outdir = PROJECT / 'backups'
    outdir.mkdir(parents=True, exist_ok=True)
    os.chmod(outdir, 0o700)

    print('== 0. open 06cb:00bb')
    print('    serial %s, bus %d address %d'
          % (dev.serial_number, dev.bus, dev.address))
    try:
        apply_host_key()
    except RuntimeError as error:
        print('ERROR: %s' % error, file=sys.stderr)
        return 2

    report = {'mode': 'hardware', 'serial': dev.serial_number, 'stamp': stamp,
              'result': None, 'certstore_sha256': None, 'blocks': []}
    tls.reset()
    usb.open_dev(dev)

    try:
        print('== 1. init sequence (same as the daemon)')
        fw = init_sequence()
        report['fwext_reported'] = status_of(fw) == 0

        print('== 2. read cert-store (partition 1)')
        try:
            certstore = read_flash(1, 0, 0x1000)
        except Exception as error:  # noqa: BLE001
            report['result'] = 'CERTSTORE_UNREADABLE'
            print()
            print('RESULT: CERTSTORE_UNREADABLE: %r' % error)
            print('  The sensor has no readable partition 1 (unprovisioned /')
            print('  clean slate).  Provision it with:')
            print('      sudo python3 tools/flash00bb.py --phase all')
            return 1
        path = outdir / ('00bb-certstore-%s-%s.bin' % (serial, stamp))
        path.write_bytes(certstore)
        os.chmod(path, 0o600)
        print('    saved %s' % path)

        print('== 3. inspect blocks and verify the HMAC against this host')
        if not analyze_certstore(certstore, report):
            return 1

        print('== 4. TLS 1.2 handshake with the existing pairing')
        try:
            tls.open()
        except Exception as error:  # noqa: BLE001
            report['result'] = 'TLS_REJECTED'
            print()
            print('RESULT: TLS_REJECTED: %r' % error)
            print('  The local key verified, but the sensor refused the session.')
            return 1

        print('    handshake OK')

        print('== 5. encrypted reads (proves the channel works)')
        info = get_flash_info()
        print('    flash %s, %d bytes, %d partition(s)'
              % (info.ic.name, info.ic.size, len(info.partitions)))
        ident = identify_sensor()
        print('    sensor type=0x%04x name=%r' % (ident.type, ident.name))

        report['result'] = 'ALREADY_PAIRED'
        print()
        print('RESULT: ALREADY_PAIRED')
        print('  This sensor is already paired to this machine.')
        print('  Do NOT wipe it.  Install the driver and enroll:')
        print('      sudo ./install-00bb.sh')
        print('      sudo -u "$USER" fprintd-enroll -f right-index-finger "$USER"')
    finally:
        print('== 6. reboot sensor (normal daemon exit path)')
        try:
            reboot()
        except RebootException:
            pass
        except Exception as error:  # noqa: BLE001
            print('    reboot failed (usually harmless): %s' % error)
        usb.dev = None

        write_report(outdir, '00bb-checkpair-%s-%s.json' % (serial, stamp),
                     report)

    return 0 if report['result'] == 'ALREADY_PAIRED' else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description='Read-only check: is the 06cb:00bb sensor paired to '
                    'this machine?')
    parser.add_argument('--certstore', metavar='PATH', type=Path,
                        help='analyse a saved cert-store backup offline '
                             '(no USB access)')
    args = parser.parse_args(argv)

    if args.certstore is not None:
        return run_offline(args.certstore)

    if os.geteuid() != 0:
        print('ERROR: run as root (needed for the USB node and for '
              '/sys/class/dmi/id/product_serial).', file=sys.stderr)
        return 2

    return run_hardware()


if __name__ == '__main__':
    sys.exit(main())
