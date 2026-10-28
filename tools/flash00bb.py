#!/usr/bin/env python3
"""Re-provision the Synaptics 06cb:00bb sensor for Linux (python-validity).

This is the *destructive* half of the 06cb:00bb support, adapted from the
working recipe reported by Joentja on uunicorn/python-validity#283 (exact same
HP Spectre x360 13-ap0xxx, sensor type 0x969, hw id 0x88, W25Q80B flash).

What it does in `--phase all`
------------------------------
1. preflight  : identify the sensor, back up the cleartext TLS cert-store
                (partition 1), and make sure the HP xpfwext is cached.
2. wipe       : send the 0x969-family reset blob (11973 bytes) + commit + reboot.
                The chip comes back with **zero partitions**.
3. provision  : re-create the five partitions (4f), do the ECDH pairing (50),
                open TLS, erase the fresh partitions and write a cert-store
                bound to *this* machine's DMI (product_name + product_serial).
                This mirrors validitysensor.init_flash() exactly.
   firmware   : in a fresh TLS session, re-upload the HP xpfwext if the wipe
                removed it (mirrors validitysensor.upload_fwext()).
4. verify     : reboot, read the new cert-store back, and complete a TLS 1.2
                handshake against the sensor.

Consequences
------------
* The existing Windows Hello pairing on the sensor is destroyed.
* Fingerprint templates stored on the sensor (Windows Hello) are destroyed.
* Windows Hello must be re-enrolled from Windows afterwards (which would, in
  turn, invalidate the Linux pairing again -- the sensor keeps one pairing).
* Nothing on your Linux disks is touched.

Usage
-----
    sudo python3 tools/flash00bb.py                     # safe preflight only
    sudo python3 tools/flash00bb.py --phase wipe        # DESTRUCTIVE, asks for serial
    sudo python3 tools/flash00bb.py --phase provision   # format+pair, then firmware
    sudo python3 tools/flash00bb.py --phase firmware    # recover a missing fwext
    sudo python3 tools/flash00bb.py --phase verify
    sudo python3 tools/flash00bb.py --phase all         # everything, asks first

Use --phase all unless you need to stop between steps.
"""

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from struct import unpack

REPO = Path(__file__).resolve().parent.parent
PROJECT = REPO
sys.path.insert(0, str(REPO))

import usb.core as ucore  # noqa: E402
from cryptography.hazmat.backends import default_backend  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

from validitysensor import blobs  # noqa: E402


def blob(name: str) -> bytes:
    """Return a firmware blob from validitysensor.blobs.

    blobs.py exposes ``init_hardcoded`` etc. as zero-argument thunks that
    *replace the module attribute with the bytes* on first use, so the same
    name is callable once and a plain bytes object afterwards.  Reading the
    module attribute directly (as this tool used to) works exactly once per
    process, which broke the wipe phase after preflight had already run.
    """
    value = getattr(blobs, name)
    return value() if callable(value) else value
from validitysensor.flash import (  # noqa: E402
    call_cleanups, erase_flash, get_flash_info, get_fw_info, read_flash, write_flash,
    write_flash_all, write_fw_signature,
)
from validitysensor.init_flash import (  # noqa: E402
    encrypt_key, flash_layout_hardcoded, partition_flash, partition_signature,
)
from validitysensor.init_data_dir import (  # noqa: E402
    PYTHON_VALIDITY_FIRMWARE_DIR, init_data_dir,
)
from validitysensor.sensor import (  # noqa: E402
    RebootException, RomInfo, identify_sensor,
    read_hw_reg32, reboot, write_hw_reg32,
)
from validitysensor.tls import tls  # noqa: E402
from validitysensor.usb import usb  # noqa: E402

VID, PID = 0x06CB, 0x00BB
FWTYPE = '6_07f_hp_mis_qm.xpfwext'
FW_CACHE = Path(PYTHON_VALIDITY_FIRMWARE_DIR) / FWTYPE
STAMP = time.strftime('%Y%m%d-%H%M%S')
BACKUP_DIR = PROJECT / 'backups'
LOG_PATH = BACKUP_DIR / ('00bb-flash-%s.log' % STAMP)

_log_file = None


def log(msg: str = ''):
    print(msg, flush=True)
    if _log_file is not None:
        _log_file.write(msg + '\n')
        _log_file.flush()


def status_of(rsp: bytes) -> int:
    return unpack('<H', rsp[:2])[0] if len(rsp) >= 2 else -1


class Abort(Exception):
    pass


def systemctl(*args: str):
    """Run ``systemctl <args>``; used for simple start/stop/mask calls."""
    subprocess.run(['systemctl', *args],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


COMPETING_UNITS = ('fprintd.service', 'open-fprintd.service', 'python3-validity.service')
_was_active = {}


def stop_competing_services():
    global _was_active
    for unit in COMPETING_UNITS:
        result = subprocess.run(['systemctl', 'is-active', '--quiet', unit], check=False)
        _was_active[unit] = result.returncode == 0
        systemctl('stop', unit)
    # Keep udev from restarting the daemon while this script owns the sensor.
    systemctl('mask', '--runtime', 'python3-validity.service')


def restart_services():
    systemctl('unmask', '--runtime', 'python3-validity.service')
    # Only bring back what was running before, and only if it is installed.
    for unit in reversed(COMPETING_UNITS):
        if not _was_active.get(unit):
            continue
        result = subprocess.run(['systemctl', 'start', unit],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                check=False)
        if result.returncode != 0:
            log('    note: could not restart %s' % unit)


def release_device():
    if usb.dev is not None:
        try:
            usb.dev.reset()
        except Exception:  # noqa: BLE001
            pass
        usb.dev = None


def wait_for_device(timeout: float = 60.0):
    log('    waiting for 06cb:00bb ...')
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        dev = ucore.find(idVendor=VID, idProduct=PID)
        if dev is not None:
            time.sleep(1.0)  # let the USB stack settle after re-enumeration
            try:
                tls.reset()
                usb.open_dev(dev)
                log('    device back at bus %d address %d'
                    % (usb.usb_dev().bus, usb.usb_dev().address))
                return
            except Exception as error:  # noqa: BLE001
                last_error = error
        time.sleep(0.5)
    raise Abort('sensor did not come back within %ds (%s). '
                'Unplug/replug power or reboot, then continue with the next phase.'
                % (timeout, last_error))


def send(label: str, data: bytes) -> bytes:
    rsp = usb.cmd(data)
    log('    %-22s -> status 0x%04x (%d bytes)' % (label, status_of(rsp), len(rsp)))
    return rsp


def send_init_sequence():
    log('    sending 01 / 19 / 43 02 / init blob')
    if status_of(send('rom info (01)', b'\x01')) != 0:
        raise Abort('ROM info rejected')
    send('19', b'\x19')
    fw_rsp = send('fwext info (43 02)', b'\x43\x02')
    init_status = status_of(send('init blob', blob('init_hardcoded')))
    if init_status != 0:
        log('    init blob rejected -> trying clean-slate variant')
        if status_of(send('init blob (clean)', blob('init_hardcoded_clean_slate'))) != 0:
            raise Abort('both init blobs were rejected')
    elif status_of(fw_rsp) != 0:
        # Same rule as Usb.send_init(): 4302 reports b004 when the fwext
        # partition is empty (zero-partition / freshly wiped sensor), and the
        # clean-slate init blob must follow.
        log('    no firmware reported (clean slate) -> sending clean-slate init blob')
        if status_of(send('init blob (clean)', blob('init_hardcoded_clean_slate'))) != 0:
            log('    WARNING: clean-slate init blob rejected; continuing')
    return fw_rsp


def open_sensor():
    wait_for_device()


def assert_target_device(force: bool):
    """Refuse to wipe anything that is not the known 0x969 HP sensor."""
    ident = identify_sensor()
    log('    identity: type=0x%04x hw-id=0x%02x name=%r'
        % (ident.type, ident.version, ident.name))
    matches = ident.type == 0x969 and 'FM-3439' in ident.name
    if not matches:
        msg = ('unexpected sensor identity (type 0x%04x, name %r); expected '
               'type 0x969 "57K0 FM-3439-xxx". Refusing to wipe.'
               % (ident.type, ident.name))
        if not force:
            raise Abort(msg + ' Re-run with --force only if you are certain.')
        log('    WARNING: ' + msg + ' (continuing because of --force)')
    if ident.version != 0x88:
        log('    note: hw id 0x%02x (the reference unit is 0x88)' % ident.version)
    return ident


def backup_certstore(info):
    ids = [p.id for p in info.partitions]
    if 1 not in ids:
        log('    partition 1 not present; nothing to back up')
        return None
    data = read_flash(1, 0, 0x1000)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    path = BACKUP_DIR / ('00bb-certstore-before-wipe-%s.bin' % STAMP)
    path.write_bytes(data)
    os.chmod(path, 0o600)
    digest = hashlib.sha256(data).hexdigest()
    log('    backup: %s (%d bytes, sha256 %s)' % (path, len(data), digest))
    log('    note: fingerprint templates in partition 4 cannot be read without '
        'the old pairing; they are lost by design.')
    return path


def extract_softpaq(archive, destination):
    """Unpack an HP SoftPaq (CAB self-extractor) and install the xpfwext."""
    import tempfile
    init_data_dir()
    with tempfile.TemporaryDirectory(prefix='00bb-fw-') as tmp:
        if shutil.which('cabextract'):
            cmd = ['cabextract', '-q', '-d', tmp, archive]
        elif shutil.which('innoextract'):
            cmd = ['innoextract', '--output-dir', tmp, '--include', FWTYPE,
                   '--collisions', 'overwrite', archive]
        else:
            raise Abort('need cabextract or innoextract: sudo apt install cabextract')
        log('    extracting: %s' % ' '.join(cmd))
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        found = None
        for root, _dirs, files in os.walk(tmp):
            if FWTYPE in files:
                found = Path(root) / FWTYPE
                break
        if result.returncode != 0 or found is None:
            raise Abort('could not extract %s from %s' % (FWTYPE, archive))
        shutil.copyfile(found, destination)
        os.chmod(destination, 0o600)


def _target_dev_type():
    from validitysensor.usb import SupportedDevices
    return SupportedDevices.DEV_BB


def download_softpaq(destination):
    """Fetch and unpack the pinned HP SoftPaq without touching the sensor.

    Deliberately does not shell out to ``validity-sensors-firmware``: that
    script re-enumerates the USB bus to detect the device and would collide
    with the handle this tool already owns.
    """
    import importlib.machinery
    import importlib.util
    import tempfile

    from validitysensor.firmware_tables import FIRMWARE_URIS

    dev_type = _target_dev_type()
    uri = FIRMWARE_URIS[dev_type]['driver']
    sha512 = FIRMWARE_URIS[dev_type]['sha512']
    log('    downloading %s' % uri)
    log('    expected sha512 %s' % sha512)

    spec = importlib.util.spec_from_file_location(
        'validity_sensors_firmware', REPO / 'bin' / 'validity-sensors-firmware',
        loader=importlib.machinery.SourceFileLoader(
            'validity_sensors_firmware', str(REPO / 'bin' / 'validity-sensors-firmware')))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    with tempfile.TemporaryDirectory(prefix='00bb-fw-') as tmp:
        path = module.download_and_extract_fw(dev_type, tmp, fwuri=uri)
        shutil.copyfile(path, destination)
        os.chmod(destination, 0o600)


def prepare_firmware(softpaq=None):
    """Make sure the xpfwext is cached *before* we wipe anything."""
    init_data_dir()
    if softpaq:
        source = Path(softpaq).expanduser()
        if not source.is_file():
            raise Abort('--softpaq %s does not exist' % source)
        extract_softpaq(str(source), FW_CACHE)

    if FW_CACHE.is_file() and FW_CACHE.stat().st_size > 0:
        log('    firmware cached: %s (%d bytes)' % (FW_CACHE, FW_CACHE.stat().st_size))
        return FW_CACHE

    log('    firmware not cached: %s' % FW_CACHE)
    if not (shutil.which('cabextract') or shutil.which('innoextract')):
        raise Abort('need cabextract or innoextract to unpack the HP SoftPaq.\n'
                    '        sudo apt install cabextract\n'
                    '        then re-run. (Nothing was wiped.)')
    try:
        download_softpaq(FW_CACHE)
    except Abort:
        raise
    except Exception as error:  # noqa: BLE001
        raise Abort('could not obtain %s from the pinned HP SoftPaq (%r).\n'
                    '        Download the HP fingerprint SoftPaq that contains '
                    '%s\n        (SP138431, or SP106161 as used by Joentja) and '
                    'pass\n        --softpaq /path/to/spXXXXXX.exe   (or --firmware '
                    '/path/to/%s).\n        Nothing was wiped.'
                    % (FWTYPE, error, FWTYPE, FWTYPE))
    if not FW_CACHE.is_file():
        raise Abort('firmware extraction produced no %s. Nothing was wiped.' % FWTYPE)
    log('    firmware ready: %s (%d bytes)' % (FW_CACHE, FW_CACHE.stat().st_size))
    return FW_CACHE


def phase_preflight(args):
    log('== PREFLIGHT (read-only; no flash writes)')
    open_sensor()
    try:
        send_init_sequence()
        info = get_flash_info()
        log('    flash: %s, %d bytes, %d partition(s)'
            % (info.ic.name, info.ic.size, len(info.partitions)))
        for p in info.partitions:
            log('      %r' % p)
        assert_target_device(args.force)
        backup_certstore(info)
        rom = RomInfo.get()
        log('    ROM: %r' % rom)
        fwi = get_fw_info(2)
        if fwi is None:
            log('    fwext: not reported (will be uploaded during provisioning)')
        else:
            log('    fwext: %d.%d buildtime %d, %d modules'
                % (fwi.major, fwi.minor, fwi.buildtime, len(fwi.modules)))
        prepare_firmware(args.softpaq)
    finally:
        try:
            reboot()
        except RebootException:
            pass
        except Exception:  # noqa: BLE001
            pass
        release_device()
    log('    preflight OK. Nothing was modified.')


def phase_wipe(args):
    log('== WIPE (DESTRUCTIVE: writes the 0x969 reset blob, erases the flash layout)')
    open_sensor()
    already_blank = False
    try:
        send_init_sequence()
        info = get_flash_info()
        if len(info.partitions) == 0:
            log('    flash already has zero partitions; nothing to wipe.')
            already_blank = True
        else:
            ident = assert_target_device(args.force)
            backup_certstore(info)
            prepare_firmware(args.softpaq)
            if not args.yes:
                expected = usb.usb_dev().serial_number or 'ERASE'
                print()
                print('This will destroy the Windows Hello pairing and every')
                print('fingerprint template stored on the sensor 06cb:00bb.')
                answer = input('Type the sensor serial (%s) to continue: '
                               % expected).strip()
                if answer != expected:
                    raise Abort('confirmation did not match; nothing was wiped.')

            rom = RomInfo.get()
            log('    ROM before wipe: %r' % rom)
            log('    sending 0x969 reset blob (%d bytes) ...' % len(blob('reset_blob')))
            status = status_of(usb.cmd(blob('reset_blob')))
            log('    reset blob -> status 0x%04x' % status)
            if status != 0:
                raise Abort('the sensor rejected the reset blob (status 0x%04x).\n'
                            '        Nothing was changed. Do NOT continue with other '
                            'reset blobs.' % status)
            log('    sending commit (10 00 * 0x61) ...')
            status = status_of(usb.cmd(b'\x10' + b'\x00' * 0x61))
            log('    commit -> status 0x%04x' % status)
            if status != 0:
                raise Abort('commit rejected (status 0x%04x).' % status)
            log('    rebooting sensor into the unprovisioned state')
            try:
                reboot()
            except RebootException:
                pass
            log('    reset accepted for %r' % (ident,))
    finally:
        release_device()

    if not already_blank:
        wait_for_device()
        log('    checking flash state ...')
        send_init_sequence()
        info = get_flash_info()
        log('    partitions after wipe: %d' % len(info.partitions))
        if len(info.partitions) != 0:
            raise Abort('the reset blob was accepted but %d partitions are still '
                        'present. Stop here and report this on issue #283.'
                        % len(info.partitions))
        try:
            reboot()
        except RebootException:
            pass
        release_device()
    log('    wipe complete. Next: --phase provision')


def phase_provision(args):
    """Format + pair, following validitysensor.init_flash().

    The library runs this same sequence whenever the daemon starts on a
    zero-partition sensor, so keeping the tool identical to it means the
    provisioned state is exactly what the daemon expects.  The one deliberate
    difference is the 0x969 register preflight from #283, inserted between the
    reset blob and 4f.  Firmware is uploaded in a separate TLS session
    afterwards (upload_fwext() does the same on a normal daemon start).
    """
    log('== PROVISION (re-create partitions, new local pairing)')
    open_sensor()
    try:
        send_init_sequence()
        info = get_flash_info()
        if len(info.partitions) == 0:
            log('    flash is unprovisioned: %s, %d bytes'
                % (info.ic.name, info.ic.size))

            log('    sending reset blob (factory path) ...')
            status = status_of(usb.cmd(blob('reset_blob')))
            log('    reset blob -> status 0x%04x' % status)
            if status != 0:
                raise Abort('reset blob rejected (0x%04x); nothing was changed' % status)

            # Register preflight, as reported for this exact unit on #283:
            # without it the 0x969 silicon refuses the 4f partition command.
            log('    register preflight (0x8000205c = 7) ...')
            write_hw_reg32(0x8000205C, 7)
            value = read_hw_reg32(0x80002080)
            log('    0x80002080 = 0x%08x' % value)
            if value not in (2, 3):
                raise Abort('unexpected register value 0x%08x (expected 2 or 3); '
                            'refusing to format.' % value)
            # Do NOT send identify_sensor() (0x75) or call_cleanups() (0x1a)
            # here.  The factory path has no pending commit, and the sensor
            # leaves the reset/factory state on 0x1a, after which 4f is
            # rejected with 0x0401 ("invalid command in this state").  The
            # working sequence on #283 is: reset_blob -> reg preflight -> 4f.

            backend = default_backend()
            skey = ec.generate_private_key(ec.SECP256R1(), backend)
            snums = skey.private_numbers()
            client_private = snums.private_value
            client_public = snums.public_numbers

            log('    sending 4f (partition table + server cert) ...')
            partition_flash(info, flash_layout_hardcoded,
                            partition_signature, client_public)
            log('    partitions created')

            RomInfo.get()
            log('    sending 50 (ECDH) ...')
            try:
                rsp = usb.cmd(b'\x50')
            finally:
                call_cleanups()
            if status_of(rsp) != 0:
                raise Abort('ECDH (50) failed: status 0x%04x' % status_of(rsp))
            payload = rsp[2:]
            length, = unpack('<L', payload[:4])
            if len(payload) != length:
                raise Abort('ECDH length mismatch (%d != %d)' % (len(payload), length))
            zeroes, server_pub = payload[4:-400], payload[-400:]
            if zeroes != b'\x00' * len(zeroes):
                raise Abort('ECDH response has unexpected non-zero bytes')
            tls.handle_ecdh(server_pub)
            tls.handle_priv(encrypt_key(client_private, client_public))
            log('    opening TLS session with the new pairing ...')
            tls.open()
            log('    TLS is up (new pairing accepted by the sensor)')

            # Same order as init_flash(): erase every new partition, then
            # write the fresh cert-store, then reboot.
            log('    erasing partitions 1, 2, 5, 6, 4 ...')
            for partition in (1, 2, 5, 6, 4):
                erase_flash(partition)
                log('      erased %d' % partition)

            log('    writing new cert-store (bound to this machine\'s DMI) ...')
            write_flash(1, 0, tls.make_tls_flash())
            log('    cert-store written')

            log('    rebooting sensor')
            try:
                reboot()
            except RebootException:
                pass
        else:
            log('    flash already has %d partition(s); skipping format/pairing'
                % len(info.partitions))
    finally:
        release_device()

    wait_for_device()
    phase_firmware(args)
    log('    provision complete. Next: --phase verify')


def phase_firmware(args):
    """Upload the xpfwext if partition 2 is empty (mirrors upload_fwext())."""
    log('== FIRMWARE (upload the HP xpfwext if it is missing)')
    open_sensor()
    try:
        send_init_sequence()
        info = get_flash_info()
        if len(info.partitions) == 0:
            raise Abort('sensor is unprovisioned (zero partitions); '
                        'run --phase provision first')

        log('    reading cert-store and opening TLS ...')
        certstore = read_flash(1, 0, 0x1000)
        tls.reset()
        tls.parse_tls_flash(certstore)
        tls.open()
        log('    TLS session established')

        try:
            fwi = get_fw_info(2)
        except Exception as error:  # noqa: BLE001
            if '044f' not in str(error):
                raise
            log('    interrupted firmware upload detected (%s)' % error)
            log('    erasing the partial firmware partition')
            erase_flash(2)
            fwi = None

        if fwi is not None:
            log('    fwext present: %d.%d, %d modules'
                % (fwi.major, fwi.minor, len(fwi.modules)))
        else:
            if not FW_CACHE.is_file():
                raise Abort('no firmware cached at %s.\n'
                            '        Run preflight with network access (it '
                            'downloads the pinned HP SoftPaq),\n        or pass '
                            '--firmware /path/to/%s.' % (FW_CACHE, FWTYPE))
            log('    register preflight (0x8000205c = 7) ...')
            write_hw_reg32(0x8000205C, 7)
            value = read_hw_reg32(0x80002080)
            log('    0x80002080 = 0x%08x' % value)
            if value not in (2, 3):
                raise Abort('unexpected register value 0x%08x (expected 2 or 3); '
                            'refusing to write firmware' % value)
            ident = identify_sensor()
            log('    sensor: %s' % ident.name)

            fwext = FW_CACHE.read_bytes()
            fwext = fwext[fwext.index(b'\x1a') + 1:]
            fwext, signature = fwext[:-0x100], fwext[-0x100:]
            log('    writing %d bytes of firmware ...' % len(fwext))
            write_flash_all(2, 0, fwext)
            write_fw_signature(2, signature)
            fwi = get_fw_info(2)
            if fwi is None:
                raise Abort('firmware upload did not take; the sensor is '
                            'provisioned but firmwareless. Re-run --phase '
                            'firmware; if it keeps failing try a different '
                            'SoftPaq via --softpaq.')
            log('    fwext now: %d.%d, %d modules'
                % (fwi.major, fwi.minor, len(fwi.modules)))

        log('    rebooting sensor')
        try:
            reboot()
        except RebootException:
            pass
        release_device()
    finally:
        release_device()
    wait_for_device()
    try:
        reboot()
    except RebootException:
        pass
    release_device()
    log('    firmware OK. Next: --phase verify')


def phase_verify(args):
    log('== VERIFY (read back the new cert-store and complete a TLS handshake)')
    open_sensor()
    try:
        send_init_sequence()
        info = get_flash_info()
        log('    flash: %s, %d partitions' % (info.ic.name, len(info.partitions)))
        for p in info.partitions:
            log('      %r' % p)
        if len(info.partitions) == 0:
            raise Abort('sensor reports zero partitions; run --phase provision')
        certstore = read_flash(1, 0, 0x1000)
        log('    cert-store: %d bytes, sha256 %s'
            % (len(certstore), hashlib.sha256(certstore).hexdigest()))
        tls.reset()
        tls.parse_tls_flash(certstore)
        log('    local private key loaded from cert-store')
        tls.open()
        log('    TLS 1.2 handshake with the sensor: OK')
        ident = identify_sensor()
        log('    identity: type=0x%04x name=%r' % (ident.type, ident.name))
        fwi = get_fw_info(2)
        if fwi is None:
            log('    WARNING: no firmware; run --phase provision again')
        else:
            log('    fwext: %d.%d, %d modules' % (fwi.major, fwi.minor, len(fwi.modules)))
    finally:
        try:
            reboot()
        except RebootException:
            pass
        except Exception:  # noqa: BLE001
            pass
        release_device()
    log('    verify OK. The sensor is paired to this machine and ready for enrollment.')


def main() -> int:
    global _log_file
    parser = argparse.ArgumentParser(
        description='Re-provision the Synaptics 06cb:00bb fingerprint sensor',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    parser.add_argument('--phase', default='preflight',
                        choices=['preflight', 'wipe', 'provision', 'firmware',
                                 'verify', 'all'])
    parser.add_argument('--firmware', help='path to an extracted %s' % FWTYPE)
    parser.add_argument('--softpaq', help='HP SoftPaq .exe to extract %s from '
                                          '(used instead of the pinned download)' % FWTYPE)
    parser.add_argument('--yes', action='store_true',
                        help='skip the interactive confirmation (dangerous)')
    parser.add_argument('--force', action='store_true',
                        help='allow wiping a sensor whose identity is not the '
                             'known 0x969 / FM-3439-xxx')
    args = parser.parse_args()

    if os.geteuid() != 0:
        print('ERROR: must run as root (USB device node is root-only).', file=sys.stderr)
        return 2

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(BACKUP_DIR, 0o700)
    _log_file = open(LOG_PATH, 'a')
    os.chmod(LOG_PATH, 0o600)

    if args.firmware:
        source = Path(args.firmware).expanduser()
        if not source.is_file():
            print('ERROR: --firmware %s does not exist' % source, file=sys.stderr)
            return 2
        init_data_dir()
        shutil.copyfile(source, FW_CACHE)
        os.chmod(FW_CACHE, 0o600)

    log('python-validity 00bb re-provisioning, phase=%s, %s' % (args.phase, STAMP))
    log('log file: %s' % LOG_PATH)

    stop_competing_services()
    try:
        if args.phase in ('preflight', 'all'):
            phase_preflight(args)
        if args.phase in ('wipe', 'all'):
            phase_wipe(args)
        if args.phase in ('provision', 'all'):
            phase_provision(args)
        if args.phase == 'firmware':
            phase_firmware(args)
        if args.phase in ('verify', 'all'):
            phase_verify(args)
    except Abort as error:
        log('\nSTOPPED: %s' % error)
        log('The device may be left in a partially provisioned state; the log is '
            'in %s.' % LOG_PATH)
        return 1
    except KeyboardInterrupt:
        log('\ninterrupted')
        return 130
    except Exception as error:  # noqa: BLE001
        import traceback
        log('\nUNEXPECTED ERROR: %r' % error)
        log(traceback.format_exc())
        log('Log: %s' % LOG_PATH)
        return 1
    finally:
        if _log_file is not None:
            _log_file.close()
            _log_file = None
        restart_services()

    log('\nDONE.')
    if args.phase in ('provision', 'firmware', 'verify', 'all'):
        log('Next: enroll a finger with   fprintd-enroll')
    return 0


if __name__ == '__main__':
    sys.exit(main())
