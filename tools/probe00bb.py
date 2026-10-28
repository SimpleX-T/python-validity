#!/usr/bin/env python3
"""Read-only probe for the Synaptics 06cb:00bb sensor (HP Spectre x360 13-ap0xxx).

What this does
--------------
1. Opens the sensor with the patched python-validity code in this tree.
2. Sends the Prometheus/97-class init sequence (01, 19, 4302, 06 02 <init blob>).
3. Reads the flash layout (3e), the sensor identity (75) and the cleartext
   TLS cert-store partition (40 / partition 1).
4. Saves the cert-store to ``backups/`` and writes a JSON report.

What this does NOT do
---------------------
* No flash writes, no erase, no 4f/50, no reset_blob.
* The only non-read command is the standard init blob, which python-validity
  sends on every single startup.
* At the end the sensor is rebooted (05 02 00), which is exactly what the
  python-validity daemon does when it exits.

Run:
    sudo python3 tools/probe00bb.py
"""

import argparse
import hashlib
import json
import os
import sys
import time
from binascii import hexlify
from pathlib import Path
from struct import unpack

REPO = Path(__file__).resolve().parent.parent
PROJECT = REPO
sys.path.insert(0, str(REPO))

import usb.core as ucore  # noqa: E402

from validitysensor import blobs  # noqa: E402
from validitysensor.flash import get_flash_info, get_fw_info, read_flash  # noqa: E402
from validitysensor.sensor import RebootException, RomInfo, identify_sensor, reboot  # noqa: E402
from validitysensor.tls import tls  # noqa: E402
from validitysensor.usb import usb  # noqa: E402

VID, PID = 0x06CB, 0x00BB


def hx(data: bytes) -> str:
    return hexlify(data).decode()


def status_of(rsp: bytes) -> int:
    return unpack('<H', rsp[:2])[0] if len(rsp) >= 2 else -1


def save_backup(name: str, data: bytes, outdir: Path):
    outdir.mkdir(parents=True, exist_ok=True)
    path = outdir / name
    path.write_bytes(data)
    os.chmod(path, 0o600)
    digest = hashlib.sha256(data).hexdigest()
    print('    saved %s (%d bytes, sha256 %s)' % (path, len(data), digest))
    return str(path), digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--output-dir', default=str(PROJECT / 'backups'),
                        help='where to store the cert-store backup and JSON report')
    parser.add_argument('--no-reboot', action='store_true',
                        help='leave the sensor in the initialized state (not recommended)')
    args = parser.parse_args()

    if os.geteuid() != 0:
        print('ERROR: the USB device node is root-only. Re-run with sudo.', file=sys.stderr)
        return 2

    outdir = Path(args.output_dir)
    report = {'usb': {}, 'steps': {}, 'partitions': [], 'firmware': None}

    print('== 0. open 06cb:00bb')
    dev = ucore.find(idVendor=VID, idProduct=PID)
    if dev is None:
        print('ERROR: 06cb:00bb not found on the USB bus.', file=sys.stderr)
        return 1
    report['usb'] = {
        'bus': int(dev.bus),
        'address': int(dev.address),
        'idVendor': '%04x' % dev.idVendor,
        'idProduct': '%04x' % dev.idProduct,
        'bcdDevice': '%04x' % dev.bcdDevice,
        'serial': dev.serial_number,
        'manufacturer': dev.manufacturer,
        'product': dev.product,
    }
    for key, value in report['usb'].items():
        print('    %-12s %s' % (key, value))

    serial = (dev.serial_number or 'unknown').replace('/', '_')
    stamp = time.strftime('%Y%m%d-%H%M%S')
    tls.reset()
    usb.open_dev(dev)
    print('    opened; config set')

    try:
        print('== 1. send 01 (ROM info)')
        rsp = usb.cmd(b'\x01')
        report['steps']['01'] = hx(rsp)
        print('    status 0x%04x, %d bytes' % (status_of(rsp), len(rsp)))
        if status_of(rsp) != 0:
            raise RuntimeError('ROM info rejected')
        rom = RomInfo.get()
        print('    %r' % rom)
        report['rom'] = {
            'timestamp': rom.timestamp, 'build': rom.build, 'major': rom.major,
            'minor': rom.minor, 'product': rom.product,
        }

        print('== 2. send 19')
        rsp = usb.cmd(b'\x19')
        report['steps']['19'] = hx(rsp)
        print('    status 0x%04x, %d bytes' % (status_of(rsp), len(rsp)))

        print('== 3. send 43 02 (firmware/ext info, cleartext)')
        r43 = usb.cmd(b'\x43\x02')
        report['steps']['4302'] = hx(r43)
        print('    status 0x%04x, %d bytes' % (status_of(r43), len(r43)))

        print('== 4. send init blob (06 02 ..., 581 bytes inner)')
        blob = blobs.init_hardcoded()
        print('    blob %d bytes, starts %s' % (len(blob), hx(blob[:10])))
        rsp = usb.cmd(blob)
        report['steps']['init_hardcoded'] = hx(rsp)
        print('    status 0x%04x' % status_of(rsp))
        if status_of(rsp) != 0:
            print('    -> retrying with init_hardcoded_clean_slate')
            rsp = usb.cmd(blobs.init_hardcoded_clean_slate())
            report['steps']['init_hardcoded_clean_slate'] = hx(rsp)
            print('    status 0x%04x' % status_of(rsp))
            if status_of(rsp) != 0:
                raise RuntimeError('init blob rejected')
        elif status_of(r43) != 0:
            print('    no firmware reported (clean slate) -> clean-slate blob')
            rsp = usb.cmd(blobs.init_hardcoded_clean_slate())
            report['steps']['init_hardcoded_clean_slate'] = hx(rsp)
            print('    status 0x%04x' % status_of(rsp))

        print('== 5. send 3e (flash info)')
        info = get_flash_info()
        print('    IC %s, %d bytes, %d partition(s)' %
              (info.ic.name, info.ic.size, len(info.partitions)))
        report['flash'] = {
            'ic': info.ic.name, 'size': info.ic.size,
            'blocks': info.blocks, 'blocksize': info.blocksize,
        }
        for p in info.partitions:
            print('    %r' % p)
            report['partitions'].append({
                'id': p.id, 'type': p.type, 'access': p.access_lvl,
                'offset': p.offset, 'size': p.size,
            })

        print('== 6. send 75 (sensor identity)')
        rsp = usb.cmd(b'\x75')
        report['steps']['75'] = hx(rsp)
        print('    status 0x%04x, %d bytes' % (status_of(rsp), len(rsp)))
        ident = identify_sensor()
        print('    type=0x%04x hw-id=0x%02x name=%r' % (ident.type, ident.version, ident.name))
        report['identity'] = {'type': ident.type, 'hw_id': ident.version,
                              'name': ident.name, 'major': ident.major}

        print('== 7. send 43 02 (fwext partition metadata)')
        try:
            fwi = get_fw_info(2)
        except Exception as error:  # noqa: BLE001
            fwi = None
            print('    not readable in this state: %s' % error)
        if fwi is None:
            print('    no firmware reported')
        else:
            print('    fwext %d.%d buildtime %d, %d module(s)' %
                  (fwi.major, fwi.minor, fwi.buildtime, len(fwi.modules)))
            report['firmware'] = {
                'major': fwi.major, 'minor': fwi.minor,
                'buildtime': fwi.buildtime, 'modules': len(fwi.modules),
            }

        print('== 8. read partition 1 (TLS cert-store, access level 7)')
        cert = read_flash(1, 0, 0x1000)
        print('    read %d bytes, head %s' % (len(cert), hx(cert[:24])))
        path, digest = save_backup('00bb-certstore-%s-%s.bin' % (serial, stamp), cert, outdir)
        report['certstore'] = {
            'path': path, 'sha256': digest, 'size': len(cert),
            'is_python_validity_format': cert[:4] == b'\x00\x00\x01\x00',
        }

        print('== 9. probe other partitions (expected to be TLS-only)')
        for part in (2, 4, 6):
            try:
                data = read_flash(part, 0, 0x40)
                print('    partition %d: %d bytes readable, head %s'
                      % (part, len(data), hx(data[:16])))
            except Exception as error:  # noqa: BLE001
                print('    partition %d: not readable without TLS (%s)' % (part, error))

        print('== 10. read-only hardware registers (preflight values)')
        for addr in (0x8000205C, 0x80002080):
            try:
                rsp = usb.cmd(b'\x07' + addr.to_bytes(4, 'little') + b'\x04')
                if status_of(rsp) == 0 and len(rsp) >= 6:
                    print('    0x%08x = 0x%08x' % (addr, unpack('<L', rsp[2:6])[0]))
                else:
                    print('    0x%08x -> status 0x%04x' % (addr, status_of(rsp)))
            except Exception as error:  # noqa: BLE001
                print('    0x%08x -> %s' % (addr, error))

        report['ok'] = True
    except Exception as error:  # noqa: BLE001
        import traceback
        report['ok'] = False
        report['error'] = repr(error)
        report['traceback'] = traceback.format_exc()
        print('\nERROR: %r' % error, file=sys.stderr)
        print(report['traceback'], file=sys.stderr)
    finally:
        if not args.no_reboot:
            print('== 11. reboot sensor (normal daemon exit path)')
            try:
                reboot()
            except RebootException:
                print('    sensor rebooting')
            except Exception as error:  # noqa: BLE001
                print('    reboot failed (usually harmless): %s' % error)
        usb.dev = None

    report_path = outdir / ('00bb-probe-%s-%s.json' % (serial, stamp))
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    os.chmod(report_path, 0o600)
    print('\nreport: %s' % report_path)
    print('Send this JSON plus the cert-store backup to the project folder; '
          'neither contains your fingerprint templates.')
    return 0 if report.get('ok') else 1


if __name__ == '__main__':
    sys.exit(main())
