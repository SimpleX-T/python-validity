#!/usr/bin/env python3
"""Offline smoke test for tools/flash00bb.py (no hardware, no root).

Fakes the USB transport and the device-side helpers, then runs the wipe and
provision phases to check command ordering and abort behaviour.

Run:
    python3 tools/test_flash_smoke.py

Needs pyusb importable (``apt install python3-usb``) because flash00bb imports
it at module level, but never opens a real device.
"""
import importlib.util
import sys
from pathlib import Path
from struct import pack
from types import SimpleNamespace
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

spec = importlib.util.spec_from_file_location('flash00bb', REPO / 'tools' / 'flash00bb.py')
F = importlib.util.module_from_spec(spec)
spec.loader.exec_module(F)


class FakeUsb:
    def __init__(self):
        self.commands = []
        # Interleaved view of tool calls and raw USB writes, used to check the
        # ordering around the destructive factory sequence.
        self.timeline = []
        self.reset_blob = b'\x06\x02' + b'R' * 100
        self.reset_response = b'\x00\x00'
        self.dev = SimpleNamespace(serial_number='SERIAL123', bus=1, address=2)

    def usb_dev(self):
        return self.dev

    def cmd(self, data):
        if callable(data):
            data = data()
        self.commands.append(data)
        self.timeline.append(('usb', data))
        if data in (b'\x01', b'\x19', b'\x43\x02', b'\x50'):
            if data == b'\x50':
                zeros = b'\x00' * 32
                pub = b'\x11' * 400
                payload = pack('<L', 4 + len(zeros) + len(pub)) + zeros + pub
                return b'\x00\x00' + payload
            if data == b'\x43\x02':
                return b'\x00\x00' + b'\x00' * 8
            return b'\x00\x00' + b'\x00' * 36
        if data == self.reset_blob:
            return self.reset_response
        if data[:1] == b'\x10':
            return b'\x00\x00'
        if data[:2] == b'\x06\x02':
            return b'\x00\x00'
        return b'\x00\x00'


def install(fake_usb, partitions):
    """Wire the fake transport and device-side helpers into the module."""
    state = {'partitions': list(partitions)}

    def flash_info():
        return SimpleNamespace(
            ic=SimpleNamespace(name='W25Q80B', size=1048576),
            blocks=256, blocksize=4096,
            partitions=[SimpleNamespace(id=i, type=1, access_lvl=7,
                                        offset=0x1000 * i, size=0x1000)
                        for i in state['partitions']])

    calls = []

    def rec(name, result=None):
        def inner(*args, **kwargs):
            calls.append((name, args))
            fake_usb.timeline.append(('call', name))
            return result
        return inner

    F.usb = fake_usb
    # The real blobs module materialises its thunks into plain bytes on first
    # use, so the fake models the state present in phase 2 of "--phase all".
    F.blobs = SimpleNamespace(reset_blob=fake_usb.reset_blob,
                              init_hardcoded=b'\x06\x02' + b'I' * 579,
                              init_hardcoded_clean_slate=b'\x06\x02' + b'C' * 579)
    F.get_flash_info = flash_info
    F.assert_target_device = lambda force: SimpleNamespace(
        type=0x969, version=0x88, name='57K0 FM-3439-004   ')
    F.backup_certstore = rec('backup')
    F.prepare_firmware = rec('firmware')
    F.partition_flash = rec('4f')
    F.write_hw_reg32 = rec('write_reg')
    F.read_hw_reg32 = lambda addr: 2
    F.identify_sensor = rec('identify', SimpleNamespace(
        type=0x969, version=0x88, name='57K0 FM-3439-004   '))
    F.call_cleanups = rec('cleanups')
    F.erase_flash = rec('erase')
    F.write_flash = rec('write_tls')
    F.write_flash_all = rec('write_fw')
    F.write_fw_signature = rec('write_fw_sig')
    F.get_fw_info = rec('fw_info', None)
    F.RomInfo.get = staticmethod(lambda: SimpleNamespace(
        timestamp=1, build=164, major=6, minor=7, product=48))
    F.reboot = mock.Mock(side_effect=F.RebootException)
    F.release_device = lambda: None
    F.wait_for_device = lambda timeout=60.0: None
    F.tls = SimpleNamespace(reset=lambda: None, handle_ecdh=rec('ecdh'),
                            handle_priv=rec('priv'), open=rec('tls_open'),
                            parse_tls_flash=rec('parse_tls'),
                            make_tls_flash=lambda: b'\x00\x00\x01\x00' + b'K' * 100)
    F.read_flash = lambda part, offset, size: b'\x00\x00\x01\x00' + b'K' * (size - 4)
    F.phase_firmware = rec('firmware_phase')
    return state, calls


ARGS = SimpleNamespace(yes=True, force=False, softpaq=None)
REAL_PHASE_FIRMWARE = F.phase_firmware
failures = []


def check(condition, message):
    if not condition:
        failures.append(message)
        print('FAIL: %s' % message)


print('--- wipe: reset blob rejected must abort')
fake = FakeUsb()
fake.reset_response = b'\x04\x04'
state, calls = install(fake, [1, 2, 6, 3, 4])
try:
    F.phase_wipe(ARGS)
    check(False, 'wipe should have aborted when the reset blob is rejected')
except F.Abort as error:
    print('ok abort:', str(error).splitlines()[0])

print('--- wipe: accepted')
fake = FakeUsb()
state, calls = install(fake, [1, 2, 6, 3, 4])
orig_get_flash = F.get_flash_info
mode = {'n': 0}


def flash_info_two_stage():
    mode['n'] += 1
    state['partitions'] = [1, 2, 6, 3, 4] if mode['n'] <= 1 else []
    return orig_get_flash()


F.get_flash_info = flash_info_two_stage
F.phase_wipe(ARGS)
check(fake.commands[0] == b'\x01', 'wipe must start with the ROM info command')
check(b'\x06\x02' + b'I' * 579 in fake.commands, 'wipe must send the init blob')
check(F.blobs.reset_blob in fake.commands, 'wipe must send the reset blob')
check(b'\x10' + b'\x00' * 0x61 in fake.commands, 'wipe must send the commit command')
print('ok wipe: %d commands' % len(fake.commands))

print('--- provision: zero partitions -> full flow')
fake = FakeUsb()
state, calls = install(fake, [])
F.get_flash_info = orig_get_flash
fw_calls = {'n': 0}


def fw_info_after_upload(part):
    fw_calls['n'] += 1
    if fw_calls['n'] == 1:
        return None
    return SimpleNamespace(major=1, minor=7, buildtime=123, modules=[])


F.get_fw_info = fw_info_after_upload
fake_fw = Path('/tmp/opencode-fake.xpfwext')
fake_fw.write_bytes(b'HPHEADER' + b'\x1a' + b'FW' * 200 + b'S' * 256)
F.FW_CACHE = fake_fw
try:
    F.phase_provision(ARGS)
finally:
    fake_fw.unlink(missing_ok=True)

names = [c[0] for c in calls]
print('calls:', names)
check('4f' in names, 'provision must send the partition table (4f)')
check('ecdh' in names, 'provision must handle the ECDH reply')
check('priv' in names, 'provision must install the local private key')
check('tls_open' in names, 'provision must open TLS')
check('write_tls' in names, 'provision must write the new cert-store')
check('write_reg' in names and names.index('write_reg') < names.index('4f'),
      'provision must do the register preflight before the 4f partition command')
check('identify' not in names[:names.index('4f')],
      'provision must not send identify (0x75) before 4f')
check('cleanups' not in names[:names.index('4f')],
      'provision must not commit (0x1a) before 4f; that leaves the factory '
      'state and the sensor answers 0401')
reset_idx = max(i for i, event in enumerate(fake.timeline)
                if event == ('usb', fake.reset_blob))
fourf_idx = fake.timeline.index(('call', '4f'))
check(reset_idx < fourf_idx,
      'provision must reset the sensor before the 4f partition command')
between = fake.timeline[reset_idx + 1:fourf_idx]
check(not any(event == ('usb', b'\x1a') for event in between),
      'no raw 0x1a may be sent between reset and 4f (see #283)')
check([v for t, v in between if t == 'call'] == ['write_reg'],
      'reset -> write_reg(0x8000205c) -> 4f is the only accepted sequence, '
      'got %r' % ([v for t, v in between if t == 'call'],))
check([a[1][0] for a in calls if a[0] == 'erase'] == [1, 2, 5, 6, 4],
      'provision must erase 1, 2, 5, 6, 4 in that order (matches init_flash)')
check('firmware_phase' in names, 'provision must hand over to the firmware phase')
print('ok provision')

print('--- provision: already formatted sensor is not re-formatted')
fake = FakeUsb()
state, calls = install(fake, [1, 2, 6, 3, 4])
F.phase_provision(ARGS)
names = [c[0] for c in calls]
check('4f' not in names, 'provision must not re-format an already provisioned sensor')
check('erase' not in names, 'provision must not erase an already provisioned sensor')
check('firmware_phase' in names, 'provision must still run the firmware phase')
print('ok provision (idempotent)')

print('--- firmware: no partitions -> abort')
fake = FakeUsb()
state, calls = install(fake, [])
F.phase_firmware = REAL_PHASE_FIRMWARE
try:
    F.phase_firmware(ARGS)
    check(False, 'firmware phase should refuse an unprovisioned sensor')
except F.Abort as error:
    print('ok abort:', str(error).splitlines()[0])

print('--- firmware: present -> no write')
fake = FakeUsb()
state, calls = install(fake, [1, 2, 6, 3, 4])
F.phase_firmware = REAL_PHASE_FIRMWARE
F.get_fw_info = lambda part: SimpleNamespace(major=1, minor=7, buildtime=1, modules=[])
F.phase_firmware(ARGS)
names = [c[0] for c in calls]
check('write_fw' not in names, 'firmware phase must not rewrite an intact fwext')
check('parse_tls' in names, 'firmware phase must load the local key from the cert-store')
print('ok firmware (present)')

print('--- firmware: missing -> upload')
fake = FakeUsb()
state, calls = install(fake, [1, 2, 6, 3, 4])
F.phase_firmware = REAL_PHASE_FIRMWARE
calls_fw = {'n': 0}


def fw_info_upload(part):
    calls_fw['n'] += 1
    return None if calls_fw['n'] == 1 else SimpleNamespace(
        major=1, minor=7, buildtime=1, modules=[])


F.get_fw_info = fw_info_upload
fake_fw = Path('/tmp/opencode-fake2.xpfwext')
fake_fw.write_bytes(b'HPHEADER' + b'\x1a' + b'FW' * 200 + b'S' * 256)
F.FW_CACHE = fake_fw
try:
    F.phase_firmware(ARGS)
finally:
    fake_fw.unlink(missing_ok=True)
names = [c[0] for c in calls]
check(names.count('write_fw') == 1, 'firmware phase must write the fwext once')
check('write_fw_sig' in names, 'firmware phase must write the signature')
check('write_reg' in names, 'firmware phase must set the pre-upload register')
print('ok firmware (upload)')

print('--- blobs: thunk form and materialised form')
F.blobs = SimpleNamespace(reset_blob=lambda: b'R' * 10)
check(F.blob('reset_blob') == b'R' * 10, 'blob() must call a thunk')
F.blobs = SimpleNamespace(reset_blob=b'R' * 10)
check(F.blob('reset_blob') == b'R' * 10,
      'blob() must not call an already materialised bytes object')
print('ok blob()')

print('--- blobs: real module replaces its own thunks')
sys.path.insert(0, str(REPO))
from validitysensor import blobs as real_blobs  # noqa: E402
from validitysensor import usb as real_usb  # noqa: E402


class FakeDev:
    idVendor = 0x06cb
    idProduct = 0x00bb


real_usb.usb.usb_dev = lambda: FakeDev()
data = real_blobs.init_hardcoded()          # first call: returns bytes
check(isinstance(data, bytes) and len(data) > 500,
      'first blob call returns the init blob')
check(isinstance(real_blobs.init_hardcoded, bytes),
      'blobs module replaces the thunk with bytes (documented behaviour)')
F.blobs = real_blobs
check(F.blob('init_hardcoded') == data,
      'blob() must still work after the module materialised the blob')
print('ok blob() with the real module')

print('--- init sequence twice in one process (the "--phase all" crash)')
fake = FakeUsb()
install(fake, [1, 2, 6, 3, 4])
F.send_init_sequence()
F.send_init_sequence()
check(fake.commands.count(b'\x01') == 2,
      'a second init sequence in the same process must still send the blobs')
print('ok init sequence repeat')

print('--- services: stop/mask, then unmask/start')
recorded = []


def fake_run(argv, **kwargs):
    recorded.append(list(argv))
    return SimpleNamespace(returncode=0)


real_units = F.COMPETING_UNITS
F.COMPETING_UNITS = ('fprintd.service',)
try:
    with mock.patch('subprocess.run', fake_run):
        F.stop_competing_services()
        F.restart_services()
finally:
    F.COMPETING_UNITS = real_units
flat = [' '.join(argv) for argv in recorded]
check('systemctl mask --runtime python3-validity.service' in flat,
      'must mask the daemon for the duration of the run')
check('systemctl unmask --runtime python3-validity.service' in flat,
      'must unmask the daemon again afterwards')
check('systemctl stop fprintd.service' in flat, 'must stop competing units')
check('systemctl start fprintd.service' in flat,
      'must restart units that were active before')
print('ok services')

if failures:
    print('\n%d SMOKE CHECK(S) FAILED' % len(failures))
    sys.exit(1)
print('\nALL SMOKE TESTS PASSED')
