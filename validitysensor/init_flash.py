import hmac
import logging
import os
import typing
from binascii import unhexlify
from hashlib import sha256
from struct import pack, unpack

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .blobs import reset_blob
from .flash import write_flash, erase_flash, call_cleanups, PartitionInfo, get_flash_info, FlashInfo, read_tls_flash
from .hw_tables import FlashIcInfo
from .sensor import reboot, RomInfo
from .tls import tls, hs_key, crt_hardcoded
from .usb import usb
from .util import assert_status, unhex

flash_layout_hardcoded = [
    #             id  type  access  offset       size
    #                       lvl
    PartitionInfo(1, 4, 7, 0x00001000, 0x00001000),  # cert store
    PartitionInfo(2, 1, 2, 0x00002000, 0x0003e000),  # xpfwext
    PartitionInfo(5, 5, 3, 0x00040000, 0x00008000),  # ???
    PartitionInfo(6, 6, 3, 0x00048000, 0x00008000),  # calibration data
    PartitionInfo(4, 3, 5, 0x00050000, 0x00080000),  # template database
]

partition_signature = unhex('''
1db02a886b007e2b47263bb8fe30bd64a1f58bea7b25f1e1ba9ae09add7ecff36333f8198339cdd713f043633710a17bc7b3f418f1d8ff435a1bf47f065dffca
727109152217fce73bf2bf8e01a1641f6a24b0c492a6a3f10114057275846842b1c8b66bd6700738524d4471bca3315ba23bb832743220ad195b60558aa79a3e
deb2604834e2bb62e890b0ce405b3b8ef2fec2aab3e22bff23f89a58ff0dc015fece5d3ed3f5496ace879a92980aec9d85eb7e9df245eae03a41acfd4e7d1cb1
dbd0df42d534904de00b6389f68867646e9d7c3d0b1dffd74070b2d0f2049b9f1dc7b0c9651c59be3ea891674725e1f2f7a484a941615b80211105978369cf71
''')

flash_layout_hardcoded_0090 = [
    #             id  type  access  offset       size
    #                       lvl
    PartitionInfo(1, 4, 7, 0x00001000, 0x00001000),  # cert store
    PartitionInfo(2, 1, 2, 0x00002000, 0x0003e000),  # xpfwext
    PartitionInfo(5, 5, 3, 0x00040000, 0x00008000),  # ???
    PartitionInfo(6, 6, 3, 0x00048000, 0x00008000),  # calibration data
    PartitionInfo(4, 3, 5, 0x00050000, 0x00030000),  # template database
]

partition_signature_0090 = unhex('''
e44f7a80d6137794d330b5d026c328a73c907f3f653d411255b7c2f8b425d870a8a53c6630ca864b84590e3c6786f0d69be4bbab5736388f8527237a0a86bbce
7ced9450c4964709e89ac535aa00787158e0a8d9b1fb75f0f7ae53d4bd11abfcf5ee67a5a71e248a426b3aff4567048fa93de65939ccfbe3f31149a82c64fbfd
6a2a6cf748e1d9bd8562cf39b1a4b307b37be223317b1b817e364f2877d29d123731314aa627cbf234e0ea69a406a4735a03a45495023ef706bdb542c949d243
ac2c08c00abf43faa5528a0a8e49b02c507b01b6f1c9abffc669d8c84d7e4a714da32aade7928eca9698b82bee6b72c642c9add80bbd7ccc4121b80220d52b8a
''')

flash_layout_d51 = [
    PartitionInfo(1, 4, 7, 0x00001000, 0x00001000),  # cert store
    PartitionInfo(2, 1, 2, 0x00002000, 0x00055000),  # xpfwext
    PartitionInfo(6, 6, 3, 0x00057000, 0x00008000),  # calibration data
    PartitionInfo(3, 2, 0x0017, 0x0005f000, 0x0004f000),  # template database part 1
    PartitionInfo(4, 3, 5, 0x000ae000, 0x00052000),  # template database part 2
]

partition_signature_d51 = unhex('''
d6b3f8c9307d0e6de3676178c18b80203fd5126ba026216c14e7e9d097a185c06728a4c0b4dcb44c8160c572672a5c30
19fdf02c2143c01d6da176e8857ca0dd4524e0e79126aaf6d90c3de3b2d50156eaff87c7e92ffb770516959fa2f0d8aa
d0249cc8d8365ec0c2d0548d220dcc4413e5b4844eb69ac05997a6cf32ddf6b6ee8f8ee50c6534c1fdc7c65618957bb7
4b97c7f49a56120f95f2793d9c2775ee4519cd7005ad6b46d1791a8758a89e4530529a28084a002c1bf55a81f6b71018
5c096d16950ae2dc6da0c16dd03b6fd19354c317ce3bf828c755c6e887d061feae643bb80437f2654d940dfea278ac66
11c9df3d04e0d107fb7f78a667417bb1
''')

crypto_backend = default_backend()


def _write_cert_store():
    # Writing the cert store as a single 4096-byte chunk can cause silent
    # buffer truncation on 0xd51-family devices. We split the write into
    # safe 64-byte chunks.
    img = tls.make_tls_flash()
    chunk_size = 64
    for offset in range(0, len(img), chunk_size):
        write_flash(1, offset, img[offset:offset+chunk_size])


def with_hdr(id: int, buf: bytes):
    return pack('<HH', id, len(buf)) + buf


def encrypt_key(client_private, client_public):
    x = unhexlify('%064x' % client_public.x)[::-1]
    y = unhexlify('%064x' % client_public.y)[::-1]
    d = unhexlify('%064x' % client_private)[::-1]

    m = x + y + d
    l = 16 - (len(m) % 16)
    m = m + bytes([l]) * l

    iv = os.urandom(0x10)
    cipher = Cipher(algorithms.AES(tls.psk_encryption_key), modes.CBC(iv), backend=crypto_backend)
    encryptor = cipher.encryptor()
    c = iv + encryptor.update(m) + encryptor.finalize()

    sig = hmac.new(tls.psk_validation_key, c, sha256).digest()
    return b'\x02' + c + sig


def make_cert(client_public):
    msg = (pack('<LL', 0x17, 0x20) + unhexlify('%064x' % client_public.x)[::-1] + (b'\0' * 0x24) +
           unhexlify('%064x' % client_public.y)[::-1] + (b'\0' * 0x4c))
    pk = ec.derive_private_key(hs_key(), ec.SECP256R1(), backend=crypto_backend)
    s = pk.sign(msg, ec.ECDSA(hashes.SHA256()))
    s = pack('<L', len(s)) + s
    msg = msg + s
    msg += b'\0' * (444 - len(msg))  # FIXME not sure this math is right
    return msg


def serialize_flash_params(ic: FlashIcInfo):
    return pack('<LLxxBx', ic.size, ic.secror_size, ic.sector_erase_cmd)


def serialize_partition(p: PartitionInfo):
    b = pack('<BBHLL', p.id, p.type, p.access_lvl, p.offset, p.size)
    b = b + b'\0' * 4 + sha256(b).digest()
    return b


def partition_flash(info: FlashInfo, layout: typing.List[PartitionInfo], signature, client_public):
    logging.info('Detected Flash IC: %s, %d bytes' % (info.ic.name, info.ic.size))

    cmd = unhex('4f 0000 0000')
    cmd += with_hdr(0, serialize_flash_params(info.ic))
    cmd += with_hdr(1,
                    b''.join([serialize_partition(p) for p in layout]) + signature)
    cmd += with_hdr(5, make_cert(client_public))
    cmd += with_hdr(3, crt_hardcoded)
    rsp = tls.cmd(cmd)
    assert_status(rsp)
    rsp = rsp[2:]
    crt_len, rsp = rsp[:4], rsp[4:]
    crt_len, = unpack('<L', crt_len)
    tls.handle_cert(rsp[:crt_len])
    rsp = rsp[crt_len:]
    # ^ TODO - figure out what the rest of rsp means


def _is_cert_store_blank(data: bytes) -> bool:
    """Return True when the TLS cert-store partition has never been written.

    A blank cert store returns all 0xff bytes; parse_tls_flash() hits the
    0xffff block-ID terminator immediately and exits without setting ecdh_q.
    """
    return len(data) == 0 or data[:2] == b'\xff\xff'


def _repair_cert_store():
    """Repair the half-initialized state: partitions exist but cert store blank.

    This mirrors the bottom half of init_flash() (from partition_flash()
    onwards), bypassing the early-return guard.  The root cause is a previous
    init_flash() run that succeeded in creating the 5-partition layout but
    crashed before write_flash(1, 0, tls.make_tls_flash()) could persist
    the ECDH + private-key material.

    Flow:
      1. Generate a fresh EC key-pair for the client identity cert.
      2. Re-run partition_flash() to (re-)provision the device cert and get
         the device-side TLS cert back.  On already-partitioned devices this
         is idempotent — the firmware updates the cert but keeps the layout.
      3. Call cmd 0x50 to retrieve the device's ECDH public key (signed by
         the Synaptics firmware key; verified inside handle_ecdh).
      4. Open a TLS session, erase partition 1, write tls.make_tls_flash().
      5. Reboot the device (raises RebootException) so open_common() gets a
         clean start with the cert store now populated.
    """
    logging.warning('TLS cert store is blank — running cert-store repair')

    skey = ec.generate_private_key(ec.SECP256R1(), crypto_backend)
    snums = skey.private_numbers()
    client_private = snums.private_value
    client_public  = snums.public_numbers

    info = get_flash_info()

    is_b7 = (usb.usb_dev().idVendor == 0x06cb and usb.usb_dev().idProduct == 0x00b7)

    layout    = flash_layout_hardcoded
    signature = partition_signature
    if is_b7:
        layout    = flash_layout_d51
        signature = partition_signature_d51
    elif usb.usb_dev().idVendor == 0x138a and usb.usb_dev().idProduct == 0x0090:
        layout    = flash_layout_hardcoded_0090
        signature = partition_signature_0090

    try:
        partition_flash(info, layout, signature, client_public)
    except Exception as exc:
        raise Exception(
            'Cert-store repair: partition_flash() failed. '
            'The device may reject re-partitioning; manual re-provisioning '
            '(e.g. boot Windows + Synaptics driver) may be required.'
        ) from exc

    RomInfo.get()

    try:
        rsp = usb.cmd(unhex('50'))
        assert_status(rsp)
    finally:
        call_cleanups()

    rsp = rsp[2:]                          # strip 2-byte status
    l, = unpack('<L', rsp[:4])
    if len(rsp) != l:
        raise Exception(
            'Cert-store repair: ECDH response length mismatch (got %d expected %d)' % (len(rsp), l)
        )
    zeroes, ecdh_data = rsp[4:-400], rsp[-400:]
    if zeroes != b'\0' * len(zeroes):
        raise Exception('Cert-store repair: unexpected non-zero prefix in ECDH response')

    tls.handle_ecdh(ecdh_data)
    tls.handle_priv(encrypt_key(client_private, client_public))

    # Open TLS session — needed to write to the cert-store partition.
    tls.open()

    erase_flash(1)
    _write_cert_store()

    logging.info('Cert-store repair: key material persisted. Rebooting device…')
    reboot()   # raises RebootException; service exits, udev restarts it cleanly


def init_flash():
    info = get_flash_info()

    if len(info.partitions) > 0:
        logging.info('Flash has %d partitions.' % len(info.partitions))
        # Detect half-initialized state: partitions created but cert store
        # never written (crash between partition_flash() and write_flash()).
        if _is_cert_store_blank(read_tls_flash()):
            _repair_cert_store()  # raises RebootException on success
        return
    else:
        logging.info('Flash was not initialized yet. Formatting...')

    # Skip reset command on 0xd51 sensor type (06cb:00b7)
    # as it is not supported and throws 0x0404.
    is_b7 = (usb.usb_dev().idVendor == 0x06cb and usb.usb_dev().idProduct == 0x00b7)
    if not is_b7:
        assert_status(usb.cmd(reset_blob))

    skey = ec.generate_private_key(ec.SECP256R1(), crypto_backend)
    snums = skey.private_numbers()
    client_private = snums.private_value
    client_public = snums.public_numbers

    layout = flash_layout_hardcoded
    signature = partition_signature

    if is_b7:
        layout = flash_layout_d51
        signature = partition_signature_d51
    elif usb.usb_dev().idVendor == 0x138a:
        if usb.usb_dev().idProduct == 0x0090:
            layout = flash_layout_hardcoded_0090
            signature = partition_signature_0090

    partition_flash(info, layout, signature, client_public)

    RomInfo.get()
    # ^ TODO: use the firmware version which to lookup pubkey for server cert validation

    try:
        rsp = usb.cmd(unhex('50'))
        assert_status(rsp)
    finally:
        call_cleanups()

    rsp = rsp[2:]
    l, = unpack('<L', rsp[:4])

    if len(rsp) != l:
        raise Exception('Length mismatch')

    zeroes, rsp = rsp[4:-400], rsp[-400:]

    if zeroes != b'\0' * len(zeroes):
        raise Exception('Expected zeroes')

    tls.handle_ecdh(rsp)
    tls.handle_priv(encrypt_key(client_private, client_public))
    tls.open()

    # Wipe newly created partitions clean
    if is_b7:
        erase_flash(1)
        erase_flash(2)
        erase_flash(6)
        erase_flash(3)
        erase_flash(4)
    else:
        erase_flash(1)
        erase_flash(2)
        erase_flash(5)
        erase_flash(6)
        erase_flash(4)

    # Persist certs and keys on cert partition.
    _write_cert_store()

    # Reboot.
    # The device will disconnect and our service will be started by udev as soon as it is connected again.
    reboot()
