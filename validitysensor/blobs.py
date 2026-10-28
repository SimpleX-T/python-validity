def __load_blob(blob: str) -> bytes:
    from .usb import usb

    if usb.usb_dev().idVendor == 0x138a:
        if usb.usb_dev().idProduct == 0x0090:
            from . import blobs_90 as blobs
        elif usb.usb_dev().idProduct == 0x0097:
            from . import blobs_97 as blobs
        elif usb.usb_dev().idProduct == 0x009d:
            from . import blobs_9d as blobs
        elif usb.usb_dev().idProduct == 0x00ab:
            from . import blobs_d51 as blobs  # HP EliteBook 840 G5; d51 reset family
    elif usb.usb_dev().idVendor == 0x06cb:
        if usb.usb_dev().idProduct == 0x009a:
            from . import blobs_9a as blobs
        elif usb.usb_dev().idProduct == 0x00b7:
            # The 138a:00ab reset payload has not been validated on this
            # 0x969 variant. Keep the established non-destructive init blobs
            # until a complete 06cb:00b7 Windows provisioning capture exists.
            from . import blobs_9a as blobs
        elif usb.usb_dev().idProduct == 0x00cb:
            from . import blobs_00cb as blobs   # HP Pavilion x360 14-dh; 0x969, own reset_blob
        elif usb.usb_dev().idProduct == 0x00bb:
            # HP Spectre x360 13-ap0xxx: same 0x969 silicon (hw id 0x88,
            # "57K0 FM-3439-004", W25Q80B) as 06cb:00cb.  Verified on hardware:
            # init_hardcoded is byte-identical to our Windows capture, and the
            # 11973-byte 0x969 reset_blob (== blobs_d51) is accepted and wipes
            # the flash.  See uunicorn/python-validity#283.
            from . import blobs_00cb as blobs

    globals()[blob] = getattr(blobs, blob)
    return globals()[blob]


init_hardcoded = lambda: __load_blob('init_hardcoded')
init_hardcoded_clean_slate = lambda: __load_blob('init_hardcoded_clean_slate')
reset_blob = lambda: __load_blob('reset_blob')
db_write_enable = lambda: __load_blob('db_write_enable')
