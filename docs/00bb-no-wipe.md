# Reusing an existing Windows Hello pairing (no wipe)

This is the long version of the "No-wipe path" section in `../README.md`.
Everything here is read-only with respect to the sensor; the only writes are
dump files under `/tmp/opencode/`.

## Why it can work at all

`checkpair.py` reports `PAIRED_TO_OTHER_HOST` when the pairing blob in
partition 1 (the cert-store) is encrypted with a different host secret than
the DMI default. That does **not** mean the pairing is unusable: Windows also
encrypted it with *some* machine-derived secret, so the pairing is potentially
recoverable if that secret can be found offline.

Only one pairing slot exists on the sensor. Finding the Windows key means Linux
and Windows Hello can share the pairing instead of replacing it.

## Candidate sources

```bash
# offline: brute-force plausible host keys against the cert-store HMAC
sudo python3 tools/hwkey_probe.py                    # DMI candidates
sudo bash tools/find_windows_guid.sh                 # read-only NTFS mount
sudo python3 tools/hwkey_probe.py --guid-file /tmp/opencode/windows-machine-guid.reg
sudo bash tools/dump_windows_pairing.sh              # driver's Pairing* values
sudo python3 tools/hwkey_probe.py --raw-file /tmp/opencode/windows-pairing.txt
sudo python3 tools/hwkey_probe.py --read-part4       # sensor's own record
```

`find_windows_guid.sh` needs no packages beyond `python3`; it parses the
SOFTWARE hive itself with `tools/scan_hive.py`. The HP driver DLL
(`synaWudfBioUsb116SGX.dll` from SP138431) reads
`HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid`, so that value is worth
trying — but on the reference machine it did **not** reproduce the pairing
HMAC.

If the Windows partition cannot be mounted (BitLocker / hibernated Windows),
boot Windows once and run:

```
reg query HKLM\SOFTWARE\Microsoft\Cryptography /v MachineGuid
```

then pass the value with `--machine-guid`.

`dump_windows_pairing.sh` is the same idea for the Synaptics driver state: the
UMDF driver keeps `PairingData`, `PairingContext` and `UnpairingContext` in the
device's registry key (`HKLM\SYSTEM\...\Enum\USB\VID_06CB&PID_00BB\...`), plus
`fwextId` and `MachineGuid` in SOFTWARE. The script mounts read-only, reads
those five values with `scan_hive.py` (one pass per hive), and writes
`Name=hex` lines to `/tmp/opencode/windows-pairing.txt` (mode 0600); string
values (`REG_SZ`) appear as `Name=text`.

`hwkey_probe.py --raw-file` then tries the whole value, its first/last 32
bytes, and every 32-byte window inside it — and string values as both ASCII and
UTF-16LE. If `PairingData` is the 32-byte key Windows used, this finds it in
seconds.

The same run also writes `/tmp/opencode/windows-pairing-names.txt`, a survey of
every value name matching `pair|gwk|fwext|validity|synaptics|hostkey`
(`scan_hive.py --list-names`). If none of the dumped values matches, that list
shows whether the driver uses a different name. Re-run the dump with
`--name <Name>` (repeatable) to add such a value to the dump — its size and, if
printable, its text are shown, and its bytes become candidates:

```bash
sudo bash tools/dump_windows_pairing.sh --name Synaptics_01 --name AppPairingId
sudo python3 tools/hwkey_probe.py --raw-file /tmp/opencode/windows-pairing.txt
```

## Using a recovered key

`hwkey_probe.py` is read-only and offline by default. If it prints
`MATCH FOUND`, verify the live sensor without writing anything:

```bash
sudo PYTHON_VALIDITY_HW_KEY=<hex from the report> python3 tools/checkpair.py
```

If that says `ALREADY_PAIRED`, install the driver as usual and make the
override persistent with a systemd drop-in:

```bash
sudo systemctl edit python3-validity.service
# in the editor:
[Service]
Environment=PYTHON_VALIDITY_HW_KEY=<hex from the report>

sudo systemctl daemon-reload
sudo systemctl restart python3-validity.service
```

Status then: Linux works, **and** Windows Hello keeps working, because the
pairing is only reused, never replaced. Only one pairing still exists, so this
is sharing, not duplicating.

## What was ruled out on the reference machine

Reference unit: HP Spectre x360 13-ap0xxx, `06cb:00bb`, sensor
`57K0 FM-3439-004`. If no candidate matches, the secret is probably TPM-sealed
and not derivable from Linux; the wipe in `../README.md` is then the only
option. Ruled out:

- DMI values (`product_name`, `product_serial`, board/BIOS strings) — 17 forms.
- Windows `MachineGuid` as ASCII, UTF-16LE and GUID text.
- Sensor partition 4, all 335872 bytes (1 GUID, 3 strings, every 32-byte
  window).
- The driver's own registry state: `PairingData`, `PairingContext`,
  `UnpairingContext` and `fwextId` are **absent**; only `MachineGuid` exists.
- `Synaptics_01` and `AppPairingId` from the name survey — the former is the
  HID match pattern `HID\VID_06CB&PID_*` (one copy per key), the latter a
  16-byte app-pairing token.
- Every full registry dump of those values fed back as raw candidate bytes.

A key that survives all of that is not stored in anything Linux can read —
TPM-sealed to Windows, or held by the sensor in a slot the host key unlocks.

## Background

- Recipe for this exact machine:
  <https://github.com/uunicorn/python-validity/issues/283>
- Clean-slate / d51 background:
  <https://github.com/uunicorn/python-validity/pull/256>
