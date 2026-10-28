# Firmware is not redistributed here

`06cb:00bb` needs the HP xpfwext payload named `6_07f_hp_mis_qm.xpfwext` for a
factory-reset or wiped sensor. That file is proprietary HP firmware, so it is
**not** part of this repository.

You do not have to fetch it by hand: `tools/flash00bb.py` and
`validity-sensors-firmware` download the pinned HP SoftPaq **SP138431**
(`sp138431.exe`, SHA512
`b9a268773ac948a4b6bfaa7a5762c58ab482aa47ea321a429ebc8dba3fcdd17ffe750d189791d8e0325b21e95161db5f751c61d7714d7460ee0a406055060a8f`),
verify that hash, and extract `6_07f_hp_mis_qm.xpfwext` with `cabextract`.
The file is cached outside the repo, in
`/var/lib/python-validity/firmware/`.

`--phase preflight` caches the firmware **before** anything is wiped, so a
wiped sensor can always be re-provisioned offline from that cache.

If your region uses a different SoftPaq, pass it explicitly:

```bash
sudo python3 tools/flash00bb.py --softpaq /path/to/spXXXXXX.exe --phase preflight
```

Joentja's original report for this machine used SP106161, which carries the
same payload. A firmware signature mismatch (`044f`) usually means the wrong
SoftPaq for your region.

See `../README.md` for the full procedure.
