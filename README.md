# Qualcomm QPIC NAND Recovery Toolkit

Tools for recovering data from raw chip-off dumps of NAND flash that was
written by a Qualcomm QPIC NAND controller. Tested on a Cisco Meraki MR33
access point (IPQ4029 SoC, S34ML01G 1Gbit SLC NAND, 2K+64 page) but should
work on any Qualcomm SoC using QPIC with BCH-4 ECC.

## ⚠️ Disclaimer

This toolkit was developed collaboratively with an AI assistant (Anthropic's
Claude). While it has been validated against a known reference implementation
(`qcom-nandc-pagify`) via a full-scale byte-perfect roundtrip test, and used
successfully against a real-world chip-off recovery, it has not been
independently reviewed or audited.

## Why these tools exist

When you read a NAND chip with a hardware programmer (XGecu, ProMan, etc.)
you get the raw page contents including the OOB (out-of-band) spare area.
The Qualcomm controller doesn't lay data out the way generic NAND tools
expect:

* User data is interleaved with bad-block-marker bytes mid-codeword
* ECC parity is intermixed with data inside each codeword
* The last codeword of each page is short
* UBIFS uses CRC32 with a different init value than UBI EC/VID headers

binwalk, ubireader, and similar tools assume a "clean" 2K (or 4K) page with
contiguous user data. Hand them a QPIC dump and they fail in confusing ways.

This toolkit bridges the gap.

## Pipeline
chip dump (with OOB)
│
▼
[ qcom_nand_extract.py ]      ← inverts QPIC interleaving, applies BCH-4 ECC
│
▼
flat logical image            ← suitable for binwalk -e or manual UBI carving
│
▼
[ carve UBI region, split per-volume ]   (~30 lines of Python, see below)
│
▼
per-volume images
│
├─ FIT firmware images   →  dumpimage -p 0 → kernel zImage
│                          dumpimage -p 1 → ramdisk (xz/cpio)
│
└─ UBIFS volumes         →  ubireader_extract_files          (works for dense)
extract_ubifs.py                  (works for sparse)

## Tools

### `qcom_nand_extract.py`

Reads a raw NAND dump (including OOB), strips ECC/BBM/padding bytes,
applies BCH-4 correction, and writes a flat logical image.
pip install --user --break-system-packages bchlib
python3 qcom_nand_extract.py dump_with_oob.bin reconstructed.bin

The output is a normal NAND image with no OOB; you can binwalk it directly,
or carve UBI volumes from it manually.

### `extract_ubifs.py`

Walks UBIFS nodes in a volume image directly, without going through the
on-disk index. This handles sparse storage volumes (where many LEBs are
unused) that crash ubireader's index walker.
pip install --user --break-system-packages python-lzo
python3 extract_ubifs.py storage_volume.bin output_dir/

### `extract_ubifs_tar.py`

Same as `extract_ubifs.py` but emits a tar archive that preserves UNIX
permissions, ownership, mtime, and symlink targets. Recommended when you
need to send the extracted filesystem somewhere.
python3 extract_ubifs_tar.py storage_volume.bin storage.tar

## Carving UBI volumes

After running `qcom_nand_extract.py`, the UBI region typically starts at a
recognizable offset (look for the `UBI#` magic). Each PEB is 128 KiB, with
4 KiB of UBI metadata (EC + VID header) at the start of each one followed
by 124 KiB of LEB data. Volumes are reconstructed by concatenating their
LEBs in `lnum` order:

```python
import struct
PEB_SIZE = 131072
DATA_OFFSET = 4096
LEB_SIZE = PEB_SIZE - DATA_OFFSET

d = open('reconstructed.bin','rb').read()
# Find UBI region start
ubi_start = d.find(b'UBI#')
d = d[ubi_start:]

volumes = {}
for peb in range(len(d) // PEB_SIZE):
    base = peb * PEB_SIZE
    if d[base:base+4] != b'UBI#': continue
    if d[base+2048:base+2052] != b'UBI!': continue
    vh = d[base+2048:base+2048+64]
    vol_id = struct.unpack('>I', vh[8:12])[0]
    lnum = struct.unpack('>I', vh[12:16])[0]
    if vol_id > 0x7fffefff: continue   # skip UBI internal volumes
    volumes.setdefault(vol_id, {})[lnum] = peb

for vol_id, lebs in volumes.items():
    # For dynamic volumes (UBIFS), use sparse layout: place each LEB at its
    # logical position with FF padding for missing LEBs. For static volumes,
    # concatenation in lnum order works.
    out = bytearray()
    for lnum in sorted(lebs):
        peb = lebs[lnum]
        base = peb * PEB_SIZE
        out += d[base + DATA_OFFSET : base + DATA_OFFSET + LEB_SIZE]
    open(f'vol_{vol_id}.bin', 'wb').write(bytes(out))
```

## References

* `qcom-nandc-pagify` (PyPI) - the encode-side reference; this toolkit is
  its inverse, and we cross-validated by encoding pseudorandom data with
  pagify and roundtripping through `qcom_nand_extract.py`.
* `drivers/mtd/nand/raw/qcom_nandc.c` in the Linux kernel - authoritative
  source for QPIC controller layout.
* `fs/ubifs/ubifs-media.h` in the Linux kernel - UBIFS on-disk structures.
* `ubireader` (PyPI) - works great for dense UBIFS volumes; falls over on
  sparse ones, which is why `extract_ubifs.py` exists.
