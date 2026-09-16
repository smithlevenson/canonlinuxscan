# Canon imageFORMULA R10 Linux reverse engineering notes

This repository documents a Linux reverse-engineering effort for the Canon imageFORMULA R10.

## Current hardware / USB model

- USB VID/PID: `1083:167f`
- The device exposes USB Mass Storage, not a USB scanner-class interface.
- The Windows-compatible LUN contains `TRANSFER.DAT` and `INDATA.DAT` mailboxes.
- The Mac LUN must not be written.
- The Windows/mailbox LUN is selected dynamically from USB ancestry plus mailbox identity; do not hard-code `/dev/sdX`.

## Mailbox layout

Windows FAT geometry observed on the R10:

- sector size: 512 bytes
- `TRANSFER.DAT` disk offset: `0x96a00`
- `INDATA.DAT` disk offset: `0x296a00`
- both files are contiguous and 2 MiB

`TRANSFER.DAT`:

- `+0x00`: 24-byte Type-1 command packet
- `+0x18`: 4-byte status field
- `+0x1c`: variable Type-2 packet

Canonical Type-1 wrapper:

```text
00 00 00 14 00 01 90 00 00 00 00 00 <CDB...>
```

For normal waiting Type-1 operations the native driver writes the command, writes `FF FF FF FF` to status, then polls until firmware changes the status value.

Mounted filesystem reads can remain stale after firmware updates the mailbox. The Linux implementation therefore uses direct block I/O and preserves surrounding sector bytes for partial-sector writes.

## Safety rules

The current executable intentionally blocks configuration and motion opcodes. There is no force/unsafe bypass.

Blocked execution opcodes include:

- `0x15`
- `0x1b` SCAN
- `0x24` SET WINDOW
- `0x2a`
- `0x31` OBJECT POSITION
- `0xd6` DEFINE SCAN MODE
- `0xe1` SET ADJUST DATA

Private Canon CDBs such as `0x3b` are mailbox payloads. Do not send them directly with SG_IO.

## Safe protocol recovered so far

Known safe commands:

- INQUIRY: `12 00 00 00 40 00`
- TEST UNIT READY: six zero bytes
- REQUEST SENSE: `03 00 00 00 0e 00`
- INQUIRY EX: `12 01 f0 00 30 00`
- StartScan state read: `28 00 8c 00 00 00 00 00 80 00`

Observed firmware/inquiry revision: `2.02`.

## Default profile reconstruction

The R10 capability tables from the bundled Mac driver establish:

- default X/Y resolution: 200 DPI (`0x1118` / `0x1119`)
- selected paper ID: 9 = LETTER
- LETTER dimensions: 10200 x 13200 in the driver's internal 1200-units-per-inch coordinate system
- capability `0x80c9` defaults to 1 and is copied to `tagScanParam+0x8a4`

For the normal default builder, `tagScanParam+0x89c` remains zero, so StartScan does not force 300 DPI.

StartScan computes `scanner+0xe90` from INQUIRY EX:

```text
e90 = floor((field_at_0x14 * 1200) / field_at_0x00)
```

For the observed INQUIRY EX response this gives:

```text
e90 = 3448 = 0x00000d78
```

With `+0x8a4 = 1`, StartScan deliberately replaces X extent with `-472` and adds 944 to the Y extent. This is native-driver behavior, not a guessed correction.

The resulting default normal scan window is therefore:

```text
window ids : 0, then 1
xres       : 200
yres       : 200
xpos       : 0
xextent    : -472 = 0xfffffe28
ypos       : 3448 = 0x00000d78
yextent    : 13200 + 944 = 14144 = 0x00003740
image mode : 5
bits       : 8
```

The two SetWindow Type-2 packets differ only at byte offset `0x14` (window ID).

## SetWindow Type-2 layout

```text
+00  BE32 0x3c
+04  00 02 b0 00
+08  4 zero bytes
+0c  BE16 0x002c
+14  window id
+15  zero
+16  x resolution BE16
+18  y resolution BE16
+1a  x position BE32
+1e  x extent BE32
+22  y position BE32
+26  y extent BE32
+2a  three zero bytes
+2d  image mode
+2e  bits
+2f  two zero bytes
+31  0x10
+32..3f zero
```

Default SetWindow #0 Type-2 body:

```text
0000: 00 00 00 3c 00 02 b0 00 00 00 00 00 00 2c 00 00
0010: 00 00 00 00 00 00 00 c8 00 c8 00 00 00 00 ff ff
0020: fe 28 00 00 0d 78 00 00 37 40 00 00 00 05 08 00
0030: 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

Default SetWindow #1 is identical except byte `0x14 = 01`.

## Calibration / AdjustLight

The structure and much of the control flow are recovered, but active calibration still contains unresolved profile/session values. The cache path can read 512 KiB beginning at scanner memory address `0x10080000` using mailbox `0x3b` GetMemory commands in chunks up to `0x2000` bytes.

Do not transmit active calibration commands until the remaining AdjustLight inputs are decoded or the native cache path is proven valid for the session.

## Current milestone

`v0.5` is intended to:

1. run only the already-safe live initialization commands;
2. derive runtime values such as `e90` from the actual INQUIRY EX response;
3. compile the native default 200-DPI Letter StartScan configuration into an exact dry-run transcript;
4. keep all configuration, calibration, positioning, scan and Type-2 transmissions physically disabled.
