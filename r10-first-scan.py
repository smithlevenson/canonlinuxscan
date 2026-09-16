#!/usr/bin/env python3

import argparse
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

VERSION = "0.4.1"

SECTOR_SIZE = 512
TRANSFER_DISK_OFFSET = 0x96A00
INDATA_DISK_OFFSET   = 0x296A00
TRANSFER_SECTOR      = TRANSFER_DISK_OFFSET // SECTOR_SIZE

STATUS_OFFSET   = 0x18
IDENTITY_OFFSET = 0x1C

# ===========================================================================
# HARD EXECUTION INTERLOCKS
# ===========================================================================

BLOCKED_EXECUTION_OPCODES = {
    0x1B: "SCAN",
    0x24: "SET WINDOW",
    0x31: "OBJECT POSITION",
    0xD6: "DEFINE SCAN MODE",
    0xE1: "SET ADJUST DATA",
}

TYPE1_NO_WAIT = {
    0x15,
    0x1B,
    0x24,
    0x2A,
    0xD6,
    0xE1,
}

# ExecRead tables recovered from R10Lite.
READ_TABLE_BYTE2 = [
    0x00, 0x80, 0x80, 0x80,
    0x84, 0x8B, 0x8C, 0x8C,
    0xA1, 0x91, 0x91, 0x91,
    0x91, 0x91, 0x91, 0x91,
]

READ_TABLE_BYTES45 = [
    bytes.fromhex(x) for x in [
        "0000", "0000", "0004", "0001",
        "0000", "0000", "0000", "0001",
        "0000", "0700", "0900", "0a00",
        "0c00", "2300", "2500", "2600",
    ]
]


# ===========================================================================
# BASIC HELPERS
# ===========================================================================

def die(msg):
    print(f"\nERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def hexline(data):
    return " ".join(f"{b:02x}" for b in data)


def hexdump(data, base=0, indent="  "):
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        h = " ".join(f"{b:02x}" for b in chunk)
        a = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        print(f"{indent}{base + off:04x}: {h:<47}  {a}")


def be16(value):
    return int(value).to_bytes(2, "big")


def be24(value):
    if not 0 <= value <= 0xFFFFFF:
        raise ValueError("value does not fit in 24 bits")
    return bytes([
        (value >> 16) & 0xFF,
        (value >> 8) & 0xFF,
        value & 0xFF,
    ])


def be32(value):
    return int(value).to_bytes(4, "big")


# ===========================================================================
# DIRECT BLOCK I/O
# ===========================================================================

def direct_read_sector(device, sector):
    p = subprocess.run(
        [
            "dd",
            f"if={device}",
            "bs=512",
            f"skip={sector}",
            "count=1",
            "iflag=direct",
            "status=none",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    if p.returncode != 0:
        die(
            f"Direct read failed on {device} sector {sector}: "
            f"{p.stderr.decode(errors='replace')}"
        )

    if len(p.stdout) != SECTOR_SIZE:
        die(
            f"Short direct read on {device} sector {sector}: "
            f"{len(p.stdout)} bytes"
        )

    return p.stdout


def direct_write_sector(device, sector, data):
    if len(data) != SECTOR_SIZE:
        die("Internal error: sector write must be exactly 512 bytes")

    with tempfile.NamedTemporaryFile(delete=False) as f:
        temp = f.name
        f.write(data)
        f.flush()
        os.fsync(f.fileno())

    try:
        p = subprocess.run(
            [
                "dd",
                f"if={temp}",
                f"of={device}",
                "bs=512",
                f"seek={sector}",
                "count=1",
                "oflag=direct",
                "conv=notrunc,fsync",
                "status=none",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        if p.returncode != 0:
            die(
                f"Direct write failed on {device} sector {sector}: "
                f"{p.stderr.decode(errors='replace')}"
            )
    finally:
        try:
            os.unlink(temp)
        except FileNotFoundError:
            pass


def direct_read_bytes(device, absolute_offset, length):
    result = bytearray()

    while length:
        sector = absolute_offset // SECTOR_SIZE
        inside = absolute_offset % SECTOR_SIZE

        block = direct_read_sector(device, sector)
        take = min(length, SECTOR_SIZE - inside)

        result.extend(block[inside:inside + take])

        absolute_offset += take
        length -= take

    return bytes(result)


def patch_sector(device, absolute_offset, payload):
    if not payload:
        return

    first_sector = absolute_offset // SECTOR_SIZE
    last_sector = (absolute_offset + len(payload) - 1) // SECTOR_SIZE

    if first_sector != last_sector:
        die("Internal error: patch_sector crosses sector boundary")

    inside = absolute_offset % SECTOR_SIZE

    block = bytearray(direct_read_sector(device, first_sector))
    block[inside:inside + len(payload)] = payload

    direct_write_sector(device, first_sector, bytes(block))


# ===========================================================================
# R10 DISCOVERY
# ===========================================================================

def usb_parent_has_r10(block_name):
    p = Path("/sys/class/block") / block_name / "device"

    try:
        p = p.resolve()
    except Exception:
        return False

    for parent in [p] + list(p.parents):
        vid = parent / "idVendor"
        pid = parent / "idProduct"

        if vid.exists() and pid.exists():
            try:
                if (
                    vid.read_text().strip().lower() == "1083"
                    and pid.read_text().strip().lower() == "167f"
                ):
                    return True
            except OSError:
                pass

    return False


def find_r10_luns():
    result = []

    for entry in sorted(Path("/sys/class/block").glob("sd*")):
        name = entry.name

        if any(c.isdigit() for c in name):
            continue

        if usb_parent_has_r10(name):
            result.append(f"/dev/{name}")

    return result


def read_identity(device):
    block = direct_read_sector(device, TRANSFER_SECTOR)

    start = (
        TRANSFER_DISK_OFFSET % SECTOR_SIZE
    ) + IDENTITY_OFFSET

    return block[start:start + 64]


def is_mailbox_lun(device):
    try:
        ident = read_identity(device)
    except Exception:
        return False

    return (
        ident.startswith(b"CANON   ")
        and ident[8:24].rstrip(b" \x00") == b"R10"
    )


def find_mailbox_lun():
    luns = find_r10_luns()

    if not luns:
        die("No Canon R10 USB LUNs detected")

    print("R10 USB LUNs detected: " + ", ".join(luns))

    candidates = [d for d in luns if is_mailbox_lun(d)]

    if len(candidates) != 1:
        die(
            "Could not uniquely identify Canon mailbox LUN. "
            f"Candidates: {candidates}"
        )

    print(f"Mailbox LUN selected: {candidates[0]}")
    return candidates[0]


def device_is_mounted(device):
    real = os.path.realpath(device)

    with open("/proc/mounts", "r", encoding="utf-8") as f:
        for line in f:
            source = os.path.realpath(line.split()[0])

            if source == real:
                return True

            if source.startswith(real) and source[len(real):].isdigit():
                return True

    return False


# ===========================================================================
# TRANSACTION REPRESENTATION
# ===========================================================================

@dataclass
class Transaction:
    name: str
    type1: Optional[bytes] = None
    type2: Optional[bytes] = None
    note: str = ""
    proven: bool = True


def make_type1(cdb):
    if len(cdb) > 12:
        raise ValueError("TYPE-1 CDB too large")

    packet = bytearray(24)

    packet[0:12] = bytes.fromhex(
        "00 00 00 14 00 01 90 00 00 00 00 00"
    )

    packet[12:12 + len(cdb)] = cdb

    return bytes(packet)


# ===========================================================================
# SAFE CDB COMPILERS
# ===========================================================================

def cdb_inquiry():
    return bytes.fromhex("12 00 00 00 40 00")


def cdb_tur():
    return bytes.fromhex("00 00 00 00 00 00")


def cdb_request_sense():
    return bytes.fromhex("03 00 00 00 0e 00")


def cdb_inquiry_ex():
    return bytes.fromhex("12 01 f0 00 30 00")


def cdb_exec_read(read_type, requested_length):
    if not 0 <= read_type <= 15:
        raise ValueError("ExecRead type must be 0..15")

    if not 0 <= requested_length <= 0xFFFFFF:
        raise ValueError("ExecRead length exceeds 24-bit field")

    cdb = bytearray(10)

    cdb[0] = 0x28
    cdb[2] = READ_TABLE_BYTE2[read_type]

    pair = READ_TABLE_BYTES45[read_type]

    cdb[4] = pair[0]
    cdb[5] = pair[1]
    cdb[6:9] = be24(requested_length)

    return bytes(cdb)


def cdb_object_position(position):
    mapping = {
        0: 0x00,
        1: 0x01,
        2: 0x04,
    }

    if position not in mapping:
        raise ValueError("ObjectPosition must be 0, 1 or 2")

    cdb = bytearray(10)
    cdb[0] = 0x31
    cdb[1] = mapping[position]

    return bytes(cdb)


def cdb_get_memory(address, length):
    if not 0 <= length <= 0x2000:
        raise ValueError("GetMemory chunk must be <= 0x2000")

    cdb = bytearray(10)

    cdb[0] = 0x3B
    cdb[2:6] = be32(address)
    cdb[6] = 0
    cdb[7:9] = be16(length)

    return bytes(cdb)


# ===========================================================================
# EXACT SET WINDOW SERIALIZER
# ===========================================================================

@dataclass
class ScanWindow:
    window_id: int
    x_resolution: int
    y_resolution: int
    x_position: int
    x_extent: int
    y_position: int
    y_extent: int
    image_mode: int
    bits_per_pixel: int


def compile_set_window(w, provenance=""):
    """
    Exact packet layout recovered from CCanoDR::ExecSetWindow.

    TYPE-1:
        opcode 24
        CDB byte 8 = 34

    TYPE-2:
        64 bytes total
        +00  BE32 0x3c
        +04  00 02 b0 00
        +08  four zero bytes
        +0c  BE16 0x002c
        +14  window id
        +16  X resolution BE16
        +18  Y resolution BE16
        +1a  X position BE32
        +1e  X extent BE32
        +22  Y position BE32
        +26  Y extent BE32
        +2d  image mode
        +2e  bits/pixel
        +31  constant 10
    """

    cdb = bytearray(10)
    cdb[0] = 0x24
    cdb[8] = 0x34

    p = bytearray(64)

    p[0:8] = bytes.fromhex(
        "00 00 00 3c 00 02 b0 00"
    )

    p[12:14] = be16(0x2C)

    p[20] = w.window_id & 0xFF

    p[22:24] = be16(w.x_resolution)
    p[24:26] = be16(w.y_resolution)

    p[26:30] = be32(w.x_position)
    p[30:34] = be32(w.x_extent)
    p[34:38] = be32(w.y_position)
    p[38:42] = be32(w.y_extent)

    p[45] = w.image_mode & 0xFF
    p[46] = w.bits_per_pixel & 0xFF

    p[49] = 0x10

    return Transaction(
        name=f"SET WINDOW {w.window_id}",
        type1=make_type1(bytes(cdb)),
        type2=bytes(p),
        note=provenance,
        proven=True,
    )


# ===========================================================================
# EXACT DEFINE SCAN MODE SERIALIZER
# ===========================================================================

@dataclass
class ScanModeParam:
    mode_type: int

    # Input structure fields used by R10Lite.
    p4: int = 0
    p5: int = 0
    p6: int = 0
    p7: int = 0
    p8: int = 0
    p10: int = 0


def compile_define_scan_mode(m, provenance=""):
    """
    Exact serialization recovered from CCanoDR::ExecDefineScanMode.

    TYPE-1 CDB:
        d6 10 00 00 14 00 00 00 00 00

    TYPE-2:
        32 bytes total
        +00  00 00 00 1c
        +04  00 02 b0 00
        +08..0b zero
        +0c onward mode-specific 20-byte parameter area
    """

    cdb = bytes.fromhex(
        "d6 10 00 00 14 00 00 00 00 00"
    )

    p = bytearray(32)

    p[0:8] = bytes.fromhex(
        "00 00 00 1c 00 02 b0 00"
    )

    if m.mode_type == 0:
        # Native driver stores 0x0e30 as LE host word -> bytes 30 0e.
        p[12:14] = bytes.fromhex("30 0e")

        # ExecDefineScanMode:
        #   if p4 != 0: base 05
        #   else:       base 04
        #
        #   p5 controls whether that value is written at +0f.
        #   p6 adds +11 = 10.
        derived = 0x05 if m.p4 else 0x04

        # Native behavior:
        #   p4=0, p5=0 -> +0x0f = 0
        #   p4=1, p5=0 -> +0x0f = 1
        #   p4=0, p5=1 -> +0x0f = 4
        #   p4=1, p5=1 -> +0x0f = 5
        if m.p4:
            p[15] = 0x01

        if m.p5:
            p[15] = derived

        if m.p6:
            p[17] = 0x10

    elif m.mode_type == 1:
        p[12:14] = bytes.fromhex("32 0e")

        p[14] = m.p4 & 0xFF
        p[15] = 0x01

        flags = 0

        if m.p5:
            flags |= 0x40

        if m.p6:
            flags |= 0x20

        if m.p10:
            flags |= 0x08

        p[18] = flags
        p[20:22] = be16(m.p8)

    elif m.mode_type == 2:
        p[12:14] = bytes.fromhex("36 0e")

        p[19] = m.p4 & 0xFF
        p[20] = m.p5 & 0xFF
        p[21] = m.p6 & 0xFF
        p[22] = m.p7 & 0xFF

    else:
        raise ValueError("DefineScanMode type must be 0, 1 or 2")

    return Transaction(
        name=f"DEFINE SCAN MODE {m.mode_type}",
        type1=make_type1(cdb),
        type2=bytes(p),
        note=provenance,
        proven=True,
    )


# ===========================================================================
# EXACT SCAN SERIALIZER
# ===========================================================================

def compile_scan(selectors, provenance=""):
    if not selectors:
        raise ValueError("SCAN requires selector")

    n = len(selectors)

    cdb = bytearray(10)
    cdb[0] = 0x1B
    cdb[4] = 1 if n <= 1 else 2

    p = bytearray(n + 12)

    p[0:4] = be32(8 + n)
    p[4:8] = bytes.fromhex("00 02 b0 00")
    p[8:8 + n] = bytes(selectors)

    return Transaction(
        name="SCAN",
        type1=make_type1(bytes(cdb)),
        type2=bytes(p),
        note=(
            f"selectors={hexline(bytes(selectors))}; "
            + provenance
        ),
        proven=True,
    )


# ===========================================================================
# SET ADJUST DATA
# ===========================================================================

def compile_set_adjust_data_unresolved():
    cdb = bytearray(10)
    cdb[0] = 0xE1

    p = bytearray(52)

    p[0:8] = bytes.fromhex(
        "00 00 00 30 00 02 b0 00"
    )

    return Transaction(
        name="SET ADJUST DATA",
        type1=make_type1(bytes(cdb)),
        type2=bytes(p),
        note=(
            "UNRESOLVED PROFILE DATA: the two SAdjustInfo values "
            "have not yet been reconstructed. Zero payload is a "
            "compiler placeholder and MUST NOT be transmitted."
        ),
        proven=False,
    )


# ===========================================================================
# GET MEMORY COMPILER
# ===========================================================================

def compile_get_memory(address, total_length):
    tx = []

    remaining = total_length
    current = address
    index = 0

    while remaining:
        chunk = min(remaining, 0x2000)

        tx.append(
            Transaction(
                name=f"GET MEMORY [{index:02d}]",
                type1=make_type1(
                    cdb_get_memory(current, chunk)
                ),
                note=(
                    f"address=0x{current:08x}, "
                    f"length=0x{chunk:04x}"
                ),
            )
        )

        current += chunk
        remaining -= chunk
        index += 1

    return tx


# ===========================================================================
# TARGET PROFILE
# ===========================================================================

@dataclass
class TargetProfile:
    resolution: int = 300
    simplex: bool = True
    color: bool = True
    one_sheet: bool = True


def compile_target_profile(state_value):
    profile = TargetProfile()

    tx = []

    tx.append(
        Transaction(
            name="PROFILE",
            note=(
                "TARGET: 300 DPI / SIMPLEX / COLOR / ONE SHEET. "
                "This describes intent, not proof of every tagScanParam byte."
            ),
            proven=False,
        )
    )

    tx.append(
        Transaction(
            name="STARTSCAN STATE READ",
            type1=make_type1(
                cdb_exec_read(6, 0x80)
            ),
            note=(
                f"PROVEN command. Current first state dword "
                f"0x{state_value:08x}."
            ),
        )
    )

    # ------------------------------------------------------------------
    # Calibration cache candidate
    # ------------------------------------------------------------------

    tx.append(
        Transaction(
            name="CALIBRATION CACHE CANDIDATE",
            note=(
                "PROVEN capability/path exists in AdjustLight: "
                "read 0x80000 bytes beginning at 0x10080000. "
                "Whether this branch is valid for this session is unresolved."
            ),
            proven=False,
        )
    )

    tx.extend(
        compile_get_memory(
            0x10080000,
            0x80000,
        )
    )

    # ------------------------------------------------------------------
    # Active calibration
    # ------------------------------------------------------------------

    tx.append(
        Transaction(
            name="ACTIVE CALIBRATION",
            note=(
                "Sequence proven; profile-dependent calibration "
                "values remain unresolved."
            ),
            proven=False,
        )
    )

    tx.append(
        compile_set_adjust_data_unresolved()
    )

    # We know the calibration DPI relationship and y_extent formula,
    # but NOT enough values to claim a runnable calibration window.
    cal_window = ScanWindow(
        window_id=0,
        x_resolution=profile.resolution,
        y_resolution=profile.resolution,
        x_position=0,
        x_extent=0,                 # unresolved
        y_position=0,               # unresolved
        y_extent=9600 // profile.resolution,
        image_mode=5,
        bits_per_pixel=12,
    )

    tx.append(
        compile_set_window(
            cal_window,
            provenance=(
                "STRUCTURE PROVEN. "
                "x_resolution=300 and y_resolution=300 are target values; "
                "y_extent=9600/300 follows AdjustLight arithmetic. "
                "x_extent and y_position are UNRESOLVED and shown as zero. "
                "image_mode=5 is the normal observed calibration mode; "
                "12-bit calibration field observed in AdjustLight."
            ),
        )
    )

    # AdjustLight builds mode 1 and mode 2 from scanner state.
    # Do not claim zeros are the actual scanner values.
    tx.append(
        compile_define_scan_mode(
            ScanModeParam(mode_type=1),
            provenance=(
                "SERIALIZER PROVEN. INPUT VALUES UNRESOLVED: "
                "AdjustLight derives these from scanner state."
            ),
        )
    )

    tx.append(
        compile_define_scan_mode(
            ScanModeParam(mode_type=2),
            provenance=(
                "SERIALIZER PROVEN. INPUT VALUES UNRESOLVED: "
                "AdjustLight derives p4..p7 from scanner state."
            ),
        )
    )

    tx.append(
        Transaction(
            name="CALIBRATION SCAN SELECTORS",
            note=(
                "UNRESOLVED first-pass device-derived selector(s). "
                "Subsequent observed AdjustLight passes use FF and FE. "
                "No calibration SCAN packet selected here."
            ),
            proven=False,
        )
    )

    # ------------------------------------------------------------------
    # Normal StartScan
    # ------------------------------------------------------------------

    tx.append(
        Transaction(
            name="NORMAL STARTSCAN CONFIGURATION",
            note=(
                "Target 300 DPI / simplex / color. "
                "Exact tagScanParam-derived geometry and mode inputs "
                "still require provenance."
            ),
            proven=False,
        )
    )

    # These windows intentionally expose the remaining geometry unknowns.
    for window_id in (0, 1):
        w = ScanWindow(
            window_id=window_id,
            x_resolution=profile.resolution,
            y_resolution=profile.resolution,
            x_position=0,
            x_extent=0,
            y_position=0,
            y_extent=0,
            image_mode=5,
            bits_per_pixel=8,
        )

        tx.append(
            compile_set_window(
                w,
                provenance=(
                    "SERIALIZER PROVEN. TARGET DPI=300. "
                    "x/y geometry values are UNRESOLVED tagScanParam/"
                    "device-state inputs and therefore displayed as zero. "
                    "Do NOT interpret zeros as selected scan geometry."
                ),
            )
        )

    # Mode 0 StartScan provenance:
    # +4/+5/+6 are sourced from tagScanParam +38/+39/+3a.
    tx.append(
        compile_define_scan_mode(
            ScanModeParam(mode_type=0),
            provenance=(
                "SERIALIZER PROVEN. INPUT p4/p5/p6 correspond to "
                "StartScan tagScanParam +0x38/+0x39/+0x3a. "
                "Their values for our target profile are UNRESOLVED."
            ),
        )
    )

    # Mode 1 StartScan provenance:
    # p4 <- +34 (sometimes forced 2)
    # p5 <- +30
    # p6 <- derived
    # p8 <- bool(+3b)
    # p10 <- +8a9
    tx.append(
        compile_define_scan_mode(
            ScanModeParam(mode_type=1),
            provenance=(
                "SERIALIZER PROVEN. StartScan sources: "
                "p4<-+0x34 (with documented forcing conditions), "
                "p5<-+0x30, p6<-derived flag, "
                "p8<-bool(+0x3b), p10<-+0x8a9. "
                "Target-profile values remain UNRESOLVED."
            ),
        )
    )

    # Mode 2:
    # p4..p7 <- +50,+54,+58,+5c, possibly reordered.
    tx.append(
        compile_define_scan_mode(
            ScanModeParam(mode_type=2),
            provenance=(
                "SERIALIZER PROVEN. StartScan normally sources "
                "p4..p7 from tagScanParam "
                "+0x50/+0x54/+0x58/+0x5c; +0x8a9 can reorder them. "
                "Target-profile values remain UNRESOLVED."
            ),
        )
    )

    # ------------------------------------------------------------------
    # Page scan
    # ------------------------------------------------------------------

    tx.append(
        Transaction(
            name="SIMPLEX PAGE SELECTOR OPTIONS",
            note=(
                "ScanPage logic is proven, but selecting 00 versus 01 "
                "depends on the unresolved +0x34 source-side mode."
            ),
            proven=False,
        )
    )

    tx.append(
        compile_scan(
            [0x00],
            provenance="valid simplex option A",
        )
    )

    tx.append(
        compile_scan(
            [0x01],
            provenance="valid simplex option B",
        )
    )

    tx.append(
        Transaction(
            name="IMAGE READ TEMPLATE",
            type1=make_type1(
                cdb_exec_read(
                    0,
                    0x100000,
                )
            ),
            note=(
                "PROVEN ExecRead type=0 encoding. "
                "1 MiB is ScanImage's maximum normal image chunk."
            ),
        )
    )

    tx.append(
        Transaction(
            name="OBJECT POSITION 0",
            type1=make_type1(
                cdb_object_position(0)
            ),
            note=(
                "PROVEN command encoding. "
                "Still execution-blocked."
            ),
        )
    )

    return tx


# ===========================================================================
# OUTPUT
# ===========================================================================

def print_transaction(tx, number):
    print()
    print("-" * 76)

    status = "PROVEN" if tx.proven else "UNRESOLVED"

    print(
        f"[{number:03d}] {tx.name} "
        f"[{status}]"
    )

    if tx.note:
        print(f"      {tx.note}")

    if tx.type1 is not None:
        print()
        print("TYPE-1:")
        hexdump(tx.type1, indent="    ")

        if len(tx.type1) >= 13:
            opcode = tx.type1[12]

            if opcode in BLOCKED_EXECUTION_OPCODES:
                print(
                    f"    EXECUTION BLOCKED: "
                    f"0x{opcode:02x} "
                    f"{BLOCKED_EXECUTION_OPCODES[opcode]}"
                )

    if tx.type2 is not None:
        print()
        print(
            f"TYPE-2 ({len(tx.type2)} bytes):"
        )
        hexdump(tx.type2, indent="    ")
        print(
            "    EXECUTION BLOCKED: "
            "TYPE-2 transmission disabled"
        )


def print_compiled_profile(state_value):
    print()
    print("=" * 76)
    print(
        "R10 v0.4.1 BYTE-ACCURATE DRY-RUN "
        "PROTOCOL COMPILER"
    )
    print("=" * 76)

    print()
    print("TARGET INTENT")
    print("  Resolution: 300 x 300 DPI")
    print("  Source:     simplex")
    print("  Color:      yes")
    print("  Pages:      one sheet")
    print()
    print("RULE:")
    print(
        "  PROVEN means packet serialization/command encoding "
        "is supported by recovered R10Lite code."
    )
    print(
        "  UNRESOLVED means a profile/session value is not yet "
        "proven. Zero in such a field is NOT a proposed value."
    )
    print()
    print(
        "  NO configuration, calibration, positioning or "
        "motion transaction will be transmitted."
    )

    tx = compile_target_profile(state_value)

    for i, item in enumerate(tx, 1):
        print_transaction(item, i)

    unresolved = [
        x for x in tx if not x.proven
    ]

    print()
    print("=" * 76)
    print("UNRESOLVED INPUT SUMMARY")
    print("=" * 76)

    for item in unresolved:
        print(f"  - {item.name}: {item.note}")

    print()
    print(
        f"Transactions/markers: {len(tx)}"
    )
    print(
        f"Unresolved markers:   {len(unresolved)}"
    )

    print()
    print("END DRY RUN")


# ===========================================================================
# SAFE MAILBOX EXECUTOR
# ===========================================================================

class R10Mailbox:
    def __init__(self, device):
        self.device = device

    def transfer_sector(self):
        return direct_read_sector(
            self.device,
            TRANSFER_SECTOR,
        )

    def status(self):
        block = self.transfer_sector()

        start = (
            TRANSFER_DISK_OFFSET % SECTOR_SIZE
        ) + STATUS_OFFSET

        return block[start:start + 4]

    def read_indata(self, length):
        return direct_read_bytes(
            self.device,
            INDATA_DISK_OFFSET,
            length,
        )

    def send_type1(self, cdb, wait=None, timeout=10.0):
        opcode = cdb[0]

        if opcode in BLOCKED_EXECUTION_OPCODES:
            die(
                "EXECUTION SAFETY INTERLOCK: refusing "
                f"opcode 0x{opcode:02x} "
                f"({BLOCKED_EXECUTION_OPCODES[opcode]})"
            )

        if wait is None:
            wait = opcode not in TYPE1_NO_WAIT

        packet = make_type1(cdb)

        print()
        print("TYPE-1 CDB:", hexline(cdb))

        patch_sector(
            self.device,
            TRANSFER_DISK_OFFSET,
            packet,
        )

        if not wait:
            print("No response wait required.")
            return 0

        # Canon ordering:
        #   write command
        #   arm status with FFFFFFFF
        #   poll until firmware changes it
        patch_sector(
            self.device,
            TRANSFER_DISK_OFFSET + STATUS_OFFSET,
            b"\xff\xff\xff\xff",
        )

        deadline = time.monotonic() + timeout

        while True:
            raw = self.status()

            if raw != b"\xff\xff\xff\xff":
                value = int.from_bytes(raw, "big")
                print(
                    f"Mailbox status: "
                    f"0x{value:08x}"
                )
                return value

            if time.monotonic() >= deadline:
                die("Mailbox response timeout")

            time.sleep(0.1)


# ===========================================================================
# SAFE INITIALIZATION
# ===========================================================================

def safe_initialization(mb):
    print()
    print("=" * 76)
    print("SAFE DEVICE INITIALIZATION")
    print("=" * 76)

    print("\n[1] INQUIRY")

    status = mb.send_type1(
        cdb_inquiry(),
        wait=True,
    )

    if status:
        die(
            f"INQUIRY failed: "
            f"0x{status:08x}"
        )

    inquiry = mb.read_indata(64)

    print("INQUIRY response:")
    hexdump(inquiry)

    print("\n[2] TEST UNIT READY")

    tur = mb.send_type1(
        cdb_tur(),
        wait=True,
    )

    print("\n[3] REQUEST SENSE")

    status = mb.send_type1(
        cdb_request_sense(),
        wait=True,
    )

    if status:
        die(
            f"REQUEST SENSE failed: "
            f"0x{status:08x}"
        )

    sense = mb.read_indata(14)

    print("Sense:")
    hexdump(sense)

    if tur:
        print(
            f"TUR returned 0x{tur:08x}; "
            "sense data shown above."
        )

    print("\n[4] INQUIRY EX")

    status = mb.send_type1(
        cdb_inquiry_ex(),
        wait=True,
    )

    if status:
        die(
            f"INQUIRY EX failed: "
            f"0x{status:08x}"
        )

    inquiry_ex = mb.read_indata(48)

    print("INQUIRY EX:")
    hexdump(inquiry_ex)

    print("\n[5] STARTSCAN STATE READ")

    cdb = cdb_exec_read(6, 0x80)

    expected = bytes.fromhex(
        "28 00 8c 00 00 00 00 00 80 00"
    )

    if cdb != expected:
        die(
            "ExecRead type-6 CDB "
            "self-test failed"
        )

    status = mb.send_type1(
        cdb,
        wait=True,
    )

    if status:
        die(
            "StartScan state read failed: "
            f"0x{status:08x}"
        )

    state = mb.read_indata(128)

    print("State response:")
    hexdump(state)

    state_value = int.from_bytes(
        state[0:4],
        "big",
    )

    print()
    print(
        f"StartScan state = "
        f"0x{state_value:08x} "
        f"({state_value})"
    )

    return state_value


# ===========================================================================
# MAIN
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Canon imageFORMULA R10 Linux mailbox "
            "probe / byte-accurate dry-run compiler"
        )
    )

    parser.add_argument(
        "--diagnostic",
        action="store_true",
        help="run safe initialization",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "run safe initialization then compile "
            "the proposed scan protocol without executing it"
        ),
    )

    args = parser.parse_args()

    if os.geteuid() != 0:
        die("Run with sudo")

    print(
        f"Canon imageFORMULA R10 Linux probe "
        f"v{VERSION}"
    )

    print(
        "CONFIGURATION AND MOTION EXECUTION "
        "ARE DISABLED."
    )

    print(
        "TYPE-2 TRANSMISSION IS NOT IMPLEMENTED."
    )

    device = find_mailbox_lun()

    print(f"\nDevice: {device}")

    if device_is_mounted(device):
        die(
            f"{device} or a child partition is mounted. "
            "Unmount scanner filesystem first."
        )

    print("Scanner filesystem: unmounted")

    identity = read_identity(device)

    if not (
        identity.startswith(b"CANON   ")
        and identity[8:24].rstrip(b" \x00") == b"R10"
    ):
        die(
            "Mailbox identity verification failed"
        )

    revision = (
        identity[24:28]
        .split(b"\x00")[0]
        .decode(errors="replace")
    )

    print(
        f"Verified: CANON R10 firmware "
        f"{revision}"
    )

    mb = R10Mailbox(device)

    print(
        "Initial mailbox status: "
        + hexline(mb.status())
    )

    if not args.diagnostic and not args.dry_run:
        print()
        print("No commands sent.")
        print()
        print("Safe options:")
        print("  --diagnostic")
        print("  --dry-run")
        return

    state_value = safe_initialization(mb)

    if args.dry_run:
        print_compiled_profile(
            state_value
        )

    print()
    print(f"v{VERSION} complete.")

    print(
        "No SET WINDOW, DEFINE SCAN MODE, SCAN, "
        "OBJECT POSITION, SET ADJUST DATA, or "
        "TYPE-2 transaction was transmitted."
    )


if __name__ == "__main__":
    main()
