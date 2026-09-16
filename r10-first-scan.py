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

VERSION = "0.6.1"

SECTOR_SIZE = 512
TRANSFER_DISK_OFFSET = 0x96A00
INDATA_DISK_OFFSET = 0x296A00
TRANSFER_SECTOR = TRANSFER_DISK_OFFSET // SECTOR_SIZE

STATUS_OFFSET = 0x18
TYPE2_OFFSET = 0x1C
IDENTITY_OFFSET = 0x1C

BLOCKED_EXECUTION_OPCODES = {
    0x15: "MODE SELECT / UNRESOLVED CONFIG",
    0x1B: "SCAN",
    0x2A: "WRITE / UNRESOLVED CONFIG",
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
    return int(value).to_bytes(2, "big", signed=False)


def be24(value):
    if not 0 <= value <= 0xFFFFFF:
        raise ValueError("value does not fit in 24 bits")
    return bytes([(value >> 16) & 0xFF, (value >> 8) & 0xFF, value & 0xFF])


def be32(value):
    return (int(value) & 0xFFFFFFFF).to_bytes(4, "big", signed=False)


def u16be(data, off):
    return int.from_bytes(data[off:off + 2], "big")


def u32be(data, off):
    return int.from_bytes(data[off:off + 4], "big")


def direct_read_sector(device, sector):
    p = subprocess.run(
        ["dd", f"if={device}", "bs=512", f"skip={sector}", "count=1", "iflag=direct", "status=none"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if p.returncode != 0:
        die(f"Direct read failed on {device} sector {sector}: {p.stderr.decode(errors='replace')}")
    if len(p.stdout) != SECTOR_SIZE:
        die(f"Short direct read on {device} sector {sector}: {len(p.stdout)} bytes")
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
                "dd", f"if={temp}", f"of={device}", "bs=512", f"seek={sector}", "count=1",
                "oflag=direct", "conv=notrunc,fsync", "status=none",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if p.returncode != 0:
            die(f"Direct write failed on {device} sector {sector}: {p.stderr.decode(errors='replace')}")
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


def direct_patch_bytes(device, absolute_offset, payload):
    if not payload:
        return
    pos = 0
    remaining = len(payload)
    while remaining:
        sector = absolute_offset // SECTOR_SIZE
        inside = absolute_offset % SECTOR_SIZE
        take = min(remaining, SECTOR_SIZE - inside)
        block = bytearray(direct_read_sector(device, sector))
        block[inside:inside + take] = payload[pos:pos + take]
        direct_write_sector(device, sector, bytes(block))
        absolute_offset += take
        pos += take
        remaining -= take


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
                if vid.read_text().strip().lower() == "1083" and pid.read_text().strip().lower() == "167f":
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
    start = (TRANSFER_DISK_OFFSET % SECTOR_SIZE) + IDENTITY_OFFSET
    return block[start:start + 64]


def is_mailbox_lun(device):
    try:
        ident = read_identity(device)
    except Exception:
        return False
    return ident.startswith(b"CANON   ") and ident[8:24].rstrip(b" \x00") == b"R10"


def is_windows_r10_lun(device):
    """Read-only fallback for mailbox LUN discovery after Type-2 overwrote +0x1c.

    The Windows LUN is the vfat/ONTOUCHLITE volume. The Mac LUN is HFS+.
    We use lsblk metadata only; this does not mount or write either LUN.
    """
    try:
        p = subprocess.run(
            ["lsblk", "-nrpo", "NAME,FSTYPE,LABEL", device],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except OSError:
        return False
    if p.returncode != 0:
        return False
    for line in p.stdout.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 2:
            continue
        fstype = parts[1].lower()
        label = parts[2].strip() if len(parts) >= 3 else ""
        if fstype in {"vfat", "fat", "fat16", "fat32"} or label.upper() == "ONTOUCHLITE":
            return True
    return False


def find_mailbox_lun():
    luns = find_r10_luns()
    if not luns:
        die("No Canon R10 USB LUNs detected")
    print("R10 USB LUNs detected: " + ", ".join(luns))

    candidates = [d for d in luns if is_mailbox_lun(d)]
    if len(candidates) == 1:
        print(f"Mailbox LUN selected by TRANSFER identity: {candidates[0]}")
        return candidates[0]

    # After any Type-2 transaction, TRANSFER+0x1c contains the most recent
    # Type-2 payload, so the boot-time CANON/R10 identity is no longer a stable
    # discriminator. Fall back to the Windows FAT/ONTOUCHLITE LUN identity.
    fat_candidates = [d for d in luns if is_windows_r10_lun(d)]
    if len(fat_candidates) == 1:
        print(
            "TRANSFER identity unavailable/overwritten; "
            f"mailbox LUN selected by Windows FAT identity: {fat_candidates[0]}"
        )
        return fat_candidates[0]

    die(
        "Could not uniquely identify Canon mailbox LUN. "
        f"TRANSFER candidates: {candidates}; Windows FAT candidates: {fat_candidates}"
    )


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
    packet[0:12] = bytes.fromhex("00 00 00 14 00 01 90 00 00 00 00 00")
    packet[12:12 + len(cdb)] = cdb
    return bytes(packet)


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
    cdb = bytearray(10)
    cdb[0] = 0x24
    cdb[8] = 0x34
    p = bytearray(64)
    p[0:8] = bytes.fromhex("00 00 00 3c 00 02 b0 00")
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


@dataclass
class ScanModeParam:
    mode_type: int
    p4: int = 0
    p5: int = 0
    p6: int = 0
    p7: int = 0
    p8: int = 0
    p10: int = 0


def compile_define_scan_mode(m, provenance=""):
    cdb = bytes.fromhex("d6 10 00 00 14 00 00 00 00 00")
    p = bytearray(32)
    p[0:8] = bytes.fromhex("00 00 00 1c 00 02 b0 00")
    if m.mode_type == 0:
        p[12:14] = bytes.fromhex("30 0e")
        derived = 0x05 if m.p4 else 0x04
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


@dataclass
class DefaultProfile:
    resolution: int = 200
    paper_name: str = "LETTER"
    paper_width: int = 10200
    paper_height: int = 13200
    x_position: int = 0
    special_x_extent: int = -472
    special_y_padding: int = 944
    image_mode: int = 5
    bits_per_pixel: int = 8


def derive_runtime_values(inquiry_ex):
    if len(inquiry_ex) < 48:
        raise ValueError("InquiryEx response must be 48 bytes")
    x_den = u16be(inquiry_ex, 0x00)
    y_den = u16be(inquiry_ex, 0x02)
    x_num = u32be(inquiry_ex, 0x14)
    y_num = u32be(inquiry_ex, 0x18)
    if x_den == 0 or y_den == 0:
        raise ValueError("InquiryEx denominator is zero")
    return {
        "e90": (x_num * 1200) // x_den,
        "e94": (y_num * 1200) // y_den,
    }


def default_setwindow_transactions(inquiry_ex):
    profile = DefaultProfile()
    runtime = derive_runtime_values(inquiry_ex)
    y_extent = profile.paper_height + profile.special_y_padding
    tx = []
    for window_id in (0, 1):
        tx.append(compile_set_window(
            ScanWindow(
                window_id=window_id,
                x_resolution=profile.resolution,
                y_resolution=profile.resolution,
                x_position=profile.x_position,
                x_extent=profile.special_x_extent,
                y_position=runtime["e90"],
                y_extent=y_extent,
                image_mode=profile.image_mode,
                bits_per_pixel=profile.bits_per_pixel,
            ),
            provenance="Recovered native default StartScan SetWindow transaction.",
        ))
    return tx, runtime


def default_define_mode_transactions():
    return [
        compile_define_scan_mode(ScanModeParam(mode_type=0, p4=0, p5=0, p6=0)),
        compile_define_scan_mode(ScanModeParam(mode_type=1, p4=0, p5=0, p6=1, p8=0, p10=0)),
        compile_define_scan_mode(ScanModeParam(mode_type=2, p4=0, p5=0, p6=0, p7=0)),
    ]


class R10Mailbox:
    def __init__(self, device):
        self.device = device

    def transfer_sector(self):
        return direct_read_sector(self.device, TRANSFER_SECTOR)

    def status(self):
        block = self.transfer_sector()
        start = (TRANSFER_DISK_OFFSET % SECTOR_SIZE) + STATUS_OFFSET
        return block[start:start + 4]

    def read_indata(self, length):
        return direct_read_bytes(self.device, INDATA_DISK_OFFSET, length)

    def poll_status(self, timeout=10.0):
        deadline = time.monotonic() + timeout
        while True:
            raw = self.status()
            if raw != b"\xff\xff\xff\xff":
                value = int.from_bytes(raw, "big")
                print(f"Mailbox status: 0x{value:08x}")
                return value
            if time.monotonic() >= deadline:
                die("Mailbox response timeout")
            time.sleep(0.1)

    def send_type1(self, cdb, wait=None, timeout=10.0):
        opcode = cdb[0]
        if opcode in BLOCKED_EXECUTION_OPCODES or opcode == 0x24:
            die(
                "EXECUTION SAFETY INTERLOCK: refusing "
                f"opcode 0x{opcode:02x}"
            )
        if wait is None:
            wait = opcode not in TYPE1_NO_WAIT
        print("\nTYPE-1 CDB:", hexline(cdb))
        direct_patch_bytes(self.device, TRANSFER_DISK_OFFSET, make_type1(cdb))
        if not wait:
            print("No response wait required.")
            return 0
        direct_patch_bytes(
            self.device,
            TRANSFER_DISK_OFFSET + STATUS_OFFSET,
            b"\xff\xff\xff\xff",
        )
        return self.poll_status(timeout=timeout)

    def send_controlled_setwindow(self, tx, timeout=10.0):
        if tx.type1 is None or tx.type2 is None:
            die("Internal error: controlled SET WINDOW requires TYPE-1 and TYPE-2")
        cdb = tx.type1[12:22]
        if not cdb or cdb[0] != 0x24:
            die("Internal error: controlled path only permits opcode 0x24")
        if len(tx.type2) != 64:
            die("Internal error: SET WINDOW Type-2 must be exactly 64 bytes")

        print(f"\nCONTROLLED TRANSACTION: {tx.name}")
        print("TYPE-2 payload:")
        hexdump(tx.type2, indent="    ")
        print("TYPE-1 CDB:", hexline(cdb))

        direct_patch_bytes(
            self.device,
            TRANSFER_DISK_OFFSET + TYPE2_OFFSET,
            tx.type2,
        )
        direct_patch_bytes(
            self.device,
            TRANSFER_DISK_OFFSET,
            tx.type1,
        )
        direct_patch_bytes(
            self.device,
            TRANSFER_DISK_OFFSET + STATUS_OFFSET,
            b"\xff\xff\xff\xff",
        )
        return self.poll_status(timeout=timeout)


def safe_initialization(mb):
    print("\n" + "=" * 76)
    print("SAFE DEVICE INITIALIZATION")
    print("=" * 76)

    print("\n[1] INQUIRY")
    status = mb.send_type1(cdb_inquiry(), wait=True)
    if status:
        die(f"INQUIRY failed: 0x{status:08x}")
    inquiry = mb.read_indata(64)
    print("INQUIRY response:")
    hexdump(inquiry)

    print("\n[2] TEST UNIT READY")
    tur = mb.send_type1(cdb_tur(), wait=True)

    print("\n[3] REQUEST SENSE")
    status = mb.send_type1(cdb_request_sense(), wait=True)
    if status:
        die(f"REQUEST SENSE failed: 0x{status:08x}")
    sense = mb.read_indata(14)
    print("Sense:")
    hexdump(sense)
    if tur:
        print(f"TUR returned 0x{tur:08x}; sense data shown above.")

    print("\n[4] INQUIRY EX")
    status = mb.send_type1(cdb_inquiry_ex(), wait=True)
    if status:
        die(f"INQUIRY EX failed: 0x{status:08x}")
    inquiry_ex = mb.read_indata(48)
    print("INQUIRY EX:")
    hexdump(inquiry_ex)
    runtime = derive_runtime_values(inquiry_ex)
    print(
        f"Derived e90={runtime['e90']} (0x{runtime['e90']:08x}), "
        f"e94={runtime['e94']} (0x{runtime['e94']:08x})"
    )

    print("\n[5] STARTSCAN STATE READ")
    cdb = cdb_exec_read(6, 0x80)
    expected = bytes.fromhex("28 00 8c 00 00 00 00 00 80 00")
    if cdb != expected:
        die("ExecRead type-6 CDB self-test failed")
    status = mb.send_type1(cdb, wait=True)
    if status:
        die(f"StartScan state read failed: 0x{status:08x}")
    state = mb.read_indata(128)
    print("State response:")
    hexdump(state)
    state_value = int.from_bytes(state[0:4], "big")
    print(f"\nStartScan state = 0x{state_value:08x} ({state_value})")
    return {
        "inquiry": inquiry,
        "sense": sense,
        "inquiry_ex": inquiry_ex,
        "state": state,
        "state_value": state_value,
    }


def post_experiment_snapshot(mb, label):
    print("\n" + "=" * 76)
    print(f"POST-EXPERIMENT SNAPSHOT: {label}")
    print("=" * 76)

    print("\nREQUEST SENSE")
    status = mb.send_type1(cdb_request_sense(), wait=True)
    if status:
        print(f"REQUEST SENSE mailbox status: 0x{status:08x}")
    sense = mb.read_indata(14)
    hexdump(sense)

    print("\nSTATE READ")
    status = mb.send_type1(cdb_exec_read(6, 0x80), wait=True)
    if status:
        print(f"STATE READ mailbox status: 0x{status:08x}")
    state = mb.read_indata(128)
    hexdump(state)


def print_dry_run(live):
    setwins, runtime = default_setwindow_transactions(live["inquiry_ex"])
    print("\n" + "=" * 76)
    print("R10 v0.6.1 DEFAULT STARTSCAN DRY RUN")
    print("=" * 76)
    print(f"e90={runtime['e90']} e94={runtime['e94']}")
    for tx in setwins + default_define_mode_transactions():
        print(f"\n{tx.name}")
        print("TYPE-1:")
        hexdump(tx.type1, indent="    ")
        print("TYPE-2:")
        hexdump(tx.type2, indent="    ")
    print("\nNo configuration transaction was transmitted.")


def run_setwindow_experiment(mb, live):
    txs, runtime = default_setwindow_transactions(live["inquiry_ex"])

    print("\n" + "=" * 76)
    print("CONTROLLED SET WINDOW EXPERIMENT")
    print("=" * 76)
    print("This path can transmit ONLY the two recovered default opcode 0x24 packets.")
    print("SCAN, DEFINE SCAN MODE, positioning, calibration and generic unsafe execution remain blocked.")
    print(f"Live e90={runtime['e90']} (0x{runtime['e90']:08x})")

    for tx in txs:
        status = mb.send_controlled_setwindow(tx)
        if status != 0:
            print(f"{tx.name} returned nonzero mailbox status 0x{status:08x}; stopping experiment.")
            post_experiment_snapshot(mb, tx.name)
            return

    post_experiment_snapshot(mb, "both SET WINDOW commands accepted")
    print("\nSET WINDOW experiment complete. No SCAN or motor command was sent.")


def main():
    parser = argparse.ArgumentParser(
        description="Canon imageFORMULA R10 Linux mailbox probe / controlled v0.6.1 experiment"
    )
    parser.add_argument("--diagnostic", action="store_true", help="run safe initialization")
    parser.add_argument("--dry-run", action="store_true", help="compile default SetWindow/DefineScanMode transcript")
    parser.add_argument(
        "--experiment-setwindow",
        action="store_true",
        help="transmit only the two recovered default SET WINDOW transactions, then stop",
    )
    args = parser.parse_args()

    if os.geteuid() != 0:
        die("Run with sudo")

    selected = sum(bool(x) for x in (args.diagnostic, args.dry_run, args.experiment_setwindow))
    if selected > 1:
        die("Choose only one of --diagnostic, --dry-run, or --experiment-setwindow")

    print(f"Canon imageFORMULA R10 Linux probe v{VERSION}")
    print("Generic configuration/motion execution remains disabled.")
    print("v0.6.1 retains the narrow active path: --experiment-setwindow.")

    device = find_mailbox_lun()
    print(f"\nDevice: {device}")
    if device_is_mounted(device):
        die(f"{device} or a child partition is mounted. Unmount scanner filesystem first.")
    print("Scanner filesystem: unmounted")

    mb = R10Mailbox(device)
    print("Initial mailbox status: " + hexline(mb.status()))

    if selected == 0:
        print("\nNo commands sent.\n")
        print("Options:")
        print("  --diagnostic")
        print("  --dry-run")
        print("  --experiment-setwindow")
        return

    live = safe_initialization(mb)

    if args.dry_run:
        print_dry_run(live)
    elif args.experiment_setwindow:
        run_setwindow_experiment(mb, live)

    print(f"\nv{VERSION} complete.")


if __name__ == "__main__":
    main()
