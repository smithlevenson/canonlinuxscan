#!/usr/bin/env python3
"""Canon R10 v0.6.1 controlled DefineScanMode experiment.

This intentionally builds on the validated v0.6 transport. It can transmit only:
  * the two recovered default SET WINDOW packets through v0.6's narrow path
  * the three exact recovered default DEFINE SCAN MODE packets (opcode 0xD6)
It contains no SCAN, ObjectPosition, SetAdjustData, 0x15, 0x2A, or generic executor.
"""

import importlib.util
import os
from pathlib import Path

BASE = Path(__file__).with_name("r10-first-scan.py")
spec = importlib.util.spec_from_file_location("r10_v06", BASE)
r10 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r10)

VERSION = "0.6.1"

EXPECTED_DEFINE_TYPE2 = (
    bytes.fromhex(
        "00 00 00 1c 00 02 b0 00 00 00 00 00 30 0e 00 00 "
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
    ),
    bytes.fromhex(
        "00 00 00 1c 00 02 b0 00 00 00 00 00 32 0e 00 01 "
        "00 00 20 00 00 00 00 00 00 00 00 00 00 00 00 00"
    ),
    bytes.fromhex(
        "00 00 00 1c 00 02 b0 00 00 00 00 00 36 0e 00 00 "
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
    ),
)
EXPECTED_D6_CDB = bytes.fromhex("d6 10 00 00 14 00 00 00 00 00")


def send_controlled_define(mb, tx, expected_type2, index, timeout=10.0):
    if tx.type1 is None or tx.type2 is None:
        r10.die("Internal error: DEFINE SCAN MODE transaction incomplete")

    cdb = tx.type1[12:22]
    if cdb != EXPECTED_D6_CDB:
        r10.die(f"Interlock: mode {index} CDB differs from recovered D6 CDB")
    if tx.type2 != expected_type2 or len(tx.type2) != 32:
        r10.die(f"Interlock: mode {index} Type-2 differs from validated transcript")

    print(f"\nCONTROLLED TRANSACTION: DEFINE SCAN MODE {index}")
    print("TYPE-2 payload:")
    r10.hexdump(tx.type2, indent="    ")
    print("TYPE-1 CDB:", r10.hexline(cdb))

    r10.direct_patch_bytes(
        mb.device,
        r10.TRANSFER_DISK_OFFSET + r10.TYPE2_OFFSET,
        tx.type2,
    )
    r10.direct_patch_bytes(mb.device, r10.TRANSFER_DISK_OFFSET, tx.type1)
    r10.direct_patch_bytes(
        mb.device,
        r10.TRANSFER_DISK_OFFSET + r10.STATUS_OFFSET,
        b"\xff\xff\xff\xff",
    )
    return mb.poll_status(timeout=timeout)


def main():
    if os.geteuid() != 0:
        r10.die("Run with sudo")

    print(f"Canon imageFORMULA R10 controlled configuration experiment v{VERSION}")
    print("Only validated SET WINDOW + exact default DEFINE SCAN MODE are enabled.")
    print("SCAN, positioning, calibration, 0x15, 0x2a and generic execution remain absent/blocked.")

    device = r10.find_mailbox_lun()
    print(f"\nDevice: {device}")
    if r10.device_is_mounted(device):
        r10.die(f"{device} or a child partition is mounted. Unmount scanner filesystem first.")
    print("Scanner filesystem: unmounted")

    # Do not require the boot-time TRANSFER+0x1c identity here. A successful
    # Type-2 transaction overwrites that mailbox area by design. Device identity
    # is instead established by USB VID/PID + the Windows FAT/ONTOUCHLITE LUN,
    # and the live INQUIRY below verifies CANON/R10/firmware before writes.
    mb = r10.R10Mailbox(device)
    print("Initial mailbox status: " + r10.hexline(mb.status()))
    live = r10.safe_initialization(mb)

    inquiry = live["inquiry"]
    if not (
        len(inquiry) >= 36
        and inquiry[8:16] == b"CANON   "
        and inquiry[16:32].rstrip(b" \x00") == b"R10"
    ):
        r10.die("Live INQUIRY identity verification failed")
    revision = inquiry[32:36].split(b"\x00")[0].decode(errors="replace")
    print(f"Verified by live INQUIRY: CANON R10 firmware {revision}")

    print("\n" + "=" * 76)
    print("PHASE 1: VALIDATED DEFAULT SET WINDOW")
    print("=" * 76)
    setwins, runtime = r10.default_setwindow_transactions(live["inquiry_ex"])
    print(f"Live e90={runtime['e90']} (0x{runtime['e90']:08x})")
    for tx in setwins:
        status = mb.send_controlled_setwindow(tx)
        if status:
            r10.post_experiment_snapshot(mb, f"{tx.name} failed")
            r10.die(f"{tx.name} returned 0x{status:08x}; DEFINE SCAN MODE not attempted")

    print("\n" + "=" * 76)
    print("PHASE 2: CONTROLLED DEFAULT DEFINE SCAN MODE")
    print("=" * 76)
    modes = r10.default_define_mode_transactions()
    if len(modes) != 3:
        r10.die("Interlock: expected exactly three DefineScanMode transactions")

    for index, (tx, expected) in enumerate(zip(modes, EXPECTED_DEFINE_TYPE2)):
        status = send_controlled_define(mb, tx, expected, index)
        if status:
            r10.post_experiment_snapshot(mb, f"DEFINE SCAN MODE {index} failed")
            r10.die(f"DEFINE SCAN MODE {index} returned 0x{status:08x}; stopping")

    r10.post_experiment_snapshot(mb, "SET WINDOW + all three DEFINE SCAN MODE commands accepted")
    print("\nConfiguration experiment complete.")
    print("No SCAN, paper-feed, ObjectPosition, or calibration command was sent.")


if __name__ == "__main__":
    main()
