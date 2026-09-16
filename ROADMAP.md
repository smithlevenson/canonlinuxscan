# Canon Linux Scan — Reverse-Engineering Roadmap

**Status:** Reverse engineering / protocol reconstruction  
**Last updated:** 2026-09-16  
**Current target:** Canon R10Lite / `CCanoDR` scanner path

## Purpose

Reconstruct the Canon R10 scanner protocol sufficiently to drive the scanner from Linux, then turn the working protocol into a maintainable Linux scanner implementation and ultimately a SANE backend.

The guiding rule is:

> **Review existing/native behavior first; innovate the Linux implementation second.**

Do not solve unexplained native behavior by blindly fuzzing command payloads when the original driver can tell us what it does.

---

## Current checkpoint

We have moved beyond simple protocol probing. The native Canon driver has been extracted and disassembled, and the important scan path has been located and partially reconstructed.

### Established

- Canon `R10Lite` binary extracted and fully disassembled.
- `CCanoDR` and `CCanoDRDS` identified.
- `CCanoDR::StartScan(tagScanParam*)` located at `0x124f8`.
- `PrepareScan()` extracted and analyzed.
- Major `CCanoDR::Exec*` protocol methods identified, including the paths for scan-window setup, scan-mode definition, object positioning, scanning, reading, and writing.
- Scanner baseline captures and hashes preserved.
- Linux probe programs established for low-level experimentation.
- `tagScanParam` fields and important stores/loads have been mapped in the native code.
- Native `DefineScanMode(type=0)` behavior has been reconstructed for the currently relevant flag combinations:
  - p4=0, p5=0 → `+0x0f = 0`
  - p4=1, p5=0 → `+0x0f = 1`
  - p4=0, p5=1 → `+0x0f = 4`
  - p4=1, p5=1 → `+0x0f = 5`
  - p6 sets `+0x11 = 0x10`
- `SetupScanner()` has been analyzed enough to identify an important initialization sequence before the normal scan path.
- `Prescan()` has been partially reconstructed.

### Important current hypothesis

The current scan failure (including the D6 rejection observed during Linux reproduction) should **not** yet be treated as proof of a bad D6 payload.

A stronger working hypothesis is that the Linux reproduction is missing some driver initialization/state transitions performed by `SetupScanner()` and/or `Prescan()` before `StartScan()`.

Therefore the next work should reproduce native initialization rather than continue blind D6 experimentation.

---

## Native initialization sequence to reconstruct

The currently identified `SetupScanner()` flow is approximately:

```text
CreateScannerList
      ↓
CCanoDR constructor
      ↓
SetOcrPath
      ↓
CCanoDR virtual call +0x10
      ↓
CCanoDR virtual call +0x20
      ↓
CCanoDR virtual call +0x50
      ↓
CCanoDR virtual call +0x50
      ↓
CCanoDR virtual call +0x28
      ↓
read capabilities 0x1112 / 0x1111
      ↓
Prescan
      ↓
StartScan
```

The exact identities, arguments, return values, and side effects of the virtual calls still need to be established.

---

# Roadmap

## Phase 1 — Freeze the baseline

**Status: Essentially complete**

Preserve the experimental artifacts rather than prematurely consolidating them. Current research artifacts include:

```text
r10-first-scan.py
r10-first-scan-v0.1.py
r10-first-scan-v0.4.py
r10-first-scan-v0.4.1.py
r10-probe.py
r10-raw-probe.py
r10-read-object.py
r10-dump-object.py

R10Lite-full.asm
PrepareScan-full.txt
PrepareScan-high-fields.txt
startscan-callers.txt
startscan-vtable.txt
startscan-tagscanparam-fields.txt
tagScanParam-stores.txt
target-capability-refs.txt
8a9-refs.txt

v0.4-dry-run.txt
v0.4.1-dry-run.txt
```

Experimental versions are useful historical records. Do not delete them simply because a newer probe supersedes them.

---

## Phase 2 — Finish the `CCanoDR` vtable map

**Status: Next task**

Resolve the important virtual-call slots, especially:

```text
+0x10
+0x20
+0x28
+0x50
```

and the relevant higher offsets encountered in `Prescan()`.

For each slot document:

```text
vtable offset
    ↓
actual CCanoDR method
    ↓
arguments
    ↓
return value
    ↓
state/field side effects
    ↓
scanner protocol operations
```

The `CCanoDR` vtable has been located around `0x55220` in the extracted binary.

Do not infer a method's purpose solely from its slot number. Trace the concrete target and callers.

---

## Phase 3 — Reconstruct `SetupScanner()` completely

Reproduce the driver's initialization behavior in the Linux research harness.

Determine:

1. Scanner discovery.
2. `CCanoDR` object construction/state initialization.
3. OCR path handling and whether it affects scanner state.
4. Every initialization virtual call.
5. Capability reads.
6. Hidden state changes caused by those calls.
7. Transition into `Prescan()`.

The goal is not merely to document the call graph. We need enough behavioral understanding to reproduce the scanner's expected state on Linux.

---

## Phase 4 — Reconstruct the `CCanoDR` state machine

Map meaningful `CCanoDR` object fields and their writers/readers.

Pay particular attention to:

- scanner state
- scan mode
- paper size
- scan window
- object position
- image buffer state
- transfer mode
- OCR-related state
- fields around the structures used by `StartScan()`
- fields populated or consumed by `Prescan()`

For each important field, record:

```text
CCanoDR + offset
    ↓
writer(s)
    ↓
reader(s)
    ↓
meaning / confidence
```

Use confidence levels when the meaning is inferred rather than directly established.

---

## Phase 5 — Reconstruct the complete `Prescan → StartScan` path

Establish the exact sequence of operations between preparation and actual acquisition.

Target model:

```text
PrepareScan
   ↓
SetWindow
   ↓
DefineScanMode
   ↓
ObjectPosition
   ↓
additional native setup
   ↓
ExecScan
   ↓
response/status handling
   ↓
image transfer
```

The missing operations and their ordering are more important than producing a superficially working command sequence.

---

## Phase 6 — Resolve the current D6 failure

Return to the live scanner only after the native initialization path is sufficiently reconstructed.

Test the hypothesis:

```text
native initialization/state
        ↓
correct protocol sequence
        ↓
StartScan
        ↓
D6 accepted
```

If D6 is still rejected, then isolate the difference systematically:

1. Compare native and Linux command sequences.
2. Compare request bytes.
3. Compare response bytes.
4. Compare ordering.
5. Compare timing where relevant.
6. Compare scanner state/capability reads.
7. Only then vary the specific D6 parameters.

Record every successful and unsuccessful experiment.

---

## Phase 7 — First real Linux scan

Once the scanner accepts the reconstructed sequence:

```text
initialize
   ↓
configure
   ↓
scan
   ↓
receive transfer
   ↓
decode image data
   ↓
write image file
```

The first milestone is a **single reliable scan**, not a polished application.

Preserve the exact successful capture as a protocol fixture.

---

## Phase 8 — Decode and validate image transfer

Compare the Linux scan with a scan made through Canon CaptureOnTouch.

Validate:

- image dimensions
- resolution
- color mode
- bit depth
- transfer size
- page boundaries
- headers/metadata
- actual image data
- multi-page behavior

Then expand coverage:

- simplex
- duplex
- different resolutions
- different paper sizes
- color
- grayscale
- black/white
- ADF multi-page scans

---

## Phase 9 — Refactor into a real implementation

Only after the protocol is understood and a real scan works should the experimental scripts be consolidated.

Target architecture:

```text
canonlinuxscan/
    transport/
    protocol/
    scanner/
    image/
    cli/
    tests/
```

Keep the reverse-engineering fixtures and raw captures separate from production code.

The implementation should prefer hostnames/configuration over hard-coded assumptions where applicable, but scanner protocol constants discovered from the native driver should be explicitly documented.

---

## Phase 10 — SANE integration

After the protocol implementation is stable, expose it through a Linux scanner interface.

Target end state:

```text
scanimage / Simple Scan / other SANE clients
                 ↓
             SANE backend
                 ↓
       canonlinuxscan protocol
                 ↓
             R10 scanner
```

SANE integration is intentionally deferred until the protocol layer is reliable.

---

# Working rules

1. **Native behavior beats speculation.**
2. **Review existing code/disassembly before adding new architecture.**
3. **Do not destroy working experimental probes.**
4. **Version meaningful protocol experiments.**
5. **Capture successful exchanges as fixtures.**
6. **Separate confirmed facts from inferred meanings.**
7. **Do not assume D6 rejection means the D6 payload is wrong.**
8. **Do not turn the project into a polished library before the protocol is understood.**
9. **A real scan is the next major milestone.**
10. **SANE comes after protocol reconstruction, not before.**

---

# Immediate next session

Start here:

```text
1. Map CCanoDR vtable.
2. Identify +0x10 / +0x20 / +0x28 / +0x50 targets.
3. Trace their callers and side effects.
4. Complete SetupScanner initialization sequence.
5. Compare that sequence against r10-first-scan.py.
6. Add only the missing native initialization to the harness.
7. Re-test StartScan/D6.
```

Do **not** restart the investigation from the existing probes, and do **not** begin with another round of arbitrary D6 payload variations unless the native path has been reproduced first.
