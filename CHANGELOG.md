# Changelog

All notable changes to **ida-adreno-qrisc** are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-06-28

Initial public release.

### Added
- **IDA Pro processor module + loader** (`ida/procs/qrisc.py`, `ida/loaders/qrisc_loader.py`)
  for Adreno command-processor microcode: SQE / PFP / PM4 firmware on a6xx, a7xx,
  and a8xx (best-effort). Pure IDAPython, targets IDA 9.x.
- **Ghidra SLEIGH module** (`ghidra/Ghidra/Processors/QRisc/`) — disassembly **and a
  decompiler** for the same ISA. Three languages: `QRisc:LE:32:{a6xx,a7xx,a8xx}`.
  Compile and round-trip verified against Ghidra 12.1.2.
- **Auxiliary loaders**: ZAP shader (`qrisc_zap_loader.py`, PIL/MDT split-binary
  parser) and GMU (`qrisc_gmu_loader.py`, routes `*_gmu.bin` to ARM Cortex-M).
- **Standalone disassembler core** (`common/qrisc_disasm.py`) — decoder + renderer,
  reusable from any host. Byte-exact vs Mesa's `qrisc-disasm` on every fixture.
- **ISA generator** (`gen/qrisc_isa_gen.py`) — reads Mesa's `qrisc.xml`,
  `adreno_pm4.xml`, and `adreno_control_regs.xml` at generation time and emits
  fully standalone Python tables. No Mesa dependency at runtime.
- **Bootstrap emulator** (`common/qrisc_emu.py`) — port of Mesa `emu.c` enough to
  run the firmware bootstrap routine and recover the populated PM4 packet jump
  table + BR/BV/LPAC sub-image bases.
- **Static dispatch-table scanner** (`common/qrisc_bootstrap.py`) — recovers the
  CP packet table by content scan when bootstrap emulation cannot complete (real
  a6xx and a8xx).
- **PM4 packet name DB** (`common/qrisc_pm4.py`) — baked, generation-aware, so the
  IDA/Ghidra runtime needs no Mesa tree.
- 47 unit tests, with a regen-determinism job and an oracle-diff job for CI.
- `ida/install.sh` install script for IDA processor + loaders.
- Documentation: README, `docs/a8xx_report.md`, `docs/aux_cores.md`, per-component
  READMEs in `ida/procs/` and `ghidra/`.

### Verified
- **Decoder oracle match**: 127/127 (a6xx fixture), 158/158 (a7xx fixture) —
  byte-exact vs Mesa `qrisc-disasm`.
- **Real-world a7xx**: `a740_sqe.fw` — **99.89% instruction-level match (17,455 /
  17,474)** vs `qrisc-disasm`; the 0.11% gap is qrisc-disasm false-positives inside
  a data table the oracle force-disassembled.
- **Real-world a6xx**: `a660_sqe.fw` loads, recovers all 80 named `CP_*` handlers,
  disassembles bootstrap + handlers.
- **Real-world a8xx**: 3 of 3 blobs (`gen80000/80100/80200_sqe.fw`) parse, decode
  at ~93–94% coverage (≈ a7xx baseline) with the a7xx encoding set. All shipped
  blobs carry the *patched* CVE-2025-21479 IB-level mask (`& 0x7`).
- Ghidra SLEIGH compiles cleanly and headless-decodes both fixtures to match the
  oracle.

### Known limitations
- **a8xx is best-effort** — same QRisc ISA family as a7xx (no new core), but a few
  candidate a8xx-only encodings remain unverified; the bootstrap emulator does not
  yet model some a8xx-specific paths and falls back to the static table scanner.
- **No IDA decompiler** for QRisc — Hex-Rays exposes no third-party API to add a
  decompiler for a custom ISA. Use the Ghidra SLEIGH module for decompilation.

[0.1.0]: ./
