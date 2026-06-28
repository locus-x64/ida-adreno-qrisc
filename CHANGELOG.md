# Changelog

[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format, [SemVer](https://semver.org/).

## [0.1.0] - 2026-06-28

Initial release.

### Added

- IDA Pro processor module + loader (`ida/procs/qrisc.py`,
  `ida/loaders/qrisc_loader.py`) for SQE / PFP / PM4 firmware on a6xx, a7xx,
  and a8xx (best-effort). Pure IDAPython, targets IDA 9.x.
- Ghidra SLEIGH module (`ghidra/Ghidra/Processors/QRisc/`) with three
  languages (`QRisc:LE:32:{a6xx,a7xx,a8xx}`). Verified against Ghidra 12.1.2.
- ZAP shader loader (PIL/MDT split-binary parser) and GMU loader (routes
  `*_gmu.bin` to ARM Cortex-M).
- Standalone disassembler core (`common/qrisc_disasm.py`). Byte-exact vs
  Mesa's `qrisc-disasm` on the fixtures.
- ISA generator (`gen/qrisc_isa_gen.py`) reads `qrisc.xml`, `adreno_pm4.xml`,
  and `adreno_control_regs.xml` and emits standalone Python tables. No Mesa
  dependency at runtime.
- Bootstrap emulator (`common/qrisc_emu.py`): port of Mesa `emu.c` sufficient
  to run the firmware bootstrap, recover the populated PM4 packet jump table,
  and read the BR/BV/LPAC sub-image bases.
- Static dispatch-table scanner (`common/qrisc_bootstrap.py`) recovers the CP
  packet table by content scan when the bootstrap emulator can't complete
  (real a6xx and a8xx).
- PM4 packet name DB (`common/qrisc_pm4.py`): baked and generation-aware.
- 47 unit tests, regen-determinism job, oracle-diff job in CI.
- `ida/install.sh`.
- Docs: README, `docs/a8xx_report.md`, `docs/aux_cores.md`, per-component
  READMEs.

### Verified

- Decoder oracle match: 127/127 (a6xx fixture), 158/158 (a7xx fixture).
- `a740_sqe.fw` (real a7xx): 99.89% instruction-level match (17,455 / 17,474)
  vs `qrisc-disasm`. The 0.11% gap is `qrisc-disasm` false-positives inside a
  data table.
- `a660_sqe.fw` (real a6xx): loads, all 80 `CP_*` handlers recovered,
  bootstrap + handlers disassemble.
- a8xx: gen80000/80100/80200_sqe.fw parse and decode at ~93-94% coverage. All
  shipped blobs carry the patched CVE-2025-21479 IB-level mask (`& 0x7`).
- Ghidra SLEIGH: all three languages compile and headless-decode the fixtures
  matching the oracle.

### Known limitations

- a8xx is best-effort. Same QRisc ISA family as a7xx, but a few candidate
  a8xx-only encodings remain unverified; the bootstrap emulator falls back to
  the static table scanner on some a8xx paths.
- No IDA decompiler for QRisc: Hex-Rays has no third-party API for custom-ISA
  decompilation. Use the Ghidra module.

[0.1.0]: ./
