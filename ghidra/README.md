# QRisc (Adreno afuc) — Ghidra SLEIGH processor module

A Ghidra processor module + decompiler for the Qualcomm Adreno command-processor
microcode ISA that Mesa calls **afuc** / **QRisc** (the SQE / PFP / PM4 firmware).
Because Ghidra's decompiler runs on SLEIGH-generated p-code, this module gives you
**disassembly *and* a decompiler** for QRisc firmware — the reason the project
routes decompilation through Ghidra rather than IDA (where adding a decompiler for
a new ISA is not supported for third parties).

Generated from Mesa's `qrisc.xml` (isaspec), pinned at commit
`4bf8fd5121122abd87aafb31e43bbbe9e3d2e921`, via the standalone decode tables in
`common/qrisc_isa_tables.py`.

## Supported generations

| Language id          | Adreno gen | Status |
|----------------------|-----------|--------|
| `QRisc:LE:32:a6xx`   | a6xx (unified SQE)          | validated against Mesa oracle |
| `QRisc:LE:32:a7xx`   | a7xx (split BR/BV + LPAC)   | validated against Mesa oracle |
| `QRisc:LE:32:a8xx`   | a8xx                        | **best-effort** — same QRisc ISA family as a7xx; decoded with the a7xx constructor set. Mesa has no a8xx-specific CP encodings, so any a8xx-only opcodes/control-regs need reverse engineering (project Stage 5). |

a5xx is intentionally out of scope (legacy PFP+PM4, partial Mesa support).

## Install

1. Copy the module into your Ghidra install:
   `cp -r ghidra/Ghidra/Processors/QRisc <GHIDRA_INSTALL>/Ghidra/Processors/QRisc`
   (the module ships pre-compiled `*.sla` files and a `Module.manifest`).
2. Restart Ghidra. The three QRisc languages appear under processor "QRisc".

To rebuild the `.sla` after editing the spec:
`<GHIDRA>/support/sleigh Ghidra/Processors/QRisc/data/languages/qrisc_a6xx.slaspec`
(and likewise for a7xx / a8xx).

To regenerate the SLEIGH from the ISA tables (tracks Mesa upstream):
`python3 ghidra/tools/qrisc_sleigh_gen.py`

## Importing firmware

CP firmware files (`a630_sqe.fw`, `gen70900_sqe.fw`, …) begin with a leading file
word that the running CP skips; the version NOP and instruction stream begin at
file **word 1** (matching Mesa `qrisc-disasm`, which does `instrs = &buf[1]`).

Quick path (single SQE image):
1. Strip the leading word:  `tail -c +5 a630_sqe.fw > a630.stream`
2. In Ghidra: **Import File** → `a630.stream`, Language `QRisc:LE:32:a6xx`
   (a730/gen709xx → a7xx; gen80xxx → a8xx), Options → base address `0x0`.
3. Run the bundled script **QRiscFirmwareHelper** (Script Manager → category
   QRisc): it marks the version/jumptbl NOP payloads as data, reports the packet
   jump-table offset, and disassembles the `bootstrap` routine at word 2.

a7xx/a8xx blobs bundle BR + BV (+ LPAC) sub-images in one `_sqe.fw`; splitting
them is handled by the shared container library (`common/`, project Stage 3).
Point each sub-image at the matching language and import separately, or extend
the helper to call that library.

GMU firmware (`*_gmu.bin`) is a **separate ARM Cortex-M core — not QRisc**; load it
with Ghidra's ARM:LE:32:Cortex. ZAP shaders are signed PIL/MDT blobs (afuc +
embedded ir3); see project Stage 6.

## Modeling notes (decompiler)

- **Registers** display as `r00`..`r19`, `sp`, `lr` (SLEIGH identifiers can't use
  `$`; the Mesa oracle shows `$00`..`$1b`). `$00` is a real register kept 0 by
  firmware convention (not modeled as a hard constant).
- **Special queue/registers** `data`, `memdata`, `regdata`, `addr`, `usraddr`,
  `rem` are **volatile** pseudo-registers, so FIFO reads / GPU-register writes
  survive optimization and read like memory-mapped I/O (e.g. `r5 = data;`).
- **cread/cwrite/sread/swrite/load/store** lower to `CALLOTHER` pcodeops
  (`qrisc_creg_read/write`, `qrisc_sreg_read/write`, `qrisc_load/store`).
- **Branch delay slots** use SLEIGH `delayslot(1)` (the instruction after a
  branch/call/waitin always executes — verified on the fixtures).
- **call/bl** push a return on a synthetic `hwstack` (cspec stack pointer `csp`)
  and use p-code `call`; **ret/sret** return; **jumpr/waitin** are computed gotos.
- **Approximations (see VALIDATION.md):** the `(rep)/(xmov)/(peek)/(sds)`
  modifiers are decoded but not rendered/semantically modeled in v1 (their bits
  are don't-care); `or $00`→`mov` and `movi … << 0` idioms are not folded;
  control-register immediates show numerically (no `@NAME`) yet.

## Validate

See `VALIDATION.md` for exact commands. Summary: all three languages compile with
the real `sleigh` with zero errors, and a6xx/a7xx disassembly matches the Mesa
reference `.asm` instruction-for-instruction (including delay-slot placement).
