# QRisc (Adreno afuc) Ghidra SLEIGH module

A Ghidra processor module + decompiler for the Adreno CP microcode ISA Mesa
calls `afuc` / `QRisc` (SQE / PFP / PM4 firmware). Ghidra's decompiler runs
on SLEIGH-generated p-code, so this module gives you disassembly and a
decompiler. IDA can't, because Hex-Rays exposes no third-party API for
custom-ISA decompilation.

Generated from Mesa `qrisc.xml` (isaspec), pinned at
`4bf8fd5121122abd87aafb31e43bbbe9e3d2e921`, via `common/qrisc_isa_tables.py`.

## Supported generations

| Language id          | Adreno gen | Status |
|----------------------|-----------|--------|
| `QRisc:LE:32:a6xx`   | a6xx (unified SQE)          | validated against Mesa oracle |
| `QRisc:LE:32:a7xx`   | a7xx (split BR/BV + LPAC)   | validated against Mesa oracle |
| `QRisc:LE:32:a8xx`   | a8xx                        | best-effort; same ISA family as a7xx, decoded with the a7xx constructor set. Any a8xx-only opcodes/control-regs need RE. |

a5xx is intentionally out of scope.

## Install

1. `cp -r ghidra/Ghidra/Processors/QRisc <GHIDRA>/Ghidra/Processors/QRisc`
2. Restart Ghidra. The three QRisc languages appear under processor "QRisc".

Rebuild the `.sla` after editing a spec:
`<GHIDRA>/support/sleigh Ghidra/Processors/QRisc/data/languages/qrisc_a6xx.slaspec`
(and a7xx / a8xx).

Regenerate the SLEIGH from the ISA tables (tracks Mesa upstream):
`python3 ghidra/tools/qrisc_sleigh_gen.py`

## Importing firmware

CP firmware files (`a630_sqe.fw`, `gen70900_sqe.fw`, ...) begin with a leading
file word the running CP skips; the version NOP and instruction stream begin
at file **word 1** (matching Mesa `qrisc-disasm`, which does
`instrs = &buf[1]`).

Single-SQE quick path:

1. Strip the leading word: `tail -c +5 a630_sqe.fw > a630.stream`
2. **Import File** -> `a630.stream`, Language `QRisc:LE:32:a6xx`
   (a730/gen709xx -> a7xx; gen80xxx -> a8xx), base `0x0`.
3. Run the **QRiscFirmwareHelper** script (category QRisc): marks the
   version/jumptbl NOPs as data, reports the packet jump-table offset, and
   disassembles `bootstrap` at word 2.

a7xx/a8xx blobs bundle BR + BV (+ LPAC) in one `_sqe.fw`. Splitting is in
`common/qrisc_bootstrap.py`; import each sub-image separately or extend the
helper.

GMU firmware (`*_gmu.bin`) is a separate ARM Cortex-M core, not QRisc. Load
with `ARM:LE:32:Cortex`. ZAP shaders are signed PIL/MDT blobs (afuc + ir3).

## Modeling notes

- Registers display as `r00`..`r19`, `sp`, `lr`. SLEIGH identifiers can't use
  `$`; Mesa shows `$00`..`$1b`. `$00` is a real register kept 0 by firmware
  convention, not a hard constant.
- `data`, `memdata`, `regdata`, `addr`, `usraddr`, `rem` are volatile
  pseudo-registers so FIFO reads / GPU register writes survive optimization
  and read like MMIO (`r5 = data;`).
- `cread`/`cwrite`/`sread`/`swrite`/`load`/`store` lower to `CALLOTHER`
  pcodeops (`qrisc_creg_read/write`, `qrisc_sreg_read/write`,
  `qrisc_load/store`).
- Branch delay slots use SLEIGH `delayslot(1)`.
- `call`/`bl` push a return on synthetic `hwstack` (cspec sp `csp`) and use
  p-code `call`; `ret`/`sret` return; `jumpr`/`waitin` are computed gotos.
- v1 approximations (see `VALIDATION.md`): `(rep)/(xmov)/(peek)/(sds)`
  modifiers are decoded but not semantically modeled; `or $00` -> `mov` and
  `movi << 0` are not folded; control-reg immediates show numerically.

## Validate

See `VALIDATION.md`. All three languages compile with `sleigh` zero-error;
a6xx/a7xx disassembly matches Mesa's reference `.asm` instruction-for-
instruction including delay slots.
