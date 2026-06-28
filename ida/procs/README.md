# QRisc (Adreno afuc) IDA processor module

`qrisc.py` is a pure-IDAPython `processor_t` for the Adreno CP microcode ISA,
covering a6xx and a7xx. a8xx is decoded best-effort with the a7xx tables.

All decoding and rendering is delegated to the shared core in `../../common`
(`qrisc_disasm.Decoder` + `qrisc_isa_tables.py`, byte-exact vs `qrisc-disasm`).
This module only adapts that core to IDA's `ev_ana_insn` / `ev_emu_insn` /
`ev_out_insn` contract.

## Install

Use `ida/install.sh` (recommended), or keep the repository layout and let the
module locate `../../common` relative to itself. Pick **"Adreno command
processor (QRisc / afuc)"** as the processor type, or let
`ida/loaders/qrisc_loader.py` set it.

Targets IDA 9.x: `ida_typeinf`, the `ev_ana/ev_emu/ev_out` events,
`switch_info_t`-compatible APIs. No `ida_struct`/`ida_enum`.

## Generation selection

The decoder is generation-aware (gen6 -> gen7 ALU opcode shift, etc.). The
module reads the generation from a netnode set by the loader:

- netnode name `"$ qrisc"`, `altval(0, 'G')` = `6` or `7`.

If the netnode is absent, defaults to gen 7. Force it from IDAPython:

```python
import ida_netnode
nn = ida_netnode.netnode("$ qrisc", 0, True)
nn.altset(0, 6, ord('G'))
```

## What it does

- **ana**: reads one 32-bit LE word, decodes via the shared `Decoder`, sets
  `itype` (one per mnemonic) and `size=4`. For
  `brne`/`breq`/`jump`/`jumpa`/`call`/`bl`, sets a single `o_near` target.
- **emu**: adds a fall-through cref into the delay slot (every QRisc
  transfer-of-control has one), plus `fl_JN`/`fl_CN` crefs to static
  branch/call targets. Flow is derived in `derive_flow()`.
- **out**: renders the decoder's text (mnemonic + `(rep)`/`(xmov)`/`(sds)`/
  `(peek)` modifiers + special regs + `@CONTROL_REG`/`%SQE_REG` names), with
  branch/call targets via `out_name_expr` so they're clickable.

## Validated vs requires-IDA

- Unit-tested without IDA (`tests/test_proc.py`): itype table, flow
  classification over both fixtures, specific opcodes (`waitin`, `ret`),
  target-EA math. `python3 -m py_compile` passes.
- Requires IDA to verify: live `processor_t` wiring (auto analysis, operand
  rendering, xref creation in a real database).

## Known simplifications

- Delay slots are modeled by always allowing flow into `ea+4`. Trades minor
  over-analysis past unconditional jumps/returns for complete coverage. A
  `PR_DELAYED`-based refinement is a clean follow-up.
- Rendering is text-driven (byte-exact); only branch/call targets are
  structured `o_near` operands. Per-operand `o_reg`/`o_imm` typing is
  possible.
- `qrisc_disasm.classify()` keys some checks on `leaf['root']`, but every
  leaf's root resolves to `#instruction`, so its branch/ret root checks are
  dead code. The module derives flow itself in `derive_flow()`. Fixing
  `classify()` to key on `leaf['name']` would let both share one classifier.
