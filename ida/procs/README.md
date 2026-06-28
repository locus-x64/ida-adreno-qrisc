# QRisc (Adreno afuc) IDA processor module

`qrisc.py` is a pure-IDAPython `processor_t` for the Adreno command-processor
microcode ISA ("afuc" / "QRisc"), covering **a6xx and a7xx** (a8xx is decoded
best-effort with the a7xx tables).

It does **not** reimplement the ISA: all decoding and rendering is delegated to
the shared, oracle-validated core in `../../common`
(`qrisc_disasm.Decoder` + `qrisc_isa_tables.py`, byte-exact vs `qrisc-disasm`:
127/127 a6xx, 158/158 a7xx). This module only adapts that core to IDA's
`ev_ana_insn` / `ev_emu_insn` / `ev_out_insn` contract.

## Install

Keep the repository layout (the module locates `../../common` relative to
itself) and either:

* copy `qrisc.py` **and** the `common/` directory into IDA's `procs/`
  directory, preserving a `common/` next to it (or adjust `sys.path`), or
* load it via IDAPython for development.

Then pick **"Adreno command processor (QRisc / afuc)"** as the processor type,
or let `ida/loaders/qrisc_loader.py` select it automatically.

Targets the IDA **9.x** SDK (uses `ida_typeinf` conventions, the
`ev_ana/ev_emu/ev_out` event pipeline, `switch_info_t`-compatible APIs). No
`ida_struct`/`ida_enum` usage.

## Generation selection

The decoder is generation-aware (the gen6→7 ALU-opcode shift, etc.). The module
reads the GPU generation from a netnode set by the loader:

* netnode name `"$ qrisc"`, `altval(0, 'G')` = `6` or `7`.

If the netnode is absent (e.g. opening a raw blob without the loader), it
defaults to **gen 7** (`DEFAULT_GEN`). Set it manually from IDAPython if needed:

```python
import ida_netnode
nn = ida_netnode.netnode("$ qrisc", 0, True)
nn.altset(0, 6, ord('G'))   # force a6xx
```

## What it does

* **ana**: reads one 32-bit LE word, decodes via the shared `Decoder`, sets
  `itype` (one per mnemonic) and `size=4`. For `brne`/`breq`/`jump`/`jumpa`/
  `call`/`bl` it sets a single `o_near` target operand (absolute EA) for
  navigation and xrefs.
* **emu**: adds a fall-through cref into the **delay slot** (every QRisc
  transfer-of-control has one), plus `fl_JN`/`fl_CN` crefs to static branch/call
  targets. Flow is derived in `derive_flow()` from the decoder's operand list +
  leaf name (see note below).
* **out**: renders the decoder's exact text (mnemonic + `(rep)`/`(xmov)`/
  `(sds)`/`(peek)` modifiers + special regs + `@CONTROL_REG` / `%SQE_REG`
  names), with branch/call targets emitted via `out_name_expr` so they are
  clickable.

## Validated vs. requires-IDA

* **Unit-tested without IDA** (`tests/test_proc.py`): the itype table, flow
  classification over both fixtures, specific opcodes (`waitin`, `ret`), and
  target-EA math — all against the shared decoder. `python3 -m py_compile`
  passes.
* **Requires IDA to verify**: the live `processor_t` wiring (segment/auto
  analysis, operand rendering, xref creation in a real database).

## Known simplifications / future work

* **Delay slots**: modeled by always allowing flow into `ea+4`. This favors
  complete coverage at the cost of minor over-analysis a few instructions past
  *unconditional* jumps/returns. A `PR_DELAYED`-based refinement (suppressing
  the post-delay fall-through for unconditional transfers) is a clean follow-up.
* **Operand granularity**: rendering is text-driven (byte-exact); only the
  branch/call target is a structured `o_near` operand. Per-operand `o_reg`/
  `o_imm` typing (for register highlighting) is a possible enhancement.
* **Upstream note for `common/`**: `qrisc_disasm.classify()` keys some checks on
  `leaf['root']`, but every leaf's root resolves to `#instruction`, so its
  branch/ret *root* checks are dead code (the name-based checks still fire for
  call/ret/jumpr/waitin, but `brne`/`breq`/`jump` get no flags). This module
  therefore derives flow itself in `derive_flow()`. Fixing `classify()` upstream
  (key on `leaf['name']` prefixes / the operand kinds) would let both share one
  classifier.
