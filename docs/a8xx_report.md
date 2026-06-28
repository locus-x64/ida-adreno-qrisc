# a8xx (Adreno 8xx) CP Microcode — Reverse-Engineering Validation Report

**Status: best-effort, NO ORACLE.** Mesa's QRisc/afuc tooling has no gen-8 gate and
its decoder *rejects* the a8xx `fw_id`, so there is no reference disassembler to
diff against. Everything below was produced by decoding the a8xx firmware
**as a7xx** (`Decoder(7)`, the only available approach) and comparing it against a
real, oracle-validated a7xx blob (`a730_sqe.fw`). **All "candidate new opcode"
claims require manual confirmation by hand-RE** — they are inferences from a
set-difference against a7xx, not validated decodes.

Date: 2026-06-22. Decoder tables pinned to Mesa commit
`4bf8fd5121122abd87aafb31e43bbbe9e3d2e921` (a7xx is the highest gen modeled).

---

## 1. Firmware obtained

Downloaded from the kernel.org / GitLab `kernel-firmware/linux-firmware` mirror
(`https://gitlab.com/kernel-firmware/linux-firmware/-/raw/main/qcom/`), raw and
**uncompressed** (no `.zst` was needed). Saved to `fixtures/` (gitignored).

| file | bytes | words | SHA-256 (first 16 hex) |
|---|---:|---:|---|
| `gen80000_sqe.fw` | 111476 | 27869 | `30ee3301534f9579…` |
| `gen80100_sqe.fw` | 119828 | 29957 | `bfcc5193269855ba…` |
| `gen80200_sqe.fw` | 118100 | 29525 | `edb2fb1679187c77…` |
| `a730_sqe.fw` (a7xx reference) | 75924 | 18981 | `4f8b288f340ff5b4…` |

All three a8xx blobs were obtained; `a730_sqe.fw` was fetched as the
oracle-validated a7xx baseline for the histogram / set-diff comparison.

---

## 2. Container framing, version, fw_id

`qrisc_fw.parse()` parses all four cleanly. Framing is standard linux-firmware
layout (file word 0 is the skipped header dword; word 1 is the version NOP and
first instruction). **gen is correctly `None`** for all three a8xx blobs (their
`fw_id` is not in the gen map), exactly as predicted — so they are decoded with
`Decoder(7)`.

| file | word0 | version word (file word 1) | fw_id `(v>>12)&0xfff` | gen | "size" word (file word 2) |
|---|---|---|---|---|---|
| `gen80000_sqe` | `0x00000000` | `0x01500077` | **`0x500`** | None | `0x01006cdc` |
| `gen80100_sqe` | `0x00000000` | `0x01700100` | **`0x700`** | None | `0x01007504` |
| `gen80200_sqe` | `0x00000000` | `0x01510088` | **`0x510`** | None | `0x01007354` |
| `a730_sqe` | `0x00000000` | `0x01730181` | `0x730` | 7 | `0x01004a24` |

Notes:
- a8xx `fw_id`s (`0x500`, `0x700`, `0x510`) are **distinct from any a7xx id**
  (`0x730/0x740/0x512/0x520`). `0x700` is *not* `0x730`, so the a7xx gen map does
  not (and should not) match — this is the documented reason `c.gen is None`.
- The version word low byte encodes the build version (`0x77`, `0x100`, `0x88`).
  Both the version word and the "size" word are CP metadata, **not** decodable
  instructions (they are counted as 2 of the undecodables below).
- **`jmptbl_offset_hint` is NOT a jump-table pointer here.** `instrs[1] & 0xffff`
  equals the *total* instruction-word count for every blob (a8xx **and** a730:
  e.g. `0x6cdc = 27868 = len(instr_words)`). It is the image word-count, not an
  offset into the stream. "Up to the jmptbl offset hint" therefore means the
  whole stream; coverage below is computed over the full instruction stream, and
  a730 is measured identically (apples-to-apples). There is no clean code/data
  split: undecodable data pockets are interspersed throughout (around word
  indices ~5k, ~6k, ~12k, ~17k), with the packet/handler jump-table and an ASCII
  build-version string sitting at the very tail.

---

## 3. BR / BV / LPAC bundle layout (Step 2)

a8xx is an **a7xx-style BR+BV(+LPAC) bundle** in a single `_sqe.fw`. The
bootstrap programs the sub-image bases via `cwrite` to the a7xx control offsets
(decoded under `A7XX_CONTROL_REG`):

```
gen80000_sqe.fw bootstrap:
  [  265] 0xa80200d6  cwrite $02, [$00 + @BV_INSTR_BASE]       ; off 0xd6 = 214
  [  267] 0xa80200d7  cwrite $02, [$00 + @BV_INSTR_BASE+0x1]
  ... (BV_INSTR_BASE / LPAC_INSTR_BASE referenced 60x total)
```

`@BV_INSTR_BASE` (off 214) and `@LPAC_INSTR_BASE` (off 217) are both written,
confirming a BR/BV/LPAC split. **The exact BV/LPAC boundary offsets are NOT in a
static header** — they are computed at runtime and require bootstrap emulation to
recover (see the `qrisc_fw.split_subimages` docstring). That is out of scope for
this best-effort pass; the whole stream is analyzed as one image (the BR image
plus the appended BV/LPAC images). a730 additionally flags `@BV_CNTL`/`@LPAC_CNTL`
writes in its bootstrap; in a8xx those specific control offsets were not flagged
near the base writes (a8xx may sequence the cntl writes differently), which is a
candidate area for hand-RE.

---

## 4. Decode coverage (Step 3)

Coverage = % of instruction-stream words that decode to a known a7xx **leaf**
under `Decoder(7)`. **Important: this measures "decodes to *some* leaf," not
"decodes *correctly*."** Opcode *values* changed silently across generations
before (a6xx→a7xx remapped `shl`/`ishr`/`rot`/`cmp` — see `research.md`). If a8xx
similarly remapped an existing opcode value, `Decoder(7)` would decode it to the
**wrong** mnemonic and still count it as "covered," inflating the percentage and
hiding the change. A same-frequency value swap is **undetectable without an
oracle**. What *can* be argued against a wholesale remap: (i) the bootstrap and
hot paths decode into coherent, in-context sequences (`cwrite @BV_INSTR_BASE`,
`and $12, 0x7`, `cread`/`add`/`breq` chains that make semantic sense), and
(ii) the mnemonic histogram matches a730 (§6). That rules out *large-scale*
remapping, but not a quiet single-value swap. Read the coverage numbers with that
residual caveat.

| file | words | undecodable | **coverage** |
|---|---:|---:|---:|
| `gen80000_sqe` | 27868 | 1653 | **94.07 %** |
| `gen80100_sqe` | 29956 | 1849 | **93.83 %** |
| `gen80200_sqe` | 29524 | 1940 | **93.43 %** |
| `a730_sqe` (a7xx reference) | 18980 | 1233 | **93.50 %** |

**Headline finding: a8xx decodes as cleanly as — or cleaner than — a real a7xx
blob.** The gen-7 **decoder** is oracle-validated (the repo's `test_disasm.py`
passes 158/158 instructions on the synthetic `qrisc_test_a7xx.fw` against Mesa's
reference). `a730_sqe.fw` is a *genuine* a7xx blob decoded with that validated
decoder — it has no oracle of its own, so its ~6.5% undecodable words are
**presumed data** (embedded constants, jump-table entries, the ASCII build
string), not missing opcodes. a8xx sits in the same band. This is strong empirical support
for the task's premise: **a8xx reuses the a7xx QRisc CP ISA; there is no new core
and most undecodables are interspersed data, not new instructions.**

### Undecodable bucketing

Undecodable words bucketed by high opcode bits. The honest interpretation: the
bulk are data. The signal is the **set-difference** — opcode signatures that
appear undecodable in a8xx but are *entirely absent* from a730.

`[26:31]` buckets present in a8xx but NOT in a730 (identical across all three a8xx
blobs): **`0x26`, `0x2c`, `0x37`**.
`[27:31]` buckets present in a8xx but not a730: **`0x13`, `0x16`, `0x1b`**.

`[0:4]` (low-opcode-field) bucketing of the undecodables is **not discriminating
on its own**: all 32 values occur in both a8xx and a730 (data words have
uniformly distributed low bits), so no `[0:4]` value is a8xx-exclusive. The signal
lives only in the *combination* with the high bits (the §5 candidates), e.g.
`[26:31]=0x26 AND [0:4]=0x1c` together — not `[0:4]=0x1c` alone.

---

## 5. Candidate NEW a8xx encodings (set-diff, instruction-like)

Three signatures pass the discriminators: (a) present in a8xx, absent in a730;
(b) observed **inside real decoded code flow** (surrounded by valid
`cread`/`add`/`breq`/`cwrite`); and (c) instruction-like. For §5a/§5b the
instruction-like evidence is **varying operand bits** (not a repeated constant or
a small data value). For §5c the words are *repeated constants* — but that is
**expected** of a low/no-operand control-flow op, so 5c's evidence is instead its
new family sub-opcode plus its delay-slot / `nop`-padding context (see §5c). All
three appear in **all three** a8xx blobs and **zero** times in a730:

| signature | gen80000 | gen80100 | gen80200 | a730 | distinct words |
|---|---:|---:|---:|---:|---:|
| `[26:31]=0x26` & `[0:4]=0x1c` (`0x98….1c`) | 13 | 15 | 14 | **0** | 5 |
| `[26:31]=0x2c` & bit15 set (`0xb….8000`) | 26 | 26 | 26 | **0** | 11 |
| `[26:31]=0x37` (`0xdc…/0xdd…`) | 11 | 15 | 15 | **0** | 3 |

### 5a. `0x98xxxxxx` with `[0:4]=0x1c` — candidate new ALU op

a7xx ALU 2-src ops live in the `0x98……` space with the 5-bit opcode in **bits
[0:4]**; the highest defined value is ~`0x1a`. These words carry `[0:4]=0x1c`
(28), an **undefined a7xx ALU opcode**. Operand fields ([20:16] dst, [25:21] src)
vary across occurrences. Example, in real code:

```
[1460] 0xb8040066  cread $04, [$00 + 0x066]
[1461] 0x98643001  add  $06, $03, $04
[1462] 0xc4c00008  breq $06, 0x0, #0x5be
[1463] 0x9803181c  <CANDIDATE>   ; opcode[0:4]=0x1c, dst=$03, src=$03
[1464] 0x9804201c  <CANDIDATE>   ; dst=$04
[1465] 0x98641801  add  $03, $03, $04
```

Distinct words: `0x9803181c, 0x9804201c, 0x980a401c, 0x9805281c, 0x9804e01c`.
**Hypothesis:** a new a8xx 2-src ALU operation (the a7xx ALU family already grew
`bic/setbit/clrbit/ubfx/bfi` over a6xx, so a new value 0x1c fits the pattern of
incremental ALU additions). Needs hand-RE to name and determine semantics.

### 5b. `0xb0/0xb1….8000` — candidate new load/store variant

Nearest a7xx leaf is `load` (`match=0xb0000000, mask=0xf800b000`); these words
set **bit 15** (`0x8000`), which the `load` mask requires to be 0, so they fall
outside the known encoding. Observed adjacent to `cwrite` in real code:

```
[5190] 0xa8020142  cwrite $02, [$00 + 0x142]
[5191] 0xb1878000  <CANDIDATE>
[5192] 0xb1888004  <CANDIDATE>
[5193] 0xa8670020  cwrite $07, [$03 + 0x020]
[5194] 0xb1878008  <CANDIDATE>
```

11 distinct words (`0xb1878000, 0xb1888004, 0xb0528000, 0xb0578004, …`). The low
nibble varies (`…0000/…8004/…8008/…800c`), consistent with an offset/sub-field.
**Hypothesis:** a new a8xx load/store (or memory-access) variant in the `0xb…`
space. Needs hand-RE.

### 5c. `0xdc…/0xdd…` (`[26:31]=0x37`) — candidate new branch/control-flow op

`[26:31]=0x37` is the a7xx "new-style branch" family (`sret` `0xdf600000`,
`jumpr` `0xdf700000`). These candidates share the family-6-bit opcode but use new
sub-opcodes in `[21:25]` = `{2, 3, 12}` (a7xx defines the higher values for
sret/jumpr). Observed in a clear control-flow position (after `brne`+`nop`,
followed by `nop` padding — i.e. a delay-slot / return-like site):

```
[12375] 0x6843308a  cmp  $03, $02, 0x308a
[12376] 0xc8620032  brne $03, b2, #0x308a
[12377] 0x01000000  nop
[12378] 0xdc400000  <CANDIDATE>   ; [26:31]=0x37, [21:25]=0x02
[12379] 0x01000000  nop
```

Distinct words: `0xdc400000, 0xdc600000, 0xdd800000`. **Hypothesis:** a new a8xx
branch/return/preempt-class instruction in the new-branch family. This is the
highest-value candidate for hand-RE because mis-decoding control flow silently
corrupts the whole function graph.

> Caveat: a bucket "absent in a730" can also mean a730 simply never used that
> *data* pattern. The discriminators above (varying operand bits + embedding in
> live code) make the instruction interpretation likely, but **not certain**.
> Each must be confirmed against the actual a8xx execution semantics by hand.

---

## 6. Mnemonic histogram anomalies (Step 4)

`gen80000_sqe` vs `a730_sqe`, % of instruction stream:

| mnemonic | gen80000 % | a730 % | note |
|---|---:|---:|---|
| cwrite | 18.49 | 17.08 | — |
| movi | 12.74 | 12.42 | — |
| or | 11.41 | 12.63 | — |
| cread | 7.65 | 6.94 | — |
| nop | 7.27 | 6.60 | — |
| brne | 6.60 | 6.73 | — |
| `<UNDECODED>` | **5.93** | **6.50** | a8xx slightly *cleaner* |
| breq | 5.34 | 5.68 | — |
| call | 3.81 | 4.42 | — |
| ubfx | 2.08 | 1.83 | — |
| **bfi** | **0.52** | **0.16** | ~3× more frequent in a8xx |
| **setbit** | **1.14** | **0.73** | ~1.6× more frequent in a8xx |

**No structural anomalies.** The distribution is essentially identical to a7xx —
same mnemonics, same rough proportions. The only deltas are usage-frequency bumps
in existing a7xx bitfield ops (`bfi`, `setbit`, `clrbit`, `ubfx`), consistent
with more bitfield manipulation in a8xx code, not new instructions. This
corroborates the same-ISA conclusion.

---

## 7. CVE-2025-21479 / `@IB_LEVEL` / `$12` (Step 5)

**Background:** CVE-2025-21479 was a `0x3 → 0x7` mask widening on accesses to the
IB-level GPR `$12`. The vulnerable a7xx instruction was
`0x2a440003 = and $04, $12, 0x3`; the fix is `0x2a440007 = and $04, $12, 0x7`.
a7xx added IB3, so the old `&0x3` mask let the set-draw-state buffer alias the
kernel ring buffer.

**a8xx finding — the vulnerable instruction is ABSENT; only the patched mask
appears, in all three a8xx blobs.** (Stated this way the finding is robust
regardless of whether `$12` still holds the IB level on a8xx — see the caveat
below; the mask itself is the load-bearing fact.)

| file | `and $*, $12, 0x7` | `and $*, $12, 0x3` (vuln) |
|---|---:|---:|
| `gen80000_sqe` | 61 | **0** |
| `gen80100_sqe` | 63 | **0** |
| `gen80200_sqe` | 62 | **0** |
| `a730_sqe` (patched) | 52 | **0** |

Every `and` against `$12` uses mask `0x7`; **zero** uses `0x3`. The exact patched
CVE instruction is present verbatim, e.g. `gen80000_sqe[563] = 0x2a440007 =
and $04, $12, 0x7` (the patched form of the CVE's `0x2a440003`). All three a8xx
firmwares therefore ship with the post-CVE-2025-21479 mask. (The fixtures are
current linux-firmware, well after the May-2025 patch, so this is expected and
confirmed empirically rather than assumed.)

**`@IB_LEVEL` (control register, offset 0x54 = 84) accesses** (decoded under
`A7XX_CONTROL_REG`):

```
gen80000_sqe (8 refs):
  [ 5868] 0xa8000054  cwrite $00,       [$00 + @IB_LEVEL]
  [ 6506] 0xb8050054  cread  $05,       [$00 + @IB_LEVEL]
  [ 6668] 0xa81d0054  cwrite $memdata,  [$00 + @IB_LEVEL]
```

vs a730 (45 refs, frequently `cwrite $12, [@IB_LEVEL]` — directly tying GPR `$12`
to the IB_LEVEL control register).

Observations:
- The offset-0x54 control register decodes consistently in a8xx and is exercised
  (read + written). The CVE's IB-level masking logic (`$12 & 0x7`) is present and
  patched.
- a8xx makes **far fewer** `@IB_LEVEL` refs (8 vs 45) and does **not** use the
  `cwrite $12, [@IB_LEVEL]` idiom that a730 uses pervasively. This suggests a8xx
  may restructure how IB-level is mirrored into the control register (possibly
  fewer redundant writes, or a relocated handler). Worth hand-RE.
- **Caveat:** the `@IB_LEVEL` *name* and offset come from the **a7xx** control-reg
  map (`A7XX_CONTROL_REG`, IB_LEVEL=84=0x54). The numeric offset (0x54) is what
  the firmware actually encodes and is reliable; the `@NAME` annotation is
  a7xx-assumed and **unverified for a8xx**. a8xx could have relocated IB_LEVEL
  (note `A7XX_GEN3_CONTROL_REG` already moves it to offset 61). Treat the symbol
  as a hint, the offset as fact.

---

## 8. Recommendations for hand-RE

1. **Treat a8xx as a7xx-plus.** Decode with `Decoder(7)`; ~94% is already
   correct. Focus manual effort only on the three candidate signatures in §5.
2. **Priority order for naming:**
   (1) the `0x37`/`0xdc` branch-family candidate (§5c) — control flow, highest
       blast radius if mis-decoded;
   (2) the `0x98…1c` ALU candidate (§5a) — likely a simple new 2-src ALU op;
   (3) the `0xb…8000` load/store candidate (§5b).
   Build masks/matches for each from the observed bit layout, add them to the
   ISA tables as gen-8 leaves, and re-measure coverage (expect it to rise toward
   the a730 data-floor of ~6.5% undecodable).
3. **Recover BV/LPAC boundaries** by emulating the bootstrap (the values written
   to `@BV_INSTR_BASE`/`@LPAC_INSTR_BASE`), then re-run coverage per sub-image —
   data-vs-code pockets may differ between BR/BV/LPAC.
4. **Add the a8xx `fw_id`s** (`0x500`, `0x700`, `0x510`) to a future gen map only
   once a real gen-8 table exists; until then, **keep decoding as a7xx** and do
   **not** silently map them to gen 7 (the current `gen=None` behavior is the
   correct, honest state).
5. **Confirm semantics, not just encodings.** Every claim here is a static
   set-difference. Validate the three candidates and the IB_LEVEL restructuring
   by tracing data flow / running the bootstrap, since **there is no oracle**.
6. **Cross-check the three blobs.** `gen80100` has a distinct `fw_id` (0x700) and
   the largest size; if encodings ever diverge between the three, gen80100 is the
   most likely to expose a8xx-only behavior.

---

## 9. Method / reproducibility

- Decoder: `common/qrisc_disasm.Decoder(7)` over `common/qrisc_fw.parse().instr_words`.
- The gen-7 decoder is oracle-validated by the repo's `tests/test_disasm.py`
  against Mesa's reference on the synthetic corpus (127/127 a6xx, 158/158 a7xx,
  0 mismatches). `a730_sqe.fw` is a real a7xx blob decoded with that validated
  decoder (no oracle of its own); its undecodables are presumed data.
- Smoke test: `tests/test_a8xx_smoke.py` (skips if blobs absent; asserts parse +
  coverage ≥ 90 %, conservatively below the observed ~93.4–94.1 %).
- All analysis is read-only over `fixtures/`; no Mesa/IDA/Ghidra dependency.

---

## Addendum: distinguishing two separate a8xx observations

Two findings here must not be conflated:

1. **Static "candidate-new encodings"** (the set-diff of undecodable words present in all
   three a8xx `_sqe.fw` blobs but absent in real a7xx `a730_sqe.fw`). These are legitimate
   decode-coverage evidence and are the right targets for hand-RE.

2. **Bootstrap-emulator divergence** (`common/qrisc_emu.py` hitting a `0xfbadc0de` poison
   word during a8xx bootstrap). This is the emulator reaching an **unmodeled memory/register
   path**, i.e. a bootstrap step it does not yet emulate — it is **not** by itself proof of a
   new instruction. The emulator therefore falls back gracefully (empty packet table) on a8xx.

Confirming whether (1) and (2) share a root cause requires hand-RE of the a8xx bootstrap
routine; until then they are reported as independent observations.
