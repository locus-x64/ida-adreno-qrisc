# QRisc SLEIGH — validation

Environment: Ghidra **12.1.2** (public release), OpenJDK 21. The compiler and a
headless decode test were run locally; results below are reproducible.

## 1. SLEIGH compile — VERIFIED (zero errors)

```
GH=ghidra/.tools/ghidra_12.1.2_PUBLIC
LD=ghidra/Ghidra/Processors/QRisc/data/languages
python3 ghidra/tools/qrisc_sleigh_gen.py            # regenerate .sinc from tables
"$GH/support/sleigh" "$LD/qrisc_a6xx.slaspec"       # -> qrisc_a6xx.sla
"$GH/support/sleigh" "$LD/qrisc_a7xx.slaspec"       # -> qrisc_a7xx.sla
"$GH/support/sleigh" "$LD/qrisc_a8xx.slaspec"       # -> qrisc_a8xx.sla
```

All three compile with **no errors**. One benign warning ("1 operation wrote to
temporaries that were not read") from the `nop` placeholder. The languages also
load cleanly in Ghidra (headless `-processor QRisc:LE:32:a6xx` succeeds).

Coverage: 53 constructors for a6xx, 61 for a7xx (every leaf in `common/
qrisc_isa_tables.py` for that gen; all shapes classified, no `UNKNOWN`).

## 2. Decode correctness vs the Mesa oracle — VERIFIED (a6xx, a7xx)

The reference `.asm` files in `fixtures/` are the canonical `qrisc-disasm` output.
Headless disassembly of the matching `.fw` (leading word stripped, base 0,
`QRiscFirmwareHelper`/`DumpAsm`) matches the oracle **instruction-for-instruction**.

Example (a6xx `qrisc_test.fw`, bootstrap):

| oracle (`qrisc-disasm`)            | this module (Ghidra)             |
|------------------------------------|----------------------------------|
| `mov $01, 0x830`                   | `mov r01,0x830,0x0`              |
| `cwrite $01,[$00 + @REG_READ_ADDR]`| `cwrite r01,[r00 + 0x27]`        |
| `mov $01, $regdata`                | `or r01,r00,regdata`            |
| `add $01, $01, 0x4`                | `add r01,r01,0x4`               |
| `rot $04, $memdata, 0x8`           | `rot r04,memdata,0x8`           |
| `mov $04, 0xdead << 16`            | `mov r04,0xdead,0x10`           |
| `waitin` / `mov $01, $data`        | `waitin` / `_or r01,r00,data`   |

The `_or` after `waitin` is Ghidra's **delay-slot marker** — confirming delay
slots are modeled correctly. a7xx (`qrisc_test_a7xx.fw`) likewise matches,
including the gen6→7 ALU opcode shifts and the **12-bit** immediate form
(`rot r04,memdata,0x8`, `ushr r04,r04,0x6` — not the 16-bit form).

Reproduce:
```
tail -c +5 fixtures/qrisc_test.fw > /tmp/a6.bin
cp -r ghidra/Ghidra/Processors/QRisc "$GH/Ghidra/Processors/QRisc"   # install
"$GH/support/analyzeHeadless" /tmp/p q -import /tmp/a6.bin \
    -processor QRisc:LE:32:a6xx -loader BinaryLoader -loader-baseAddr 0x0 \
    -scriptPath ghidra/tools -postScript DumpAsm.java -noanalysis -deleteProject
```

Differences are **cosmetic and documented** (see README "Modeling notes"):
register names `rNN` vs `$NN`; `or $00`→`mov` idiom not folded; `movi` shift shown
as an operand instead of `<< n`; control-reg immediates numeric (no `@NAME`).

## 3. Decompiler (p-code) — STRUCTURALLY VERIFIED, output review PENDING

The p-code semantics compile and the volatile-register / pcodeop / delayslot /
call-ret model is in place, so F5 produces pseudocode. A systematic review of
decompiled `CP_*` handler quality (and tuning `qrisc_*` pcodeop signatures) is the
remaining polish item; it requires the Stage-3 packet-table analyzer to name
handlers first.

## 4. Known approximations (tracked)

- `(rep)/(xmov)/(peek)/(sds)` modifiers: decoded (bits don't-care) but not shown
  or semantically modeled. `(rep)` (repeat `$rem` times) and `(xmov)` (extra
  moves) have real side effects not yet modeled.
- `preincrement` (`!`): shown; the offset-register update side effect not modeled.
- `setsecure`: pcodeop only; its conditional 2-instruction skip not modeled.
- `load/store` ignore the 64-bit-address high half from `@LOAD_STORE_HI`.
- `$00`-reads-zero and the `or $00`→`mov` / `brne $00,b0`→`jump` idioms: the
  unconditional-jump form IS emitted (more-specific constructor); the `mov` and
  zero-source folds are not.
- a8xx: decoded as a7xx; unverified for any a8xx-only encodings.
