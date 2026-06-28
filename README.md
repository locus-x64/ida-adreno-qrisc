# ida-adreno-qrisc

**Reverse-engineering toolkit for Qualcomm Adreno GPU command-processor (CP) microcode** —
the 32-bit microcontroller ISA that Mesa calls **afuc** / **QRisc** (renamed in Mesa 26.1.0).

Covers the modern unified-SQE generations **a6xx, a7xx, and a8xx** (a8xx is best-effort),
plus the auxiliary firmware cores (ZAP, GMU). Also handles legacy a5xx PFP+PM4 enough to load.

| Backend  | What you get | Status |
|----------|--------------|--------|
| **IDA Pro 9.x** | Processor module + loader → disassembly, xrefs/call-graph, packet-table → `CP_*` handler naming | **99.89% instruction-level match vs `qrisc-disasm`** on real `a740_sqe.fw` |
| **Ghidra 12.x** | SLEIGH language → disassembly **+ decompiler** (Hex-Rays doesn't expose a third-party decompiler API; SLEIGH gives one for free) | Compiles cleanly; headless decode matches the oracle |

Both backends are driven from **one ISA generator** that reads Mesa's
`qrisc.xml`/`adreno_pm4.xml`/`adreno_control_regs.xml` and emits standalone
Python tables — so neither runtime backend depends on Mesa.

> **Why this exists.** The CP firmware (`*_sqe.fw`, `*_pfp.fw`/`*_pm4.fw`) is exactly
> what parses and executes the PM4 command stream. Being able to read it in IDA or
> Ghidra is valuable for GPU security research (e.g. **CVE-2025-21479** was a single
> `and $x, $12, 0x3 → 0x7` mask change in `gen70900_sqe.fw`) and for open-source
> driver work (freedreno, Turnip). No public IDA / Ghidra module for this ISA
> existed before.

---

## Quickstart

### IDA Pro

```sh
git clone https://example.invalid/ida-adreno-qrisc
cd ida-adreno-qrisc
sudo ./ida/install.sh /opt/idapro-9.0      # adjust to your IDA path
```

Then in IDA, open any `*_sqe.fw` / `*_pfp.fw` / `*_pm4.fw` / `*_zap.{mdt,mbn}` /
`*_gmu.bin`. The loader auto-detects the GPU generation; the processor module
disassembles using oracle-validated tables.

If you'd rather not copy into IDA, set `QRISC_HOME` and just drop the four entry
files into `procs/` and `loaders/`:
```sh
export QRISC_HOME=$PWD
```

### Ghidra (decompiler)

```sh
cp -r ghidra/Ghidra/Processors/QRisc <GHIDRA_INSTALL_DIR>/Ghidra/Processors/
# restart Ghidra
```

See [`ghidra/README.md`](ghidra/README.md) for details, language IDs, and the
`QRiscFirmwareHelper` post-import script that marks the version/jumptable NOPs.

### Test it locally (no IDA / Ghidra needed)

```sh
python3 -m pip install --user pytest
python3 -m pytest -q                 # 47 tests
python3 tests/test_disasm.py         # decoder vs qrisc-disasm oracle
```

---

## Verified

| Target | Result |
|---|---|
| Mesa fixture `qrisc_test.fw`       (a6xx) | **127 / 127** byte-exact vs `qrisc-disasm` |
| Mesa fixture `qrisc_test_a7xx.fw`  (a7xx) | **158 / 158** byte-exact vs `qrisc-disasm` |
| Real `a660_sqe.fw` (a6xx, ~10 KB)         | Loads; all 80 `CP_*` handlers recovered + named; bootstrap + handlers disassemble |
| Real `a730_sqe.fw` (a7xx, ~75 KB)         | Bootstrap emulator recovers packet table + BR/BV/LPAC split |
| Real `a740_sqe.fw` (a7xx, ~75 KB)         | **17,455 / 17,474 = 99.89% instruction-level match** vs `qrisc-disasm`; the 0.11% gap is `qrisc-disasm` false-positives inside a data table |
| Real `gen80000/80100/80200_sqe.fw` (a8xx) | Loads; ~93–94% decode coverage (≈ a7xx baseline). All shipped blobs carry the *patched* CVE-2025-21479 mask (`& 0x7`); the vulnerable `& 0x3` form is absent |
| Ghidra SLEIGH (a6xx, a7xx, a8xx)          | All three languages compile under Ghidra 12.1.2; headless decode matches the oracle |
| `pytest` suite                            | 47 / 47 |

---

## Repository layout

```
gen/qrisc_isa_gen.py        # generator: Mesa qrisc.xml -> standalone tables
common/
  qrisc_isa_tables.py       # AUTO-GENERATED decode tables (pinned Mesa commit)
  qrisc_disasm.py           # standalone decoder/renderer (oracle-validated)
  qrisc_fw.py               # .fw container parser (gen detect, header, split)
  qrisc_pm4.py              # baked PM4 CP_* opcode -> name DB
  qrisc_bootstrap.py        # packet-table + BR/BV/LPAC recovery
  qrisc_emu.py              # QRisc bootstrap emulator (port of Mesa emu.c)
  qrisc_pil.py              # Qualcomm PIL/MDT (ZAP) container parser
ida/
  procs/qrisc.py            # IDA processor module
  loaders/qrisc_loader.py   # IDA loader for SQE/PFP/PM4 .fw
  loaders/qrisc_zap_loader.py    # ZAP shader loader
  loaders/qrisc_gmu_loader.py    # GMU -> ARM Cortex-M routing
  install.sh
ghidra/
  Ghidra/Processors/QRisc/  # SLEIGH language + scripts
  tools/qrisc_sleigh_gen.py # SLEIGH-from-tables generator
  README.md  VALIDATION.md
fixtures/                   # license-clean Mesa test corpus (only)
tests/                      # 47 unit tests
docs/                       # a8xx-report, aux-cores, research-notes
```

---

## Regenerating the ISA tables

`common/qrisc_isa_tables.py` is generated from Mesa, pinned at commit
`4bf8fd5121122abd87aafb31e43bbbe9e3d2e921`. To refresh against a newer Mesa:

```sh
git clone --no-checkout --depth 1 --filter=blob:none \
    https://gitlab.freedesktop.org/mesa/mesa.git third_party/mesa
git -C third_party/mesa sparse-checkout set src/freedreno src/compiler/isaspec
git -C third_party/mesa checkout
python3 gen/qrisc_isa_gen.py
python3 -m pytest -q                # 47/47 must hold
```

The generator reuses Mesa's own `isa.py` parser at generation time to resolve
`extends` chains, `<gen>` gates, fields, overrides, and display templates, then
emits plain-data tables. The runtime (IDA / Ghidra) has zero Mesa dependency.

---

## Known limitations

- **No decompiler in IDA** for QRisc — Hex-Rays exposes no third-party API for a
  custom-ISA decompiler. Use the Ghidra SLEIGH module for decompilation.
- **a8xx is best-effort** — same QRisc ISA family as a7xx (no new core), but some
  candidate a8xx-only encodings remain to be reverse-engineered (see
  `docs/a8xx_report.md`). The bootstrap emulator falls back to a static
  packet-table content scan on a8xx.
- The IDA processor module and loaders are validated by unit tests + structural
  review + a real-blob diff against `qrisc-disasm` (99.89% on a740). Full
  behavior with very large databases needs further field testing.

---

## License & attribution

This project is licensed under the **MIT License** (see [LICENSE](LICENSE)).

ISA definitions and PM4 packet names are generated from
[Mesa 3D](https://gitlab.freedesktop.org/mesa/mesa) (MIT-licensed) — see
[NOTICE](NOTICE) for details and the pinned upstream commit. The license-clean
test fixtures in `fixtures/` are reproduced from Mesa's own tests.

Adreno, Qualcomm, and Snapdragon are trademarks of Qualcomm Incorporated. This
project is unaffiliated with Qualcomm.
