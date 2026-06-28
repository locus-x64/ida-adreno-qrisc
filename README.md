# ida-adreno-qrisc

Reverse-engineering tooling for Qualcomm Adreno GPU command-processor (CP)
microcode. The ISA is what Mesa calls `afuc` (renamed `QRisc` in 26.1.0).

Covers a6xx, a7xx, and a8xx (a8xx is best-effort), plus the auxiliary
firmware cores (ZAP, GMU). Legacy a5xx PFP+PM4 loads but isn't fully tested.

| Backend  | What you get | Status |
|----------|--------------|--------|
| IDA Pro 9.x | Processor module + loader: disassembly, xrefs, packet-table -> `CP_*` handler naming | 99.89% instruction match vs `qrisc-disasm` on real `a740_sqe.fw` |
| Ghidra 12.x | SLEIGH language: disassembly + decompiler (Hex-Rays has no third-party decompiler API; SLEIGH does) | Compiles cleanly; headless decode matches the oracle |

One ISA generator reads Mesa's `qrisc.xml` / `adreno_pm4.xml` /
`adreno_control_regs.xml` and emits standalone Python tables. Neither runtime
backend depends on Mesa.

Background: the CP firmware (`*_sqe.fw`, `*_pfp.fw`/`*_pm4.fw`) parses and
executes the PM4 command stream. CVE-2025-21479 was a single
`and $x, $12, 0x3 -> 0x7` mask change in `gen70900_sqe.fw`.

## Quickstart

### IDA Pro

```sh
git clone https://github.com/locus-x64/ida-adreno-qrisc
cd ida-adreno-qrisc
sudo ./ida/install.sh /opt/idapro-9.0
```

Open any `*_sqe.fw` / `*_pfp.fw` / `*_pm4.fw` / `*_zap.{mdt,mbn}` / `*_gmu.bin`.
The loader auto-detects the GPU generation.

Without copying into IDA, set `QRISC_HOME` and drop the four entry files in:

```sh
export QRISC_HOME=$PWD
```

### Ghidra

```sh
cp -r ghidra/Ghidra/Processors/QRisc <GHIDRA>/Ghidra/Processors/
```

Restart Ghidra. See [`ghidra/README.md`](ghidra/README.md) for language IDs and
the `QRiscFirmwareHelper` import script.

### Run the tests

```sh
python3 -m pip install --user pytest
python3 -m pytest -q
python3 tests/test_disasm.py
```

## Verified

| Target | Result |
|---|---|
| `qrisc_test.fw` (a6xx fixture) | 127 / 127 byte-exact vs `qrisc-disasm` |
| `qrisc_test_a7xx.fw` (a7xx fixture) | 158 / 158 byte-exact vs `qrisc-disasm` |
| `a660_sqe.fw` (a6xx, ~10 KB) | Loads; 80 `CP_*` handlers recovered; bootstrap + handlers disassemble |
| `a730_sqe.fw` (a7xx, ~75 KB) | Bootstrap emulator recovers packet table + BR/BV/LPAC split |
| `a740_sqe.fw` (a7xx, ~75 KB) | 17,455 / 17,474 = 99.89% match vs `qrisc-disasm` |
| `gen80000/80100/80200_sqe.fw` (a8xx) | Loads; ~93-94% decode coverage. All shipped blobs carry the patched CVE-2025-21479 mask (`& 0x7`); the vulnerable `& 0x3` is absent |
| Ghidra SLEIGH (a6xx, a7xx, a8xx) | All three compile under 12.1.2; headless decode matches |
| `pytest` | 47 / 47 |

## Layout

```
gen/qrisc_isa_gen.py        # Mesa qrisc.xml -> standalone tables
common/
  qrisc_isa_tables.py       # AUTO-GENERATED decode tables
  qrisc_disasm.py           # standalone decoder/renderer
  qrisc_fw.py               # .fw container parser
  qrisc_pm4.py              # baked CP_* opcode -> name DB
  qrisc_bootstrap.py        # packet-table + BR/BV/LPAC recovery
  qrisc_emu.py              # bootstrap emulator
  qrisc_pil.py              # PIL/MDT (ZAP) parser
ida/
  procs/qrisc.py
  loaders/qrisc_loader.py
  loaders/qrisc_zap_loader.py
  loaders/qrisc_gmu_loader.py
  install.sh
ghidra/Ghidra/Processors/QRisc/  # SLEIGH language + scripts
fixtures/                   # Mesa test corpus only
tests/
docs/
```

## Regenerating the ISA tables

`common/qrisc_isa_tables.py` is generated from Mesa at commit
`4bf8fd5121122abd87aafb31e43bbbe9e3d2e921`. To refresh:

```sh
git clone --no-checkout --depth 1 --filter=blob:none \
    https://gitlab.freedesktop.org/mesa/mesa.git third_party/mesa
git -C third_party/mesa sparse-checkout set src/freedreno src/compiler/isaspec
git -C third_party/mesa checkout
python3 gen/qrisc_isa_gen.py
python3 -m pytest -q
```

The generator reuses Mesa's `isa.py` to resolve `extends`, `<gen>` gates,
fields, overrides, and display templates, then emits plain-data tables.

## Limitations

- No decompiler in IDA: Hex-Rays exposes no third-party API for custom-ISA
  decompilation. Use Ghidra for that.
- a8xx is best-effort: same QRisc ISA family as a7xx, but candidate a8xx-only
  encodings remain to be RE'd (see `docs/a8xx_report.md`). The bootstrap
  emulator falls back to a static packet-table scan on a8xx.
- IDA integration: unit-tested + verified against `qrisc-disasm` (99.89% on
  a740). Behaviour on very large databases needs more field testing.

## License

MIT (see [LICENSE](LICENSE)).

ISA tables and PM4 names are generated from
[Mesa 3D](https://gitlab.freedesktop.org/mesa/mesa) (MIT); see [NOTICE](NOTICE).
Fixtures in `fixtures/` are reproduced from Mesa.

Adreno, Qualcomm, and Snapdragon are trademarks of Qualcomm Incorporated. This
project is unaffiliated with Qualcomm.
