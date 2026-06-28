# Contributing to ida-adreno-qrisc

Thanks for your interest in helping out. This project is small and pragmatic;
the bar is "make it correct, keep the tests green, keep it boring."

## Ground rules

1. **Mesa `qrisc.xml` is the source of truth** for the ISA. Don't hand-edit
   `common/qrisc_isa_tables.py` — it is generated. Re-generate via
   `python3 gen/qrisc_isa_gen.py` against a pinned Mesa checkout, then commit
   the regenerated table together with the generator change.
2. **The oracle is `qrisc-disasm`** (Mesa's reference disassembler) for a6xx
   and a7xx. For changes that affect decoding, run:
   ```sh
   python3 tests/test_disasm.py        # 127/127 + 158/158 must hold
   python3 -m pytest -q                # 47/47 must hold
   ```
3. **Don't redistribute Qualcomm firmware**. The only blobs in `fixtures/` that
   ship with the repo are the license-clean Mesa fixtures (`qrisc_test*.fw`,
   `qrisc_test*.asm`). Everything else is gitignored on purpose.

## Setup

```sh
git clone <your fork> ida-adreno-qrisc
cd ida-adreno-qrisc
python3 -m pip install --user pytest
python3 -m pytest -q                  # confirm baseline is green
```

For regen / oracle work you also need a sparse blobless clone of Mesa under
`third_party/mesa/` (see `.github/workflows/ci.yml` for the exact commands).

## Patch scope

- **Bug fixes**: small, targeted, with a regression test where reasonable.
- **New features**: open an issue first if it changes the interface (IDA proc
  fields, loader plan structure, public functions in `common/`).
- **a8xx work**: very welcome — see `docs/a8xx_report.md` for the open
  candidate-new encodings.
- **New generations / new auxiliary firmware**: please bring evidence (Mesa
  patches, real-blob test corpus, kernel sources).

## Testing changes

- Decoder/renderer changes: must keep the oracle test (`test_disasm.py`) at
  zero mismatches.
- Generator changes: regenerate `common/qrisc_isa_tables.py` and commit it; the
  CI `regen-check` job will fail otherwise.
- IDA/Ghidra integration changes that need a real environment to verify: say
  so in the PR; reviewers may ask for screenshots or a snippet of the output
  against a public reference blob.

## Style

- Python: stdlib only in `common/` and `gen/`; pure IDAPython in `ida/`;
  4-space indent; type hints not required but welcome on new code.
- Don't add files just to add files. Comments only when the *why* is not
  obvious from the code.

## Reporting issues

When opening an issue, please include:
- IDA / Ghidra version
- GPU generation (a6xx, a7xx, a8xx)
- The firmware filename (e.g. `gen70900_sqe.fw`), not the blob itself
- The shortest reproducer (a code snippet, or a few specific words from the .fw
  with their expected vs actual disassembly)

## License

By contributing, you agree that your contributions are licensed under the
project's [MIT License](LICENSE).
