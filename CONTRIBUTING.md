# Contributing

Small project, plain rules.

## Ground rules

1. `common/qrisc_isa_tables.py` is generated. Don't hand-edit it. Regenerate
   with `python3 gen/qrisc_isa_gen.py` against a pinned Mesa checkout and
   commit the regenerated file with the generator change.
2. The oracle is `qrisc-disasm` (Mesa) for a6xx and a7xx. For decode changes:
   ```sh
   python3 tests/test_disasm.py        # 127/127 + 158/158 must hold
   python3 -m pytest -q                # 47/47 must hold
   ```
3. Don't redistribute Qualcomm firmware. The only blobs in `fixtures/` that
   ship with the repo are the Mesa fixtures (`qrisc_test*.{fw,asm}`).
   Everything else is gitignored.

## Setup

```sh
git clone <your fork> ida-adreno-qrisc
cd ida-adreno-qrisc
python3 -m pip install --user pytest
python3 -m pytest -q
```

For regen / oracle work you also need a sparse blobless clone of Mesa under
`third_party/mesa/` (see `.github/workflows/ci.yml`).

## Patch scope

- Bug fixes: small, targeted, with a regression test where reasonable.
- New features: open an issue first if they change the public interface
  (IDA proc fields, loader plan structure, `common/`).
- a8xx work: see `docs/a8xx_report.md` for open candidate encodings.
- New generations / new aux firmware: bring evidence (Mesa patches, real
  blobs, kernel sources).

## Testing changes

- Decoder/renderer changes must keep `test_disasm.py` at zero mismatches.
- Generator changes: regenerate `common/qrisc_isa_tables.py` and commit it
  (CI `regen-check` fails otherwise).
- IDA/Ghidra integration changes that need a real environment: say so in the
  PR; reviewers may ask for output snippets against a public reference blob.

## Style

- Python: stdlib only in `common/` and `gen/`; pure IDAPython in `ida/`;
  4-space indent. Type hints optional.
- Comments only when the *why* isn't obvious from the code.

## Reporting issues

Include:

- IDA / Ghidra version
- GPU generation (a6xx, a7xx, a8xx)
- The firmware filename (e.g. `gen70900_sqe.fw`), not the blob
- The shortest reproducer (a code snippet, or specific words from the .fw
  with expected vs actual disassembly)

## License

By contributing, you agree to license your contributions under the project's
[MIT License](LICENSE).
