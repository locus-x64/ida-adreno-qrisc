"""
Validate the standalone QRisc decoder/renderer against Mesa's reference
disassembly (the qrisc-disasm oracle) for the license-clean fixtures.

We compare instruction text after normalizing:
  * trailing `; ...` comments (GPU-reg/pipe-reg annotations we don't replicate),
  * branch/call/jump `#target` operands (the oracle names them from entrypoint
    discovery; we emit numeric targets), normalized to `#?` on both sides.

This isolates *decode + operand* correctness (the part the IDA module reuses)
from label naming.
"""
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "common"))

import qrisc_isa_tables  # noqa: E402,F401
from qrisc_disasm import Decoder, gen_of  # noqa: E402

FIX = os.path.join(ROOT, "fixtures")

_TARGET_RE = re.compile(r"#\S+")


def read_words(path):
    with open(path, "rb") as fh:
        data = fh.read()
    n = len(data) // 4
    return list(struct.unpack("<%dI" % n, data[:n * 4]))


def norm(line):
    line = line.split(";", 1)[0]          # drop trailing comment
    line = _TARGET_RE.sub("#?", line)     # normalize branch/call targets
    return " ".join(line.split())         # collapse whitespace


def oracle_code_lines(asm_path):
    """Ordered lines that consume a word, stopping at the jumptbl data section.

    Each entry: (is_payload, normalized_text, raw_text).
    Payload lines ('[....]') consume a word but are not semantically compared.
    """
    out = []
    with open(asm_path) as fh:
        for raw in fh:
            s = raw.strip()
            if not s or s.startswith(";"):
                continue
            if s.startswith(".jumptbl") or s == "jumptbl:":
                break
            if s.startswith("."):          # other directives: no word
                continue
            if s.endswith(":"):            # label: no word
                continue
            if s.startswith("["):          # payload / nop-data: consumes a word
                out.append((True, None, s))
            else:
                out.append((False, norm(s), s))
    return out


def validate(fw_path, asm_path, gen_hint=None):
    words = read_words(fw_path)
    gen = gen_of(words[1], default=gen_hint)
    assert gen is not None, "could not determine gen for %s" % fw_path
    dec = Decoder(gen)
    lines = oracle_code_lines(asm_path)

    compared = matched = 0
    mismatches = []
    for i, (is_payload, want, raw) in enumerate(lines):
        word = words[1 + i]
        if is_payload:
            continue
        insn = dec.disasm(word, pc=i)
        got = norm(insn.text) if insn is not None else "<UNDECODED %08x>" % word
        compared += 1
        if got == want:
            matched += 1
        else:
            mismatches.append((i, word, want, got))
    return gen, compared, matched, mismatches


def test_oracle_match():
    """pytest entry: decoder must byte-match the qrisc-disasm oracle."""
    for fw, asm, hint in (("qrisc_test.fw", "qrisc_test.asm", 6),
                          ("qrisc_test_a7xx.fw", "qrisc_test_a7xx.asm", 7)):
        gen, compared, matched, mm = validate(
            os.path.join(FIX, fw), os.path.join(FIX, asm), hint)
        assert not mm, "%s: %d/%d match; first mismatch: %r" % (
            fw, matched, compared, mm[0] if mm else None)
        assert compared > 0


def _verify_targets(fw_path, asm_path):
    """Check computed branch/call/setsecure targets against the oracle's labels.

    The oracle names targets from entrypoint discovery; we map each label to its
    instruction-word index and assert our numeric target matches. This verifies
    the target arithmetic (pc+offset / absolute literal / setsecure pc+3) that
    backs every IDA o_near xref -- which norm() deliberately hides.
    """
    from qrisc_disasm import Decoder, gen_of
    words = read_words(fw_path)
    dec = Decoder(gen_of(words[1]))
    widx = 0
    label = {}
    entries = []
    with open(asm_path) as fh:
        for raw in fh:
            s = raw.strip()
            if not s or s.startswith(";"):
                continue
            if s.startswith(".jumptbl") or s == "jumptbl:":
                break
            if s.startswith("."):
                continue
            if s.endswith(":"):
                label[s[:-1]] = widx
                continue
            entries.append((widx, s))
            widx += 1
    checked = bad = 0
    for wi, line in entries:
        if line.startswith("[") or "#" not in line:
            continue
        m = re.search(r"#(\S+)", line.split(";")[0])
        if not m:
            continue
        tok = m.group(1)
        if tok in label:
            exp = label[tok]
        elif tok.startswith("0x"):
            exp = int(tok, 16)
        else:
            continue
        insn = dec.disasm(words[1 + wi], pc=wi)
        tgt = insn.flow.get("target")
        if tgt is None:
            for op in insn.operands:
                if op["kind"] in ("rel", "abs"):
                    tgt = op["target"]
        checked += 1
        if tgt != exp:
            bad += 1
    return checked, bad


def test_branch_targets():
    """Branch/call/setsecure target arithmetic must match the oracle labels."""
    for fw, asm in (("qrisc_test.fw", "qrisc_test.asm"),
                    ("qrisc_test_a7xx.fw", "qrisc_test_a7xx.asm")):
        checked, bad = _verify_targets(os.path.join(FIX, fw), os.path.join(FIX, asm))
        assert checked > 0 and bad == 0, "%s: %d/%d target mismatches" % (
            fw, bad, checked)


def main():
    cases = [
        ("qrisc_test.fw", "qrisc_test.asm", 6),
        ("qrisc_test_a7xx.fw", "qrisc_test_a7xx.asm", 7),
    ]
    total_fail = 0
    for fw, asm, hint in cases:
        gen, compared, matched, mm = validate(
            os.path.join(FIX, fw), os.path.join(FIX, asm), hint)
        print("=== %s (a%dxx): %d/%d instructions match ===" %
              (fw, gen, matched, compared))
        for (i, word, want, got) in mm[:40]:
            print("  [%3d] %08x\n      want: %s\n      got : %s"
                  % (i, word, want, got))
        if len(mm) > 40:
            print("  ... and %d more" % (len(mm) - 40))
        total_fail += len(mm)
    print("\nTOTAL mismatches: %d" % total_fail)
    return 1 if total_fail else 0


if __name__ == "__main__":
    sys.exit(main())
