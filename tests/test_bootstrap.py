"""Tests for common/qrisc_bootstrap.py (packet table + sub-image bases)."""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "common"))

import qrisc_fw          # noqa: E402
import qrisc_bootstrap   # noqa: E402

FIX = os.path.join(ROOT, "fixtures")


def _instrs(name):
    data = open(os.path.join(FIX, name), "rb").read()
    return qrisc_fw.parse(data)


def test_jumptable_region_a6xx():
    c = _instrs("qrisc_test.fw")
    start, count = qrisc_bootstrap.jumptable_region(c.instr_words)
    assert start == (c.instr_words[1] & 0xffff) == 129
    assert count == 0x80


def test_packet_table_a6xx():
    c = _instrs("qrisc_test.fw")
    entries = qrisc_bootstrap.recover_packet_table(c.instr_words, 6)
    by_op = {e["opcode"]: e for e in entries}
    # Verified handler indices probed against the fixture.
    assert by_op[0x48]["name"] == "CP_ME_INIT"
    assert by_op[0x48]["handler_word_index"] == 34
    assert by_op[0x48]["handler_addr"] == qrisc_bootstrap.INSTRUCTION_BASE + 34 * 4
    assert by_op[0x3d]["name"] == "CP_MEM_WRITE"
    assert by_op[0x3d]["handler_word_index"] == 37
    # unnamed opcodes get UNKN fallbacks
    assert any(not e["named"] for e in entries)


def test_extract_bases_a6xx_single():
    c = _instrs("qrisc_test.fw")
    assert qrisc_bootstrap.extract_instr_bases(c.instr_words, 6) == (None, None)


def test_extract_bases_returns_tuple():
    # a7xx test fixture is a single-image test program (not a real BR+BV bundle):
    # the heuristic must not crash and must return a 2-tuple.
    c = _instrs("qrisc_test_a7xx.fw")
    res = qrisc_bootstrap.extract_instr_bases(c.instr_words, 7)
    assert isinstance(res, tuple) and len(res) == 2


def _run():
    for fn in (test_jumptable_region_a6xx, test_packet_table_a6xx,
               test_extract_bases_a6xx_single, test_extract_bases_returns_tuple):
        fn()
        print("ok", fn.__name__)


if __name__ == "__main__":
    _run()
    print("test_bootstrap: PASS")
