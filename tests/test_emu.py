"""
Tests for the QRisc bootstrap emulator (common/qrisc_emu.py) and the
emulator-backed recovery in common/qrisc_bootstrap.py.

Always-on assertions use the license-clean Mesa fixtures. Real-blob assertions
(a730 / gen80xxx) run only when those gitignored blobs are present in fixtures/.
"""
import os
import struct
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "common"))

import qrisc_fw            # noqa: E402
import qrisc_emu           # noqa: E402
import qrisc_bootstrap     # noqa: E402
import qrisc_pm4           # noqa: E402

FIX = os.path.join(ROOT, "fixtures")


def _words(name):
    with open(os.path.join(FIX, name), "rb") as fh:
        data = fh.read()
    return qrisc_fw.parse(data)


def _have(name):
    return os.path.exists(os.path.join(FIX, name))


# ---- ALU sanity ----------------------------------------------------------
def test_alu_basic():
    e = qrisc_emu.Emu([0, 0, 0], 6)
    assert e.alu("add", 0xffffffff, 1) == 0 and e.carry == 1
    assert e.alu("addhi", 0, 0) == 1            # carry from previous add
    assert e.alu("sub", 0, 1) == 0xffffffff and e.carry == 0xffffffff
    assert e.alu("and", 0xf0, 0x3c) == 0x30
    assert e.alu("or", 0xf0, 0x0f) == 0xff
    assert e.alu("shl", 1, 4) == 0x10
    assert e.alu("ushr", 0x80000000, 4) == 0x08000000
    assert e.alu("ishr", 0x80000000, 4) == 0xf8000000
    assert e.alu("bic", 0xff, 0x0f) == 0xf0
    assert e.alu("cmp", 5, 5) == 0x2b and e.alu("cmp", 6, 5) == 0x00 and e.alu("cmp", 4, 5) == 0x1e


# ---- fixtures (always) ---------------------------------------------------
def test_fixture_a6xx_bootstrap():
    c = _words("qrisc_test.fw")
    emu = qrisc_emu.run_bootstrap(c.instr_words, c.gen, fw_id=c.fw_id)
    assert emu.waitin and not emu.bootstrap_finished
    assert sum(1 for x in emu.jmptbl if x) >= 100        # table populated
    loc = qrisc_emu.find_jump_table(c.instr_words, emu.jmptbl)
    assert loc == (c.jmptbl_offset_hint)                 # matches static hint
    assert emu.instr_bases() == (None, None)             # single image


def test_fixture_a7xx_bootstrap_splits_subimages():
    c = _words("qrisc_test_a7xx.fw")
    emu = qrisc_emu.run_bootstrap(c.instr_words, c.gen, fw_id=c.fw_id)
    bv, lpac = emu.instr_bases()
    assert bv is not None and lpac is not None
    assert 0 < bv < lpac < len(c.instr_words)            # plausible split


def test_recover_packet_table_fixture():
    c = _words("qrisc_test.fw")
    tbl = qrisc_bootstrap.recover_packet_table(c.instr_words, c.gen)
    assert len(tbl) == qrisc_bootstrap.JUMPTBL_ENTRIES
    assert qrisc_bootstrap.recovery_method(c.instr_words, c.gen) == "emulated"
    by_name = {e["name"]: e for e in tbl if e["named"]}
    assert "CP_ME_INIT" in by_name
    me = by_name["CP_ME_INIT"]
    assert me["handler_addr"] == qrisc_bootstrap.INSTRUCTION_BASE + me["handler_word_index"] * 4


# ---- real blobs (skip if absent) -----------------------------------------
@pytest.mark.skipif(not _have("a730_sqe.fw"), reason="real a730 blob not present")
def test_real_a730_emulated_recovery():
    c = _words("a730_sqe.fw")
    words = c.instr_words
    # emulator-backed recovery succeeds where the static hint is wrong:
    assert qrisc_bootstrap.recovery_method(words, c.gen) == "emulated"
    loc, _cnt = qrisc_bootstrap.jumptable_region(words, c.gen)
    assert loc != (words[1] & 0xffff)          # static hint is a size word here
    bv, lpac = qrisc_bootstrap.extract_instr_bases(words, c.gen)
    assert bv is not None and lpac is not None
    assert 0 < bv < lpac <= len(words)
    tbl = qrisc_bootstrap.recover_packet_table(words, c.gen)
    me = next(e for e in tbl if e["name"] == "CP_ME_INIT")
    assert 0 < me["handler_word_index"] < bv   # handler inside the BR image


@pytest.mark.parametrize("name", ["gen80000_sqe.fw", "gen80100_sqe.fw", "gen80200_sqe.fw"])
def test_real_a8xx_recovery_does_not_crash(name):
    if not _have(name):
        pytest.skip("a8xx blob %s not present" % name)
    c = _words(name)
    words = c.instr_words
    gen = c.gen if c.gen is not None else 7
    # a8xx bootstrap may diverge (greenfield); recovery must still return
    # cleanly without raising. The static content scan recovers the dispatch
    # table even when emulation can't complete, so 'static' is a valid (good)
    # outcome alongside 'emulated'/'hint'/'none'.
    method = qrisc_bootstrap.recovery_method(words, gen)
    assert method in ("emulated", "static", "hint", "none")
    # a8xx packet-table recovery: the emulator diverges on a8xx-new encodings,
    # but the static dispatch-table scan typically still finds the table. A
    # full table or an empty one is acceptable; recovery must not raise.
    tbl = qrisc_bootstrap.recover_packet_table(words, gen)
    assert isinstance(tbl, list)
    assert len(tbl) in (0, qrisc_bootstrap.JUMPTBL_ENTRIES)
    qrisc_bootstrap.extract_instr_bases(words, gen)   # must not raise
