"""Tests for common/qrisc_pm4.py (PM4 packet opcode -> name DB)."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "common"))

import qrisc_pm4  # noqa: E402


# Use the public db() accessor: it prefers the baked PM4_PACKETS table from
# qrisc_isa_tables (always shipped) and only falls back to parsing Mesa's
# adreno_pm4.xml when the table is missing. The IDA/Ghidra runtime uses db(),
# not load(), so this is what we actually want to test in CI.


def test_known_opcodes():
    db = qrisc_pm4.db()
    assert db.packet_name(0x48, 6) == "CP_ME_INIT"
    assert db.packet_name(0x3d, 6) == "CP_MEM_WRITE"
    assert db.packet_name(0x3f, 6) == "CP_INDIRECT_BUFFER"
    assert db.packet_name(0x43, 6) == "CP_SET_DRAW_STATE"   # A4XX-
    assert db.packet_name(0x53, 6) == "CP_SMMU_TABLE_UPDATE"  # A5XX-


def test_a8xx_gating():
    db = qrisc_pm4.db()
    # CP_BARRIER (0x59) and CP_MEMORY_MAP_UPDATE (0x58) are A8XX-only.
    assert db.packet_name(0x59, 8) == "CP_BARRIER"
    assert db.packet_name(0x58, 8) == "CP_MEMORY_MAP_UPDATE"
    # ...and must NOT resolve to those names on earlier gens.
    assert db.packet_name(0x59, 6) != "CP_BARRIER"
    assert db.packet_name(0x59, 7) != "CP_BARRIER"


def test_variant_parser():
    assert qrisc_pm4._parse_variants(None) == (0, qrisc_pm4.INF)
    assert qrisc_pm4._parse_variants("A6XX") == (6, 6)
    assert qrisc_pm4._parse_variants("A6XX-") == (6, qrisc_pm4.INF)
    assert qrisc_pm4._parse_variants("A2XX-A4XX") == (2, 4)


def test_map_for_gen():
    db = qrisc_pm4.db()
    m6 = db.map_for_gen(6)
    m8 = db.map_for_gen(8)
    assert m6.get(0x48) == "CP_ME_INIT"
    assert 0x59 not in m6 or m6[0x59] != "CP_BARRIER"
    assert m8.get(0x59) == "CP_BARRIER"


def _run():
    for fn in (test_known_opcodes, test_a8xx_gating, test_variant_parser,
               test_map_for_gen):
        fn()
        print("ok", fn.__name__)


if __name__ == "__main__":
    _run()
    print("test_pm4: PASS")
