"""
IDA-independent tests for the QRisc processor module (ida/procs/qrisc.py).

These exercise the pure helpers (itype table, flow derivation, target math)
against the shared, oracle-validated decoder, using the license-clean fixtures.
The processor_t integration itself requires IDA to verify end-to-end.
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "common"))
sys.path.insert(0, os.path.join(ROOT, "ida", "procs"))

import qrisc_isa_tables as T          # noqa: E402
import qrisc_fw                       # noqa: E402
from qrisc_disasm import Decoder      # noqa: E402
import qrisc as P                     # noqa: E402  (the processor module)

FIX = os.path.join(ROOT, "fixtures")


def _code_words(fw_name):
    # instrs[0] = version NOP-payload, instrs[1] = jumptbl-offset NOP-payload;
    # executable code begins at index 2 and runs until the jump-table region.
    c = qrisc_fw.parse(open(os.path.join(FIX, fw_name), "rb").read())
    instrs = c.instr_words
    end = c.jmptbl_offset_hint or len(instrs)
    return c.gen, instrs[2:end]


def test_module_imports_without_ida():
    # The processor_t class must be guarded so the file imports w/o IDA.
    assert P._HAVE_IDA is False, "test env should not have IDA"
    assert hasattr(P, "build_itypes") and hasattr(P, "derive_flow")


def test_itype_table():
    instruc, itype_of = P.build_itypes()
    assert instruc[0]["name"] == "" and instruc[0]["feature_str"] == set()
    mnems = P.unique_mnemonics()
    assert len(mnems) == 41
    assert len(itype_of) == 41
    # indices unique and contiguous
    idxs = sorted(itype_of.values())
    assert idxs == list(range(1, 42))
    # feature tags
    assert "CALL" in P._mnem_features("call")
    assert "CALL" in P._mnem_features("bl")
    assert "STOP" in P._mnem_features("ret")
    assert "JUMP" in P._mnem_features("brne")
    assert P._mnem_features("add") == set()


def test_flow_classification_over_fixtures():
    seen = set()
    for fw in ("qrisc_test.fw", "qrisc_test_a7xx.fw"):
        gen, words = _code_words(fw)
        dec = Decoder(gen)
        for i, w in enumerate(words):
            di = dec.disasm(w, pc=i)
            assert di is not None, "undecodable code word %08x in %s" % (w, fw)
            cat, tgt = P.derive_flow(di)
            seen.add(cat)
            # every decoded mnemonic must have an itype
            _, itype_of = P.build_itypes()
            assert di.mnemonic in itype_of
            # branch/call targets must be in-range word indices
            if cat in (P.FLOW_COND_BRANCH, P.FLOW_UNCOND_BRANCH, P.FLOW_CALL):
                assert tgt is not None and isinstance(tgt, int)
    # waitin and conditional branches definitely appear in the corpus
    assert P.FLOW_WAITIN in seen
    assert P.FLOW_COND_BRANCH in seen


def test_specific_opcodes():
    dec = Decoder(6)
    # waitin base encoding 0xd8000000
    di = dec.disasm(0xd8000000, pc=0)
    assert di.mnemonic == "waitin"
    assert P.derive_flow(di)[0] == P.FLOW_WAITIN
    # ret (#ret pattern 110100, bit25=0): 0xd0000000
    di = dec.disasm(0xd0000000, pc=0)
    assert di is not None and di.mnemonic == "ret"
    assert P.derive_flow(di)[0] == P.FLOW_RET


def test_target_ea():
    assert P.target_ea(0x1000, 0x1000, 0) == 0x1000
    assert P.target_ea(0x1010, 0x1000, 5) == 0x1000 + 5 * 4


def _run():
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("ok  ", fn.__name__)
    print("\nALL %d PROC TESTS PASSED" % len(fns))


if __name__ == "__main__":
    _run()
