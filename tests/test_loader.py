"""Tests for ida/loaders/qrisc_loader.py (IDA-independent logic)."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "common"))
sys.path.insert(0, os.path.join(ROOT, "ida", "loaders"))

import qrisc_loader  # noqa: E402

FIX = os.path.join(ROOT, "fixtures")


class FakeLI(object):
    """Minimal IDA loader_input_t stand-in (seek/read/size)."""
    def __init__(self, data):
        self._d = data
        self._p = 0

    def seek(self, off):
        self._p = off

    def read(self, n):
        r = self._d[self._p:self._p + n]
        self._p += len(r)
        return r

    def size(self):
        return len(self._d)


def _data(name):
    return open(os.path.join(FIX, name), "rb").read()


def test_filename_matches():
    assert qrisc_loader.filename_matches("a630_sqe.fw")
    assert qrisc_loader.filename_matches("gen80000_sqe.fw")
    assert qrisc_loader.filename_matches("a530_pm4.fw")
    assert not qrisc_loader.filename_matches("a630_gmu.bin")


def test_recognize():
    info = qrisc_loader.recognize(_data("qrisc_test.fw"), "a630_sqe.fw")
    assert info is not None and info["gen"] == 6
    info7 = qrisc_loader.recognize(_data("qrisc_test_a7xx.fw"), "a730_sqe.fw")
    assert info7 is not None and info7["gen"] == 7
    # garbage + non-matching name -> rejected
    assert qrisc_loader.recognize(b"\x00" * 64, "notes.txt") is None


def test_build_plan_a6xx():
    plan = qrisc_loader.build_plan(_data("qrisc_test.fw"))
    assert plan["gen"] == 6
    assert len(plan["images"]) == 1
    img = plan["images"][0]
    assert img["name"] == "SQE"
    assert img["base_addr"] == qrisc_loader.INSTRUCTION_BASE
    assert img["jmptbl_addr"] == qrisc_loader.INSTRUCTION_BASE + 129 * 4
    pkts = {p["name"]: p for p in img["packets"] if p["named"]}
    assert "CP_ME_INIT" in pkts
    assert pkts["CP_ME_INIT"]["handler_addr"] == \
        qrisc_loader.INSTRUCTION_BASE + 34 * 4


def test_accept_file():
    res = qrisc_loader.accept_file(FakeLI(_data("qrisc_test.fw")), "a630_sqe.fw")
    assert res != 0
    assert res["processor"] == "QRisc"
    assert "a6xx" in res["format"]
    assert qrisc_loader.accept_file(FakeLI(b"\x00" * 64), "notes.txt") == 0


def _run():
    for fn in (test_filename_matches, test_recognize, test_build_plan_a6xx,
               test_accept_file):
        fn()
        print("ok", fn.__name__)


if __name__ == "__main__":
    _run()
    print("test_loader: PASS")
