#!/usr/bin/env python3
"""
Tests for the auxiliary-core loaders (importable without IDA):
  - qrisc_gmu_loader.parse_gmu_blocks (pure GMU block-container parser)
  - qrisc_zap_loader.accept_file (PIL/MDT recognition, no IDA needed)
  - both loader modules import cleanly with idaapi absent (guarded)

Run:  python3 tests/test_pil_loaders.py   or   python3 -m pytest tests/test_pil_loaders.py
"""

import os
import struct
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.join(_ROOT, "common"),
           os.path.join(_ROOT, "ida", "loaders"),
           os.path.join(_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import qrisc_gmu_loader as gmu  # noqa: E402
import qrisc_zap_loader as zap  # noqa: E402
import test_pil  # reuse the synthetic-MDT builders  # noqa: E402


class FakeLI(object):
    """Minimal stand-in for IDA's loader_input_t (seek/read/size/filename)."""
    def __init__(self, data, filename="synthetic_zap.mdt"):
        self._b = data
        self._p = 0
        self._fn = filename

    def seek(self, off, whence=0):
        self._p = off

    def read(self, n=None):
        if n is None:
            n = len(self._b) - self._p
        d = self._b[self._p:self._p + n]
        self._p += len(d)
        return d

    def size(self):
        return len(self._b)

    def filename(self):
        return self._fn


def _make_gmu_blocks(spec):
    out = b""
    for addr, btype, value, payload in spec:
        out += struct.pack("<IIII", addr, len(payload), btype, value) + payload
    return out


def test_gmu_blocks_parse():
    spec = [
        (0x0,    0, 0, b"\x01\x02\x03\x04" * 8),   # ITCM block @0
        (0x9000, 1, 0, b"\xaa" * 64),              # DTCM block
    ]
    data = _make_gmu_blocks(spec)
    blocks = gmu.parse_gmu_blocks(data)
    assert blocks is not None
    assert len(blocks) == 2
    assert blocks[0]["addr"] == 0x0 and blocks[0]["size"] == 32
    assert blocks[1]["addr"] == 0x9000 and blocks[1]["data"] == b"\xaa" * 64


def test_gmu_blocks_reject_flat():
    # Random-ish flat Thumb image should NOT be misread as block container.
    data = bytes((i * 7 + 3) & 0xFF for i in range(4096))
    assert gmu.parse_gmu_blocks(data) is None


def test_gmu_blocks_reject_unaligned():
    # size not word-aligned -> reject
    data = struct.pack("<IIII", 0, 5, 0, 0) + b"\x00" * 5
    assert gmu.parse_gmu_blocks(data) is None


def test_gmu_accept_file_name():
    data = bytes(256)
    assert gmu.accept_file(FakeLI(data, "junk.bin"), "junk.bin") == 0
    res = gmu.accept_file(FakeLI(data, "a630_gmu.bin"), "a630_gmu.bin")
    assert isinstance(res, dict) and res["processor"] == "arm"
    # an ELF named *_gmu.bin is rejected (GMU bin is raw, not ELF)
    elf = b"\x7fELF" + bytes(252)
    assert gmu.accept_file(FakeLI(elf, "weird_gmu.bin"), "weird_gmu.bin") == 0


def test_zap_accept_file_on_synthetic_mdt():
    _, image, _ = test_pil._layout32()
    res = zap.accept_file(FakeLI(image, "a530_zap.mdt"), "a530_zap.mdt")
    assert isinstance(res, dict), res
    assert res["processor"] == "QRisc"
    assert "ELF32" in res["format"]


def test_zap_accept_file_rejects_non_pil():
    junk = b"NOTELF" + bytes(200)
    assert zap.accept_file(FakeLI(junk, "x.mbn"), "x.mbn") == 0


def test_loaders_expose_api():
    for mod in (gmu, zap):
        assert callable(mod.accept_file)
        assert callable(mod.load_file)
    # idaapi is absent in this environment -> guards must have set _HAVE_IDA False
    assert gmu._HAVE_IDA is False
    assert zap._HAVE_IDA is False
    # load_file must no-op safely (return 0) without IDA rather than throw
    assert gmu.load_file(FakeLI(bytes(64), "a.bin"), 0, "") == 0
    assert zap.load_file(FakeLI(bytes(64), "a.mbn"), 0, "") == 0


def _run_all():
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print("PASS", fn.__name__)
        except Exception as e:  # noqa: BLE001
            failed += 1
            print("FAIL", fn.__name__, "->", repr(e))
    print("\n%d/%d passed" % (len(fns) - failed, len(fns)))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
