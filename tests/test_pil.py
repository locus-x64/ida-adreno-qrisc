#!/usr/bin/env python3
"""
Unit tests for common/qrisc_pil.py -- the Qualcomm PIL/MDT parser.

No real signed ZAP blob is available (and they aren't license-clean to ship),
so these tests synthesize minimal but format-correct ELF32/ELF64 MDT containers
(combined .mbn and split .mdt + .bNN) in a temp dir and verify parsing,
segment classification, payload extraction, and flat reconstruction.

Run:  python3 tests/test_pil.py     or    python3 -m pytest tests/test_pil.py
"""

import os
import struct
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "common"))
import qrisc_pil as pil  # noqa: E402

PT_NULL = 0
PT_LOAD = 1
PF_X, PF_W, PF_R = 1, 2, 4
HASH_FLAGS = pil.QCOM_MDT_TYPE_HASH | PF_R

EHDR32 = 52
PHENT32 = 32
EHDR64 = 64
PHENT64 = 56


def _build_phdrs32(phdrs):
    out = b""
    for p in phdrs:
        out += struct.pack("<IIIIIIII", p["type"], p["offset"], p["vaddr"],
                           p["paddr"], p["filesz"], p["memsz"], p["flags"],
                           p.get("align", 0))
    return out


def _build_ehdr32(phnum, entry=0x2000):
    ident = b"\x7fELF" + bytes([pil.ELFCLASS32, pil.ELFDATA2LSB, 1]) + b"\x00" * 9
    rest = struct.pack("<HHIIIIIHHH",
                       2,        # e_type ET_EXEC
                       40,       # e_machine (arbitrary)
                       1,        # e_version
                       entry,    # e_entry
                       EHDR32,   # e_phoff
                       0,        # e_shoff
                       0,        # e_flags
                       EHDR32,   # e_ehsize
                       PHENT32,  # e_phentsize
                       phnum)    # e_phnum
    rest += struct.pack("<HHH", 0, 0, 0)  # shentsize, shnum, shstrndx
    return ident + rest


def _build_phdrs64(phdrs):
    out = b""
    for p in phdrs:
        out += struct.pack("<IIQQQQQQ", p["type"], p["flags"], p["offset"],
                           p["vaddr"], p["paddr"], p["filesz"], p["memsz"],
                           p.get("align", 0))
    return out


def _build_ehdr64(phnum, entry=0x2000):
    ident = b"\x7fELF" + bytes([pil.ELFCLASS64, pil.ELFDATA2LSB, 1]) + b"\x00" * 9
    rest = struct.pack("<HHIQQQIHHH",
                       2, 40, 1, entry, EHDR64, 0, 0, EHDR64, PHENT64, phnum)
    rest += struct.pack("<HHH", 0, 0, 0)
    return ident + rest


# Synthetic payloads
HASH_DATA = bytes(range(64))
CODE_DATA = b"".join(struct.pack("<I", 0x01000000 | i) for i in range(32))  # 128B
DATA_DATA = b"\xa5" * 96


def _layout32():
    """Three-segment ELF32: metadata(0) + hash(1) + code(2). Returns phdrs and
    the combined image bytes."""
    hdr_size = EHDR32 + 3 * PHENT32  # 52 + 96 = 148
    off_hash = hdr_size
    off_code = off_hash + len(HASH_DATA)
    phdrs = [
        # seg0: metadata -- must be non-PT_LOAD (holds ELF header+phdrs)
        dict(type=PT_NULL, offset=0, vaddr=0, paddr=0,
             filesz=hdr_size, memsz=0, flags=PF_R),
        # seg1: hash segment
        dict(type=PT_LOAD, offset=off_hash, vaddr=0x100, paddr=0x100,
             filesz=len(HASH_DATA), memsz=len(HASH_DATA), flags=HASH_FLAGS),
        # seg2: afuc/QRisc code (executable)
        dict(type=PT_LOAD, offset=off_code, vaddr=0x2000, paddr=0x2000,
             filesz=len(CODE_DATA), memsz=len(CODE_DATA), flags=PF_R | PF_X),
    ]
    ehdr = _build_ehdr32(3)
    image = ehdr + _build_phdrs32(phdrs) + HASH_DATA + CODE_DATA
    return phdrs, image, off_code


def _write_combined(d, name="a530_zap.mbn"):
    _, image, off_code = _layout32()
    p = os.path.join(d, name)
    with open(p, "wb") as fh:
        fh.write(image)
    return p, off_code


def _write_split(d, base="a530_zap"):
    """Split form: .mdt holds ehdr+phdrs+hash (segments 0,1); .b02 holds code."""
    phdrs, image, off_code = _layout32()
    mdt_path = os.path.join(d, base + ".mdt")
    with open(mdt_path, "wb") as fh:
        fh.write(image[:off_code])          # everything up to the code payload
    with open(os.path.join(d, base + ".b02"), "wb") as fh:
        fh.write(CODE_DATA)                  # split payload for segment 2
    return mdt_path, off_code


# --------------------------------------------------------------------------

def test_parse_combined_classifies_segments():
    with tempfile.TemporaryDirectory() as d:
        p, off_code = _write_combined(d)
        img = pil.parse_mdt(p)
        assert not img.is64 and img.little_endian
        assert len(img.segments) == 3
        kinds = [s.kind for s in img.segments]
        assert kinds == ["metadata", "hash", "code"], kinds
        assert img.hash_segment is not None and img.hash_segment.index == 1
        assert [s.index for s in img.code_segments] == [2]
        assert pil.is_combined(img, p) is True


def test_reconstruct_combined_places_code():
    with tempfile.TemporaryDirectory() as d:
        p, off_code = _write_combined(d)
        flat, img = pil.reconstruct_image(p)
        assert flat[off_code:off_code + len(CODE_DATA)] == CODE_DATA
        # hash payload is where the phdr says
        hseg = img.hash_segment
        assert flat[hseg.offset:hseg.offset + hseg.filesz] == HASH_DATA


def test_split_form_reads_bNN_and_reconstructs():
    with tempfile.TemporaryDirectory() as d:
        mdt, off_code = _write_split(d)
        img = pil.parse_mdt(mdt)
        assert len(img.segments) == 3
        assert pil.is_combined(img, mdt) is False    # .b02 present
        code = img.code_segments[0]
        data = pil.read_segment_data(img, mdt, code)
        assert data == CODE_DATA
        flat, _ = pil.reconstruct_image(mdt)
        assert flat[off_code:off_code + len(CODE_DATA)] == CODE_DATA
        # metadata/hash still readable from the .mdt itself
        hseg = img.hash_segment
        assert flat[hseg.offset:hseg.offset + hseg.filesz] == HASH_DATA


def test_split_and_combined_reconstruct_identically():
    with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
        pc, _ = _write_combined(d1)
        pm, _ = _write_split(d2)
        flat_c, _ = pil.reconstruct_image(pc)
        flat_m, _ = pil.reconstruct_image(pm)
        assert flat_c == flat_m


def test_identify_payload():
    with tempfile.TemporaryDirectory() as d:
        p, off_code = _write_combined(d)
        info = pil.identify_payload(p)
        assert info["combined"] is True
        assert len(info["afuc"]) == 1
        a = info["afuc"][0]
        assert a["segment"] == 2 and a["vaddr"] == 0x2000 and a["size"] == len(CODE_DATA)
        # the hash segment must never be offered as afuc/ir3
        assert all(c["segment"] != 1 for c in info["ir3_candidates"])
        assert any("UNCONFIRMED" in n for n in info["notes"])


def test_split_segment_path():
    assert pil.split_segment_path("a530_zap.mdt", 0) == "a530_zap.b00"
    assert pil.split_segment_path("a530_zap.mdt", 2) == "a530_zap.b02"
    assert pil.split_segment_path("/x/y/gen80000_zap.mdt", 12) == "/x/y/gen80000_zap.b12"


def test_bss_segment_has_no_file_data():
    """A loadable BSS segment (filesz=0, memsz>0) returns empty payload bytes."""
    with tempfile.TemporaryDirectory() as d:
        hdr_size = EHDR32 + 2 * PHENT32
        phdrs = [
            dict(type=PT_NULL, offset=0, vaddr=0, paddr=0, filesz=hdr_size,
                 memsz=0, flags=PF_R),
            dict(type=PT_LOAD, offset=hdr_size, vaddr=0x3000, paddr=0x3000,
                 filesz=0, memsz=0x400, flags=PF_R | PF_W),  # BSS
        ]
        image = _build_ehdr32(2) + _build_phdrs32(phdrs)
        p = os.path.join(d, "bss.mbn")
        with open(p, "wb") as fh:
            fh.write(image)
        img = pil.parse_mdt(p)
        bss = img.segments[1]
        assert bss.loadable and bss.kind == "data"
        assert pil.read_segment_data(img, p, bss) == b""


def test_elf64_parses():
    with tempfile.TemporaryDirectory() as d:
        hdr_size = EHDR64 + 2 * PHENT64
        off_code = hdr_size
        phdrs = [
            dict(type=PT_NULL, offset=0, vaddr=0, paddr=0, filesz=hdr_size,
                 memsz=0, flags=PF_R),
            dict(type=PT_LOAD, offset=off_code, vaddr=0x2000, paddr=0x2000,
                 filesz=len(CODE_DATA), memsz=len(CODE_DATA), flags=PF_R | PF_X),
        ]
        image = _build_ehdr64(2) + _build_phdrs64(phdrs) + CODE_DATA
        p = os.path.join(d, "zap64.mbn")
        with open(p, "wb") as fh:
            fh.write(image)
        img = pil.parse_mdt(p)
        assert img.is64
        assert len(img.segments) == 2
        assert img.code_segments[0].vaddr == 0x2000
        flat, _ = pil.reconstruct_image(p)
        assert flat[off_code:off_code + len(CODE_DATA)] == CODE_DATA


def test_rejects_non_elf():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "junk.mbn")
        with open(p, "wb") as fh:
            fh.write(b"NOTELF" + b"\x00" * 100)
        try:
            pil.parse_mdt(p)
        except pil.PilError:
            return
        raise AssertionError("expected PilError for non-ELF input")


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
