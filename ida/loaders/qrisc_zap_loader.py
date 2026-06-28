"""IDA loader for Adreno ZAP shader firmware.

ZAP (*_zap.mdt + *_zap.bNN, or *.mbn) is a Qualcomm PIL/MDT signed split-
binary; payload is afuc/QRisc plus an embedded ir3 shader, no packet table.
Parses the PIL container (common/qrisc_pil.py), maps the afuc/QRisc code
segment for the QRisc processor module at instruction base 0x1000, and
maps the embedded ir3 region as separate annotated DATA so it isn't mis-
decoded.

Use ida/install.sh to install. Signature verification is not performed.
The afuc-vs-ir3 boundary is best-effort; refine interactively.
"""

import os
import sys

# --- locate the shared common modules, install-location-agnostic -----------
# Repo, copied beside this file in IDA's loaders/ dir, IDA's python/ dir, or
# QRISC_HOME (repo or its common/ dir). See ida/install.sh.
_HERE = os.path.dirname(os.path.abspath(__file__))
_env = os.environ.get("QRISC_HOME")
_cands = ([_env, os.path.join(_env, "common")] if _env else []) + [
    _HERE,
    os.path.join(_HERE, "qrisc_common"),
    os.path.normpath(os.path.join(_HERE, "..", "common")),
    os.path.normpath(os.path.join(_HERE, "..", "..", "common")),
]
for _p in _cands:
    if _p and os.path.isfile(os.path.join(_p, "qrisc_pil.py")) and _p not in sys.path:
        sys.path.insert(0, _p)
        break
try:
    import qrisc_pil
except Exception:  # noqa: BLE001
    qrisc_pil = None

# --- IDA APIs, guarded so this file imports cleanly without IDA -------------
try:
    import idaapi
    import ida_segment
    import ida_bytes
    import ida_idp
    import ida_entry
    import ida_nalt
    import ida_loader
    _HAVE_IDA = True
except Exception:  # noqa: BLE001
    _HAVE_IDA = False

PROCESSOR_NAME = "QRisc"
QRISC_INSTR_BASE = 0x1000      # afuc instruction-memory base (SQE convention)
IR3_SEG_BASE = 0x40000000      # arbitrary high base for the embedded ir3 region


def _read_li(li):
    li.seek(0)
    return li.read(li.size())


def _looks_like_pil(data):
    return len(data) >= 4 and data[:4] == b"\x7fELF"


def accept_file(li, filename):
    """Return a format description if this is an Adreno ZAP PIL/MDT image."""
    if qrisc_pil is None:
        return 0
    try:
        data = _read_li(li)
    except Exception:  # noqa: BLE001
        return 0
    if not _looks_like_pil(data):
        return 0
    name = os.path.basename(filename or "").lower()
    is_zap = ("zap" in name) or name.endswith(".mdt") or name.endswith(".mbn")
    # Parse to confirm it is a PIL/MDT (has a non-PT_LOAD metadata seg 0 +
    # at least one loadable segment); only then claim it.
    try:
        img = qrisc_pil.parse_mdt_bytes(data, source_path=filename)
    except Exception:  # noqa: BLE001
        return 0
    if not img.segments or img.segments[0].type == qrisc_pil.PT_LOAD:
        return 0
    if not img.loadable_segments and not is_zap:
        return 0
    bits = 64 if img.is64 else 32
    return {
        "format": "Adreno ZAP (PIL/MDT, afuc+ir3) [ELF%d]" % bits,
        "processor": PROCESSOR_NAME,
    }


def _resolve_path(filename):
    """Best-effort on-disk path so split .bNN siblings can be gathered."""
    candidates = []
    if filename and os.path.exists(filename):
        candidates.append(filename)
    if _HAVE_IDA:
        try:
            p = ida_nalt.get_input_file_path()
            if p and os.path.exists(p):
                candidates.append(p)
        except Exception:  # noqa: BLE001
            pass
    return candidates[0] if candidates else None


def _add_seg(start, data, name, sclass):
    end = start + len(data)
    seg = idaapi.segment_t()
    seg.start_ea = start
    seg.end_ea = end
    seg.bitness = 1  # 32-bit
    ida_segment.add_segm_ex(seg, name, sclass, ida_segment.ADDSEG_NOSREG)
    ida_bytes.put_bytes(start, bytes(data))
    return start, end


def load_file(li, neflags, format):
    if not _HAVE_IDA:
        return 0
    if qrisc_pil is None:
        idaapi.warning("qrisc_zap_loader: common/qrisc_pil.py not importable")
        return 0

    ida_idp.set_processor_type(PROCESSOR_NAME, ida_idp.SETPROC_LOADER)

    path = _resolve_path(li.filename() if hasattr(li, "filename") else None)
    data = _read_li(li)

    if path:
        # Handles both split (.mdt + .bNN) and combined (.mbn) forms.
        flat, img = qrisc_pil.reconstruct_image(path)
        info = qrisc_pil.identify_payload(path)
    else:
        # Stream-only fallback: combined container in the opened file.
        img = qrisc_pil.parse_mdt_bytes(data)
        flat = bytearray(max((s.offset + s.filesz for s in img.segments
                              if s.filesz), default=0))
        for s in img.segments:
            if s.filesz:
                flat[s.offset:s.offset + s.filesz] = data[s.offset:s.offset + s.filesz]
        flat = bytes(flat)
        info = {"afuc": [{"segment": s.index, "vaddr": s.vaddr,
                          "offset": s.offset, "size": s.filesz}
                         for s in img.code_segments],
                "ir3_candidates": [], "combined": True,
                "notes": ["stream-only load; split .bNN siblings not gathered"]}

    afuc = info.get("afuc") or []
    if not afuc:
        idaapi.warning("qrisc_zap_loader: no executable afuc segment found; "
                       "loading the largest loadable segment as code")
        loadable = [s for s in img.loadable_segments]
        if not loadable:
            return 0
        biggest = max(loadable, key=lambda s: s.filesz)
        afuc = [{"segment": biggest.index, "vaddr": biggest.vaddr,
                 "offset": biggest.offset, "size": biggest.filesz}]

    # Map each afuc code segment at the QRisc instruction base (sequential if
    # there is more than one). Branch/call targets resolve against this base.
    cur = QRISC_INSTR_BASE
    first_code = None
    for i, a in enumerate(afuc):
        seg_bytes = flat[a["offset"]:a["offset"] + a["size"]]
        name = "QRISC_ZAP%d" % i if i else "QRISC_ZAP"
        start, end = _add_seg(cur, seg_bytes, name, "CODE")
        if first_code is None:
            first_code = start
        idaapi.set_cmt(start, "Adreno ZAP afuc/QRisc payload (PIL seg %d, "
                              "vaddr 0x%x)" % (a["segment"], a["vaddr"]), 1)
        cur = (end + 0xFFF) & ~0xFFF

    # Embedded ir3 region(s): map separately as DATA, clearly annotated. ir3 is
    # a *different* ISA (shader); do not let the QRisc decoder run over it.
    ir3_base = IR3_SEG_BASE
    for j, r in enumerate(info.get("ir3_candidates") or []):
        size = r.get("size", 0)
        off = r.get("offset", 0)
        if not size:
            continue
        seg_bytes = flat[off:off + size]
        start, end = _add_seg(ir3_base, seg_bytes, "IR3_SHADER%d" % j, "DATA")
        idaapi.set_cmt(start, "Embedded ir3 shader (UNCONFIRMED boundary; PIL "
                              "seg %s). Decode with an ir3 disassembler, not "
                              "QRisc." % r.get("segment"), 1)
        ir3_base = (end + 0xFFF) & ~0xFFF

    if first_code is not None:
        ida_entry.add_entry(first_code, first_code, "zap_start", 1)

    for n in info.get("notes", []):
        idaapi.msg("qrisc_zap_loader: %s\n" % n)
    return 1
