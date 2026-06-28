"""
qrisc_gmu_loader.py -- IDA Pro loader for Adreno GMU firmware ("*_gmu.bin").

The GMU (Graphics Management Unit) is a SEPARATE micro-controller from the
command processor: an ARM Cortex-M3 class core (ARMv7-M, Thumb). It is NOT afuc
/QRisc -- do not use the QRisc processor module on it. This loader routes the
image to IDA's stock ARM processor in Thumb mode with Cortex-M defaults.

The newer a6xx/a7xx/a8xx "*_gmu.bin" images use a simple block container:

    struct block { u32 addr; u32 size; u32 type; u32 value; u8 data[size]; }

repeated to EOF (mirrors the kernel a6xx_gmu_fw_load loop). Each block targets a
memory region (e.g. ITCM/DTCM) at `addr`. This loader best-effort parses that
container and maps one IDA segment per block at its `addr`; if the data does not
look like the block container it falls back to a single flat Thumb segment at 0.

Install: copy into <IDA>/loaders/ and open a *_gmu.bin file. If IDA does not
auto-select the Cortex-M variant, set it via Options > General > Processor (ARMv7-M).
"""

import os

try:
    import idaapi
    import ida_segment
    import ida_bytes
    import ida_idp
    import ida_entry
    import ida_segregs
    _HAVE_IDA = True
except Exception:  # noqa: BLE001
    _HAVE_IDA = False

GMU_DEFAULT_BASE = 0x0          # ITCM / vector table base when format is flat
BLOCK_HDR_SIZE = 16            # 4 x u32


def _read_li(li):
    li.seek(0)
    return li.read(li.size())


def parse_gmu_blocks(data):
    """Best-effort parse of the GMU block container.

    Returns a list of dicts {addr, size, type, value, data} if the whole file
    parses as a clean sequence of blocks ending at (or padded to) EOF, else None.
    Pure parsing -- no IDA dependency, so it is unit-testable.
    """
    import struct
    n = len(data)
    if n < BLOCK_HDR_SIZE:
        return None
    blocks = []
    off = 0
    while off + BLOCK_HDR_SIZE <= n:
        addr, size, btype, value = struct.unpack_from("<IIII", data, off)
        # sanity: size must be word-aligned and fit in the file
        if size % 4 != 0:
            return None
        if off + BLOCK_HDR_SIZE + size > n:
            return None
        if size == 0 and off + BLOCK_HDR_SIZE == n:
            # trailing empty terminator block is acceptable
            blocks.append({"addr": addr, "size": 0, "type": btype,
                           "value": value, "data": b""})
            off = n
            break
        payload = data[off + BLOCK_HDR_SIZE: off + BLOCK_HDR_SIZE + size]
        blocks.append({"addr": addr, "size": size, "type": btype,
                       "value": value, "data": payload})
        off += BLOCK_HDR_SIZE + size
    # require we consumed (almost) the whole file and found a few plausible blocks
    if not blocks:
        return None
    if n - off > 4:          # more than a tiny pad left over -> not block format
        return None
    # extra plausibility: at least one non-trivial block, addresses look like
    # tightly-clustered SRAM offsets (< 1 MiB) rather than random
    if all(b["size"] == 0 for b in blocks):
        return None
    if any(b["addr"] > 0x00100000 for b in blocks):
        return None
    return blocks


def accept_file(li, filename):
    name = os.path.basename(filename or "").lower()
    if not name.endswith("_gmu.bin") and "gmu" not in name:
        return 0
    try:
        head = li.read(4) if hasattr(li, "read") else b""
    except Exception:  # noqa: BLE001
        head = b""
    if head[:4] == b"\x7fELF":
        return 0  # ELF -> not a raw GMU block image
    return {
        "format": "Adreno GMU firmware (ARM Cortex-M3 / ARMv7-M Thumb)",
        "processor": "arm",
    }


def _add_seg(start, data, name, sclass, thumb=True):
    seg = idaapi.segment_t()
    seg.start_ea = start
    seg.end_ea = start + max(len(data), 1)
    seg.bitness = 1  # 32-bit
    ida_segment.add_segm_ex(seg, name, sclass, ida_segment.ADDSEG_NOSREG)
    if data:
        ida_bytes.put_bytes(start, bytes(data))
    if thumb:
        try:
            treg = ida_idp.str2reg("T")
            if treg >= 0:
                ida_segregs.split_sreg_range(start, treg, 1, ida_segregs.SR_user)
        except Exception:  # noqa: BLE001
            pass
    return seg.start_ea, seg.end_ea


def _mark_cortex_m_vectors(base, data):
    """Cortex-M vector table: [0]=initial SP, [1]=reset vector (Thumb, |1)."""
    import struct
    if len(data) < 8:
        return
    reset = struct.unpack_from("<I", data, 4)[0] & ~1
    try:
        idaapi.set_cmt(base + 0, "initial SP", 0)
        idaapi.set_cmt(base + 4, "reset vector -> 0x%x" % reset, 0)
        ida_entry.add_entry(reset, reset, "reset", 1)
    except Exception:  # noqa: BLE001
        pass


def load_file(li, neflags, format):
    if not _HAVE_IDA:
        return 0
    ida_idp.set_processor_type("arm", ida_idp.SETPROC_LOADER)
    data = _read_li(li)

    blocks = parse_gmu_blocks(data)
    if blocks:
        first = None
        for i, b in enumerate(blocks):
            if not b["data"]:
                continue
            start, _ = _add_seg(b["addr"], b["data"],
                                "GMU_BLK%d_t%d" % (i, b["type"]), "CODE")
            idaapi.set_cmt(start, "GMU block %d type=%d value=0x%x size=0x%x"
                           % (i, b["type"], b["value"], b["size"]), 1)
            if first is None:
                first = (start, b["data"])
        if first:
            _mark_cortex_m_vectors(first[0], first[1])
        idaapi.msg("qrisc_gmu_loader: parsed %d GMU blocks\n" % len(blocks))
    else:
        # Flat fallback: single Thumb segment at the default base.
        _add_seg(GMU_DEFAULT_BASE, data, "GMU", "CODE")
        _mark_cortex_m_vectors(GMU_DEFAULT_BASE, data)
        idaapi.msg("qrisc_gmu_loader: flat load (no GMU block header detected)\n")

    idaapi.msg("qrisc_gmu_loader: ARM Cortex-M/Thumb. If the disassembly looks "
               "wrong, set the processor variant to ARMv7-M in Processor options.\n")
    return 1
