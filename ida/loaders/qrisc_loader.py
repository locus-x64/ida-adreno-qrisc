"""IDA loader for Adreno QRisc CP microcode .fw blobs (a6xx/a7xx/a8xx).

Drop into IDA's loaders/ directory. Recognizes *_sqe.fw / *_pfp.fw /
*_pm4.fw / genNNNNN_sqe.fw plus the KGSL extra-leading-dword variant.

On load: parses the container (qrisc_fw), splits BR/BV/LPAC sub-images on
a7xx/a8xx, creates one CODE segment per sub-image at base 0x1000, marks the
embedded jump table as DATA, recovers the packet table and names each
handler CP_* (qrisc_pm4), stashes gen + per-image bases in a netnode for
the processor module, and adds the bootstrap entry point.

IDA-independent logic (recognition, segment/packet plan) is factored into
plain functions so it's unit-testable without IDA; all idaapi/ida_* imports
are guarded.

Processor-module contract:
  PROC_NAME == "QRisc"
  NETNODE_NAME == "$ qrisc"
  altval(NN_GEN_KEY) = generation int (5..8)
  per-image base hashval: NN_IMAGE_HASH "<base_ea>" -> "<NAME>:<gen>"
Branch/call targets resolve relative to the containing segment's base
(each sub-image's pc/literal is 0-based from its own INSTRUCTION_BASE).
"""

import os
import sys
import struct

def _locate_qrisc_common():
    """Put the shared qrisc_* modules on sys.path, install-location-agnostic.

    Works whether this file runs from the repo, is installed into IDA's flat
    loaders/ dir with the common modules copied beside it (or into IDA's
    python/ dir), or QRISC_HOME points at the repo (or its common/ dir).
    """
    here = os.path.dirname(os.path.abspath(__file__))
    env = os.environ.get("QRISC_HOME")
    cands = []
    if env:
        cands += [env, os.path.join(env, "common")]
    cands += [
        here,                                                  # copied beside us
        os.path.join(here, "qrisc_common"),                    # bundled subdir
        os.path.normpath(os.path.join(here, "..", "common")),
        os.path.normpath(os.path.join(here, "..", "..", "common")),
    ]
    for c in cands:
        if c and os.path.isfile(os.path.join(c, "qrisc_disasm.py")):
            if c not in sys.path:
                sys.path.insert(0, c)
            return c
    return None


if _locate_qrisc_common() is None:
    raise ImportError(
        "qrisc_loader: cannot find the shared qrisc_* modules. Copy common/*.py "
        "next to this file (or into IDA's python/ dir), or set QRISC_HOME to the "
        "adreno-qrisc checkout. See ida/install.sh.")

import qrisc_fw          # noqa: E402
import qrisc_bootstrap   # noqa: E402
import qrisc_pm4         # noqa: E402
from qrisc_disasm import Decoder  # noqa: E402

PROC_NAME = "QRisc"
NETNODE_NAME = "$ qrisc"
NN_GEN_KEY = 0           # netnode.altval(NN_GEN_KEY) -> gen
INSTRUCTION_BASE = qrisc_fw.INSTRUCTION_BASE

_FW_SUFFIXES = ("_sqe.fw", "_pfp.fw", "_pm4.fw")

try:
    import idaapi          # noqa: F401
    import ida_idp
    import ida_bytes
    import ida_segment
    import ida_name
    import ida_entry
    import ida_netnode
    import ida_ua
    _HAVE_IDA = True
except Exception:
    _HAVE_IDA = False


# ----------------------------------------------------------------------------
# IDA-independent logic (unit-testable)
# ----------------------------------------------------------------------------
def filename_matches(filename):
    base = os.path.basename(filename or "").lower()
    return base.endswith(_FW_SUFFIXES)


def recognize(data, filename=""):
    """Return a dict describing the blob, or None if not QRisc firmware."""
    try:
        c = qrisc_fw.parse(data)
    except Exception:
        return None
    if c.gen is None:
        # Unknown fw_id. Only accept if the filename strongly suggests it.
        if not filename_matches(filename):
            return None
    return {
        "gen": c.gen,
        "fw_id": c.fw_id,
        "kgsl": c.kgsl,
        "instr_start": c.instr_start,
        "n_words": len(c.instr_words),
        "container": c,
    }


def build_plan(data, gen_override=None):
    """Produce the full load plan (IDA-independent).

    Returns {gen, kgsl, images: [ {name, start_word, n_words, base_addr,
    jmptbl_addr, jmptbl_count, packets:[...] } ]}.
    """
    c = qrisc_fw.parse(data, gen_override=gen_override)
    gen = c.gen
    instrs = c.instr_words
    bv_off, lpac_off = qrisc_bootstrap.extract_instr_bases(instrs, gen)
    images = c.split_subimages(bv_offset=bv_off, lpac_offset=lpac_off)

    # Compute each image's start word within the instruction stream.
    starts = {}
    if len(images) == 1:
        starts[images[0].name] = 0
    else:
        starts["BR"] = 0
        if bv_off:
            starts["BV"] = bv_off
        if lpac_off:
            starts["LPAC"] = lpac_off

    plan_images = []
    pm = qrisc_pm4.db()
    for img in images:
        start = starts.get(img.name, 0)
        base = INSTRUCTION_BASE + start * 4
        region = qrisc_bootstrap.jumptable_region(img.words)
        jmptbl_addr = (base + region[0] * 4) if region else None
        jmptbl_count = region[1] if region else 0
        packets = qrisc_bootstrap.recover_packet_table(
            img.words, gen if gen is not None else 7, pm4db=pm, base=base)
        plan_images.append({
            "name": img.name,
            "start_word": start,
            "n_words": len(img.words),
            "base_addr": base,
            "jmptbl_addr": jmptbl_addr,
            "jmptbl_count": jmptbl_count,
            "packets": packets,
        })
    return {"gen": gen, "kgsl": c.kgsl, "instr_start": c.instr_start,
            "images": plan_images}


def _read_all(li):
    li.seek(0)
    return li.read(li.size())


# ----------------------------------------------------------------------------
# IDA entry points
# ----------------------------------------------------------------------------
def accept_file(li, filename):
    data = _read_all(li)
    info = recognize(data, filename)
    if info is None:
        return 0
    gen = info["gen"]
    gtxt = ("a%dxx" % gen) if gen is not None else "unknown-gen"
    return {"format": "Adreno QRisc/afuc CP microcode (%s)" % gtxt,
            "processor": PROC_NAME}


def load_file(li, neflags, fmt):
    if not _HAVE_IDA:
        return 0
    data = _read_all(li)
    plan = build_plan(data)

    ida_idp.set_processor_type(PROC_NAME, ida_idp.SETPROC_LOADER)

    nn = ida_netnode.netnode()
    nn.create(NETNODE_NAME)
    if plan["gen"] is not None:
        nn.altset(NN_GEN_KEY, plan["gen"])

    instr_start = plan["instr_start"]
    for img in plan["images"]:
        base = img["base_addr"]
        size = img["n_words"] * 4
        # file offset of this image's first word
        file_off = (instr_start + img["start_word"]) * 4
        img_bytes = data[file_off:file_off + size]
        words = list(struct.unpack("<%dI" % (len(img_bytes) // 4), img_bytes))
        seg = ida_segment.segment_t()
        seg.start_ea = base
        seg.end_ea = base + size
        seg.bitness = 1  # 32-bit
        ida_segment.add_segm_ex(seg, "%s_%s" % (PROC_NAME, img["name"]),
                                "CODE", ida_segment.ADDSEG_OR_DIE)
        ida_bytes.put_bytes(base, img_bytes)

        # mark the embedded jump table as data
        if img["jmptbl_addr"] is not None:
            for k in range(img["jmptbl_count"]):
                ea = img["jmptbl_addr"] + k * 4
                ida_bytes.create_dword(ea, 4)

        # The leading words are NOP-payloads (fw id/version, packet-table
        # offset, ...) whose low bits carry data, so they do NOT decode as
        # instructions. Mark them as data and find where real code begins.
        dec = Decoder(plan["gen"] if plan["gen"] is not None else 7)
        bw = 0
        while bw < min(len(words), 64) and dec.disasm(words[bw], pc=bw) is None:
            ida_bytes.create_dword(base + bw * 4, 4)
            bw += 1

        # Name + make-code each packet handler. The dispatch targets are reached
        # via the computed jump table (which IDA cannot follow), so add them as
        # code entry points: this both disassembles and names them.
        seen = {}
        for p in img["packets"]:
            ea = p["handler_addr"]
            if not p["named"] or ea in seen:
                continue
            nm = "%s_%s" % (img["name"], p["name"]) if img["name"] != "SQE" \
                else p["name"]
            seen[ea] = nm
            ida_entry.add_entry(ea, ea, nm, 1)   # makecode=True
            ida_ua.create_insn(ea)               # force disassembly at the entry

        # bootstrap / reset entry at the first decodable instruction
        boot = base + bw * 4
        if boot not in seen:
            ida_entry.add_entry(boot, boot, "%s_reset" % img["name"], 1)
            ida_ua.create_insn(boot)

    return 1
