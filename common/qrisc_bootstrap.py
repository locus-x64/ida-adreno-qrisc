"""
qrisc_bootstrap.py -- packet jump-table recovery and BR/BV/LPAC sub-image
boundary extraction for QRisc/afuc firmware.

Two services, both consumed by the IDA loader (Stage 3) and the processor
module's xref pass. Each is now **emulator-backed** (accurate on real blobs)
with a static-heuristic fallback when emulation can't complete:

1. recover_packet_table(words, gen) -> list of handler entries
   The CP's core loop parses each PM4 packet header and dispatches via a jump
   table. PRIMARY path: run the firmware bootstrap (qrisc_emu) so it populates
   the 0x80-entry table via @PACKET_TABLE_WRITE exactly as the hardware does,
   then locate that table in the image (Mesa find_jump_table). FALLBACK: the
   static `instrs[1] & 0xffff` hint -- but that hint is a *size word* on real
   a6xx+ images, so it is reliable only for the small Mesa fixtures.

2. extract_instr_bases(words, gen) -> (bv_offset, lpac_offset)
   PRIMARY: read @BV_INSTR_BASE / @LPAC_INSTR_BASE (a7xx/a8xx) or
   CP_LPAC_SQE_INSTR_BASE (a6xx) after running bootstrap -- byte-exact, the same
   computation Mesa's disasm uses. FALLBACK: a structural alignment heuristic.

VERIFIED: the emulator path recovers the table + BV/LPAC split on the real a730
blob (where the static hint is wrong) and matches the static result on the Mesa
fixtures. a8xx bootstrap diverges on a8xx-new encodings (greenfield) and falls
back to the heuristic -- query recovery_method() to tell which path was used.
"""

try:
    from . import qrisc_fw as _fw
    from . import qrisc_pm4 as _pm4
    from . import qrisc_disasm as _qd
    from . import qrisc_emu as _emu
except Exception:  # pragma: no cover
    import qrisc_fw as _fw
    import qrisc_pm4 as _pm4
    import qrisc_disasm as _qd
    import qrisc_emu as _emu

JUMPTBL_ENTRIES = _fw.JUMPTBL_ENTRIES      # 0x80
INSTRUCTION_BASE = _fw.INSTRUCTION_BASE    # 0x1000
ALIGN_WORDS = 8                            # 32-byte alignment (fallback)

# Single-entry memo so the loader's separate calls share one bootstrap run.
_LAST = {"key": None, "emu": None, "loc": None}


def _gen_for(words, gen):
    if gen is not None:
        return gen
    g = _qd.gen_of(words[0]) if words else None
    return g if g is not None else 7  # a8xx / unknown -> decode as a7xx


def _bootstrap(words, gen):
    """Run (and memoize) the bootstrap emulator. Returns (emu, jmptbl_loc) or
    (None, None) if emulation faults (caller falls back to the heuristic)."""
    key = (len(words), words[0] if words else 0,
           words[1] if len(words) > 1 else 0, words[-1] if words else 0)
    if _LAST["key"] == key:
        return _LAST["emu"], _LAST["loc"]
    emu = loc = None
    try:
        fw_id = _qd.fwid_of(words[0]) if words else 0
        emu = _emu.run_bootstrap(words, _gen_for(words, gen), fw_id=fw_id)
        loc = _emu.find_jump_table(words, emu.jmptbl)
    except _emu.EmuError:
        emu = loc = None
    _LAST.update(key=key, emu=emu, loc=loc)
    return emu, loc


# --------------------------------------------------------------------------
# Packet table
# --------------------------------------------------------------------------
def _static_find_jumptable(words):
    """Locate the 0x80-entry dispatch table by content, no emulation needed.

    The table is 0x80 consecutive words, each a handler instruction index
    (0 < idx < image_size). Scan for windows where *every* entry is in range;
    require uniqueness (or pick the one with the most distinct handlers) to
    avoid coincidental runs. Verified on real a660_sqe.fw: a single window at
    word 7960 whose opcode-0x48 entry is CP_ME_INIT's handler. Returns the
    start word index, or None. (Used when bootstrap emulation can't complete,
    e.g. real a6xx images whose bootstrap spins on unmodeled hardware waits.)
    """
    n = len(words)
    if n < JUMPTBL_ENTRIES + 4:
        return None
    cands = []
    for off in range(2, n - JUMPTBL_ENTRIES):
        if all(0 < words[off + i] < n for i in range(JUMPTBL_ENTRIES)):
            cands.append(off)
    if not cands:
        return None
    if len(cands) == 1:
        return cands[0]
    # multiple all-in-range windows: a real dispatch table has many distinct
    # handler targets; prefer that (and, as a tiebreak, the later one).
    return max(cands, key=lambda o: (len(set(words[o:o + JUMPTBL_ENTRIES])), o))


def jumptable_region(words, gen=None):
    """Return (start_word_index, count) of the jump table, or None.

    Emulator-located when possible; else a static content scan; else the
    `instrs[1]&0xffff` hint (reliable only for the Mesa fixtures)."""
    emu, loc = _bootstrap(words, gen)
    if emu is not None and loc is not None:
        return (loc, min(JUMPTBL_ENTRIES, len(words) - loc))
    off = _static_find_jumptable(words)
    if off is not None:
        return (off, min(JUMPTBL_ENTRIES, len(words) - off))
    if len(words) < 2:
        return None
    start = words[1] & 0xffff
    if start < 2 or start >= len(words):
        return None
    return (start, min(JUMPTBL_ENTRIES, len(words) - start))


def recover_packet_table(words, gen, pm4db=None, base=INSTRUCTION_BASE,
                         image_base_word=0):
    """List of packet-handler entries recovered from the jump table.

    Each entry: {opcode, name, named, handler_word_index, handler_addr}.
    `image_base_word` is kept for signature stability (each sub-image is mapped
    at `base`).
    """
    pm = pm4db or _pm4.db()
    gg = _gen_for(words, gen)
    emu, _loc = _bootstrap(words, gen)

    if emu is not None:
        handlers = list(emu.jmptbl)            # accurate: built by bootstrap
    else:
        region = jumptable_region(words, gen)  # static-scan / hint fallback
        if region is None:
            return []
        start, count = region
        handlers = [words[start + i] for i in range(count)]
    if len(handlers) < JUMPTBL_ENTRIES:
        handlers = handlers + [0] * (JUMPTBL_ENTRIES - len(handlers))

    out = []
    for i in range(JUMPTBL_ENTRIES):
        handler = handlers[i]
        name = pm.packet_name(i, gg)
        out.append({
            "opcode": i,
            "name": name if name is not None else "UNKN%d" % i,
            "named": name is not None,
            "handler_word_index": handler,
            "handler_addr": base + handler * 4,
        })
    return out


def recovery_method(words, gen=None):
    """Diagnostics: which path recovered the packet table.
    'emulated' (bootstrap ran), 'static' (content scan), 'hint' (instrs[1]),
    or 'none'."""
    emu, loc = _bootstrap(words, gen)
    if emu is not None and loc is not None:
        return "emulated"
    if _static_find_jumptable(words) is not None:
        return "static"
    if len(words) >= 2 and 2 <= (words[1] & 0xffff) < len(words):
        return "hint"
    return "none"


# --------------------------------------------------------------------------
# BR/BV/LPAC sub-image boundaries
# --------------------------------------------------------------------------
def extract_instr_bases(words, gen):
    """(bv_offset, lpac_offset) in instruction-word units, or None each.

    Emulator-backed (reads *_INSTR_BASE) with a structural heuristic fallback.
    a6xx single images return (None, None).
    """
    emu, _loc = _bootstrap(words, gen)
    if emu is not None:
        return emu.instr_bases()
    return _heuristic_instr_bases(words, _gen_for(words, gen))


# ----- static heuristic fallback (used only when emulation faults) ---------
def _align_up(x, a):
    return (x + a - 1) // a * a


def _looks_like_subimage(words, start):
    if start + 2 >= len(words):
        return False
    hint = words[start + 1] & 0xffff
    if hint < 2:
        return False
    return start + hint + JUMPTBL_ENTRIES <= len(words)


def _heuristic_instr_bases(words, gen):
    if gen is None or gen < 7 or len(words) < 4:
        return (None, None)
    br_hint = words[1] & 0xffff
    if br_hint < 2 or br_hint + JUMPTBL_ENTRIES > len(words):
        return (None, None)
    bv = _align_up(br_hint + JUMPTBL_ENTRIES, ALIGN_WORDS)
    if bv >= len(words) or not _looks_like_subimage(words, bv):
        return (None, None)
    bv_hint = words[bv + 1] & 0xffff
    lpac = _align_up(bv + bv_hint + JUMPTBL_ENTRIES, ALIGN_WORDS)
    if lpac < len(words) and _looks_like_subimage(words, lpac):
        return (bv, lpac)
    return (bv, None)
