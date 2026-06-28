"""QRisc/afuc firmware container parsing. Stdlib only.

Mirrors Mesa qrisc/disasm.c: word 0 is a skipped header dword, word 1 is the
version NOP / first instruction, fw_id = (word1 >> 12) & 0xfff. KGSL blobs
have one extra leading dword vs linux-firmware; we detect that by looking
for the leading word whose fw_id is known. a7xx/a8xx bundle BR+BV(+LPAC) in
one _sqe.fw; BV/LPAC offsets aren't in a static header (the bootstrap
routine programs them via cwrite), so split_subimages() returns a single
image unless offsets are supplied. Instruction memory base is 0x1000.
"""

import struct

try:
    from . import qrisc_disasm as _qd
except Exception:  # pragma: no cover
    import qrisc_disasm as _qd

INSTRUCTION_BASE = 0x1000          # conventional SQE instruction-memory base
JUMPTBL_ENTRIES = 0x80             # CP opcode handler-table size


class FwImage(object):
    """One decodable QRisc sub-image (BR / BV / LPAC, or a single image)."""
    __slots__ = ("name", "words", "gen", "jmptbl_offset")

    def __init__(self, name, words, gen, jmptbl_offset=None):
        self.name = name              # 'SQE'/'BR'/'BV'/'LPAC'
        self.words = words            # instruction words (index 0 == version NOP)
        self.gen = gen
        self.jmptbl_offset = jmptbl_offset

    def __repr__(self):
        return "<FwImage %s gen=a%dxx words=%d jmptbl=%s>" % (
            self.name, self.gen, len(self.words),
            None if self.jmptbl_offset is None else hex(self.jmptbl_offset))


class FwContainer(object):
    """Parsed .fw container."""
    __slots__ = ("words", "instr_start", "version_word", "fw_id", "gen",
                 "kgsl", "header_words")

    def __init__(self, data, gen_override=None):
        if len(data) % 4:
            data = data[: len(data) // 4 * 4]
        self.words = list(struct.unpack("<%dI" % (len(data) // 4), data))
        if len(self.words) < 3:
            raise ValueError("firmware too short (%d words)" % len(self.words))

        # Locate the version word: disasm.c uses index 1. KGSL blobs have one
        # extra leading dword (version at index 2). Pick the candidate whose
        # fw_id is recognized; default to index 1 (linux-firmware layout).
        self.instr_start = 1
        self.kgsl = False
        gen = None
        for idx in (1, 2, 0):
            if idx >= len(self.words):
                continue
            g = _qd.gen_of(self.words[idx])
            if g is not None:
                self.instr_start = idx
                self.kgsl = (idx == 2)
                gen = g
                break
        self.version_word = self.words[self.instr_start]
        self.fw_id = _qd.fwid_of(self.version_word)
        self.gen = gen_override if gen_override is not None else gen
        self.header_words = self.words[: self.instr_start]

    @property
    def instr_words(self):
        return self.words[self.instr_start:]

    @property
    def jmptbl_offset_hint(self):
        """instrs[1] & 0xffff -- static jump-table offset hint (word index in
        the instruction stream)."""
        instrs = self.instr_words
        return (instrs[1] & 0xffff) if len(instrs) > 1 else None

    def split_subimages(self, bv_offset=None, lpac_offset=None):
        """Return the list of FwImage sub-images.

        For a6xx (single SQE) returns one image. For a7xx/a8xx, BR/BV/LPAC
        boundaries require bv_offset/lpac_offset (in instruction-word units,
        relative to the start of the instruction stream) obtained from bootstrap
        emulation (qrisc_bootstrap.extract_instr_bases). If not supplied, a
        single 'SQE'/'BR' image is returned (best-effort).
        """
        instrs = self.instr_words
        gen = self.gen
        if self.gen is not None and self.gen >= 7 and bv_offset:
            images = []
            br_end = min(x for x in (bv_offset, lpac_offset, len(instrs)) if x)
            images.append(FwImage("BR", instrs[:br_end], gen,
                                  self.jmptbl_offset_hint))
            if lpac_offset and bv_offset < lpac_offset:
                images.append(FwImage("BV", instrs[bv_offset:lpac_offset], gen))
                images.append(FwImage("LPAC", instrs[lpac_offset:], gen))
            elif lpac_offset:
                images.append(FwImage("BV", instrs[bv_offset:], gen))
            else:
                images.append(FwImage("BV", instrs[bv_offset:], gen))
            return images
        name = "SQE" if (gen is None or gen >= 6) else "PM4"
        return [FwImage(name, instrs, gen, self.jmptbl_offset_hint)]


def parse(data, gen_override=None):
    return FwContainer(data, gen_override=gen_override)
