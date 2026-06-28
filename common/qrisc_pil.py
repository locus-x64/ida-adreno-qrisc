"""
qrisc_pil.py -- standalone Qualcomm PIL / MDT (split-binary) parser.

Adreno ZAP shaders ("*_zap.mdt" + "*_zap.bNN", or a single "*.mbn") ship as
Qualcomm "Peripheral Image Loader" (PIL) signed split-binaries:

    <name>.mdt  = ELF header + program-header table + metadata/hash/signature
    <name>.bNN  = the payload of program-header index NN (split form)
    <name>.mbn  = everything concatenated in one file (combined form)

The ZAP payload itself is afuc/QRisc instructions plus an embedded ir3 shader,
with NO packet table (unlike the SQE microcode).

This module is dependency-free (stdlib only) so it can be reused both by the IDA
loader and by offline tooling/tests. It does NOT verify signatures -- it only
parses the container so the afuc/ir3 payload can be extracted and disassembled.

Field semantics follow the Linux kernel drivers/soc/qcom/mdt_loader.c:
    QCOM_MDT_TYPE_MASK    = 0x07000000   (bits 24..26 of p_flags)
    QCOM_MDT_TYPE_HASH    = 0x02000000
    QCOM_MDT_RELOCATABLE  = 0x08000000   (BIT(27))

  mdt_phdr_loadable(phdr):
      p_type == PT_LOAD  and
      (p_flags & TYPE_MASK) != TYPE_HASH  and
      p_memsz != 0

  - program header index 0 is required to be non-PT_LOAD (it holds the ELF
    header + phdrs, i.e. the "metadata" segment).
  - the hash segment is the first index >= 1 whose type bits == TYPE_HASH.
  - split payload file name: replace the last 3 chars of the .mdt name with
    "b%02d" % index  (e.g. a530_zap.mdt -> a530_zap.b02).
"""

import os
import struct

# ---- ELF / PIL constants -------------------------------------------------

PT_NULL = 0
PT_LOAD = 1
PT_NOTE = 4

PF_X = 0x1
PF_W = 0x2
PF_R = 0x4

QCOM_MDT_TYPE_MASK = 0x07000000
QCOM_MDT_TYPE_HASH = 0x02000000
QCOM_MDT_RELOCATABLE = 0x08000000

ELFMAG = b"\x7fELF"
ELFCLASS32 = 1
ELFCLASS64 = 2
ELFDATA2LSB = 1
ELFDATA2MSB = 2


class PilError(Exception):
    pass


class Segment(object):
    """One PIL/MDT program-header segment, with a Qualcomm 'kind' classification.

    kind is one of: 'metadata' | 'hash' | 'code' | 'data'
        metadata - ELF header/phdr container (index 0, non-PT_LOAD)
        hash     - signature/hash table segment (TYPE_HASH)
        code     - loadable, executable (PF_X) -> afuc/QRisc candidate
        data     - loadable, non-executable (or BSS)
    """

    __slots__ = ("index", "type", "flags", "offset", "vaddr", "paddr",
                 "filesz", "memsz", "align", "kind")

    def __init__(self, index, p_type, p_flags, p_offset, p_vaddr, p_paddr,
                 p_filesz, p_memsz, p_align):
        self.index = index
        self.type = p_type
        self.flags = p_flags
        self.offset = p_offset
        self.vaddr = p_vaddr
        self.paddr = p_paddr
        self.filesz = p_filesz
        self.memsz = p_memsz
        self.align = p_align
        self.kind = self._classify()

    @property
    def is_hash(self):
        return (self.flags & QCOM_MDT_TYPE_MASK) == QCOM_MDT_TYPE_HASH

    @property
    def is_relocatable(self):
        return bool(self.flags & QCOM_MDT_RELOCATABLE)

    @property
    def loadable(self):
        # Matches kernel mdt_phdr_loadable().
        return self.type == PT_LOAD and not self.is_hash and self.memsz != 0

    @property
    def executable(self):
        return bool(self.flags & PF_X)

    @property
    def mdt_type(self):
        return (self.flags & QCOM_MDT_TYPE_MASK) >> 24

    def _classify(self):
        if self.is_hash:
            return "hash"
        if self.type != PT_LOAD:
            return "metadata"
        if self.memsz == 0:
            return "metadata"
        return "code" if self.executable else "data"

    def to_dict(self):
        return {
            "index": self.index,
            "type": self.type,
            "vaddr": self.vaddr,
            "paddr": self.paddr,
            "offset": self.offset,
            "filesz": self.filesz,
            "memsz": self.memsz,
            "flags": self.flags,
            "kind": self.kind,
            "loadable": self.loadable,
            "executable": self.executable,
        }

    def __repr__(self):
        return ("Segment(#%d kind=%s vaddr=0x%x off=0x%x filesz=0x%x "
                "memsz=0x%x flags=0x%x)" % (self.index, self.kind, self.vaddr,
                                            self.offset, self.filesz,
                                            self.memsz, self.flags))


class PilImage(object):
    """Parsed PIL/MDT container metadata (ELF header + program headers)."""

    def __init__(self, is64, little_endian, entry, segments, ehdr_size,
                 phoff, phentsize, phnum, source_path=None):
        self.is64 = is64
        self.little_endian = little_endian
        self.entry = entry
        self.segments = segments
        self.ehdr_size = ehdr_size
        self.phoff = phoff
        self.phentsize = phentsize
        self.phnum = phnum
        self.source_path = source_path

    @property
    def loadable_segments(self):
        return [s for s in self.segments if s.loadable]

    @property
    def code_segments(self):
        """Executable loadable segments -- afuc/QRisc payload candidates."""
        return [s for s in self.segments if s.loadable and s.executable]

    @property
    def data_segments(self):
        return [s for s in self.segments if s.loadable and not s.executable]

    @property
    def hash_segment(self):
        for s in self.segments:
            if s.is_hash:
                return s
        return None

    def summary(self):
        lines = ["PIL/MDT image: %s ELF, %s-endian, entry=0x%x, %d segments" % (
            "64-bit" if self.is64 else "32-bit",
            "little" if self.little_endian else "big", self.entry,
            len(self.segments))]
        for s in self.segments:
            lines.append("  " + repr(s))
        return "\n".join(lines)


# ---- ELF parsing ---------------------------------------------------------

def _parse_elf_header(buf):
    if len(buf) < 16 or buf[:4] != ELFMAG:
        raise PilError("not an ELF/MDT file (bad magic)")
    ei_class = buf[4]
    ei_data = buf[5]
    if ei_class == ELFCLASS32:
        is64 = False
    elif ei_class == ELFCLASS64:
        is64 = True
    else:
        raise PilError("unknown ELF class %d" % ei_class)
    if ei_data == ELFDATA2LSB:
        little = True
        en = "<"
    elif ei_data == ELFDATA2MSB:
        little = False
        en = ">"
    else:
        raise PilError("unknown ELF data encoding %d" % ei_data)

    if not is64:
        # Elf32_Ehdr: after e_ident[16]: e_type H, e_machine H, e_version I,
        # e_entry I, e_phoff I, e_shoff I, e_flags I, e_ehsize H,
        # e_phentsize H, e_phnum H, ...
        fmt = en + "HHIIIIIHHH"
        sz = struct.calcsize(fmt)
        if len(buf) < 16 + sz:
            raise PilError("truncated ELF32 header")
        (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags,
         e_ehsize, e_phentsize, e_phnum) = struct.unpack_from(fmt, buf, 16)
    else:
        # Elf64_Ehdr: e_type H, e_machine H, e_version I, e_entry Q,
        # e_phoff Q, e_shoff Q, e_flags I, e_ehsize H, e_phentsize H, e_phnum H
        fmt = en + "HHIQQQIHHH"
        sz = struct.calcsize(fmt)
        if len(buf) < 16 + sz:
            raise PilError("truncated ELF64 header")
        (e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags,
         e_ehsize, e_phentsize, e_phnum) = struct.unpack_from(fmt, buf, 16)

    return {
        "is64": is64, "little": little, "endian": en, "entry": e_entry,
        "phoff": e_phoff, "phentsize": e_phentsize, "phnum": e_phnum,
        "ehsize": e_ehsize, "type": e_type, "machine": e_machine,
    }


def _parse_phdrs(buf, hdr):
    en = hdr["endian"]
    segs = []
    for i in range(hdr["phnum"]):
        off = hdr["phoff"] + i * hdr["phentsize"]
        if not hdr["is64"]:
            fmt = en + "IIIIIIII"  # type,off,vaddr,paddr,filesz,memsz,flags,align
            if len(buf) < off + struct.calcsize(fmt):
                raise PilError("truncated ELF32 phdr %d" % i)
            (p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags,
             p_align) = struct.unpack_from(fmt, buf, off)
        else:
            # Elf64_Phdr: type I, flags I, offset Q, vaddr Q, paddr Q,
            # filesz Q, memsz Q, align Q
            fmt = en + "IIQQQQQQ"
            if len(buf) < off + struct.calcsize(fmt):
                raise PilError("truncated ELF64 phdr %d" % i)
            (p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz,
             p_align) = struct.unpack_from(fmt, buf, off)
        segs.append(Segment(i, p_type, p_flags, p_offset, p_vaddr, p_paddr,
                            p_filesz, p_memsz, p_align))
    return segs


def parse_mdt(path):
    """Parse a .mdt / .mbn container's ELF header + program headers.

    Returns a PilImage. Does not read segment payloads (see read_segment_data
    / reconstruct_image for that).
    """
    with open(path, "rb") as fh:
        buf = fh.read()
    return parse_mdt_bytes(buf, source_path=path)


def parse_mdt_bytes(buf, source_path=None):
    hdr = _parse_elf_header(buf)
    segs = _parse_phdrs(buf, hdr)
    return PilImage(hdr["is64"], hdr["little"], hdr["entry"], segs,
                    hdr["ehsize"], hdr["phoff"], hdr["phentsize"],
                    hdr["phnum"], source_path=source_path)


# ---- segment payload access ---------------------------------------------

def split_segment_path(mdt_path, index):
    """Filename of the split payload for a segment, per kernel mdt_loader.c:
    replace the last 3 chars of the .mdt name with 'b%02d'."""
    base = mdt_path
    if len(base) < 3:
        raise PilError("mdt path too short: %r" % mdt_path)
    return base[:-3] + ("b%02d" % index)


def read_segment_data(image, container_path, segment, container_bytes=None):
    """Return the on-file payload bytes (filesz) for one segment.

    Resolution order (handles split AND combined containers uniformly):
      1. if a sibling <base>.bNN file exists -> read it (the whole file is the
         segment payload, as produced by the split PIL form);
      2. otherwise read from the container at [p_offset : p_offset+p_filesz]
         (combined .mbn, and inline metadata/hash segments in a .mdt).
    """
    if segment.filesz == 0:
        return b""  # BSS / no on-file data
    bnn = split_segment_path(container_path, segment.index)
    if os.path.exists(bnn):
        with open(bnn, "rb") as fh:
            data = fh.read()
        # split .bNN files hold exactly the segment payload from offset 0
        if len(data) >= segment.filesz:
            return data[:segment.filesz]
        return data  # short file: return what's there (caller may warn)
    if container_bytes is None:
        with open(container_path, "rb") as fh:
            container_bytes = fh.read()
    return container_bytes[segment.offset:segment.offset + segment.filesz]


def is_combined(image, container_path):
    """Heuristic: True if this looks like a single combined .mbn (no .bNN
    payload files present for the loadable segments)."""
    for s in image.loadable_segments:
        if s.filesz and os.path.exists(split_segment_path(container_path, s.index)):
            return False
    return True


def reconstruct_image(container_path):
    """Reconstruct the flat, loaded image (equivalent to pil-squasher output).

    Returns (flat_bytes, image). Each segment's filesz bytes are placed at its
    p_offset. The result reproduces a combined .mbn from either container form.
    """
    with open(container_path, "rb") as fh:
        container_bytes = fh.read()
    image = parse_mdt_bytes(container_bytes, source_path=container_path)

    total = 0
    for s in image.segments:
        if s.filesz:
            total = max(total, s.offset + s.filesz)
    out = bytearray(total)
    for s in image.segments:
        if not s.filesz:
            continue
        data = read_segment_data(image, container_path, s, container_bytes)
        out[s.offset:s.offset + len(data)] = data
    return bytes(out), image


# ---- afuc / ir3 payload identification -----------------------------------

def identify_payload(container_path):
    """Locate the afuc/QRisc code segment(s) and a best-effort embedded-ir3
    region within a ZAP image.

    Returns a dict:
      {
        'image': PilImage,
        'combined': bool,
        'afuc': [ {segment, vaddr, offset, size, data_source} ... ],
        'ir3_candidates': [ {segment|region, ...} ],   # best-effort, UNCONFIRMED
        'notes': [str, ...],
      }

    CAVEAT: with no public, license-clean signed ZAP blob to test against, the
    afuc-vs-ir3 split inside the code payload is heuristic. ZAP is documented as
    "afuc + embedded ir3 shader, no packet table"; the embedded ir3 typically
    lives at the tail of, or in a separate region of, the executable payload.
    The disassembler should decode from the start as afuc and treat a trailing
    region that stops decoding cleanly as the candidate ir3 boundary.
    """
    image = parse_mdt(container_path)
    combined = is_combined(image, container_path)
    notes = []

    afuc = []
    for s in image.code_segments:
        afuc.append({
            "segment": s.index,
            "vaddr": s.vaddr,
            "offset": s.offset,
            "size": s.filesz,
            "memsz": s.memsz,
            "data_source": "container@0x%x" % s.offset if combined
                           else os.path.basename(split_segment_path(container_path, s.index)),
        })

    if not afuc:
        notes.append("no executable (PF_X) loadable segment found; ZAP payload "
                     "may be flagged data-only -- inspect data segments manually")

    ir3 = []
    # Heuristic: any sizeable non-executable data segment, or a second code
    # segment, is an ir3 candidate. Confirmation requires running the QRisc
    # disassembler and finding where clean afuc decoding ends.
    for s in image.data_segments:
        if s.filesz >= 64:
            ir3.append({"segment": s.index, "vaddr": s.vaddr,
                        "offset": s.offset, "size": s.filesz,
                        "basis": "non-executable data segment"})
    if len(afuc) > 1:
        for extra in afuc[1:]:
            ir3.append({"segment": extra["segment"], "vaddr": extra["vaddr"],
                        "offset": extra["offset"], "size": extra["size"],
                        "basis": "secondary executable segment"})
    notes.append("ir3 region identification is best-effort/UNCONFIRMED "
                 "(no real ZAP blob available); confirm with the QRisc decoder.")

    return {
        "image": image,
        "combined": combined,
        "afuc": afuc,
        "ir3_candidates": ir3,
        "notes": notes,
    }


# ---- CLI ----------------------------------------------------------------

def _main(argv):
    import sys
    if len(argv) < 2:
        print("usage: qrisc_pil.py <file.mdt|file.mbn>")
        return 2
    path = argv[1]
    info = identify_payload(path)
    print(info["image"].summary())
    print("combined:", info["combined"])
    print("afuc code segments:", info["afuc"])
    print("ir3 candidates:", info["ir3_candidates"])
    for n in info["notes"]:
        print("note:", n)
    flat, _ = reconstruct_image(path)
    print("reconstructed flat image: %d bytes" % len(flat))
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(_main(sys.argv))
