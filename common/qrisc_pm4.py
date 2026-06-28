"""
qrisc_pm4.py -- Adreno PM4 type-7 packet opcode -> name database.

Parses Mesa's `adreno_pm4.xml` (enum `adreno_pm4_type3_packets`, varset="chip")
into a CP-opcode -> name map, honouring per-generation `variants=` gating so
a8xx-only packets (e.g. CP_BARRIER=0x59, CP_MEMORY_MAP_UPDATE=0x58) are included
for gen 8. Used by the loader / bootstrap helper to name packet handlers.

Stdlib only. Default XML path is the pinned Mesa tree; pass an override path to
`load()` for other trees.

Generations are integers: 5 (a5xx) .. 8 (a8xx). The `chip` enum maps AnXX -> n.

Variant string grammar (from rnn):
    ""            -> all generations
    "A6XX"        -> exactly gen 6
    "A6XX-"       -> gen 6 and later
    "A2XX-A4XX"   -> gens 2..4 inclusive
"""

import os
import re
import xml.etree.ElementTree as ET

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
DEFAULT_PM4_XML = os.path.join(
    _ROOT, "third_party", "mesa", "src", "freedreno", "registers", "adreno",
    "adreno_pm4.xml")

ENUM_NAME = "adreno_pm4_type3_packets"
INF = 1 << 30

_CHIP_RE = re.compile(r"^A(\d)XX$")


def _localname(tag):
    return tag.rsplit("}", 1)[-1]


def _chip_to_gen(tok):
    m = _CHIP_RE.match(tok.strip())
    return int(m.group(1)) if m else None


def _parse_variants(variants):
    """Return (lo, hi) inclusive generation range for a variants string."""
    if not variants:
        return (0, INF)
    v = variants.strip()
    if v.endswith("-") and "-" not in v[:-1]:        # "A6XX-"
        lo = _chip_to_gen(v[:-1])
        return (lo if lo is not None else 0, INF)
    if "-" in v:                                       # "A2XX-A4XX"
        a, b = v.split("-", 1)
        lo, hi = _chip_to_gen(a), _chip_to_gen(b)
        return (lo if lo is not None else 0, hi if hi is not None else INF)
    g = _chip_to_gen(v)                                # "A6XX"
    return (g, g) if g is not None else (0, INF)


class Pm4Db(object):
    """opcode -> [ (name, lo, hi) ... ] over all generations."""

    def __init__(self, entries):
        # entries: list of (opcode, name, lo, hi)
        self._by_opcode = {}
        for opcode, name, lo, hi in entries:
            self._by_opcode.setdefault(opcode, []).append((name, lo, hi))
        self.entries = entries

    def packet_name(self, opcode, gen):
        """Best (most specific) CP_* name for `opcode` at `gen`, else None."""
        best = None
        best_span = None
        for name, lo, hi in self._by_opcode.get(opcode, ()):
            if lo <= gen <= hi:
                span = hi - lo
                if best is None or span < best_span:
                    best, best_span = name, span
        return best

    def map_for_gen(self, gen):
        """{opcode: name} for all packets valid at `gen`."""
        out = {}
        for opcode in self._by_opcode:
            n = self.packet_name(opcode, gen)
            if n is not None:
                out[opcode] = n
        return out


def load(xml_path=None):
    xml_path = xml_path or DEFAULT_PM4_XML
    root = ET.parse(xml_path).getroot()
    entries = []
    for enum in root.iter():
        if _localname(enum.tag) != "enum" or enum.attrib.get("name") != ENUM_NAME:
            continue
        for val in enum:
            if _localname(val.tag) != "value":
                continue
            name = val.attrib.get("name")
            raw = val.attrib.get("value")
            if name is None or raw is None:
                continue
            opcode = int(raw, 0)
            lo, hi = _parse_variants(val.attrib.get("variants"))
            entries.append((opcode, name, lo, hi))
    if not entries:
        raise ValueError("enum %s not found in %s" % (ENUM_NAME, xml_path))
    return Pm4Db(entries)


def _baked():
    """Prefer the generated table (qrisc_isa_tables.PM4_PACKETS) so the runtime
    needs no Mesa tree. Returns a Pm4Db or None."""
    try:
        import qrisc_isa_tables as _t
        ents = getattr(_t, "PM4_PACKETS", None)
        if ents:
            return Pm4Db([tuple(e) for e in ents])
    except Exception:
        pass
    return None


# convenience module-level singletons (lazy)
_DB = None


def db():
    """PM4 DB: baked table first (standalone), then Mesa XML (dev/regen), then
    an empty DB (so a missing Mesa tree degrades to no packet names, not a crash).
    """
    global _DB
    if _DB is None:
        _DB = _baked()
    if _DB is None:
        try:
            _DB = load()
        except Exception:
            _DB = Pm4Db([])
    return _DB


def packet_name(opcode, gen):
    return db().packet_name(opcode, gen)
