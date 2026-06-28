#!/usr/bin/env python3
"""
qrisc_isa_gen.py -- generate standalone QRisc (afuc) decode tables for the
IDA processor module and the Ghidra SLEIGH skeleton, from Mesa's qrisc.xml.

Ground truth: src/freedreno/qrisc/qrisc.xml (isaspec). We reuse Mesa's own
parser (src/compiler/isaspec/isa.py) at *generation* time to resolve the
`extends` inheritance chains, <gen> gates, fields, overrides and display
templates -- then emit fully-resolved, plain-data Python tables so the runtime
decoder (which runs inside IDA, with no Mesa available) needs zero dependencies.

Pinned Mesa commit: 4bf8fd5121122abd87aafb31e43bbbe9e3d2e921

Output: common/qrisc_isa_tables.py
"""

import os
import sys
import pprint
import xml.etree.ElementTree as ET

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MESA = os.path.join(REPO, "third_party", "mesa")
QRISC_XML = os.path.join(MESA, "src", "freedreno", "qrisc", "qrisc.xml")
ISASPEC = os.path.join(MESA, "src", "compiler", "isaspec")
OUT = os.path.join(REPO, "common", "qrisc_isa_tables.py")

PINNED_COMMIT = "4bf8fd5121122abd87aafb31e43bbbe9e3d2e921"

sys.path.insert(0, ISASPEC)
from isa import ISA  # noqa: E402

MASK32 = (1 << 32) - 1


def chain(isa, bs):
    """Return [leaf, parent, ..., root] following `extends`."""
    out = []
    while bs is not None:
        out.append(bs)
        bs = isa.bitsets[bs.extends] if bs.extends else None
    return out


def field_to_dict(isa, f):
    d = {
        "name": f.name,
        "low": f.low,
        "high": f.high,
        "type": f.type,
    }
    if getattr(f, "display", None):
        d["display"] = f.display
    # params: e.g. BASE field passes PREINCREMENT down into #control-base
    if getattr(f, "params", None):
        d["params"] = [list(p) for p in f.params]
    # derived fields carry an expression (by name) instead of a bit range;
    # resolve the name to its source text so the runtime decoder can eval it.
    if f.__class__.__name__ == "BitSetDerivedField":
        d["derived"] = True
        d["expr"] = resolve_expr(isa, getattr(f, "expr", None))
    return d


def resolve_expr(isa, name):
    """Resolve an expression *name* to its source text (decoder evals text)."""
    if name is None:
        return None
    e = isa.expressions.get(name)
    return e.expr if e is not None else name


def case_to_dict(isa, case):
    """A bitset case: optional expr (override), display, and its own fields."""
    d = {
        "expr": resolve_expr(isa, case.expr),  # text, or None for default case
        "display": case.display,  # may be None (inherit) or '' (empty)
        "fields": [field_to_dict(isa, f) for f in case.fields.values()],
    }
    return d


def collect_referenced_types(isa, type_name, into):
    """Recursively capture bitset-typed operand sub-encodings (#src,#dst,...)."""
    if type_name in into:
        return
    if type_name in isa.bitsets:
        bs = isa.bitsets[type_name]
        rec = bitset_struct(isa, bs)
        into[type_name] = rec
        for c in rec["cases"]:
            for f in c["fields"]:
                collect_referenced_types(isa, f["type"], into)


def bitset_struct(isa, bs):
    """Resolved structure of a single bitset (no extends merge): cases+size."""
    # cases[:-1] are overrides (expr set), cases[-1] is default
    return {
        "name": bs.name,
        "size": bs.get_size(),
        "cases": [case_to_dict(isa, c) for c in bs.cases],
    }


def resolve_display(isa, lf):
    """Nearest default-case display template walking leaf -> root."""
    for bs in chain(isa, lf):
        dflt = bs.cases[-1]
        if dflt.display is not None:
            return isa.resolve_templates(dflt.display)
    return None


def build_leaf(isa, lf, nested):
    pat = lf.get_pattern()
    match = pat.match & MASK32
    dontcare = pat.dontcare & MASK32
    mask = pat.mask & MASK32
    care_mask = mask & (~dontcare & MASK32)

    # Merge default-case fields along the whole extends chain (root..leaf).
    fields = {}
    overrides = []  # (expr_name, display, [fields]) collected leaf->root
    for bs in chain(isa, lf):
        # default case fields
        for f in bs.cases[-1].fields.values():
            fields[f.name] = field_to_dict(isa, f)
            collect_referenced_types(isa, f.type, nested)
        # override cases (expr-gated alternate display/fields)
        for c in bs.cases[:-1]:
            disp = isa.resolve_templates(c.display) if c.display is not None else None
            ofields = []
            for f in c.fields.values():
                ofields.append(field_to_dict(isa, f))
                collect_referenced_types(isa, f.type, nested)
            overrides.append({
                "expr": resolve_expr(isa, c.expr),
                "display": disp,
                "fields": ofields,
            })

    return {
        "name": lf.name,
        "mnemonic": lf.display_name,
        "root": lf.get_root().name,
        "gen_min": lf.get_gen_min(),
        "gen_max": lf.get_gen_max(),
        "match": match,
        "mask": care_mask,
        "size": lf.get_size(),
        "display": resolve_display(isa, lf),
        "fields": list(fields.values()),
        "overrides": overrides,
    }


def enum_to_dict(en):
    # v.value is a string ('0', '0x1c'); v.displayname is the display text and
    # may legitimately be '' (e.g. #xmov value 0), so don't use get_displayname().
    return {int(v.value, 0): v.displayname for v in en.values.values()}


def expr_text(e):
    # BitSetExpression stores the C-ish expression text in .expr
    return getattr(e, "expr", None)


CONTROL_REGS_XML = os.path.join(
    MESA, "src", "freedreno", "registers", "adreno", "adreno_control_regs.xml")

# Maps GPU generation -> rnn domain name (see Mesa qrisc/util.c qrisc_util_init).
# a750 uses A7XX_GEN3_CONTROL_REG; the default a7xx domain is A7XX_CONTROL_REG.
GEN_CONTROL_DOMAIN = {5: "A5XX_CONTROL_REG", 6: "A6XX_CONTROL_REG",
                      7: "A7XX_CONTROL_REG"}
SQE_DOMAIN = "A6XX_SQE_REG"  # gen >= 6


def _localname(tag):
    return tag.rsplit("}", 1)[-1]  # strip {namespace}


def parse_reg_domains(xmlpath):
    """Parse rnn <domain> blocks -> {domain: [(offset, nwords, name), ...]}.

    reg32 spans 1 word, reg64 spans 2 (its hi word renders as NAME+0x1).
    """
    domains = {}
    if not os.path.exists(xmlpath):
        return domains
    root = ET.parse(xmlpath).getroot()
    for dom in root.iter():
        if _localname(dom.tag) != "domain":
            continue
        name = dom.attrib.get("name")
        regs = []
        for child in dom:
            ln = _localname(child.tag)
            if ln not in ("reg32", "reg64"):
                continue
            off = int(child.attrib["offset"], 0)
            nwords = 2 if ln == "reg64" else 1
            regs.append((off, nwords, child.attrib["name"]))
        regs.sort()
        domains[name] = regs
    return domains


def main():
    assert os.path.exists(QRISC_XML), "Mesa qrisc.xml not found: %s" % QRISC_XML
    isa = ISA(QRISC_XML)

    nested = {}
    leaves = [build_leaf(isa, lf, nested) for lf in isa.instructions()]
    # Stable, deterministic order: by gen, then most-specific mask first, then name.
    leaves.sort(key=lambda r: (r["gen_min"], r["gen_max"], -bin(r["mask"]).count("1"), r["name"]))

    enums = {name: enum_to_dict(en) for name, en in isa.enums.items()}
    exprs = {name: expr_text(e) for name, e in isa.expressions.items()}

    reg_domains = parse_reg_domains(CONTROL_REGS_XML)

    # PM4 packet name DB: bake it into the tables so the runtime (IDA/Ghidra)
    # needs no Mesa tree. Reuse qrisc_pm4's parser (in common/).
    sys.path.insert(0, os.path.dirname(OUT))
    import qrisc_pm4  # noqa: E402
    pm4_xml = os.path.join(MESA, "src", "freedreno", "registers", "adreno",
                           "adreno_pm4.xml")
    pm4_packets = [list(e) for e in qrisc_pm4.load(pm4_xml).entries]

    with open(OUT, "w") as fh:
        fh.write('"""AUTO-GENERATED by gen/qrisc_isa_gen.py from Mesa qrisc.xml.\n')
        fh.write("Pinned Mesa commit: %s\n" % PINNED_COMMIT)
        fh.write("Do not edit by hand -- regenerate instead.\n")
        fh.write('"""\n\n')
        fh.write("PINNED_COMMIT = %r\n\n" % PINNED_COMMIT)
        pp = pprint.PrettyPrinter(indent=1, width=100, sort_dicts=False)
        fh.write("ENUMS = " + pp.pformat(enums) + "\n\n")
        fh.write("EXPRS = " + pp.pformat(exprs) + "\n\n")
        fh.write("NESTED = " + pp.pformat(nested) + "\n\n")
        # gen -> control-register rnn domain (qrisc/util.c); sqe regs gen>=6
        fh.write("GEN_CONTROL_DOMAIN = " + pp.pformat(GEN_CONTROL_DOMAIN) + "\n\n")
        fh.write("SQE_DOMAIN = %r\n\n" % SQE_DOMAIN)
        fh.write("REG_DOMAINS = " + pp.pformat(reg_domains) + "\n\n")
        # PM4 packets: (opcode, name, gen_lo, gen_hi) -- baked so runtime needs no XML
        fh.write("PM4_PACKETS = " + pp.pformat(pm4_packets) + "\n\n")
        fh.write("INSTRUCTIONS = " + pp.pformat(leaves) + "\n")

    # ---- stats ----
    by_gen = {5: 0, 6: 0, 7: 0}
    for r in leaves:
        for g in (5, 6, 7):
            if r["gen_min"] <= g <= r["gen_max"]:
                by_gen[g] += 1
    print("wrote %s" % OUT)
    print("leaves: %d   enums: %d   exprs: %d   nested bitsets: %d"
          % (len(leaves), len(enums), len(exprs), len(nested)))
    print("decodable per gen: a5xx=%d a6xx=%d a7xx=%d" % (by_gen[5], by_gen[6], by_gen[7]))
    print("nested types captured:", sorted(nested.keys()))
    print("enums:", sorted(enums.keys()))
    print("exprs:")
    for k, v in exprs.items():
        print("   %-28s %s" % (k, (v or "").strip().replace("\n", " ")))
    # sanity: a couple of representative leaves
    print("\nsample leaves:")
    for want in ("add", "or", "movi", "cwrite", "brneb", "waitin", "nop", "jumpr"):
        for r in leaves:
            if r["name"] == want:
                print("  %-8s gen[%d..%s] match=%08x mask=%08x  disp=%r"
                      % (r["name"], r["gen_min"],
                         "inf" if r["gen_max"] == MASK32 else r["gen_max"],
                         r["match"], r["mask"], r["display"]))
                break


if __name__ == "__main__":
    main()
