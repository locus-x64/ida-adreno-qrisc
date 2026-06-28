#!/usr/bin/env python3
"""
qrisc_sleigh_gen.py -- generate a Ghidra SLEIGH module for the Adreno QRisc
(afuc) command-processor ISA, from the standalone decode tables produced by
gen/qrisc_isa_gen.py (common/qrisc_isa_tables.py), which in turn come from
Mesa's qrisc.xml (pinned commit 4bf8fd5...).

Emits, under ghidra/Ghidra/Processors/QRisc/data/languages/:
  - qrisc.sinc       (core: spaces, registers, token+fields, attaches, pcodeops,
                      operand sub-tables, branch-target operands)
  - qrisc_gen6.sinc  (a6xx instruction constructors)
  - qrisc_gen7.sinc  (a7xx instruction constructors; a8xx reuses these)

The .slaspec / .ldefs / .pspec / .cspec files are hand-written (committed) and
@include the generated .sinc files.

Design notes (see ghidra/VALIDATION.md for the full rationale):
  * Code space is byte-addressed, 4 bytes/insn. Word offsets in the ISA are
    scaled x4. Image is expected mapped at address 0 (word i -> byte i*4).
  * GPRs r00..r19, sp(0x1a), lr(0x1b). $00 is a real register (the firmware
    keeps it 0 by convention; not modelled as a hard constant).
  * Special queue/reg pseudo-registers (rem,data,memdata,regdata,addr,usraddr)
    are VOLATILE registers, so reads/writes survive decompiler optimization and
    read like memory-mapped FIFO/registers.
  * cread/cwrite/sread/swrite/load/store -> CALLOTHER pcodeops (creg/sreg/mem).
  * Branch delay slots -> SLEIGH delayslot(1). call/bl push return; ret/sret ->
    return; jumpr/waitin -> computed goto.
  * Modifiers (rep)/(xmov)/(peek)/(sds): bits left don't-care in v1 (decode is
    unaffected); preincrement '!' is shown. Tracked in VALIDATION.md.
"""

import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "common"))
import qrisc_isa_tables as T  # noqa: E402

LANGDIR = os.path.join(REPO, "ghidra", "Ghidra", "Processors", "QRisc",
                       "data", "languages")
MASK32 = (1 << 32) - 1

# ---------------------------------------------------------------------------
# register lists (index 0..31 for the 5-bit src/dst fields)
# ---------------------------------------------------------------------------
GPRS = ["r%02x" % i for i in range(0x1a)] + ["sp", "lr"]   # 0x00..0x1b
SRC_REGS = GPRS + ["rem", "memdata", "regdata", "data"]    # 0x1c..0x1f
DST_REGS = GPRS + ["rem", "addr", "usraddr", "data"]       # 0x1c..0x1f
SPECIAL_REGS = ["rem", "data", "memdata", "regdata", "addr", "usraddr"]


def runs(mask):
    """Contiguous set-bit ranges of `mask` as [(lo, hi), ...]."""
    out = []
    i = 0
    while i < 32:
        if mask & (1 << i):
            j = i
            while j < 32 and (mask & (1 << j)):
                j += 1
            out.append((i, j - 1))
            i = j
        else:
            i += 1
    return out


def field_val(match, lo, hi):
    return (match >> lo) & ((1 << (hi - lo + 1)) - 1)


# ---------------------------------------------------------------------------
# per-instruction SLEIGH emission
# ---------------------------------------------------------------------------
OPFIELDS = set()   # collected (lo,hi) opcode constraint fields
IMMFIELDS = set()  # collected (lo,hi) immediate operand fields (width varies by gen)


def imm_field(rec, fname, default=(0, 15)):
    """Return the SLEIGH field name for immediate `fname`, using its ACTUAL bit
    range from the record (gen7 shl/ushr/ishr/rot use a 12-bit immediate, not 16)."""
    allf = list(rec["fields"])
    for o in rec["overrides"]:
        allf += o["fields"]
    for f in allf:
        if f["name"] == fname:
            lo, hi = f["low"], f["high"]
            break
    else:
        lo, hi = default
    IMMFIELDS.add((lo, hi))
    return "imm_%d_%d" % (lo, hi)


def opcode_constraint(rec):
    """Constraint string (field=value & ...) for the opcode/care bits."""
    parts = []
    for (lo, hi) in runs(rec["mask"]):
        OPFIELDS.add((lo, hi))
        parts.append("op%d_%d=0x%x" % (lo, hi, field_val(rec["match"], lo, hi)))
    return parts


# ALU 2-src reg-form p-code by mnemonic. d=dest, a=src1, b=src2.
ALU2 = {
    "add":  "{d} = {a} + {b};",
    "sub":  "{d} = {a} - {b};",
    "and":  "{d} = {a} & {b};",
    "or":   "{d} = {a} | {b};",
    "xor":  "{d} = {a} ^ {b};",
    "shl":  "{d} = {a} << {b};",
    "ushr": "{d} = {a} >> {b};",
    "ishr": "{d} = {a} s>> {b};",
    "bic":  "{d} = {a} & ~{b};",
    "addhi": "{d} = qrisc_addhi({a}, {b});",
    "subhi": "{d} = qrisc_subhi({a}, {b});",
    "rot":  "{d} = qrisc_rotl({a}, {b});",
    "mul8": "{d} = qrisc_mul8({a}, {b});",
    "min":  "{d} = qrisc_min({a}, {b});",
    "max":  "{d} = qrisc_max({a}, {b});",
    "cmp":  "{d} = qrisc_cmp({a}, {b});",
    "setbit": "{d} = qrisc_setbit({a}, {b});",
}
# ALU 2-src immediate-form (src2 = imm16). dest is at [16:20] (d16).
ALU2_IMM = {
    "add": "{d} = {a} + {imm};", "sub": "{d} = {a} - {imm};",
    "and": "{d} = {a} & {imm};", "or": "{d} = {a} | {imm};",
    "xor": "{d} = {a} ^ {imm};", "shl": "{d} = {a} << {imm};",
    "ushr": "{d} = {a} >> {imm};", "ishr": "{d} = {a} s>> {imm};",
    "bic": "{d} = {a} & ~{imm};",
    "addhi": "{d} = qrisc_addhi({a}, {imm});",
    "subhi": "{d} = qrisc_subhi({a}, {imm});",
    "rot": "{d} = qrisc_rotl({a}, {imm});",
    "mul8": "{d} = qrisc_mul8({a}, {imm});",
    "min": "{d} = qrisc_min({a}, {imm});",
    "max": "{d} = qrisc_max({a}, {imm});",
    "cmp": "{d} = qrisc_cmp({a}, {imm});",
}


def classify(rec):
    d = rec["display"] or ""
    n = rec["name"]
    if n in ("ret", "iret"):
        return "RET"
    if n == "sret":
        return "SRET"
    if n == "jumpr":
        return "JUMPR"
    if n == "waitin":
        return "WAITIN"
    if n == "setsecure":
        return "SETSECURE"
    if n in ("call", "bl", "jumpa"):
        return "ABS"
    if n == "nop":
        return "NOP"
    if "cwrite" in d:
        return "CWRITE"
    if "cread" in d:
        return "CREAD"
    if "swrite" in d:
        return "SWRITE"
    if "sread" in d:
        return "SREAD"
    if "load " in d:
        return "LOAD"
    if "store" in d:
        return "STORE"
    if "b{LO}, b{HI}" in d:
        return "BITFIELD"
    if "#{OFFSET}" in d and "b{BIT}" in d:
        return "BR_BIT"
    if "#{OFFSET}" in d and "0x{IMMED}" in d:
        return "BR_IMM"
    if "<< {SHIFT}" in d:
        return "MOVI"
    if "b{BIT}" in d:
        return "SETCLRBIT"
    if "0x{RIMMED}" in d and "{SRC1}" in d:
        return "ALU2_IMM"
    if "0x{IMMED}" in d and "{DST}" in d and "{SRC1}" not in d:
        return "ALU1_IMM"
    if "{SRC2}" in d:
        return "ALU2_REG"
    if "{SRC1}" in d:
        return "ALU1_REG"
    return "UNKNOWN"


def emit_insn(rec):
    """Return SLEIGH constructor text (possibly multiple) for one leaf record."""
    shape = classify(rec)
    mn = rec["mnemonic"]
    cons = opcode_constraint(rec)
    out = []

    def C(display, ops, sem, extra=None):
        # pattern = opcode constraints & value constraints & bare operand fields
        pat = " & ".join(cons + (extra or []) + ops)
        return ":%s is %s {\n%s\n}\n" % (display, pat, sem)

    if shape == "ALU2_REG":
        sem = ALU2.get(mn, "{d} = qrisc_%s({a}, {b});" % mn)
        sem = "    " + sem.format(d="d11", a="s21", b="s16")
        out.append(C("%s d11, s21, s16" % mn, ["d11", "s21", "s16"], sem))
    elif shape == "ALU1_REG":
        sem = "    d11 = ~s16;" if mn == "not" else "    d11 = qrisc_msb(s16);"
        out.append(C("%s d11, s16" % mn, ["d11", "s16"], sem))
    elif shape == "ALU2_IMM":
        imm = imm_field(rec, "RIMMED")
        tmpl = ALU2_IMM.get(mn, "{d} = qrisc_%s({a}, {imm});" % mn)
        sem = "    local i:4 = %s;\n    " % imm + tmpl.format(d="d16", a="s21", imm="i")
        out.append(C("%s d16, s21, %s" % (mn, imm), ["d16", "s21", imm], sem))
    elif shape == "ALU1_IMM":  # noti
        imm = imm_field(rec, "IMMED")
        out.append(C("%s d16, %s" % (mn, imm), ["d16", imm],
                     "    local i:4 = %s;\n    d16 = ~i;" % imm))
    elif shape == "MOVI":
        imm = imm_field(rec, "RIMMED")
        out.append(C("mov d16, %s, sh5" % imm, ["d16", imm, "sh5"],
                     "    local i:4 = %s;\n    local sh:4 = sh5;\n"
                     "    d16 = i << sh;" % imm))
    elif shape == "SETCLRBIT":
        if mn == "setbit":
            sem = "    local b:4 = bit_1_5;\n    d16 = s21 | (1:4 << b);"
        else:
            sem = "    local b:4 = bit_1_5;\n    d16 = s21 & ~(1:4 << b);"
        out.append(C("%s d16, s21, bit_1_5" % mn, ["d16", "s21", "bit_1_5"], sem))
    elif shape == "BITFIELD":
        if mn == "ubfx":
            sem = ("    local lo:4 = blo;\n    local hi:4 = bhi;\n"
                   "    d16 = qrisc_ubfx(s21, lo, hi);")
        else:
            sem = ("    local lo:4 = blo;\n    local hi:4 = bhi;\n"
                   "    d16 = qrisc_bfi(d16, s21, lo, hi);")
        out.append(C("%s d16, s21, blo, bhi" % mn,
                     ["d16", "s21", "blo", "bhi"], sem))
    elif shape == "CWRITE":
        sem = ("    local idx:4 = s21 + base12;\n"
               "    qrisc_creg_write(idx, s16);")
        out.append(C("cwrite s16, [s21 + base12]preinc",
                     ["s16", "s21", "base12", "preinc"], sem))
    elif shape == "CREAD":
        out.append(C("cread d16, [s21 + base12]preinc",
                     ["d16", "s21", "base12", "preinc"],
                     "    d16 = qrisc_creg_read(s21 + base12);"))
    elif shape == "SWRITE":
        out.append(C("swrite s16, [s21 + base12]preinc",
                     ["s16", "s21", "base12", "preinc"],
                     "    qrisc_sreg_write(s21 + base12, s16);"))
    elif shape == "SREAD":
        out.append(C("sread d16, [s21 + base12]preinc",
                     ["d16", "s21", "base12", "preinc"],
                     "    d16 = qrisc_sreg_read(s21 + base12);"))
    elif shape == "LOAD":
        out.append(C("load d16, [s21 + base12]preinc",
                     ["d16", "s21", "base12", "preinc"],
                     "    d16 = qrisc_load(s21 + base12);"))
    elif shape == "STORE":
        out.append(C("store s16, [s21 + base12]preinc",
                     ["s16", "s21", "base12", "preinc"],
                     "    qrisc_store(s21 + base12, s16);"))
    elif shape == "BR_IMM":
        cond = "!=" if mn == "brne" else "=="
        sem = "    delayslot(1);\n    if (s21 %s imm5) goto rel;" % cond
        out.append(C("%s s21, imm5, rel" % mn, ["s21", "imm5", "rel"], sem))
    elif shape == "BR_BIT":
        if rec["name"] == "brneb":
            out.append(C("jump rel", ["rel"],
                         "    delayslot(1);\n    goto rel;",
                         extra=["s21=0", "bit5b=0"]))
        test = "== 0" if mn == "brne" else "!= 0"
        sem = ("    delayslot(1);\n"
               "    if (((s21 >> bit5b) & 1) %s) goto rel;" % test)
        out.append(C("%s s21, bit5b, rel" % mn, ["s21", "bit5b", "rel"], sem))
    elif shape == "ABS":
        if rec["name"] == "call":
            sem = ("    local ra:4 = inst_start + 8;\n"
                   "    csp = csp - 4;\n"
                   "    *[hwstack]:4 csp = ra;\n"
                   "    delayslot(1);\n"
                   "    call abs;")
        elif rec["name"] == "bl":
            sem = ("    lr = (inst_start >> 2) + 2;\n"
                   "    delayslot(1);\n"
                   "    call abs;")
        else:  # jumpa
            sem = "    delayslot(1);\n    goto abs;"
        out.append(C("%s abs" % mn, ["abs"], sem))
    elif shape == "RET":
        sem = ("    local ra:4 = *[hwstack]:4 csp;\n"
               "    csp = csp + 4;\n"
               "    delayslot(1);\n"
               "    return [ra];")
        out.append(C(mn, [], sem))
    elif shape == "SRET":
        sem = ("    local t:4 = lr << 2;\n"
               "    delayslot(1);\n"
               "    return [t];")
        out.append(C("sret", [], sem))
    elif shape == "JUMPR":
        sem = ("    local t:4 = s0 << 2;\n"
               "    delayslot(1);\n"
               "    goto [t];")
        out.append(C("jump s0", ["s0"], sem))
    elif shape == "WAITIN":
        sem = ("    delayslot(1);\n"
               "    local h:4 = qrisc_waitin();\n"
               "    goto [h];")
        out.append(C("waitin", [], sem))
    elif shape == "SETSECURE":
        out.append(C("setsecure", [], "    qrisc_setsecure();"))
    elif shape == "NOP":
        out.append(C("nop", [], "    nop_dummy:1 = 0:1;"))
    else:
        out.append("# UNKNOWN shape for %s : %r\n" % (rec["name"], rec["display"]))
    return "".join(out)


# ---------------------------------------------------------------------------
# core .sinc emission
# ---------------------------------------------------------------------------
def emit_core():
    L = []
    A = L.append
    A("# AUTO-GENERATED core SLEIGH for QRisc (afuc). Source: Mesa %s" % T.PINNED_COMMIT)
    A("# Generated by ghidra/tools/qrisc_sleigh_gen.py -- do not edit by hand.\n")
    A("define endian=little;")
    A("define alignment=4;\n")
    A("define space code     type=ram_space      size=4 default;")
    A("define space register type=register_space size=4;")
    A("define space CREG     type=ram_space      size=4;")
    A("define space SREG     type=ram_space      size=4;")
    A("define space MEM      type=ram_space      size=8;")
    A("define space hwstack  type=ram_space      size=4;\n")
    # GPRs at 0x00 stride 4
    gpr_line = " ".join(GPRS)
    A("define register offset=0x00 size=4 [ %s ];" % gpr_line)
    A("define register offset=0x80 size=4 [ %s ];" % " ".join(SPECIAL_REGS))
    A("define register offset=0x100 size=4 [ pc csp ];\n")

    # token + fields: operand fields first, opcode fields appended after collection
    # (we collect OPFIELDS by emitting instructions first; so emit core last).
    return "\n".join(L)


def emit_token():
    L = ["define token instr(32)"]
    # operand fields
    operand_fields = [
        ("rep", 26, 26), ("peek", 8, 8), ("xmov", 9, 10), ("sds", 12, 13),
        ("preinc", 14, 14),
        ("d11", 11, 15), ("d16", 16, 20),
        ("s21", 21, 25), ("s16", 16, 20), ("s0", 0, 4),
        ("sh5", 21, 25),
        ("imm16", 0, 15), ("imm5", 16, 20),
        ("boff", 0, 15),
        ("bit_1_5", 1, 5), ("bit5b", 16, 20),
        ("blo", 0, 4), ("bhi", 5, 9),
        ("base12", 0, 11), ("t26", 0, 25),
    ]
    signed = {"boff"}
    for (nm, lo, hi) in operand_fields:
        s = " signed" if nm in signed else ""
        L.append("  %-8s = (%d,%d)%s" % (nm, lo, hi, s))
    # immediate operand fields (width varies by gen; collected during emission)
    for (lo, hi) in sorted(IMMFIELDS):
        L.append("  imm_%d_%d = (%d,%d)" % (lo, hi, lo, hi))
    # opcode constraint fields (collected during instruction emission)
    for (lo, hi) in sorted(OPFIELDS):
        L.append("  op%d_%d = (%d,%d)" % (lo, hi, lo, hi))
    L.append(";\n")
    # attaches
    L.append("attach variables [ s21 s16 s0 ] [ %s ];" % " ".join(SRC_REGS))
    L.append("attach variables [ d11 d16 ] [ %s ];" % " ".join(DST_REGS))
    L.append('attach names [ preinc ] [ "" "!" ];\n')
    # pcodeops
    for op in ["qrisc_creg_read", "qrisc_creg_write", "qrisc_sreg_read",
               "qrisc_sreg_write", "qrisc_load", "qrisc_store", "qrisc_waitin",
               "qrisc_setsecure", "qrisc_rotl", "qrisc_cmp", "qrisc_mul8",
               "qrisc_msb", "qrisc_min", "qrisc_max", "qrisc_ubfx", "qrisc_bfi",
               "qrisc_addhi", "qrisc_subhi", "qrisc_setbit"]:
        L.append("define pcodeop %s;" % op)
    L.append("")
    # branch-target operands (relative word offset *4; absolute word *4)
    L.append("rel: reloc is boff [ reloc = inst_start + boff * 4; ] "
             "{ export *:4 reloc; }")
    L.append("abs: reloc is t26 [ reloc = t26 * 4; ] "
             "{ export *:4 reloc; }")
    L.append("")
    return "\n".join(L)


def main():
    os.makedirs(LANGDIR, exist_ok=True)

    gen6 = [r for r in T.INSTRUCTIONS if r["gen_min"] <= 6 <= r["gen_max"]]
    gen7 = [r for r in T.INSTRUCTIONS if r["gen_min"] <= 7 <= r["gen_max"]]

    body6 = "".join(emit_insn(r) for r in gen6)
    body7 = "".join(emit_insn(r) for r in gen7)  # populates OPFIELDS fully too

    core = emit_core() + "\n" + emit_token()

    with open(os.path.join(LANGDIR, "qrisc.sinc"), "w") as f:
        f.write(core)
    hdr = "# AUTO-GENERATED instruction constructors -- do not edit.\n\n"
    with open(os.path.join(LANGDIR, "qrisc_gen6.sinc"), "w") as f:
        f.write(hdr + body6)
    with open(os.path.join(LANGDIR, "qrisc_gen7.sinc"), "w") as f:
        f.write(hdr + body7)

    # report unknowns
    unk = [r["name"] for r in (gen6 + gen7) if classify(r) == "UNKNOWN"]
    print("gen6 constructors:", len(gen6), " gen7 constructors:", len(gen7))
    print("opcode fields:", len(OPFIELDS))
    if unk:
        print("UNKNOWN shapes:", sorted(set(unk)))
    else:
        print("all shapes classified OK")


if __name__ == "__main__":
    main()
