"""Standalone QRisc (afuc) decoder + renderer.

Consumes the generated tables in qrisc_isa_tables.py. No Mesa / IDA /
Ghidra dependency. Reused by tests/test_disasm.py (oracle diff) and the
IDA processor module.

Decoding (mirrors Mesa isaspec): a word matches a leaf when
(word & leaf.mask) == leaf.match, most-specific (largest mask popcount)
wins, gated by GPU generation. Operands render from the leaf's display
template via {TOKEN} substitution; override cases are chosen by their
guard expression.

Generations: 6 (a6xx), 7 (a7xx). a8xx uses the gen-7 tables (best-effort).
"""

try:
    from . import qrisc_isa_tables as T  # package-relative
except Exception:  # pragma: no cover - direct/script import
    import qrisc_isa_tables as T

MASK32 = (1 << 32) - 1

# fw_id (== (word1>>12)&0xfff) -> GPU generation, from Mesa qrisc/util.c.
FWID_TO_GEN = {
    0x730: 7, 0x740: 7, 0x512: 7, 0x520: 7,   # a730/a740/gen70500/a750
    0x6ee: 6, 0x6dc: 6, 0x6dd: 6,             # a630/a650/a660
    0x5ff: 5,                                  # a530
}


def fwid_of(version_word):
    """Firmware id from the version dword (file word 1)."""
    return (version_word >> 12) & 0xfff


def gen_of(version_word, default=None):
    """GPU generation from the version dword, or `default` if unknown."""
    return FWID_TO_GEN.get(fwid_of(version_word), default)


def _bits(word, lo, hi):
    return (word >> lo) & ((1 << (hi - lo + 1)) - 1)


def _sx(value, width):
    """Sign-extend `value` of given bit `width`."""
    if value & (1 << (width - 1)):
        return value - (1 << width)
    return value


def _eval_py(text, vals):
    """Evaluate an isaspec expression (C-ish) against a field-value dict."""
    if text is None:
        return None
    py = text.replace("&&", " and ").replace("||", " or ")
    try:
        return eval(py, {"__builtins__": {}}, dict(vals))  # noqa: S307
    except Exception:
        return None


def _eval_expr(text, vals):
    """Boolean guard evaluation (override/case selection)."""
    return bool(_eval_py(text, vals))


def _eval_num(text, vals):
    """Numeric evaluation (derived field values, e.g. setsecure TARGET=3)."""
    v = _eval_py(text, vals)
    return int(v) if isinstance(v, (int, bool)) else 0


class Insn(object):
    """Decoded instruction: rich enough for both text + IDA emu/xrefs."""
    __slots__ = ("pc", "word", "leaf", "mnemonic", "root", "text",
                 "operands", "flow")

    def __init__(self, pc, word, leaf):
        self.pc = pc
        self.word = word
        self.leaf = leaf
        self.mnemonic = leaf["mnemonic"] if leaf else None
        self.root = leaf["root"] if leaf else None
        self.text = None
        self.operands = []   # list of dicts: {kind, value, ...} for IDA
        self.flow = {}       # control-flow facts for ev_emu (see classify())

    def __repr__(self):
        return "<Insn pc=%#x %s>" % (self.pc, self.text)


class Decoder(object):
    def __init__(self, gen):
        self.gen = gen
        decodable = [r for r in T.INSTRUCTIONS
                     if r["gen_min"] <= gen <= r["gen_max"]]
        # most-specific first so the first (word & mask)==match wins
        decodable.sort(key=lambda r: bin(r["mask"]).count("1"), reverse=True)
        self.instrs = decodable
        self.creg = self._regmap(T.REG_DOMAINS.get(
            T.GEN_CONTROL_DOMAIN.get(gen, ""), []))
        self.sqereg = self._regmap(
            T.REG_DOMAINS.get(T.SQE_DOMAIN, []) if gen >= 6 else [])
        self._pc = 0

    @staticmethod
    def _regmap(regs):
        spans = [(off, off + nw, name) for off, nw, name in regs]

        def lookup(rid):
            for off, end, name in spans:
                if off <= rid < end:
                    d = rid - off
                    return name if d == 0 else "%s+0x%x" % (name, d)
            return None
        return lookup

    # -- decode ------------------------------------------------------------
    def decode(self, word):
        word &= MASK32
        for r in self.instrs:
            if (word & r["mask"]) == r["match"]:
                return r
        return None

    # -- render ------------------------------------------------------------
    def disasm(self, word, pc=0):
        """Return an Insn (text + operands + flow), or None if undecodable."""
        word &= MASK32
        leaf = self.decode(word)
        if leaf is None:
            return None
        self._pc = pc
        insn = Insn(pc, word, leaf)
        insn.text = self._render_entity(
            leaf["display"], leaf["fields"], leaf["overrides"], word, {},
            mnemonic=leaf["mnemonic"], top=insn)
        classify(insn)
        return insn

    def _render_entity(self, display, fields, overrides, word, params,
                       mnemonic=None, top=None):
        # field name -> def (defaults), and field name -> raw value
        fdef = {f["name"]: f for f in fields}
        vals = {}
        for f in fields:
            if f.get("derived"):
                vals[f["name"]] = _eval_num(f.get("expr"), vals)
            else:
                vals[f["name"]] = _bits(word, f["low"], f["high"])
        vals.update(params)  # parent-passed params (e.g. PREINCREMENT)

        # choose display: first override whose guard holds, else default.
        # The guard may reference the override's *own* fields (e.g. SPECIALREG
        # aliasing REG over the same bits), so extract those before evaluating.
        chosen = display
        for ov in overrides or []:
            evalvals = dict(vals)
            for f in ov.get("fields", []):
                if not f.get("derived"):
                    evalvals[f["name"]] = _bits(word, f["low"], f["high"])
            if _eval_expr(ov["expr"], evalvals):
                chosen = ov["display"]
                vals = evalvals
                for f in ov.get("fields", []):
                    fdef[f["name"]] = f
                break

        if chosen is None:
            return mnemonic or ""
        return self._subst(chosen, fdef, vals, mnemonic, top)

    def _subst(self, template, fdef, vals, mnemonic, top):
        out = []
        i = 0
        while i < len(template):
            c = template[i]
            if c == "{":
                j = template.index("}", i)
                tok = template[i + 1:j]
                out.append(self._render_token(tok, fdef, vals, mnemonic, top))
                i = j + 1
            else:
                out.append(c)
                i += 1
        return "".join(out)

    def _render_token(self, tok, fdef, vals, mnemonic, top):
        if tok == "NAME":
            return mnemonic or ""
        if tok not in fdef:
            return ""  # unresolved template token (e.g. sread XREG) -> empty
        return self._render_field(fdef[tok], vals.get(tok, 0), vals, top)

    def _render_field(self, fd, value, parent_vals, top):
        t = fd["type"]
        if t == "bool":
            return fd.get("display", "") if value else ""
        if t in T.ENUMS:
            disp = T.ENUMS[t].get(value)
            return disp if disp is not None else "0x%x" % value
        if t in T.NESTED:
            params = {}
            for pair in fd.get("params", []):
                pname, pas = pair[0], pair[1]
                params[pas] = parent_vals.get(pname, 0)
            nst = T.NESTED[t]
            default = nst["cases"][-1]
            overrides = nst["cases"][:-1]
            return self._render_entity(default["display"], default["fields"],
                                       overrides, value, params, top=top)
        if t == "hex":
            return "%x" % value
        if t in ("uint", "uint8_t"):
            return "%d" % value
        if t == "int":
            return "%d" % _sx(value, fd["high"] - fd["low"] + 1)
        if t == "branch":
            # relative to this instruction's pc (word units)
            tgt = (self._pc + _sx(value, fd["high"] - fd["low"] + 1)) & MASK32
            if top is not None:
                top.operands.append({"kind": "rel", "target": tgt})
            return "0x%x" % tgt
        if t == "absbranch":
            tgt = value & MASK32
            if top is not None:
                top.operands.append({"kind": "abs", "target": tgt})
            return "0x%x" % tgt
        if t == "custom":
            if fd["name"] == "CONTROLREG":
                n = self.creg(value)
                return "@" + n if n else "0x%03x" % value
            if fd["name"] == "SQEREG":
                n = self.sqereg(value)
                return "%" + n if n else "0x%03x" % value
        return "0x%x" % value


# ----- control-flow classification (for the IDA ev_emu_insn stage) ---------
# NB: keyed on the leaf *name*, NOT leaf['root'] -- every leaf's isaspec root is
# "#instruction", so root-based family detection would be dead code.
_BRANCH_NAMES = {"brnei", "breqi", "brneb", "breqb"}   # mnemonics brne/breq
_RET_NAMES = {"ret", "iret", "sret"}


def classify(insn):
    """Annotate insn.flow with control-flow facts.

    Keys: is_branch, is_cond, is_call, is_ret, is_indirect, is_stop,
          has_delay_slot, target (abs/rel, when statically known).

    `has_delay_slot` means the *next* instruction always executes (QRisc has a
    branch delay slot). `is_stop` means control does not fall through *past* the
    delay slot (unconditional transfer / return). The IDA emu stage uses these
    to add the delay-slot fall-through cref plus the taken-target cref.
    """
    f = {"is_branch": False, "is_cond": False, "is_call": False,
         "is_ret": False, "is_indirect": False, "is_stop": False,
         "has_delay_slot": False, "target": None}
    if insn.leaf is None:
        insn.flow = f
        return f
    name = insn.leaf["name"]
    text = (insn.text or "").lstrip()

    if name in _BRANCH_NAMES:
        f["is_branch"] = True
        f["has_delay_slot"] = True
        # `jump #x` is the brneb $00,b0 alias -> unconditional (always taken),
        # rendered with the "jump" mnemonic by the override.
        is_jump = text.startswith("jump ")
        f["is_cond"] = not is_jump
        f["is_stop"] = is_jump
        for op in insn.operands:
            if op["kind"] == "rel":
                f["target"] = op["target"]
    elif name in ("call", "bl"):
        f["is_call"] = True
        f["has_delay_slot"] = True
        for op in insn.operands:
            if op["kind"] == "abs":
                f["target"] = op["target"]
    elif name == "jumpa":
        f["is_branch"] = True
        f["has_delay_slot"] = True
        f["is_stop"] = True
        for op in insn.operands:
            if op["kind"] == "abs":
                f["target"] = op["target"]
    elif name in _RET_NAMES:
        f["is_ret"] = True
        f["is_stop"] = True
        f["has_delay_slot"] = True
    elif name == "jumpr":
        f["is_indirect"] = True
        f["is_ret"] = True   # jump $lr used as return
        f["is_stop"] = True
        f["has_delay_slot"] = True
    elif name == "waitin":
        # parses next packet header and dispatches via the jump table
        f["is_branch"] = True
        f["is_indirect"] = True
        f["has_delay_slot"] = True
    insn.flow = f
    return f
