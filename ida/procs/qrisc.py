"""IDA Pro processor module for Adreno CP microcode (afuc/QRisc).

Pure IDAPython, IDA 9.x. Covers a6xx and a7xx; a8xx is decoded best-effort
via the a7xx tables. Decoding is delegated to ../../common (qrisc_disasm +
qrisc_isa_tables); this file adapts that to IDA's processor_t (ana/emu/out).

The loader (ida/loaders/qrisc_loader.py) stores the GPU generation in a
netnode. Without that, defaults to gen 7. Use ida/install.sh to install.

The pure helpers (itype table, flow derivation, target computation) are
unit-tested in tests/test_proc.py. The live processor_t wiring requires IDA.
"""

import os
import sys

# --- locate the shared core, install-location-agnostic -------------------
# Works from the repo, when common/*.py are copied beside this file in IDA's
# procs/ dir (or into IDA's python/ dir), or via QRISC_HOME (repo or its
# common/ dir). See ida/install.sh.
def _locate_qrisc_common():
    here = os.path.dirname(os.path.abspath(__file__))
    env = os.environ.get("QRISC_HOME")
    cands = []
    if env:
        cands += [env, os.path.join(env, "common")]
    cands += [
        here,
        os.path.join(here, "qrisc_common"),
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
        "qrisc proc: cannot find the shared qrisc_* modules. Copy common/*.py "
        "next to this file (or into IDA's python/ dir), or set QRISC_HOME. "
        "See ida/install.sh.")

import qrisc_isa_tables as T          # noqa: E402
from qrisc_disasm import Decoder, gen_of, fwid_of  # noqa: E402,F401

DEFAULT_GEN = 7
NETNODE_NAME = "$ qrisc"
NETNODE_GEN_TAG = "G"   # supval/altval slot for the generation

# ---------------------------------------------------------------------------
# IDA-independent core (unit-tested without IDA present)
# ---------------------------------------------------------------------------

# Flow categories returned by derive_flow().
FLOW_NORMAL = "normal"
FLOW_COND_BRANCH = "cond_branch"     # brne/breq (rel target, conditional)
FLOW_UNCOND_BRANCH = "uncond_branch"  # jump / jumpa (rel/abs target, taken)
FLOW_CALL = "call"                    # call / bl
FLOW_RET = "ret"                      # ret / iret / sret / jumpr ($lr)
FLOW_WAITIN = "waitin"               # packet dispatch (indirect)


def unique_mnemonics():
    """Stable, sorted list of distinct mnemonics across all gens."""
    seen = []
    s = set()
    for r in sorted(T.INSTRUCTIONS, key=lambda r: (r["mnemonic"], r["name"])):
        mn = r["mnemonic"]
        if mn not in s:
            s.add(mn)
            seen.append(mn)
    return seen


def build_itypes():
    """Return (instruc, itype_of).

    instruc[0] is a reserved invalid entry; instruc[i] = {'name','feature_str'}.
    itype_of maps mnemonic -> itype index. feature_str is a set of capability
    tags ('CALL','JUMP','STOP') resolved to CF_* when IDA is present.
    """
    instruc = [{"name": "", "feature_str": set()}]   # itype 0 = invalid
    itype_of = {}
    for mn in unique_mnemonics():
        itype_of[mn] = len(instruc)
        instruc.append({"name": mn, "feature_str": _mnem_features(mn)})
    return instruc, itype_of


_CALL_MNEMS = {"call", "bl"}
_RET_MNEMS = {"ret", "iret", "sret"}
_JUMP_MNEMS = {"jump", "jumpa", "brne", "breq", "waitin"}


def _mnem_features(mn):
    f = set()
    if mn in _CALL_MNEMS:
        f.add("CALL")
    if mn in _RET_MNEMS:
        f.add("STOP")
    if mn in _JUMP_MNEMS:
        f.add("JUMP")
    if mn == "jumpr":          # indirect jump used as return
        f.add("JUMP")
        f.add("STOP")
    return f


def derive_flow(di):
    """Classify control flow from a decoded Insn (independent of common.classify,
    whose root-based branch check is a no-op since every root is '#instruction').

    Returns (category, target_word) where target_word is the absolute
    instruction-word index of a statically-known target, else None.
    """
    if di is None or di.leaf is None:
        return FLOW_NORMAL, None
    name = di.leaf["name"]
    mn = di.leaf["mnemonic"]

    target = None
    kind = None
    for op in di.operands:
        kind = op["kind"]
        target = op["target"]
        break

    if name in _CALL_MNEMS:
        return FLOW_CALL, target
    if name in ("ret", "iret", "sret", "jumpr"):
        return FLOW_RET, None
    if name == "waitin":
        return FLOW_WAITIN, None
    if name == "jumpa":
        return FLOW_UNCOND_BRANCH, target
    if kind == "rel":
        # brneb $00,b0 renders mnemonic 'jump' (unconditional); else conditional
        if mn == "jump":
            return FLOW_UNCOND_BRANCH, target
        return FLOW_COND_BRANCH, target
    return FLOW_NORMAL, None


def target_ea(insn_ea, seg_start, target_word):
    """Absolute IDA address of an instruction-word target within a sub-image."""
    return seg_start + target_word * 4


def read_gen_default(version_word=None):
    """Best-effort gen when no netnode is set: from version word, else default."""
    if version_word is not None:
        g = gen_of(version_word)
        if g is not None:
            return g
    return DEFAULT_GEN


# ---------------------------------------------------------------------------
# IDA processor_t integration (only when running inside IDA)
# ---------------------------------------------------------------------------
try:
    import idaapi
    import ida_idp
    import ida_bytes
    import ida_ua
    import ida_netnode
    import ida_idaapi
    from ida_idp import CF_CALL, CF_JUMP, CF_STOP
    from idaapi import (o_void, o_reg, o_imm, o_near, o_displ,
                        dt_dword, fl_F, fl_JN, fl_CN)
    _HAVE_IDA = True
except Exception:
    _HAVE_IDA = False


# Register file: $00..$19, $sp, $lr, the special src/dst regs, then segregs.
REG_NAMES = (["$%02x" % i for i in range(0x1a)] + ["$sp", "$lr"] +
             ["$rem", "$memdata", "$regdata", "$data", "$addr", "$usraddr"] +
             ["CS", "DS"])


if _HAVE_IDA:

    class qrisc_processor_t(idaapi.processor_t):
        id = 0x8000 + 0x71  # custom processor id ('q')
        # Match IDA's own scriptable modules (msp430/ebc/spu): declare segment
        # registers (PR_SEGS) even though QRisc has none, allow register names
        # (PR_RNAMESOK), 32-bit, default 32-bit segments, hex numbers.
        flag = (ida_idp.PR_USE32 | ida_idp.PRN_HEX | ida_idp.PR_DEFSEG32 |
                ida_idp.PR_SEGS | ida_idp.PR_RNAMESOK)
        flag2 = 0
        # QRisc has no segmentation; we still must declare the (fake) segment
        # register bytes IDA requires. 0 = segment registers are 0 bytes wide.
        segreg_size = 0
        cnbits = 8
        dnbits = 8
        psnames = ["qrisc"]
        plnames = ["Adreno command processor (QRisc / afuc)"]
        assembler = {
            "flag": ida_idp.ASH_HEXF3 | ida_idp.AS_UNEQU | ida_idp.AS_COLON |
                    ida_idp.ASB_BINF4 | ida_idp.AS_N2CHR,
            "uflag": 0,
            "name": "QRisc assembler",
            "origin": ".org",
            "end": ".end",
            "cmnt": ";",
            "ascsep": '"',
            "accsep": "'",
            "esccodes": "\"'",
            "a_ascii": ".ascii",
            "a_byte": ".byte",
            "a_word": ".word",
            "a_dword": ".dword",
            "a_bss": "dfs %s",
            "a_seg": "seg",
            "a_curip": ".",
            "a_public": "",
            "a_weak": "",
            "a_extrn": ".extern",
            "a_comdef": "",
            "a_align": ".align",
            "lbrace": "(",
            "rbrace": ")",
            "a_mod": "%",
            "a_band": "&",
            "a_bor": "|",
            "a_xor": "^",
            "a_bnot": "~",
            "a_shl": "<<",
            "a_shr": ">>",
            "a_sizeof_fmt": "size %s",
        }

        def __init__(self):
            super().__init__()
            self._decoders = {}
            self.instruc, self._itype_of = self._build_idp_instrucs()
            self.instruc_start = 0
            self.instruc_end = len(self.instruc)
            self.reg_names = REG_NAMES
            self.reg_first_sreg = REG_NAMES.index("CS")
            self.reg_last_sreg = REG_NAMES.index("DS")
            self.reg_code_sreg = REG_NAMES.index("CS")
            self.reg_data_sreg = REG_NAMES.index("DS")
            self.segreg_size = 0  # also set on the instance (belt and suspenders)

        # -- setup -----------------------------------------------------------
        def _build_idp_instrucs(self):
            base, itype_of = build_itypes()
            feat_map = {"CALL": CF_CALL, "JUMP": CF_JUMP, "STOP": CF_STOP}
            out = []
            for e in base:
                feat = 0
                for tag in e["feature_str"]:
                    feat |= feat_map.get(tag, 0)
                out.append({"name": e["name"] or "(bad)", "feature": feat})
            return out, itype_of

        def _gen(self):
            nn = ida_netnode.netnode(NETNODE_NAME)
            if nn != idaapi.BADNODE:
                g = nn.altval(0, NETNODE_GEN_TAG)
                if g:
                    return int(g)
            return DEFAULT_GEN

        def _decoder(self):
            g = self._gen()
            d = self._decoders.get(g)
            if d is None:
                d = Decoder(g)
                self._decoders[g] = d
            return d

        def _seg_start(self, ea):
            seg = idaapi.getseg(ea)
            return seg.start_ea if seg else (ea & ~0xfff)

        def _decode_ea(self, ea):
            try:
                w = ida_bytes.get_wide_dword(ea)
            except Exception:
                return None
            base = self._seg_start(ea)
            pc_word = (ea - base) // 4
            return self._decoder().disasm(w, pc=pc_word)

        # -- analysis --------------------------------------------------------
        def ev_ana_insn(self, insn):
            w = ida_bytes.get_wide_dword(insn.ea)
            base = self._seg_start(insn.ea)
            pc_word = (insn.ea - base) // 4
            di = self._decoder().disasm(w, pc=pc_word)
            if di is None:
                return 0
            insn.itype = self._itype_of.get(di.mnemonic, 0)
            insn.size = 4
            cat, tgt = derive_flow(di)
            if tgt is not None and cat in (FLOW_COND_BRANCH, FLOW_UNCOND_BRANCH,
                                           FLOW_CALL):
                op = insn.ops[0]
                op.type = o_near
                op.dtype = dt_dword
                op.addr = target_ea(insn.ea, base, tgt)
                op.offb = 0
            return insn.size

        # -- emulation / xrefs ----------------------------------------------
        def ev_emu_insn(self, insn):
            di = self._decode_ea(insn.ea)
            if di is None:
                return 0
            cat, tgt = derive_flow(di)
            nxt = insn.ea + 4

            # Delay slot: QRisc executes the instruction at ea+4 even after a
            # branch/call/jump/ret/waitin. Once IDA classifies the branch as a
            # jump (o_near operand + CF_JUMP) it suppresses linear flow into the
            # delay slot, and an ordinary fl_F cref isn't enough to force it, so
            # explicitly disassemble the delay-slot instruction here. (We accept
            # minor over-analysis past unconditional jumps/returns rather than
            # miss the delay slot.)
            if cat != FLOW_NORMAL:
                ida_ua.create_insn(nxt)
            insn.add_cref(nxt, 0, fl_F)

            if cat == FLOW_CALL and insn.ops[0].type == o_near:
                insn.add_cref(insn.ops[0].addr, 0, fl_CN)
            elif cat in (FLOW_COND_BRANCH, FLOW_UNCOND_BRANCH) and \
                    insn.ops[0].type == o_near:
                insn.add_cref(insn.ops[0].addr, 0, fl_JN)
            return 1

        # -- output ----------------------------------------------------------
        def ev_out_insn(self, ctx):
            import re
            di = self._decode_ea(ctx.insn.ea)
            if di is None:
                ctx.out_line("; <undecodable>")
                ctx.flush_outbuf()
                return
            text = di.text
            # Render mnemonic (with modifiers) + operands; make a near target
            # clickable via out_name_expr.
            sp = text.find(" ")
            if sp < 0:
                ctx.out_custom_mnem(text)
                ctx.flush_outbuf()
                return
            ctx.out_custom_mnem(text[:sp])
            rest = text[sp + 1:]
            m = re.search(r"#0x[0-9a-fA-F]+", rest)
            op0 = ctx.insn.ops[0]
            if m and op0.type == o_near:
                ctx.out_line(rest[:m.start()])
                ctx.out_line("#")
                if not ctx.out_name_expr(op0, op0.addr, ida_idaapi.BADADDR):
                    ctx.out_tagon(idaapi.COLOR_ERROR)
                    ctx.out_line(rest[m.start() + 1:m.end()])
                    ctx.out_tagoff(idaapi.COLOR_ERROR)
                ctx.out_line(rest[m.end():])
            else:
                ctx.out_line(rest)
            ctx.flush_outbuf()

        def ev_out_operand(self, ctx, op):
            # Operands are rendered inside ev_out_insn; nothing to do here.
            return True

    def PROCESSOR_ENTRY():
        return qrisc_processor_t()
