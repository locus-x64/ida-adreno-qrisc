"""
qrisc_emu.py -- a minimal QRisc/afuc bootstrap emulator.

Faithful (but bootstrap-focused) port of Mesa's qrisc/emu.c + emu-regs.c. Its
job is to RUN the firmware bootstrap routine so we can recover, on REAL blobs:
  * the packet jump table (0x80 CP-opcode handler indices), populated by the
    firmware via @PACKET_TABLE_WRITE control-register writes, and
  * the BR/BV/LPAC sub-image boundaries, from the @BV_INSTR_BASE /
    @LPAC_INSTR_BASE / CP_LPAC_SQE_INSTR_BASE registers the bootstrap programs.

Why an emulator: on real a6xx+ images `instrs[1] & 0xffff` is a size word, not
the table pointer, and the BV/LPAC bases are computed at runtime relative to
CP_SQE_INSTR_BASE. Mesa's disasm runs `emu_run_bootstrap()` for exactly this.

Dependencies: stdlib + the validated `qrisc_disasm.Decoder` (for decode) and
`qrisc_isa_tables` (for control/sqe register offsets). No IDA/Ghidra/Mesa.

Scope/parity notes:
  * GPU memory is modelled as a sparse {byte_addr: dword} dict (Mesa uses an 8GB
    mmap); the firmware image is copied to EMU_INSTR_BASE (0x1000) like Mesa.
  * CP_SQE_INSTR_BASE GPU offset moved on a8xx (0x830 a6xx/a7xx -> 0x816 a8xx);
    we seed BOTH candidates to 0x1000 so the bootstrap's read returns 0x1000
    regardless, and compute offsets as (INSTR_BASE_reg - 0x1000)//4.
  * waitin ends the bootstrap (its dispatch/delay-slot don't run), matching Mesa.
  * Unmodelled corners (draw-state regs, privileged mem hi) are inert for the
    bootstrap path; on any decode/exec fault we raise EmuError so callers can
    fall back to the static heuristic.
"""

try:
    from . import qrisc_disasm as _qd
    from . import qrisc_isa_tables as _T
except Exception:  # pragma: no cover
    import qrisc_disasm as _qd
    import qrisc_isa_tables as _T

MASK32 = (1 << 32) - 1
EMU_INSTR_BASE = 0x1000
JMPTBL_SIZE = 0x80
STEP_CAP = 4_000_000

# GPR special-register numbers (qrisc.h)
REG_SP, REG_LR, REG_REM = 0x1a, 0x1b, 0x1c
REG_MEMDATA, REG_ADDR = 0x1d, 0x1d   # 0x1d: $memdata (src) / $addr (dst)
REG_REGDATA, REG_USRADDR = 0x1e, 0x1e
REG_DATA = 0x1f

# GPU register offsets (a6xx.xml). CP_SQE_INSTR_BASE differs on a8xx.
GPU_CP_SQE_INSTR_BASE = (0x830, 0x816)       # a6xx/a7xx, a8xx
GPU_CP_LPAC_SQE_INSTR_BASE = 0xb82
GPU_CP_LPAC_SQE_CNTL = 0xb81

# ALU mnemonics handled by emu_alu
_ALU = {"add", "addhi", "sub", "subhi", "and", "or", "xor", "not", "shl",
        "ushr", "ishr", "rot", "mul8", "min", "max", "cmp", "bic", "msb",
        "setbit"}


class EmuError(Exception):
    pass


def _u32(x):
    return x & MASK32


def _sx(value, width):
    return value - (1 << width) if value & (1 << (width - 1)) else value


def _domain_offsets(domain_name):
    """name -> offset for an rnn register domain in the tables."""
    out = {}
    for off, _nwords, name in _T.REG_DOMAINS.get(domain_name, []):
        out.setdefault(name, off)
    return out


class Emu(object):
    def __init__(self, image_words, gen, fw_id=0, processor="SQE"):
        self.gen = gen
        self.fw_id = fw_id
        self.processor = processor
        self.instrs = list(image_words)
        self.sizedwords = len(self.instrs)
        self.dec = _qd.Decoder(7 if (gen is None or gen >= 7) else gen)

        self.gpr = [0] * 32
        self.pc = 0
        self.carry = 0
        self.control = {}
        self.sqe = [0] * 0x10
        self.gpu = {}
        self.pipe = {}
        self.jmptbl = [0] * JMPTBL_SIZE
        self.gpumem = {}
        self.branch_target = 0
        self.waitin = False
        self.bootstrap_mode = False
        self.bootstrap_finished = False
        self.data_mode = "ADDR"
        self.steps = 0

        cdom = _T.GEN_CONTROL_DOMAIN.get(self.dec.gen, "A7XX_CONTROL_REG")
        self.coff = _domain_offsets(cdom)
        self.soff = _domain_offsets(_T.SQE_DOMAIN)  # A6XX_SQE_REG (SP, STACK0)

        self._init_state()

    # -- control/sqe register offset helpers -------------------------------
    def _c(self, name):
        off = self.coff.get(name)
        if off is None:
            raise EmuError("control reg %s not in domain" % name)
        return off

    def _s(self, name):
        off = self.soff.get(name)
        if off is None:
            raise EmuError("sqe reg %s not in domain" % name)
        return off

    # -- init --------------------------------------------------------------
    def _init_state(self):
        for i, w in enumerate(self.instrs):
            self.gpumem[EMU_INSTR_BASE + 4 * i] = _u32(w)
        # Seed CP_SQE_INSTR_BASE (both a6xx/a7xx and a8xx offsets) = 0x1000.
        for off in GPU_CP_SQE_INSTR_BASE:
            self.gpu[off] = EMU_INSTR_BASE
            self.gpu[off + 1] = 0
        # fw-id specific control presets (Mesa emu_init); best-effort for a8xx.
        fid = self.fw_id
        if fid == 0x520:                      # a750
            self._set_control(0, 7 << 28); self._set_control(2, 0x40 << 8)
        elif fid in (0x730, 0x740, 0x512):    # a730/a740/gen70500
            self._set_control(0xef, 1 << 21); self._set_control(0, 7 << 28)
        elif fid == 0x6dd:                     # a660
            self._set_control(0, 3 << 28)
        elif fid == 0x6dc:                     # a650
            self._set_control(0, 1 << 28)
        elif self.dec.gen >= 7:                # a8xx / unknown gen7-class default
            self._set_control(0, 7 << 28)

    # -- memory ------------------------------------------------------------
    def mem_read(self, addr):
        return self.gpumem.get(addr & ~3 & ((1 << 40) - 1), 0)

    def mem_write(self, addr, val):
        self.gpumem[addr & ~3 & ((1 << 40) - 1)] = _u32(val)

    # -- gpr ---------------------------------------------------------------
    def get_gpr(self, n, peek=False):
        if n == 0x00:
            return 0
        if n in (REG_MEMDATA, REG_REGDATA, REG_DATA):
            return self._fifo_read(n, peek)
        return self.gpr[n]

    def set_gpr(self, n, val):
        val = _u32(val)
        if n in (REG_ADDR, REG_USRADDR, REG_DATA):
            self._fifo_write(n, val)
        else:
            self.gpr[n] = val

    # -- control / sqe / gpu / pipe ---------------------------------------
    def get_control(self, n):
        return self.control.get(n, 0)

    def _set_control(self, n, val):
        self.control[n] = _u32(val)

    def set_control(self, n, val):
        self.control[n] = _u32(val)
        if n == self._c("PACKET_TABLE_WRITE"):
            wa = self.get_control(self._c("PACKET_TABLE_WRITE_ADDR"))
            if wa < JMPTBL_SIZE:
                self.jmptbl[wa] = _u32(val)
            self.control[self._c("PACKET_TABLE_WRITE_ADDR")] = wa + 1
        elif n == self._c("REG_WRITE"):
            wa = self.get_control(self._c("REG_WRITE_ADDR"))
            flags = wa >> 16
            wa &= 0xffff
            self.set_gpu(wa, val)
            self.control[self._c("REG_WRITE_ADDR")] = ((wa + 1) & 0xffff) | (flags << 16)
        elif self.dec.gen >= 7 and "BV_CNTL" in self.coff and n == self._c("BV_CNTL"):
            self._thread_sync_clear(1 << 1)
        elif self.dec.gen >= 7 and "LPAC_CNTL" in self.coff and n == self._c("LPAC_CNTL"):
            self._thread_sync_clear(1 << 2)

    def _thread_sync_clear(self, bits):
        ts = self.coff.get("THREAD_SYNC")
        if ts is not None:
            self.control[ts] = self.get_control(ts) & ~bits & MASK32

    def get_control64(self, name):
        off = self.coff.get(name)
        if off is None:
            return 0
        return self.get_control(off) | (self.get_control(off + 1) << 32)

    def get_sqe(self, n):
        return self.sqe[n] if 0 <= n < len(self.sqe) else 0

    def set_sqe(self, n, val):
        if 0 <= n < len(self.sqe):
            self.sqe[n] = _u32(val)

    def get_gpu(self, n):
        return self.gpu.get(n, 0)

    def set_gpu(self, n, val):
        self.gpu[n] = _u32(val)
        if n == GPU_CP_LPAC_SQE_CNTL:
            self._thread_sync_set(1 << 1)

    def _thread_sync_set(self, bits):
        ts = self.coff.get("THREAD_SYNC")
        if ts is not None:
            self.control[ts] = self.get_control(ts) | bits

    def set_pipe(self, n, val):
        self.pipe[n] = _u32(val)
        # NRT_DATA write -> memory write (not needed for bootstrap); inert here.

    # -- fifo / streaming regs --------------------------------------------
    def _fifo_read(self, n, peek):
        if n == REG_MEMDATA:
            rd = self.get_control(self._c("MEM_READ_DWORDS"))
            addr = self.get_control64("MEM_READ_ADDR")
            if rd > 0 and not peek:
                self.control[self._c("MEM_READ_DWORDS")] = rd - 1
                a = self.coff["MEM_READ_ADDR"]
                na = (addr + 4)
                self.control[a] = na & MASK32
                self.control[a + 1] = (na >> 32) & MASK32
            return self.mem_read(addr)
        if n == REG_REGDATA:
            rd = self.get_control(self._c("REG_READ_DWORDS"))
            addr = self.get_control(self._c("REG_READ_ADDR"))
            if rd > 0 and not peek:
                self.control[self._c("REG_READ_DWORDS")] = rd - 1
                self.control[self._c("REG_READ_ADDR")] = addr + 1
            return self.get_gpu(addr)
        if n == REG_DATA:
            if self.bootstrap_mode:
                self.bootstrap_finished = True
                return 0
            raise EmuError("$data read outside bootstrap")
        raise EmuError("not a fifo reg: %#x" % n)

    def _fifo_write(self, n, val):
        if n in (REG_ADDR, REG_USRADDR):
            self.data_mode = "ADDR" if n == REG_ADDR else "USRADDR"
            self.gpr[n] = val
            if val > 0xffff:
                self.data_mode = "PIPE"
        elif n == REG_DATA:
            reg = REG_ADDR if self.data_mode in ("ADDR", "PIPE") else REG_USRADDR
            regoff = self.gpr[reg]
            if regoff > 0xffff:               # pipe register write
                if not (regoff & 0x40000):
                    self.gpr[reg] = _u32(regoff + 0x01000000)
                self.set_pipe(regoff >> 24, val)
            else:                              # gpu register write
                self.gpr[reg] = _u32(regoff + 1)
                self.set_gpu(regoff, val)

    # -- ALU ---------------------------------------------------------------
    def alu(self, op, a, b):
        a &= MASK32
        b &= MASK32
        if op == "add":
            t = a + b
            self.carry = (t >> 32) & MASK32
            return t & MASK32
        if op == "addhi":
            return _u32(a + b + self.carry)
        if op == "sub":
            t = (a - b) & ((1 << 64) - 1)
            self.carry = (t >> 32) & MASK32
            return t & MASK32
        if op == "subhi":
            return _u32(a - b + self.carry)
        if op == "and":
            return a & b
        if op == "or":
            return a | b
        if op == "xor":
            return a ^ b
        if op == "not":
            return _u32(~a)
        if op == "shl":
            return _u32(a << (b & 31)) if b < 32 else 0
        if op == "ushr":
            return a >> b if b < 32 else 0
        if op == "ishr":
            return _u32(_sx(a, 32) >> (b if b < 32 else 31))
        if op == "rot":
            r = b & 31
            return _u32((a << r) | (a >> (32 - r))) if r else a
        if op == "mul8":
            return (a & 0xff) * (b & 0xff)
        if op == "min":
            return min(a, b)
        if op == "max":
            return max(a, b)
        if op == "cmp":
            return 0x00 if a > b else (0x2b if a == b else 0x1e)
        if op == "bic":
            return a & _u32(~b)
        if op == "msb":
            return (b.bit_length() - 1) if b else 0
        if op == "setbit":
            bit = b >> 1
            v = b & 1
            return (a & _u32(~(1 << bit))) | (v << bit)
        raise EmuError("unhandled alu op %s" % op)

    # -- field extraction --------------------------------------------------
    @staticmethod
    def _fields(leaf, word):
        fv = {}
        for f in leaf["fields"]:
            if f.get("derived"):
                continue
            fv[f["name"]] = (word >> f["low"]) & ((1 << (f["high"] - f["low"] + 1)) - 1)
        return fv

    # -- one instruction (no rep/pc handling) ------------------------------
    def exec_instr(self, leaf, word):
        mn = leaf["mnemonic"]
        nm = leaf["name"]
        fv = self._fields(leaf, word)
        g = self.get_gpr
        rep = fv.get("REP", 0)

        if mn in _ALU:
            src1 = g(fv.get("SRC1", 0))
            if "SRC2" in fv:                       # 2-src register form
                src2 = g(fv["SRC2"], bool(fv.get("PEEK", 0)))
            elif "RIMMED" in fv:                   # 2-src immediate
                src2 = fv["RIMMED"]
            elif "IMMED" in fv:                    # 1-src immediate (noti)
                src2 = fv["IMMED"]
            else:                                  # 1-src register (not/msb)
                src2 = src1
            val = self.alu(mn, src1, src2)
            self.set_gpr(fv.get("DST", 0), val)
            xmov = fv.get("XMOV", 0)
            if xmov:
                self._do_xmov(xmov, fv.get("SRC2", fv.get("SRC1", 0)), fv.get("DST", 0))
        elif nm == "movi":
            self.set_gpr(fv["DST"], _u32(fv["RIMMED"] << fv.get("SHIFT", 0)))
        elif nm == "setbiti":
            self.set_gpr(fv["DST"], g(fv["SRC"]) | (1 << fv["BIT"]))
        elif nm == "clrbit":
            self.set_gpr(fv["DST"], g(fv["SRC"]) & _u32(~(1 << fv["BIT"])))
        elif nm == "ubfx":
            lo, hi = fv["LO"], fv["HI"]
            self.set_gpr(fv["DST"], (g(fv["SRC"]) >> lo) & ((1 << (hi - lo + 1)) - 1))
        elif nm == "bfi":
            lo, hi = fv["LO"], fv["HI"]
            src = (g(fv["SRC"]) & ((1 << (hi - lo + 1)) - 1)) << lo
            self.set_gpr(fv["DST"], g(fv["DST"]) | _u32(src))
        elif nm == "cwrite":
            src1 = g(fv["SRC"]); off = g(fv["OFFSET"]); reg = _u32(off + fv["BASE"])
            if fv.get("PREINCREMENT", 0):
                self.set_gpr(fv["OFFSET"], reg)
            self.set_control(reg, src1)
        elif nm == "cread":
            off = g(fv["OFFSET"])
            if fv.get("PREINCREMENT", 0):
                self.set_gpr(fv["OFFSET"], _u32(off + fv["BASE"]))
            self.set_gpr(fv["DST"], self.get_control(_u32(off + fv["BASE"])))
        elif nm == "swrite":
            src1 = g(fv["SRC"]); off = g(fv["OFFSET"])
            if fv.get("PREINCREMENT", 0):
                self.set_gpr(fv["OFFSET"], _u32(off + fv["BASE"]))
            self.set_sqe(_u32(off + fv["BASE"]), src1)
        elif nm == "sread":
            off = g(fv["OFFSET"])
            if fv.get("PREINCREMENT", 0):
                self.set_gpr(fv["OFFSET"], _u32(off + fv["BASE"]))
            self.set_gpr(fv["DST"], self.get_sqe(_u32(off + fv["BASE"])))
        elif nm == "load":
            addr = self._ls_addr(fv["OFFSET"]) + fv["IMMED"]
            if fv.get("PREINCREMENT", 0):
                self.set_gpr(fv["OFFSET"], _u32(g(fv["OFFSET"]) + fv["IMMED"]))
            self.set_gpr(fv["DST"], self.mem_read(addr))
        elif nm == "store":
            addr = self._ls_addr(fv["OFFSET"]) + fv["IMMED"]
            if fv.get("PREINCREMENT", 0):
                self.set_gpr(fv["OFFSET"], _u32(g(fv["OFFSET"]) + fv["IMMED"]))
            self.mem_write(addr, g(fv["SRC"]))
        elif nm in ("brnei", "breqi", "brneb", "breqb"):
            off = _u32(self.pc + _sx(fv["OFFSET"], 16))
            src = g(fv["SRC"])
            take = ((nm == "brnei" and src != fv["IMMED"]) or
                    (nm == "breqi" and src == fv["IMMED"]) or
                    (nm == "brneb" and not (src & (1 << fv["BIT"]))) or
                    (nm == "breqb" and (src & (1 << fv["BIT"]))))
            if take:
                self.branch_target = off
        elif nm == "call":
            sp = self.get_sqe(self._s("SP"))
            self.set_sqe(self._s("STACK0") + sp, _u32(self.pc + 2))
            self.set_sqe(self._s("SP"), sp + 1)
            self.branch_target = fv["TARGET"]
        elif nm == "bl":
            self.set_gpr(REG_LR, _u32(self.pc + 2))
            self.branch_target = fv["TARGET"]
        elif nm in ("ret", "iret"):
            sp = self.get_sqe(self._s("SP"))
            if sp > 0:
                self.branch_target = self.get_sqe(self._s("STACK0") + sp - 1)
                self.set_sqe(self._s("SP"), sp - 1)
        elif nm == "jumpr":
            self.branch_target = g(fv["SRC1"])
        elif nm == "sret":
            self.branch_target = g(REG_LR)
        elif nm == "jumpa":
            self.branch_target = fv["TARGET"]
        elif nm == "waitin":
            self.waitin = True
        elif nm in ("nop", "setsecure"):
            pass
        else:
            raise EmuError("unhandled instr %s/%s @%#x" % (mn, nm, self.pc))

        if rep:
            self.gpr[REG_REM] = _u32(self.gpr[REG_REM] - 1)

    def _ls_addr(self, gpr):
        hi = self.get_control(self.coff.get("LOAD_STORE_HI", 0)) if "LOAD_STORE_HI" in self.coff else 0
        return ((hi << 32) + self.get_gpr(gpr))

    def _do_xmov(self, xmov, src2, dst):
        m = min(xmov, self.gpr[REG_REM])
        val = self.get_gpr(src2)
        if m >= 1:
            self.gpr[REG_REM] = _u32(self.gpr[REG_REM] - 1)
            self.set_gpr(REG_DATA, val)
        if m >= 2:
            self.gpr[REG_REM] = _u32(self.gpr[REG_REM] - 1)
            self.set_gpr(REG_DATA, val)
        if m >= 3:
            self.gpr[REG_REM] = _u32(self.gpr[REG_REM] - 1)
            self.set_gpr(dst, val)

    # -- step --------------------------------------------------------------
    def step(self):
        if self.pc >= len(self.instrs):
            raise EmuError("pc out of range: %#x" % self.pc)
        word = _u32(self.instrs[self.pc])
        leaf = self.dec.decode(word)
        if leaf is None:
            if (word >> 27) == 0:
                leaf = {"mnemonic": "nop", "name": "nop", "fields": []}
            else:
                raise EmuError("undecodable %08x @%#x" % (word, self.pc))

        bt = self.branch_target
        self.branch_target = 0
        win = self.waitin
        self.waitin = False

        if self._fields(leaf, word).get("REP", 0):
            while self.gpr[REG_REM]:
                self.exec_instr(leaf, word)
                self.steps += 1
                if self.steps > STEP_CAP:
                    raise EmuError("step cap exceeded (rep)")
        else:
            self.exec_instr(leaf, word)

        self.pc = _u32(self.pc + 1)
        if bt:
            self.pc = bt
        # waitin dispatch (win) is intentionally not executed -- bootstrap ends.

    def run_bootstrap(self):
        self.bootstrap_mode = True
        self.bootstrap_finished = False
        while not self.bootstrap_finished and not self.waitin:
            self.step()
            self.steps += 1
            if self.steps > STEP_CAP:
                raise EmuError("step cap exceeded")
        self.bootstrap_mode = False
        return self

    # -- results -----------------------------------------------------------
    def instr_bases(self):
        """(bv_offset, lpac_offset) in instruction-word units, or None each."""
        bv = lpac = None
        if self.dec.gen >= 7:
            bvb = self.get_control64("BV_INSTR_BASE")
            lpb = self.get_control64("LPAC_INSTR_BASE")
            if bvb and bvb >= EMU_INSTR_BASE:
                bv = (bvb - EMU_INSTR_BASE) // 4
            if lpb and lpb >= EMU_INSTR_BASE:
                lpac = (lpb - EMU_INSTR_BASE) // 4
        else:
            lpb = (self.get_gpu(GPU_CP_LPAC_SQE_INSTR_BASE) |
                   (self.get_gpu(GPU_CP_LPAC_SQE_INSTR_BASE + 1) << 32))
            if lpb and lpb >= EMU_INSTR_BASE:
                lpac = (lpb - EMU_INSTR_BASE) // 4
        # sanity
        n = self.sizedwords
        if bv is not None and not (0 < bv < n):
            bv = None
        if lpac is not None and not (0 < lpac <= n):
            lpac = None
        if bv is not None and lpac is not None and not (bv < lpac):
            lpac = None
        return (bv, lpac)


def find_jump_table(image_words, jmptbl):
    """Locate the populated jump table contents in the image (Mesa
    find_jump_table). Returns the start word index, or None."""
    n = len(image_words)
    k = len(jmptbl)
    if k == 0 or n < k:
        return None
    for i in range(0, n - k + 1):
        if image_words[i:i + k] == jmptbl:
            return i
    return None


def run_bootstrap(image_words, gen, fw_id=0, processor="SQE"):
    """Convenience: build + run. Raises EmuError on any fault."""
    return Emu(image_words, gen, fw_id=fw_id, processor=processor).run_bootstrap()
