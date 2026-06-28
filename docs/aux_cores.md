# Adreno auxiliary firmware cores (GMU, ZAP, AQE)

The command processor (SQE / PFP+ME) microcode is the main target of this
package's QRisc processor module. But an Adreno firmware bundle ships several
*other* cores. This document covers how each is handled.

| Core | File(s) | ISA / core | Handling |
|------|---------|-----------|----------|
| GMU  | `*_gmu.bin` | ARM Cortex-M3 (ARMv7-M, Thumb) | `ida/loaders/qrisc_gmu_loader.py` → stock ARM |
| ZAP  | `*_zap.mdt`+`.bNN`, or `*.mbn` | afuc/QRisc + embedded ir3 (PIL/MDT signed) | `ida/loaders/qrisc_zap_loader.py` + `common/qrisc_pil.py` |
| AQE  | `gen70900_aqe.fw`, `gen8x_aqe.fw` | "Application QRisc Engine" (QRisc *family*, **UNCONFIRMED**) | best-effort via the QRisc decoder (see below) |

---

## GMU — `*_gmu.bin`

The GMU is a **separate** micro-controller from the CP: an **ARM Cortex-M3 /
ARMv7-M** core executing **Thumb**. It is **not** afuc/QRisc — never point the
QRisc processor module at it.

`qrisc_gmu_loader.py`:
- `accept_file` matches `*_gmu.bin` (and rejects an ELF, which would not be a raw
  GMU image).
- `load_file` sets the processor to `arm`, Thumb mode, and best-effort parses the
  GMU **block container**:

  ```c
  struct block { u32 addr; u32 size; u32 type; u32 value; u8 data[size]; }  // repeated to EOF
  ```

  (mirrors the kernel `a6xx_gmu_fw_load` loop). Each block is mapped as its own
  segment at `addr` (e.g. ITCM/DTCM regions). If the data does not parse as a
  clean block sequence, it falls back to a single flat Thumb segment at base 0.
- The Cortex-M vector table is annotated: word[0] = initial SP, word[1] = reset
  vector (Thumb, low bit cleared), and an entry point is created at the reset
  vector.

If IDA does not auto-pick the Cortex-M variant, set it to **ARMv7-M** under
*Options → General → Processor*.

> The exact `type` codes (ITCM vs DTCM vs …) and any image header preceding the
> first block were **not** confirmed against a real blob; the parser is
> conservative (rejects anything that doesn't cleanly tile to EOF with
> sane, tightly-clustered addresses) and is documented as best-effort.

---

## ZAP — `*_zap.mdt` / `*.mbn`

The ZAP shader takes the GPU out of TrustZone "secure" mode. It is a Qualcomm
**PIL/MDT signed split-binary**:

```
<name>.mdt   ELF header + program-header table + metadata + hash/signature
<name>.bNN   payload of program-header index NN          (split form)
<name>.mbn   all of the above concatenated in one file   (combined form)
```

Its payload is **afuc/QRisc instructions plus an embedded ir3 shader, with NO
packet table** (unlike the SQE).

### `common/qrisc_pil.py` (standalone parser, stdlib-only)
- Parses ELF32 **and** ELF64 headers + program headers.
- Classifies each segment `kind ∈ {metadata, hash, code, data}` using the kernel
  semantics (`drivers/soc/qcom/mdt_loader.c`):
  - `QCOM_MDT_TYPE_MASK = 0x07000000`, `QCOM_MDT_TYPE_HASH = 0x02000000`,
    `QCOM_MDT_RELOCATABLE = 0x08000000`.
  - segment 0 is required to be non-`PT_LOAD` (the ELF-header/metadata segment);
    the hash segment is the first index ≥1 whose type bits == `TYPE_HASH`;
    a segment is *loadable* iff `PT_LOAD && type!=HASH && p_memsz!=0`.
  - executable (`PF_X`) loadable segments are `code` (afuc candidates), the rest
    `data`.
- Reads segment payloads from `<base>.bNN` (split, filename = last 3 chars of the
  `.mdt` name replaced with `b%02d`) or from the container at `p_offset`
  (combined / inline metadata+hash) — uniformly.
- `reconstruct_image()` rebuilds the flat loaded image (equivalent to
  `pil-squasher`); `identify_payload()` returns the afuc code segment(s) plus
  best-effort ir3 candidates.
- **Does not** verify signatures — static analysis only.

### `ida/loaders/qrisc_zap_loader.py`
- `accept_file` recognises a PIL/MDT (ELF magic + non-PT_LOAD segment 0) named
  `*zap*` / `.mdt` / `.mbn`.
- `load_file` reconstructs the image, maps each afuc/QRisc `code` segment at the
  **instruction base `0x1000`** convention (so branch/call targets resolve like
  the SQE), and maps the **embedded ir3 region separately as DATA**, annotated,
  so the QRisc decoder does not run over a different ISA. It resolves the
  on-disk path (to gather `.bNN` siblings) and falls back to a stream-only
  combined load if the path is unavailable.

> **Caveat:** no public, license-clean *signed* ZAP blob was available to test
> against, so the afuc-vs-ir3 boundary is **best-effort/UNCONFIRMED**. ZAP is
> documented as "afuc + embedded ir3, no packet table"; the embedded ir3
> typically sits at the tail of, or in a separate region of, the executable
> payload. Confirm the boundary interactively: decode from the start as QRisc and
> treat the point where clean afuc decoding stops as the ir3 start. The PIL
> parser itself is fully unit-tested against synthetic ELF32/ELF64 MDT and
> split/combined forms (`tests/test_pil.py`).

---

## AQE — `gen70900_aqe.fw`, `gen8x_aqe.fw`

a7xx/a8xx add an **AQE ("Application QRisc Engine")** — a separate core inside
the CP used for ray-tracing, shipped as its own `*_aqe.fw` blob. By name it is in
the **QRisc family**, but **its instruction encoding compatibility with the SQE
QRisc ISA is UNCONFIRMED** in this project (no upstream RE, no test fixture).

### Best-effort decode hook
Once `common/qrisc_disasm.py` (the standalone QRisc decoder built on
`common/qrisc_isa_tables.py`) is available, try it on an AQE blob:

1. Strip the leading header word like the SQE container: the instruction stream
   begins at **word index 1** (`fw_id = (word1 >> 12) & 0xfff`), instruction base
   `0x1000` (see `disasm.c`).
2. Run the decoder over the stream with `gen=7` (a7xx AQE) or `gen=8`
   decoded-as-a7xx (a8xx AQE), recording the clean-decode ratio.

```python
# pseudocode for the AQE compatibility probe (wire up once the decoder lands)
import struct
words = list(struct.iter_unpack("<I", open("gen70900_aqe.fw", "rb").read()))
stream = [w[0] for w in words][1:]          # skip header word, like SQE
ok = total = 0
for w in stream:
    total += 1
    if qrisc_disasm.decode(w, gen=7) is not None:   # not an illegal encoding
        ok += 1
print("clean-decode ratio: %.1f%%" % (100.0 * ok / total))
```

### What would CONFIRM shared ISA
- A **high clean-decode ratio** (≳95%) with **recognisable afuc idioms**: the
  `waitin` / `mov $01, $data` packet-loop tail, `cwrite`/`cread` against known
  control registers, `(rep)`/`(xmov)` modifiers, `call`/`ret` structure.
- Sensible control-flow: branch/call targets landing inside the image, a
  plausible bootstrap routine near the start.

### What would REFUTE it
- A low clean-decode ratio, opcodes that don't map, or a different instruction
  width/header layout — in which case AQE needs its own ISA spec and is **out of
  scope** until upstream (Mesa/kernel AQE patches) or original RE documents it.

Until such a probe is run on a real AQE blob, treat AQE support as **deferred /
best-effort**, exactly as scoped.
