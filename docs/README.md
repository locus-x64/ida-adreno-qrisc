# docs/

Project documentation, in roughly increasing order of depth.

| File | Contents |
|---|---|
| [`aux_cores.md`](aux_cores.md)         | GMU (ARM Cortex-M, not afuc), ZAP shader (PIL/MDT + afuc + ir3), AQE engine — how they're handled |
| [`a8xx_report.md`](a8xx_report.md)     | Best-effort a8xx analysis: decode coverage on real `gen80000/80100/80200_sqe.fw`, candidate-new opcodes for hand-RE, CVE-2025-21479 status |
| [`research-notes.md`](research-notes.md) | Original research brief: ISA background, generation differences, IDA SDK considerations, prior art. Useful as project history; the runtime details may have evolved |

For installation, see the top-level [README](../README.md). For backend-specific
docs see [`../ida/procs/README.md`](../ida/procs/README.md) and
[`../ghidra/README.md`](../ghidra/README.md).
