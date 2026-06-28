# Test fixtures

This directory ships only the Mesa test corpus used as the disassembler
oracle:

| File | Origin | Use |
|---|---|---|
| `qrisc_test.fw`       | Mesa `src/freedreno/tests/reference/qrisc_test.fw`       | a6xx, assembled from `qrisc_test.asm` |
| `qrisc_test.asm`      | Mesa `src/freedreno/tests/reference/qrisc_test.asm`      | a6xx reference disassembly |
| `qrisc_test_a7xx.fw`  | Mesa `src/freedreno/tests/reference/qrisc_test_a7xx.fw`  | a7xx, assembled from `qrisc_test_a7xx.asm` |
| `qrisc_test_a7xx.asm` | Mesa `src/freedreno/tests/reference/qrisc_test_a7xx.asm` | a7xx reference disassembly |

Same files Mesa uses for its own `qrisc-asm` / `qrisc-disasm` round-trip
tests, included so the project's tests run anywhere without a Mesa checkout.
MIT-licensed per Mesa.

## Real Qualcomm blobs are not included

The `.gitignore` excludes everything else under `fixtures/`. To test against
real firmware, pull blobs you have the right to use from
[linux-firmware](https://gitlab.com/kernel-firmware/linux-firmware) (`qcom/`):

```sh
curl -O https://gitlab.com/kernel-firmware/linux-firmware/-/raw/main/qcom/a630_sqe.fw
curl -O https://gitlab.com/kernel-firmware/linux-firmware/-/raw/main/qcom/a730_sqe.fw
curl -O https://gitlab.com/kernel-firmware/linux-firmware/-/raw/main/qcom/gen80000_sqe.fw
```

Or use Qualcomm's downloadable Adreno UMD .deb. Do not commit these.
