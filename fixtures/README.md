# Test fixtures

This directory ships **only the license-clean Mesa test corpus** for the QRisc
disassembler oracle:

| File                       | Origin | Use |
|----------------------------|--------|-----|
| `qrisc_test.fw`            | Mesa `src/freedreno/tests/reference/qrisc_test.fw`            | a6xx, assembled from `qrisc_test.asm` |
| `qrisc_test.asm`           | Mesa `src/freedreno/tests/reference/qrisc_test.asm`           | a6xx reference disassembly (oracle)   |
| `qrisc_test_a7xx.fw`       | Mesa `src/freedreno/tests/reference/qrisc_test_a7xx.fw`       | a7xx, assembled from `qrisc_test_a7xx.asm` |
| `qrisc_test_a7xx.asm`      | Mesa `src/freedreno/tests/reference/qrisc_test_a7xx.asm`      | a7xx reference disassembly (oracle)   |

These are the same files Mesa uses for its own `qrisc-asm` / `qrisc-disasm`
round-trip tests, included so this project's own tests run anywhere without a
Mesa checkout. Both files are MIT-licensed per Mesa.

## Real Qualcomm blobs are NOT included

The .gitignore deliberately excludes everything else under `fixtures/`. If you
want to test against real firmware, pull blobs you have the right to use from
[linux-firmware](https://gitlab.com/kernel-firmware/linux-firmware) (`qcom/`):

```sh
# Examples — pick the ones for your test target
curl -O https://gitlab.com/kernel-firmware/linux-firmware/-/raw/main/qcom/a630_sqe.fw
curl -O https://gitlab.com/kernel-firmware/linux-firmware/-/raw/main/qcom/a730_sqe.fw
curl -O https://gitlab.com/kernel-firmware/linux-firmware/-/raw/main/qcom/gen80000_sqe.fw
```

Or use Qualcomm's downloadable Adreno UMD .deb. Do NOT commit these to the
repository.
