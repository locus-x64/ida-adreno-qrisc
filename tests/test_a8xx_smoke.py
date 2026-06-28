"""
a8xx (Adreno 8xx) CP microcode smoke test.

BEST-EFFORT, NO ORACLE. Mesa's QRisc/afuc tooling has no gen-8 gate and its
decoder rejects the a8xx fw_id, so there is no reference disassembler. a8xx
reuses the a7xx QRisc CP ISA (no new core), so we decode it as a7xx
(`Decoder(7)`) -- the only available approach (see common/qrisc_disasm.py and
docs/a8xx_report.md).

This test SKIPS gracefully when the firmware blob is absent: the a8xx blobs are
gitignored (downloaded into fixtures/ separately), so CI without the blob simply
skips. When a blob IS present it asserts:
  * the container parses,
  * gen is None (a8xx fw_id is not in the gen map -- expected),
  * decode coverage (% of words decoding to a known a7xx leaf) exceeds a
    conservative documented threshold.

The observed coverage at authoring time was ~93.4-94.1% (vs ~93.5% for the
oracle-validated a730_sqe.fw reference); the threshold is set conservatively to
90% so the test is robust to minor firmware-revision drift.
"""
import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "common"))

import qrisc_isa_tables  # noqa: E402,F401  (ensure tables import cleanly)
import qrisc_fw  # noqa: E402
from qrisc_disasm import Decoder  # noqa: E402

FIX = os.path.join(ROOT, "fixtures")

# Conservative floor, below the observed ~93.4-94.1% so revision drift is OK.
COVERAGE_THRESHOLD = 0.90

# The three a8xx CP firmware blobs (linux-firmware qcom/). Gitignored -> absent
# blobs cause a clean SKIP rather than a failure.
A8XX_BLOBS = ["gen80000_sqe.fw", "gen80100_sqe.fw", "gen80200_sqe.fw"]


def _present(name):
    return os.path.isfile(os.path.join(FIX, name))


def _coverage(words):
    """Fraction of instruction words that decode to a known leaf under gen-7."""
    dec = Decoder(7)
    if not words:
        return 0.0
    decoded = sum(1 for i, w in enumerate(words) if dec.disasm(w, i) is not None)
    return decoded / len(words)


@pytest.mark.parametrize("blob", A8XX_BLOBS)
def test_a8xx_parses_and_decodes(blob):
    path = os.path.join(FIX, blob)
    if not _present(blob):
        pytest.skip("a8xx blob %s not present in fixtures/ (gitignored)" % blob)

    with open(path, "rb") as fh:
        data = fh.read()

    # 1. Container parses.
    c = qrisc_fw.parse(data)
    assert len(c.instr_words) > 1000, "implausibly short a8xx image"

    # 2. gen is unknown for a8xx (fw_id not in the gen map) -- documented & expected.
    assert c.gen is None, (
        "a8xx fw_id %#05x unexpectedly mapped to gen %r; report assumes gen=None"
        % (c.fw_id, c.gen)
    )

    # 3. Decode coverage (decoded as a7xx) exceeds the documented threshold.
    cov = _coverage(c.instr_words)
    assert cov >= COVERAGE_THRESHOLD, (
        "%s decode coverage %.3f%% below threshold %.0f%%"
        % (blob, cov * 100, COVERAGE_THRESHOLD * 100)
    )


def test_a8xx_at_least_one_blob_or_skip():
    """Aggregate guard: if no a8xx blob is present, skip the whole suite cleanly."""
    if not any(_present(b) for b in A8XX_BLOBS):
        pytest.skip("no a8xx blobs in fixtures/ (gitignored); nothing to validate")
    # At least one present: sanity-check the decoder is usable on it.
    present = next(b for b in A8XX_BLOBS if _present(b))
    with open(os.path.join(FIX, present), "rb") as fh:
        c = qrisc_fw.parse(fh.read())
    assert _coverage(c.instr_words) >= COVERAGE_THRESHOLD


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
