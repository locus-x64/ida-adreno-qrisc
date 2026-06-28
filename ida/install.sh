#!/usr/bin/env bash
#
# Install the QRisc (Adreno afuc) IDA processor module + loaders into an IDA
# installation. The shared common/*.py modules are copied into a `qrisc_common/`
# subdirectory beside the entry files (a subdir, so IDA does not try to load
# them as loaders/processors); the entry files locate them automatically.
#
# Usage:  ida/install.sh /path/to/IDA      e.g.  ida/install.sh /opt/idapro-9.0
#
# Alternative (no copy): export QRISC_HOME=/path/to/this/repo  and drop the
# entry files into IDA's procs/ and loaders/ dirs.
#
set -euo pipefail

IDA="${1:?usage: ida/install.sh <IDA_DIR>   (e.g. /opt/idapro-9.0)}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"

[ -d "$IDA/procs" ] && [ -d "$IDA/loaders" ] || {
    echo "error: '$IDA' has no procs/ and loaders/ — not an IDA install dir" >&2
    exit 1
}

echo "Installing QRisc from $REPO into $IDA ..."

# Processor module + shared core (in a subdir beside it)
install -m 0644 "$REPO/ida/procs/qrisc.py" "$IDA/procs/qrisc.py"
mkdir -p "$IDA/procs/qrisc_common"
cp "$REPO"/common/qrisc_*.py "$IDA/procs/qrisc_common/"

# Loaders + shared core
for L in qrisc_loader qrisc_zap_loader qrisc_gmu_loader; do
    install -m 0644 "$REPO/ida/loaders/$L.py" "$IDA/loaders/$L.py"
done
mkdir -p "$IDA/loaders/qrisc_common"
cp "$REPO"/common/qrisc_*.py "$IDA/loaders/qrisc_common/"

echo "Done."
echo "  procs/qrisc.py + procs/qrisc_common/"
echo "  loaders/{qrisc_loader,qrisc_zap_loader,qrisc_gmu_loader}.py + loaders/qrisc_common/"
echo
echo "Open a *_sqe.fw / *_pfp.fw / *_pm4.fw (or *_zap.mdt / *_gmu.bin) in IDA."
