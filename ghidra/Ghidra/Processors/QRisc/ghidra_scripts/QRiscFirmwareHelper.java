// QRiscFirmwareHelper -- post-import setup for an Adreno SQE/PFP/PM4 firmware
// blob that has been imported raw (BinaryLoader, base 0x0) with a QRisc language.
//
// Assumes the imported image is the INSTRUCTION STREAM with the leading file
// word (word0) already stripped, i.e. image word0 = version NOP, word1 = packet
// jump-table offset NOP, word2 = first real instruction (the bootstrap routine).
// This matches Mesa qrisc-disasm, which does `instrs = &buf[1]`.
//
// What it does:
//   * marks the 2 leading NOP-payload words (version, jumptbl offset) as data
//   * creates and disassembles an entry point "bootstrap" at word2 (byte 8)
//   * reports the packet jump-table offset encoded in word1[0:15]
//
// Full container parsing (KGSL extra-dword detection, BR/BV/LPAC sub-image
// splitting) lives in the shared container library (common/, Stage 3); see
// ghidra/README.md for the recommended end-to-end import flow.
//
// @category QRisc
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DWordDataType;

public class QRiscFirmwareHelper extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address base = currentProgram.getAddressFactory()
                .getDefaultAddressSpace().getAddress(0);
        Address version = base;
        Address jumptbl = base.add(4);
        Address boot = base.add(8);

        // version + jumptbl-offset are NOP payloads read as data by the bootstrap.
        clearListing(version, jumptbl.add(3));
        createData(version, new DWordDataType());
        createData(jumptbl, new DWordDataType());
        setEOLComment(version, "firmware id / version (NOP payload)");

        int jtoff = getInt(jumptbl) & 0xffff;
        setEOLComment(jumptbl, "packet jump-table word offset = 0x" +
                Integer.toHexString(jtoff));
        println("QRisc: packet jump-table at word 0x" + Integer.toHexString(jtoff) +
                " (byte 0x" + Integer.toHexString(jtoff * 4) + ")");

        DisassembleCommand cmd = new DisassembleCommand(boot, null, true);
        cmd.applyTo(currentProgram, monitor);
        createFunction(boot, "bootstrap");
        createLabel(boot, "bootstrap", true);
        println("QRisc: disassembled bootstrap routine at " + boot);
    }
}
