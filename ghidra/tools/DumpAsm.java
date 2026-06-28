// Ghidra GhidraScript: disassemble from byte 8 and print the listing.
// @category QRisc
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;

public class DumpAsm extends GhidraScript {
    @Override
    public void run() throws Exception {
        Address start = currentProgram.getAddressFactory()
                .getDefaultAddressSpace().getAddress(8);
        DisassembleCommand cmd = new DisassembleCommand(start, null, true);
        cmd.applyTo(currentProgram, monitor);
        println("==== QRISC-DISASM-DUMP-BEGIN ====");
        int n = 0;
        for (Instruction ins : currentProgram.getListing().getInstructions(true)) {
            println(ins.getAddress() + ": " + ins.toString());
            if (++n > 400) break;
        }
        println("==== QRISC-DISASM-DUMP-END (" + n + " insns) ====");
    }
}
