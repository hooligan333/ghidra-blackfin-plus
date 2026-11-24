// One-off after installing a Blackfin+ spec with LSETUPZ/LSETUPLEZ support. Programs disassembled
// with an older spec decoded these as plain LSETUP (the LOP bits were ignored), and the loop-end
// instruction lacks the loop0z/loop1z context bit that makes a skipped loop resume after it.
// This finds every loop setup whose raw encoding is LSETUPZ/LSETUPLEZ (ROP 01/11, LOP 01/10,
// bit 15 of the second halfword clear), re-disassembles it, sets the context bit at its loop end
// and re-disassembles that instruction too. References and functions are kept. Safe to run again.
//@category Blackfin
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class FixLoopZContext extends GhidraScript {
	@Override
	public void run() throws Exception {
		Register z0 = currentProgram.getRegister("loop0z");
		Register z1 = currentProgram.getRegister("loop1z");
		if (z0 == null || z1 == null) {
			printerr("This program's language has no loop0z/loop1z context bits; install the updated extension first.");
			return;
		}
		Memory mem = currentProgram.getMemory();
		Listing listing = currentProgram.getListing();
		ProgramContext ctx = currentProgram.getProgramContext();

		List<Address> setups = new ArrayList<>();
		for (Instruction ins : listing.getInstructions(true)) {
			if (!ins.getMnemonicString().startsWith("LSETUP") || ins.getLength() != 4) continue;
			int w0 = mem.getShort(ins.getAddress()) & 0xffff;
			int w1 = mem.getShort(ins.getAddress().add(2)) & 0xffff;
			int rop = (w0 >> 5) & 3, lop = (w1 >> 10) & 3;
			if ((w0 >> 7) != 0x1c1 || (rop != 1 && rop != 3) || (w1 >> 15) != 0 || (lop != 1 && lop != 2)) continue;
			setups.add(ins.getAddress());
		}

		int fixedSetup = 0, fixedEnd = 0;
		for (Address a : setups) {
			int w0 = mem.getShort(a) & 0xffff;
			int w1 = mem.getShort(a.add(2)) & 0xffff;
			boolean lc1 = ((w0 >> 4) & 1) == 1;
			Address end = a.add((w1 & 0x3ff) * 2L);
			Register z = lc1 ? z1 : z0;

			Instruction setup = listing.getInstructionAt(a);
			if (setup != null && !setup.getMnemonicString().equals(((w1 >> 10) & 3) == 1 ? "LSETUPZ" : "LSETUPLEZ")) {
				clearListing(a, setup.getMaxAddress());
				new DisassembleCommand(new AddressSet(a, a.add(3)), null, false).applyTo(currentProgram, monitor);
				fixedSetup++;
			}
			BigInteger cur = ctx.getValue(z, end, false);
			if (cur == null || cur.intValue() != 1) {
				Instruction endIns = listing.getInstructionAt(end);
				Address last = endIns != null ? endIns.getMaxAddress() : end;
				if (endIns != null) clearListing(end, last);
				ctx.setValue(z, end, end, BigInteger.ONE);
				if (endIns != null) new DisassembleCommand(end, null, false).applyTo(currentProgram, monitor);
				fixedEnd++;
			}
		}
		println("FixLoopZContext: " + setups.size() + " LSETUPZ/LSETUPLEZ by encoding; " + fixedSetup +
			" setups re-disassembled, " + fixedEnd + " loop ends updated");
	}
}
