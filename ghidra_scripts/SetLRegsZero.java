// Decompiler aid for the circular-addressing semantics (I-register post-modify wraps into
// [B, B+L) when L != 0). The Blackfin C run-time model requires L0-L3 to be zero at function
// boundaries, and compiled code that does not set an L register itself runs with L = 0.
// For every function that contains no instruction writing L0-L3, this records the register
// values L0..L3 = 0 over the function body, so the decompiler folds the wrap logic away.
// Functions that write an L register (hand-written circular-buffer code) are left alone.
// Only register-value annotations are changed; instructions and functions are untouched.
// Safe to run again. Undo with Edit -> Undo.
//@category Blackfin
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import java.math.BigInteger;

public class SetLRegsZero extends GhidraScript {
	@Override
	public void run() throws Exception {
		Register[] ls = new Register[4];
		for (int i = 0; i < 4; i++) {
			ls[i] = currentProgram.getRegister("L" + i);
			if (ls[i] == null) { printerr("No register L" + i + " in this language."); return; }
		}
		ProgramContext ctx = currentProgram.getProgramContext();
		Listing listing = currentProgram.getListing();
		int set = 0, skipped = 0;
		for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
			monitor.checkCancelled();
			boolean writesL = false;
			outer:
			for (Instruction ins : listing.getInstructions(f.getBody(), true)) {
				for (Object o : ins.getResultObjects()) {
					if (o instanceof Register r) {
						for (Register l : ls) if (r.equals(l) || r.getBaseRegister().equals(l)) { writesL = true; break outer; }
					}
				}
			}
			if (writesL) { skipped++; continue; }
			for (AddressRange rg : f.getBody().getAddressRanges())
				for (Register l : ls) ctx.setValue(l, rg.getMinAddress(), rg.getMaxAddress(), BigInteger.ZERO);
			set++;
		}
		println("SetLRegsZero: L0-L3 = 0 recorded in " + set + " functions; " + skipped + " functions write an L register and were left alone");
	}
}
