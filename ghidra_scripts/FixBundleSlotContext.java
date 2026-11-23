// Re-disassembles parallel bundles whose slots were disassembled before the language spec marked
// bundle slots with the "inslot" context (bundle-ordering fix). Needed once per existing program after
// installing the patched Blackfin+ extension; new imports do not need it.
// Keeps references, comments, symbols and functions; only the bundle's three instructions are redone.
//@category Blackfin
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.math.BigInteger;
import java.util.*;

public class FixBundleSlotContext extends GhidraScript {
	@Override
	protected void run() throws Exception {
		Register inslot = currentProgram.getRegister("inslot");
		if (inslot == null) {
			printerr("This program's language has no 'inslot' context: install the patched extension first.");
			return;
		}
		Listing listing = currentProgram.getListing();
		ReferenceManager rm = currentProgram.getReferenceManager();
		List<Address[]> todo = new ArrayList<>();
		for (Instruction ins : listing.getInstructions(true)) {
			if (ins.getDelaySlotDepth() == 0 || !ins.getMnemonicString().endsWith("||")) continue;
			Address end = ins.getMaxAddress();
			boolean stale = false;
			Instruction s = ins.getNext();
			for (int k = 0; k < ins.getDelaySlotDepth() && s != null && s.isInDelaySlot(); k++, s = s.getNext()) {
				BigInteger v = s.getValue(inslot, false);
				if (v == null || v.intValue() != 1) stale = true;
				end = s.getMaxAddress();
			}
			if (stale) todo.add(new Address[] { ins.getAddress(), end });
		}
		println("Bundles to re-disassemble: " + todo.size());
		int done = 0, failed = 0, refsRestored = 0;
		for (Address[] r : todo) {
			monitor.checkCancelled();
			AddressSet range = new AddressSet(r[0], r[1]);
			List<Reference> saved = new ArrayList<>();
			for (Address a : range.getAddresses(true)) saved.addAll(Arrays.asList(rm.getReferencesFrom(a)));
			listing.clearCodeUnits(r[0], r[1], false);
			new DisassembleCommand(range, range, false).applyTo(currentProgram, monitor);
			Instruction ins = listing.getInstructionAt(r[0]);
			boolean ok = ins != null && ins.getDelaySlotDepth() > 0;
			for (Instruction s = ok ? ins.getNext() : null; ok && s != null && s.getMinAddress().compareTo(r[1]) <= 0; s = s.getNext()) {
				BigInteger v = s.getValue(inslot, false);
				if (v == null || v.intValue() != 1) ok = false;
			}
			if (!ok) {
				failed++;
				printerr("Not fixed: bundle at " + r[0]);
			}
			for (Reference ref : saved) {
				if (ref.getReferenceType().isFallthrough()) continue;
				boolean present = false;
				for (Reference n : rm.getReferencesFrom(ref.getFromAddress())) {
					if (n.getToAddress().equals(ref.getToAddress()) && n.getOperandIndex() == ref.getOperandIndex()) { present = true; break; }
				}
				if (!present) {
					rm.addReference(ref);
					refsRestored++;
				}
			}
			done++;
		}
		println("Re-disassembled " + done + " bundles (" + failed + " not fixed), restored " + refsRestored + " references.");
	}
}
