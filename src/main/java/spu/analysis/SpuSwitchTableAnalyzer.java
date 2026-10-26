package spu.analysis;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.*;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.pcode.EquateSymbol;
import ghidra.program.model.pcode.JumpTable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Recovers SPU switch tables.  GCC compiles a switch over a dense range into
 *
 * <pre>
 *   ila     base, table          (or ilhu/iohl, possibly plus ai)
 *   shli    off, index, 2
 *   clgti   t, index, N          (cases 0..N; the default is taken when index > N)
 *   a       addr, base, off
 *   lqx     q, base, off         (the quadword holding the entry)
 *   rotqby  target, q, addr      (entry into the preferred slot)
 *   bi      target
 * </pre>
 *
 * Ghidra's decompiler cannot follow the quadword load and rotate, so it treats the jump as a call.
 * This analyzer reads the table, adds the computed-jump references, disassembles the cases,
 * types the table and writes a jump-table override, which the decompiler turns into a switch.
 */
public class SpuSwitchTableAnalyzer extends AbstractAnalyzer {

	private static final String NAME = "SPU Switch Tables";
	private static final String DESCRIPTION =
		"Recovers SPU jump tables (ila/shli/a/lqx/rotqby/bi) so disassembly and the decompiler " +
			"see the switch cases.";
	private static final int WINDOW = 1024;
	private static final int MAX_CASES = 1024;

	public SpuSwitchTableAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.FUNCTION_ANALYZER);
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguage().getProcessor().toString().equals("SPU");
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Listing listing = program.getListing();
		List<Function> funcs = new ArrayList<>();
		for (Function f : program.getFunctionManager().getFunctions(set, true)) {
			funcs.add(f);
		}
		for (Function f : funcs) {
			monitor.checkCancelled();
			// a newly found case may contain another switch: repeat until nothing changes
			for (int pass = 0; pass < 8; pass++) {
				boolean changed = false;
				List<Instruction> jumps = new ArrayList<>();
				for (Instruction ins : listing.getInstructions(f.getBody(), true)) {
					if (isIndirectJump(ins)) {
						jumps.add(ins);
					}
				}
				for (Instruction ins : jumps) {
					if (hasComputedJumpRefs(program, ins)) {
						continue; // already resolved
					}
					changed |= recover(program, f, ins, monitor, log);
				}
				if (!changed) {
					break;
				}
			}
		}
		return true;
	}

	private static boolean hasComputedJumpRefs(Program program, Instruction ins) {
		for (Reference r : program.getReferenceManager().getReferencesFrom(ins.getAddress())) {
			if (r.getReferenceType() == RefType.COMPUTED_JUMP) {
				return true;
			}
		}
		return false;
	}

	/** Instructions that can execute right before ins: fall-through and branch sources. */
	private static List<Instruction> preds(Program program, Instruction ins) {
		List<Instruction> out = new ArrayList<>();
		Address a = ins.getAddress();
		Instruction lin = program.getListing().getInstructionBefore(a);
		if (lin != null && a.equals(lin.getFallThrough())) {
			out.add(lin);
		}
		for (Reference r : program.getReferenceManager().getReferencesTo(a)) {
			RefType t = r.getReferenceType();
			if (t.isFlow() && !t.isCall() && !t.isFallthrough()) {
				Instruction src = program.getListing().getInstructionAt(r.getFromAddress());
				if (src != null && !out.contains(src)) {
					out.add(src);
				}
			}
		}
		return out;
	}

	/**
	 * Breadth-first walk backwards from an instruction up to WINDOW steps; returns the first
	 * instruction accepted by the test.  Calls end a path unless the register of interest is
	 * callee-saved (r80-r127 in the SPU ABI).
	 */
	private static Instruction searchBack(Program program, Instruction from,
			java.util.function.Predicate<Instruction> test) {
		return searchBack(program, from, test, false);
	}

	private static Instruction searchBack(Program program, Instruction from,
			java.util.function.Predicate<Instruction> test, boolean throughCalls) {
		java.util.ArrayDeque<Instruction> queue = new java.util.ArrayDeque<>();
		java.util.Map<Address, Integer> depth = new java.util.HashMap<>();
		for (Instruction p : preds(program, from)) {
			queue.add(p);
			depth.put(p.getAddress(), 1);
		}
		while (!queue.isEmpty()) {
			Instruction ins = queue.poll();
			if (ins.getFlowType().isCall() && !throughCalls) {
				continue;
			}
			if (test.test(ins)) {
				return ins;
			}
			int d = depth.get(ins.getAddress());
			if (d >= WINDOW) {
				continue;
			}
			for (Instruction p : preds(program, ins)) {
				if (!depth.containsKey(p.getAddress())) {
					depth.put(p.getAddress(), d + 1);
					queue.add(p);
				}
			}
		}
		return null;
	}

	/** Unconditional indirect branch through a register other than lr (bi, bid, bie). */
	private static boolean isIndirectJump(Instruction ins) {
		FlowType ft = ins.getFlowType();
		if (!ft.isJump() || !ft.isComputed() || ft.isConditional()) {
			return false;
		}
		Register r = ins.getRegister(0);
		return ins.getMnemonicString().startsWith("bi") && r != null && !r.getName().equals("lr");
	}

	private boolean recover(Program program, Function f, Instruction bi, TaskMonitor monitor,
			MessageLog log) throws CancelledException {
		Register target = bi.getRegister(0);
		Instruction rot = def(program, bi, target);
		if (rot == null || !rot.getMnemonicString().equals("rotqby")) {
			return false;
		}
		Instruction load = def(program, rot, rot.getRegister(1));
		Instruction addr = def(program, rot, rot.getRegister(2));
		if (load == null || addr == null || !addr.getMnemonicString().equals("a")) {
			return false;
		}
		// the quadword load must address the same base+offset as the rotate amount
		if (load.getMnemonicString().equals("lqx")) {
			if (!sameRegs(load.getRegister(1), load.getRegister(2), addr.getRegister(1),
				addr.getRegister(2))) {
				return false;
			}
		}
		else if (!(load.getMnemonicString().equals("lqd") && scalar(load, 1) == 0 &&
			addr.getRegister(0).equals(register(load, 1)))) {
			return false;
		}
		// one addend is a constant (the table), the other index << 2
		Long base = null;
		Register index = null;
		for (int i = 1; i <= 2; i++) {
			Register b = addr.getRegister(i);
			Register o = addr.getRegister(3 - i);
			Long c = constant(program, addr, b, 0);
			Instruction sh = def(program, addr, o);
			if (c != null && sh != null && sh.getMnemonicString().equals("shli") &&
				scalar(sh, 2) == 2) {
				base = c;
				index = sh.getRegister(1);
				break;
			}
		}
		if (base == null || index == null) {
			return false;
		}
		int count = bound(program, bi, index);
		Address table = bi.getAddress().getNewAddress(base & 0x3ffffL);
		List<Address> targets = readTable(program, table, count);
		if (targets.isEmpty()) {
			return false;
		}

		ReferenceManager rm = program.getReferenceManager();
		AddressSet starts = new AddressSet();
		ArrayList<Address> dest = new ArrayList<>();
		for (Address t : targets) {
			rm.addMemoryReference(bi.getAddress(), t, RefType.COMPUTED_JUMP, SourceType.ANALYSIS,
				CodeUnit.MNEMONIC);
			if (!dest.contains(t)) {
				dest.add(t);
			}
			if (program.getListing().getInstructionAt(t) == null) {
				starts.add(t);
			}
		}
		if (!starts.isEmpty()) {
			new DisassembleCommand(starts, null, true).applyTo(program, monitor);
		}
		try {
			DataUtilities.createData(program, table,
				new ArrayDataType(PointerDataType.dataType, targets.size(), 4), -1,
				DataUtilities.ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
		}
		catch (CodeUnitInsertionException e) {
			// the table overlaps code or other data: keep the references only
		}
		CreateFunctionCmd.fixupFunctionBody(program, f, monitor);
		try {
			new JumpTable(bi.getAddress(), dest, true, EquateSymbol.FORMAT_DEFAULT).writeOverride(f);
		}
		catch (Exception e) {
			log.appendMsg(NAME, "jump table at " + bi.getAddress() + ": " + e.getMessage());
		}
		return true;
	}

	private static boolean sameRegs(Register a, Register b, Register c, Register d) {
		return a != null && b != null && c != null && d != null &&
			((a.equals(c) && b.equals(d)) || (a.equals(d) && b.equals(c)));
	}

	/** Number of table entries: N+1 from "clgti t, index, N", else scan the table. */
	private static int bound(Program program, Instruction from, Register index) {
		Instruction ins = searchBack(program, from,
			i -> i.getMnemonicString().equals("clgti") && index.equals(i.getRegister(1)));
		if (ins != null) {
			long n = scalar(ins, 2);
			if (n >= 0 && n < MAX_CASES) {
				return (int) n + 1;
			}
		}
		return -1;
	}

	private static List<Address> readTable(Program program, Address table, int count) {
		List<Address> out = new ArrayList<>();
		Memory mem = program.getMemory();
		int n = count > 0 ? count : MAX_CASES;
		for (int i = 0; i < n; i++) {
			try {
				long v = mem.getInt(table.add(4L * i)) & 0xffffffffL;
				Address t = table.getNewAddress(v);
				MemoryBlock b = mem.getBlock(t);
				if ((v & 3) != 0 || b == null || !b.isExecute()) {
					if (count > 0) {
						return new ArrayList<>();
					}
					break;
				}
				out.add(t);
			}
			catch (MemoryAccessException | AddressOutOfBoundsException e) {
				return count > 0 ? new ArrayList<>() : out;
			}
		}
		return out;
	}

	/** The closest earlier instruction (within WINDOW steps of flow) whose p-code writes reg. */
	private static Instruction def(Program program, Instruction from, Register reg) {
		if (reg == null) {
			return null;
		}
		return searchBack(program, from, ins -> {
			for (PcodeOp op : ins.getPcode()) {
				Varnode out = op.getOutput();
				if (out != null && out.isRegister() && overlaps(out, reg)) {
					return true;
				}
			}
			return false;
		}, calleeSaved(reg));
	}

	private static boolean calleeSaved(Register r) {
		String n = r.getBaseRegister().getName();
		if (!n.matches("r\\d+")) {
			return false;
		}
		int i = Integer.parseInt(n.substring(1));
		return i >= 80 && i <= 127;
	}

	private static boolean overlaps(Varnode v, Register r) {
		long a = v.getOffset();
		long b = r.getAddress().getOffset();
		return a < b + r.getMinimumByteSize() && b < a + v.getSize();
	}

	/** Value of reg's preferred slot just before instruction at, from constant formation. */
	private static Long constant(Program program, Instruction at, Register reg, int depth) {
		if (depth > 4) {
			return null;
		}
		Instruction d = def(program, at, reg);
		if (d == null) {
			return null;
		}
		String m = d.getMnemonicString();
		switch (m) {
			case "ila":
				return scalar(d, 1) & 0x3ffff;
			case "il":
				return scalar(d, 1) & 0xffffffffL;
			case "ilhu":
				return (scalar(d, 1) << 16) & 0xffffffffL;
			case "iohl": {
				Long hi = constant(program, d, reg, depth + 1);
				return hi == null ? null : (hi | (scalar(d, 1) & 0xffff));
			}
			case "ai": {
				Long b = constant(program, d, d.getRegister(1), depth + 1);
				return b == null ? null : ((b + scalar(d, 2)) & 0xffffffffL);
			}
			case "ori":
				if (scalar(d, 2) == 0) {
					return constant(program, d, d.getRegister(1), depth + 1);
				}
				return null;
			default:
				return null;
		}
	}

	/** A register among the objects of an operand such as "0x10(r3)". */
	private static Register register(Instruction ins, int op) {
		for (Object o : ins.getOpObjects(op)) {
			if (o instanceof Register r) {
				return r;
			}
		}
		return null;
	}

	private static long scalar(Instruction ins, int op) {
		Object[] objs = ins.getOpObjects(op);
		for (Object o : objs) {
			if (o instanceof Scalar s) {
				return s.getSignedValue();
			}
		}
		return Long.MIN_VALUE;
	}
}
