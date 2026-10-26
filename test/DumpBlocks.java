// Writes every memory block: "<name> <start-hex> <size>" lines to <out>.map and the bytes of the
// initialized ones to <out>.<name>.bin, plus the address of every external symbol Ghidra created
// ("extern <name> <address-hex>") and of every other symbol ("sym <name> <address-hex>").
// Script args: <out-prefix>
//@category Testing

import java.io.FileOutputStream;
import java.io.PrintStream;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class DumpBlocks extends GhidraScript {
	@Override
	protected void run() throws Exception {
		String out = getScriptArgs()[0];
		try (PrintStream map = new PrintStream(out + ".map")) {
			for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
				if (!b.isLoaded()) {
					continue;
				}
				map.printf("%s %x %d%n", b.getName(), b.getStart().getOffset(), b.getSize());
				if (!b.isInitialized()) {
					continue;
				}
				byte[] data = new byte[(int) b.getSize()];
				b.getBytes(b.getStart(), data);
				try (FileOutputStream f = new FileOutputStream(out + "." + b.getName() + ".bin")) {
					f.write(data);
				}
			}
			SymbolIterator it = currentProgram.getSymbolTable().getAllSymbols(true);
			for (Symbol s : it) {
				MemoryBlock b = currentProgram.getMemory().getBlock(s.getAddress());
				if (b != null && b.getName().equals(MemoryBlock.EXTERNAL_BLOCK_NAME)) {
					map.printf("extern %s %x%n", s.getName(), s.getAddress().getOffset());
				}
				else if (b != null && s.isPrimary() && s.getAddress().isMemoryAddress()) {
					map.printf("sym %s %x%n", s.getName(), s.getAddress().getOffset());
				}
			}
		}
	}
}
