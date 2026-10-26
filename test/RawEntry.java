// Pre-script for raw SPU images: disassemble and create a function at the image start (the
// local store image's entry point, address 0 for the Linux spufs save/restore code).
//@category Testing

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

public class RawEntry extends GhidraScript {
	@Override
	protected void run() throws Exception {
		Address a = currentProgram.getMinAddress();
		disassemble(a);
		createFunction(a, "_start");
		currentProgram.getSymbolTable().addExternalEntryPoint(a);
	}
}
