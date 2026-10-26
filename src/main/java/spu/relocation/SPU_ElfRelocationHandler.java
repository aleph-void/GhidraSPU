package spu.relocation;

import ghidra.app.util.bin.format.elf.*;
import ghidra.app.util.bin.format.elf.relocation.AbstractElfRelocationHandler;
import ghidra.app.util.bin.format.elf.relocation.ElfRelocationContext;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.reloc.Relocation.Status;
import ghidra.program.model.reloc.RelocationResult;

/**
 * Applies SPU ELF relocations (same formulas and field masks as binutils bfd/elf32-spu.c).
 */
public class SPU_ElfRelocationHandler
		extends AbstractElfRelocationHandler<SPU_ElfRelocationType, ElfRelocationContext<?>> {

	private static final int SPU_I7 = 0x001fc000;
	private static final int SPU_I9 = 0x0180007f;
	private static final int SPU_I9I = 0x0000c07f;
	private static final int SPU_I10 = 0x00ffc000;
	private static final int SPU_I16 = 0x007fff80;
	private static final int SPU_I18 = 0x01ffff80;

	public SPU_ElfRelocationHandler() {
		super(SPU_ElfRelocationType.class);
	}

	@Override
	public boolean canRelocate(ElfHeader elf) {
		return elf.e_machine() == SPU_ElfConstants.EM_SPU;
	}

	private static int field(int old, int mask, int value) {
		return (old & ~mask) | (value & mask);
	}

	@Override
	protected RelocationResult relocate(ElfRelocationContext<?> elfRelocationContext,
			ElfRelocation relocation, SPU_ElfRelocationType type, Address relocationAddress,
			ElfSymbol elfSymbol, Address symbolAddr, long symbolValue, String symbolName)
			throws MemoryAccessException {

		Program program = elfRelocationContext.getProgram();
		Memory memory = program.getMemory();

		if (type == SPU_ElfRelocationType.R_SPU_NONE) {
			return RelocationResult.SKIPPED;
		}
		if (type == SPU_ElfRelocationType.R_SPU_ADD_PIC) {
			// The linker rewrites "a rt,ra,rb" to "ai rt,ra,0" when the symbol is not defined.
			if (elfSymbol == null || symbolAddr == null ||
				elfSymbol.getSectionHeaderIndex() == ElfSectionHeaderConstants.SHN_UNDEF) {
				int old = memory.getInt(relocationAddress);
				memory.setInt(relocationAddress, (old & 0x00003fff) | 0x1c000000);
				return new RelocationResult(Status.APPLIED, 4);
			}
			return RelocationResult.SKIPPED;
		}
		if (type == SPU_ElfRelocationType.R_SPU_PPU32 ||
			type == SPU_ElfRelocationType.R_SPU_PPU64) {
			// Effective addresses in the PPU program: nothing to apply in the SPU image.
			markAsUnhandled(program, relocationAddress, type, relocation.getSymbolIndex(),
				symbolName, elfRelocationContext.getLog());
			return RelocationResult.UNSUPPORTED;
		}

		if (handleUnresolvedSymbol(elfRelocationContext, relocation, relocationAddress)) {
			return RelocationResult.FAILURE;
		}

		int p = (int) relocationAddress.getOffset();
		int s = (int) symbolValue;
		int a = (int) relocation.getAddend();
		int old = memory.getInt(relocationAddress);
		int v;
		switch (type) {
			case R_SPU_ADDR10:
				v = field(old, SPU_I10, ((s + a) >> 4) << 14);
				break;
			case R_SPU_ADDR16:
				v = field(old, SPU_I16, ((s + a) >> 2) << 7);
				break;
			case R_SPU_ADDR16_HI:
				v = field(old, SPU_I16, ((s + a) >>> 16) << 7);
				break;
			case R_SPU_ADDR16_LO:
				v = field(old, SPU_I16, (s + a) << 7);
				break;
			case R_SPU_ADDR18:
				v = field(old, SPU_I18, (s + a) << 7);
				break;
			case R_SPU_ADDR32:
				v = s + a;
				break;
			case R_SPU_REL16:
				v = field(old, SPU_I16, ((s + a - p) >> 2) << 7);
				break;
			case R_SPU_ADDR7:
				v = field(old, SPU_I7, (s + a) << 14);
				break;
			case R_SPU_REL9: {
				int d = (s + a - p) >> 2;
				v = field(old, SPU_I9, (d & 0x7f) | ((d & 0x180) << 16));
				break;
			}
			case R_SPU_REL9I: {
				int d = (s + a - p) >> 2;
				v = field(old, SPU_I9I, (d & 0x7f) | ((d & 0x180) << 7));
				break;
			}
			case R_SPU_ADDR10I:
				v = field(old, SPU_I10, (s + a) << 14);
				break;
			case R_SPU_ADDR16I:
			case R_SPU_ADDR16X:
				v = field(old, SPU_I16, (s + a) << 7);
				break;
			case R_SPU_REL32:
				v = s + a - p;
				break;
			default:
				markAsUnhandled(program, relocationAddress, type, relocation.getSymbolIndex(),
					symbolName, elfRelocationContext.getLog());
				return RelocationResult.UNSUPPORTED;
		}
		memory.setInt(relocationAddress, v);
		return new RelocationResult(Status.APPLIED, 4);
	}
}
