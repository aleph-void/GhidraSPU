package spu.relocation;

import ghidra.app.util.bin.format.elf.relocation.ElfRelocationType;

/** SPU ELF relocation types (binutils include/elf/spu.h). */
public enum SPU_ElfRelocationType implements ElfRelocationType {
	R_SPU_NONE(0),
	R_SPU_ADDR10(1),     // I10 field, (S + A) >> 4
	R_SPU_ADDR16(2),     // I16 field, (S + A) >> 2
	R_SPU_ADDR16_HI(3),  // I16 field, (S + A) >> 16
	R_SPU_ADDR16_LO(4),  // I16 field, (S + A) & 0xffff
	R_SPU_ADDR18(5),     // I18 field, S + A
	R_SPU_ADDR32(6),     // word, S + A
	R_SPU_REL16(7),      // I16 field, (S + A - P) >> 2
	R_SPU_ADDR7(8),      // I7 field, S + A
	R_SPU_REL9(9),       // hbra/hbrr RO field, (S + A - P) >> 2
	R_SPU_REL9I(10),     // hbr RO field, (S + A - P) >> 2
	R_SPU_ADDR10I(11),   // I10 field, S + A
	R_SPU_ADDR16I(12),   // I16 field, S + A
	R_SPU_REL32(13),     // word, S + A - P
	R_SPU_ADDR16X(14),   // I16 field, S + A
	R_SPU_PPU32(15),     // word, PPU effective address (not part of the SPU image)
	R_SPU_PPU64(16),     // doubleword, PPU effective address
	R_SPU_ADD_PIC(17);   // marks "a rt,ra,rb" that becomes "ai rt,ra,0" for undefined weak symbols

	public final int typeId;

	private SPU_ElfRelocationType(int typeId) {
		this.typeId = typeId;
	}

	@Override
	public int typeId() {
		return typeId;
	}
}
