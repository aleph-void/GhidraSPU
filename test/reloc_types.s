# One instance of every SPU relocation type (except the PPU ones), for test/reloc_check.py.
	.text
	.global f
f:
	ila	$3,data_sym          # R_SPU_ADDR18
	ilhu	$4,data_sym@h        # R_SPU_ADDR16_HI
	iohl	$4,data_sym@l        # R_SPU_ADDR16_LO
	lqa	$5,data_sym          # R_SPU_ADDR16
	lqr	$6,data_sym          # R_SPU_REL16
	brsl	$lr,ext_func         # R_SPU_REL16 (undefined symbol)
	lqd	$7,data_sym($8)      # R_SPU_ADDR10
	ai	$9,$9,small_sym      # R_SPU_ADDR10I (weak absolute symbol)
	il	$10,small_sym        # R_SPU_ADDR16I
	cbd	$11,tiny_sym($12)    # R_SPU_ADDR7
	hbrr	far_br,f2            # R_SPU_REL9 + R_SPU_REL16
	hbr	far_br,$lr           # R_SPU_REL9I
	bi	$lr
f2:	bi	$lr
	.section .text.far,"ax",@progbits
	.global far_br
far_br:	brsl	$lr,f2
	bi	$lr
	.data
	.align	4
	.long	data_sym             # R_SPU_ADDR32
	.long	ext_data - .         # R_SPU_REL32
	.long	ext_data             # R_SPU_ADDR32 (undefined symbol)
	.align	4
	.global	data_sym
data_sym:
	.long	1, 2, 3, 4
	.text
# "a $3,$4,$5" with R_SPU_ADD_PIC: gas has no syntax for it, so these two words are emitted
# as R_SPU_ADDR32 words that addpic.py turns into the instruction and R_SPU_ADD_PIC (17).
	.global	pic_undef, pic_def
pic_undef:
	.long	ext_func             # -> a $3,$4,$5 + R_SPU_ADD_PIC ext_func: becomes ai $3,$4,0
pic_def:
	.long	f                    # -> a $3,$4,$5 + R_SPU_ADD_PIC f (defined): unchanged
	.weak	small_sym
	.set	small_sym, 100
	.weak	tiny_sym
	.set	tiny_sym, 5
