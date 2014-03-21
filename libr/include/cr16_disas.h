#ifndef CR16_DISASM_H
#define CR16_DISASM_H

#define CR16_INSTR_MAXLEN	24
#define STOR_LOAD_MASK		0x181F

struct cr16_cmd {
	char	instr[CR16_INSTR_MAXLEN];
	char	operands[CR16_INSTR_MAXLEN];
};

int cr16_decode_command(const ut8 *instr, struct cr16_cmd *cmd);

enum cr16_opcodes {
	CR16_ADD	= 0x0,
	CR16_ADDU	= 0x1,
	CR16_BITI	= 0x2,
	CR16_MUL	= 0x3,
	CR16_ASHU	= 0x4,
	CR16_LSH	= 0x5,
	CR16_XOR	= 0x6,
	CR16_CMP	= 0x7,
	CR16_AND	= 0x8,
	CR16_ADDC	= 0x9,
	CR16_BCOND01	= 0xA,
	CR16_TBIT	= 0xB,
	CR16_MOV	= 0xC,
	CR16_SUB	= 0xF,
	CR16_SUBC	= 0xD,
	CR16_OR		= 0xE,
	CR16_MOVD	= 0x19,
	CR16_MULSB	= 0x30,
	CR16_MULSW	= 0x31,
	CR16_MULUW	= 0x3F,
	CR16_MOVXB	= 0x34,
	CR16_MOVZB	= 0x35,
	CR16_SCOND	= 0x37,
	CR16_TBIT_R_R	= 0x3B,
	CR16_TBIT_I_R	= 0x1B,
	CR16_JUMP	= 0x2A,
	CR16_JAL	= 0x3A,
	CR16_BAL	= 0x1A,
	CR16_LPR	= 0x38,
	CR16_SPR	= 0x39,
	CR16_BCOND_2	= 0x0A,
	CR16_PUSH	= 0xD8,
	CR16_POP	= 0xD9,
	CR16_POPRET_1	= 0xDA,
	CR16_POPRET_2	= 0xDB,
	CR16_LOADM	= 0xFC,
	CR16_STORM	= 0xFD,
};

enum cr16_opcodes_long {
	CR16_RETX	= 0x79FE,
	CR16_DI		= 0x7DDE,
	CR16_EI		= 0x7DFE,
	CR16_NOP	= 0x0200,
	CR16_WAIT	= 0x7FFE,
	CR16_EWAIT	= 0x7FD6,
};

enum cr16_cmd_forms {
	CR16_I_R	= 0x0,
	CR16_R_R	= 0x1,
};

enum cr16_regs {
	CR16_R0		= 0,
	CR16_R1,
	CR16_R2,
	CR16_R3,
	CR16_R4,
	CR16_R5,
	CR16_R6,
	CR16_R7,
	CR16_R8,
	CR16_R9,
	CR16_R10,
	CR16_R11,
	CR16_R12,
	CR16_R13,
	CR16_RA,
	CR16_SP,
};

enum cr16_dedic_regs {
	CR16_PSR	= 0x1,
	CR16_INTBASE	= 0x3,
	CR16_ISP	= 0xB,
};

enum cr16_conds {
	CR16_COND_EQ	= 0x0,
	CR16_COND_NE,
	CR16_COND_CS,
	CR16_COND_CC,
	CR16_COND_HI,
	CR16_COND_LS,
	CR16_COND_GT,
	CR16_COND_LE,
	CR16_COND_FS,
	CR16_COND_FC,
	CR16_COND_LO,
	CR16_COND_HS,
	CR16_COND_LT,
	CR16_COND_GE,
};

#endif /* CR16_DISASM_H */
