/* Copyright (C) 2008-2018 - pancake, unlogic, emvivre */

#include <r_flag.h>
#include <r_core.h>
#include <r_asm.h>
#include <r_lib.h>
#include <r_types.h>
#include <stdio.h>
#include <string.h>

static ut64 getnum(RAsm *a, const char *s);

#define ENCODING_SHIFT 0
#define OPTYPE_SHIFT   6
#define REGMASK_SHIFT  16
#define OPSIZE_SHIFT   24

// How to encode the operand?
#define OT_REGMEM      (1 << (ENCODING_SHIFT + 0))
#define OT_SPECIAL     (1 << (ENCODING_SHIFT + 1))
#define OT_IMMEDIATE   (1 << (ENCODING_SHIFT + 2))
#define OT_JMPADDRESS  (1 << (ENCODING_SHIFT + 3))

// Register indices - by default, we allow all registers
#define OT_REGALL   (0xff << REGMASK_SHIFT)

// Memory or register operands: how is the operand written in assembly code?
#define OT_MEMORY      (1 << (OPTYPE_SHIFT + 0))
#define OT_CONSTANT    (1 << (OPTYPE_SHIFT + 1))
#define OT_GPREG      ((1 << (OPTYPE_SHIFT + 2)) | OT_REGALL)
#define OT_SEGMENTREG ((1 << (OPTYPE_SHIFT + 3)) | OT_REGALL)
#define OT_FPUREG     ((1 << (OPTYPE_SHIFT + 4)) | OT_REGALL)
#define OT_MMXREG     ((1 << (OPTYPE_SHIFT + 5)) | OT_REGALL)
#define OT_XMMREG     ((1 << (OPTYPE_SHIFT + 6)) | OT_REGALL)
#define OT_CONTROLREG ((1 << (OPTYPE_SHIFT + 7)) | OT_REGALL)
#define OT_DEBUGREG   ((1 << (OPTYPE_SHIFT + 8)) | OT_REGALL)
#define OT_SREG       ((1 << (OPTYPE_SHIFT + 9)) | OT_REGALL)
// more?

#define OT_REGTYPE    ((OT_GPREG | OT_SEGMENTREG | OT_FPUREG | OT_MMXREG | OT_XMMREG | OT_CONTROLREG | OT_DEBUGREG) & ~OT_REGALL)

// Register mask
#define OT_REG(num)  ((1 << (REGMASK_SHIFT + (num))) | OT_REGTYPE)

#define OT_UNKNOWN    (0 << OPSIZE_SHIFT)
#define OT_BYTE       (1 << OPSIZE_SHIFT)
#define OT_WORD       (2 << OPSIZE_SHIFT)
#define OT_DWORD      (4 << OPSIZE_SHIFT)
#define OT_QWORD      (8 << OPSIZE_SHIFT)
#define OT_OWORD     (16 << OPSIZE_SHIFT)
#define OT_TBYTE     (32 << OPSIZE_SHIFT)

#define ALL_SIZE     (OT_BYTE | OT_WORD | OT_DWORD | OT_QWORD | OT_OWORD)

// For register operands, we mostl don't care about the size.
// So let's just set all relevant flags.
#define OT_FPUSIZE  (OT_DWORD | OT_QWORD | OT_TBYTE)
#define OT_XMMSIZE  (OT_DWORD | OT_QWORD | OT_OWORD)

// Macros for encoding
#define OT_REGMEMOP(type)  (OT_##type##REG | OT_MEMORY | OT_REGMEM)
#define OT_REGONLYOP(type) (OT_##type##REG | OT_REGMEM)
#define OT_MEMONLYOP       (OT_MEMORY | OT_REGMEM)
#define OT_MEMIMMOP        (OT_MEMORY | OT_IMMEDIATE)
#define OT_REGSPECOP(type) (OT_##type##REG | OT_SPECIAL)
#define OT_IMMOP           (OT_CONSTANT | OT_IMMEDIATE)
#define OT_MEMADDROP       (OT_MEMORY | OT_IMMEDIATE)

// Some operations are encoded via opcode + spec field
#define SPECIAL_SPEC 0x00010000
#define SPECIAL_MASK 0x00000007

#define MAX_OPERANDS 3
#define MAX_REPOP_LENGTH 20

const ut8 SEG_REG_PREFIXES[] = {0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65};

typedef enum tokentype_t {
	TT_EOF,
	TT_WORD,
	TT_NUMBER,
	TT_SPECIAL
} x86newTokenType;

typedef enum register_t {
	X86R_UNDEFINED = -1,
	X86R_EAX = 0, X86R_ECX, X86R_EDX, X86R_EBX, X86R_ESP, X86R_EBP, X86R_ESI, X86R_EDI, X86R_EIP,
	X86R_AX = 0, X86R_CX, X86R_DX, X86R_BX, X86R_SP, X86R_BP, X86R_SI, X86R_DI,
	X86R_AL = 0, X86R_CL, X86R_DL, X86R_BL, X86R_AH, X86R_CH, X86R_DH, X86R_BH,
	X86R_RAX = 0, X86R_RCX, X86R_RDX, X86R_RBX, X86R_RSP, X86R_RBP, X86R_RSI, X86R_RDI, X86R_RIP,
	X86R_R8 = 0, X86R_R9, X86R_R10, X86R_R11, X86R_R12, X86R_R13, X86R_R14, X86R_R15,
	X86R_CS = 0, X86R_SS, X86R_DS, X86R_ES, X86R_FS, X86R_GS	// Is this the right order?
} Register;

typedef struct operand_t {
	ut32 type;
	st8 sign;
	union {
		struct {
			Register reg;
			bool extended;
		};
		struct {
			long offset;
			st8 offset_sign;
			Register regs[2];
			int scale[2];
		};
		struct {
			ut64 immediate;
			bool is_good_flag;
		};
		struct {
			char rep_op[MAX_REPOP_LENGTH];
		};
	};
} Operand;

typedef struct Opcode_t {
	char *mnemonic;
	ut32 op[3];
	size_t op_len;
	bool is_short;
	ut8 opcode[3];
	int operands_count;
	Operand operands[MAX_OPERANDS];
	bool has_bnd;
} Opcode;

static ut8 getsib(const ut8 sib) {
	if (!sib) {
		return 0;
	}
	return (sib & 0x8) ? 3 : getsib ((sib << 1) | 1) - 1;
}

static int is_al_reg(const Operand *op) {
	if (op->type & OT_MEMORY) {
		return 0;
	}
	if (op->reg == X86R_AL && op->type & OT_BYTE) {
		return 1;
	}
	return 0;
}

static int oprep(RAsm *a, ut8 *data, const Opcode *op);

static int process_16bit_group_1(RAsm *a, ut8 *data, const Opcode *op, int op1) {
	int l = 0;
	int immediate = op->operands[1].immediate * op->operands[1].sign;

	data[l++] = 0x66;
	if (op->operands[1].immediate < 128) {
		data[l++] = 0x83;
		data[l++] = op->operands[0].reg | (0xc0 + op1 + op->operands[0].reg);
	} else {
		if (op->operands[0].reg == X86R_AX) {
			data[l++] = 0x05 + op1;
		} else {
			data[l++] = 0x81;
			data[l++] = (0xc0 + op1) | op->operands[0].reg;
		}
	}
	data[l++] = immediate;
	if (op->operands[1].immediate > 127) {
		data[l++] = immediate >> 8;
	}

	return l;
}

static int process_group_1(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	int modrm = 0;
	int mod_byte = 0;
	int offset = 0;
	int mem_ref = 0;
	st32 immediate = 0;

	if (!op->operands[1].is_good_flag) {
		return -1;
	}
	if (a->bits == 64 && op->operands[0].type & OT_QWORD) {
		data[l++] = 0x48;
	}
	if (!strcmp (op->mnemonic, "adc")) {
		modrm = 2;
	} else if (!strcmp (op->mnemonic, "add")) {
		modrm = 0;
	} else if (!strcmp (op->mnemonic, "or")) {
		modrm = 1;
	} else if (!strcmp (op->mnemonic, "and")) {
		modrm = 4;
	} else if (!strcmp (op->mnemonic, "xor")) {
		modrm = 6;
	} else if (!strcmp (op->mnemonic, "sbb")) {
		modrm = 3;
	} else if (!strcmp (op->mnemonic, "sub")) {
		modrm = 5;
	} else if (!strcmp (op->mnemonic, "cmp")) {
		modrm = 7;
	}
	immediate = op->operands[1].immediate * op->operands[1].sign;

	if (op->operands[0].type & OT_DWORD ||
		op->operands[0].type & OT_QWORD) {
		if (op->operands[1].immediate < 128) {
			data[l++] = 0x83;
		} else if (op->operands[0].reg != X86R_EAX ||
		           op->operands[0].type & OT_MEMORY) {
			data[l++] = 0x81;
		}
	} else if (op->operands[0].type & OT_BYTE) {
		if (op->operands[1].immediate > 255) {
			eprintf ("Error: Immediate exceeds bounds\n");
			return -1;
		}
		data[l++] = 0x80;
	}
	if (op->operands[0].type & OT_MEMORY) {
		offset = op->operands[0].offset * op->operands[0].offset_sign;
		if (op->operands[0].offset || op->operands[0].regs[0] == X86R_EBP) {
			mod_byte = 1;
		}
		if (offset < ST8_MIN || offset > ST8_MAX) {
			mod_byte = 2;
		}
		int reg0 = op->operands[0].regs[0];
		if (reg0 == -1) {
			mem_ref = 1;
			reg0 = 5;
			mod_byte = 0;
		}
		data[l++] = mod_byte << 6 | modrm << 3 | reg0;
		if (op->operands[0].regs[0] == X86R_ESP) {
			data[l++] = 0x24;
		}
		if (mod_byte || mem_ref) {
			data[l++] = offset;
			if (mod_byte == 2 || mem_ref) {
				data[l++] = offset >> 8;
				data[l++] = offset >> 16;
				data[l++] = offset >> 24;
			}
		}
	} else {
		if (op->operands[1].immediate > 127 && op->operands[0].reg == X86R_EAX) {
			data[l++] = 5 | modrm << 3 | op->operands[0].reg;
		} else {
			mod_byte = 3;
			data[l++] = mod_byte << 6 | modrm << 3 | op->operands[0].reg;
		}

	}

	data[l++] = immediate;
	if ((immediate > 127 || immediate < -128) &&
	    ((op->operands[0].type & OT_DWORD) || (op->operands[0].type & OT_QWORD))) {
		data[l++] = immediate >> 8;
		data[l++] = immediate >> 16;
		data[l++] = immediate >> 24;
	}
	return l;
}

static int process_group_2(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	int modrm = 0;
	int mod_byte = 0;
	int reg0 = 0;

	if (a->bits == 64 && op->operands[0].type & OT_QWORD) { data[l++] = 0x48; }

	if (!strcmp (op->mnemonic, "rol")) {
		modrm = 0;
	} else if (!strcmp (op->mnemonic, "ror")) {
		modrm = 1;
	} else if (!strcmp (op->mnemonic, "rcl")) {
		modrm = 2;
	} else if (!strcmp (op->mnemonic, "rcr")) {
		modrm = 3;
	} else if (!strcmp (op->mnemonic, "shl")) {
		modrm = 4;
	} else if (!strcmp (op->mnemonic, "shr")) {
		modrm = 5;
	} else if (!strcmp (op->mnemonic, "sal")) {
		modrm = 6;
	} else if (!strcmp (op->mnemonic, "sar")) {
		modrm = 7;
	}

	st32 immediate = op->operands[1].immediate * op->operands[1].sign;
	if (immediate > 255 || immediate < -128) {
		eprintf ("Error: Immediate exceeds bounds\n");
		return -1;
	}

	if (op->operands[0].type & (OT_DWORD | OT_QWORD)) {
		if (op->operands[1].type & (OT_GPREG | OT_BYTE)) {
			data[l++] = 0xd3;
		} else if (immediate == 1) {
			data[l++] = 0xd1;
		} else {
			data[l++] = 0xc1;
		}
	} else if (op->operands[0].type & OT_BYTE) {
		if (op->operands[1].type & (OT_GPREG | OT_WORD)) {
			data[l++] = 0xd2;
		} else if (immediate == 1) {
			data[l++] = 0xd0;
		} else {
			data[l++] = 0xc0;
		}
	}
	if (op->operands[0].type & OT_MEMORY) {
		reg0 = op->operands[0].regs[0];
		mod_byte = 0;
	} else {
		reg0 = op->operands[0].reg;
		mod_byte = 3;
	}
	data[l++] = mod_byte << 6 | modrm << 3 | reg0;
	if (immediate != 1 && !(op->operands[1].type & OT_GPREG)) {
		data[l++] = immediate;
	}
	return l;
}

static int process_1byte_op(RAsm *a, ut8 *data, const Opcode *op, int op1) {
	int l = 0;
	int mod_byte = 0;
	int reg = 0;
	int rm = 0;
	int rex = 0;
	int mem_ref = 0;
	st32 offset = 0;
	int ebp_reg = 0;

	if (!op->operands[1].is_good_flag) {
		return -1;
	}

	if (op->operands[0].reg == X86R_AL && op->operands[1].type & OT_CONSTANT) {
		data[l++] = op1 + 4;
		data[l++] = op->operands[1].immediate * op->operands[1].sign;
		return l;
	}

	if (a->bits == 64) {
		if (!(op->operands[0].type & op->operands[1].type)) {
			return -1;
		}
	}

	if (a->bits == 64 &&
		((op->operands[0].type & OT_QWORD) |
		 (op->operands[1].type & OT_QWORD))) {
		if (op->operands[0].extended) {
				rex = 1;
		}
		if (op->operands[1].extended) {
			rex += 4;
		}
		data[l++] = 0x48 | rex;
	}

	if (op->operands[0].type & OT_MEMORY && op->operands[1].type & OT_REGALL) {
		if (a->bits == 64 && (op->operands[0].type & OT_DWORD) &&
		    (op->operands[1].type & OT_DWORD)) {
			data[l++] = 0x67;
		}
		if (op->operands[0].type & OT_BYTE && op->operands[1].type & OT_BYTE) {
			data[l++] = op1;
		} else if (op->operands[0].type & (OT_DWORD | OT_QWORD) &&
			   op->operands[1].type & (OT_DWORD | OT_QWORD)) {
			data[l++] = op1 + 0x1;
		} else {
			eprintf ("Error: mismatched operand sizes\n");
			return -1;
		}
		reg = op->operands[1].reg;
		rm = op->operands[0].regs[0];
		offset = op->operands[0].offset * op->operands[0].offset_sign;
		if (rm == -1) {
			rm = 5;
			mem_ref = 1;
		} else {
			if (offset) {
				mod_byte = 1;
				if (offset < ST8_MIN || offset > ST8_MAX) {
					mod_byte = 2;
				}
			} else if (op->operands[0].regs[1] != X86R_UNDEFINED) {
				rm = 4;
				offset = op->operands[0].regs[1] << 3;
			}
		}
	} else if (op->operands[0].type & OT_REGALL) {
		if (op->operands[1].type & OT_MEMORY) {
			if (op->operands[0].type & OT_BYTE && op->operands[1].type & OT_BYTE) {
				data[l++] = op1 + 0x2;
			} else if (op->operands[0].type & (OT_DWORD | OT_QWORD) &&
					   op->operands[1].type & (OT_DWORD | OT_QWORD)) {
				data[l++] = op1 + 0x3;
			} else {
				eprintf ("Error: mismatched operand sizes\n");
				return -1;
			}
			reg = op->operands[0].reg;
			rm = op->operands[1].regs[0];

			if (op->operands[1].scale[0] > 1) {
				if (op->operands[1].regs[1] != X86R_UNDEFINED) {
					data[l++] = op->operands[0].reg << 3 | 4;
					data[l++] = getsib (op->operands[1].scale[0]) << 6 |
										op->operands[1].regs[0] << 3 |
										op->operands[1].regs[1];
					return l;
				}
				data[l++] = op->operands[0].reg << 3 | 4; // 4 = SIB
				data[l++] = getsib (op->operands[1].scale[0]) << 6 | op->operands[1].regs[0] << 3 | 5;
				data[l++] = op->operands[1].offset * op->operands[1].offset_sign;
				data[l++] = 0;
				data[l++] = 0;
				data[l++] = 0;
				return l;
			}
			offset = op->operands[1].offset * op->operands[1].offset_sign;
			if (offset) {
				mod_byte = 1;
				if (offset < ST8_MIN || offset > ST8_MAX) {
					mod_byte = 2;
				}
			}

		} else if (op->operands[1].type & OT_REGALL) {
			if (op->operands[0].type & OT_BYTE && op->operands[1].type & OT_BYTE) {
				data[l++] = op1;
			} else if (op->operands[0].type & OT_DWORD && op->operands[1].type & OT_DWORD) {
				data[l++] = op1 + 0x1;
			}
			if (a->bits == 64) {
				if (op->operands[0].type & OT_QWORD &&
					op->operands[1].type & OT_QWORD) {
					data[l++] = op1 + 0x1;
				}
			}

			mod_byte = 3;
			reg = op->operands[1].reg;
			rm = op->operands[0].reg;
		}
	}
	if (op->operands[0].regs[0] == X86R_EBP ||
	    op->operands[1].regs[0] == X86R_EBP) {
			//reg += 8;
			ebp_reg = 1;
	}
	data[l++] = mod_byte << 6 | reg << 3 | rm;

	if (op->operands[0].regs[0] == X86R_ESP ||
	    op->operands[1].regs[0] == X86R_ESP) {
			data[l++] = 0x24;
	}
	if (offset || mem_ref || ebp_reg) {
	//if ((mod_byte > 0 && mod_byte < 3) || mem_ref) {
		data[l++] = offset;
		if (mod_byte == 2 || mem_ref) {
			data[l++] = offset >> 8;
			data[l++] = offset >> 16;
			data[l++] = offset >> 24;
		}
	}
	return l;
}

static int opadc(RAsm *a, ut8 *data, const Opcode *op) {
	if (op->operands[1].type & OT_CONSTANT) {
		if (op->operands[0].type & OT_GPREG &&
		    op->operands[0].type & OT_WORD) {
			return process_16bit_group_1 (a, data, op, 0x10);
		}
		if (!is_al_reg (&op->operands[0])) {
			return process_group_1 (a, data, op);
		}
	}
	return process_1byte_op (a, data, op, 0x10);
}

static int opadd(RAsm *a, ut8 *data, const Opcode *op) {
	if (op->operands[1].type & OT_CONSTANT) {
		if (op->operands[0].type & OT_GPREG &&
		    op->operands[0].type & OT_WORD) {
			return process_16bit_group_1 (a, data, op, 0x00);
		}
		if (!is_al_reg (&op->operands[0])) {
			return process_group_1 (a, data, op);
		}
	}
	return process_1byte_op (a, data, op, 0x00);
}

static int opand(RAsm *a, ut8 *data, const Opcode *op) {
	if (op->operands[1].type & OT_CONSTANT) {
		if (op->operands[0].type & OT_GPREG &&
		    op->operands[0].type & OT_WORD) {
			return process_16bit_group_1 (a, data, op, 0x20);
		}
		if (!is_al_reg (&op->operands[0])) {
			return process_group_1 (a, data, op);
		}
	}
	return process_1byte_op (a, data, op, 0x20);
}

static int opcmp(RAsm *a, ut8 *data, const Opcode *op) {
	if (op->operands[1].type & OT_CONSTANT) {
		if (op->operands[0].type & OT_GPREG &&
		    op->operands[0].type & OT_WORD) {
			return process_16bit_group_1 (a, data, op, 0x38);
		}
		if (!is_al_reg (&op->operands[0])) {
			return process_group_1 (a, data, op);
		}
	}
	return process_1byte_op (a, data, op, 0x38);
}

static int opsub(RAsm *a, ut8 *data, const Opcode *op) {
	if (op->operands[1].type & OT_CONSTANT) {
		if (op->operands[0].type & OT_GPREG &&
		    op->operands[0].type & OT_WORD) {
			return process_16bit_group_1 (a, data, op, 0x28);
		}
		if (!is_al_reg (&op->operands[0])) {
			return process_group_1 (a, data, op);
		}
	}
	return process_1byte_op (a, data, op, 0x28);
}

static int opor(RAsm *a, ut8 * data, const Opcode *op) {
	if (op->operands[1].type & OT_CONSTANT) {
		if (op->operands[0].type & OT_GPREG &&
		    op->operands[0].type & OT_WORD) {
			return process_16bit_group_1 (a, data, op, 0x08);
		}
		if (!is_al_reg (&op->operands[0])) {
			return process_group_1 (a, data, op);
		}
	}
	return process_1byte_op (a, data, op, 0x08);
}

static int opxor(RAsm *a, ut8 * data, const Opcode *op) {
	if (op->operands_count < 2) {
		return -1;
	}
	if (op->operands[1].type & OT_CONSTANT) {
		if (op->operands[0].type & OT_GPREG &&
		    op->operands[0].type & OT_WORD) {
			return process_16bit_group_1 (a, data, op, 0x30);
		}
		if (!is_al_reg (&op->operands[0])) {
			return process_group_1 (a, data, op);
		}
	}
	return process_1byte_op (a, data, op, 0x30);
}

static int opnot(RAsm *a, ut8 * data, const Opcode *op)
{
	int l = 0;

	if(op->operands[0].reg == X86R_UNDEFINED)  {
		return -1;
	}

	data[l++] = 0xf7;
	data[l++] = 0xd0 | op->operands[0].reg;

	return l;
}

static int opsbb(RAsm *a, ut8 *data, const Opcode *op) {
	if (op->operands[1].type & OT_CONSTANT) {
		if (op->operands[0].type & OT_GPREG &&
		    op->operands[0].type & OT_WORD) {
			return process_16bit_group_1 (a, data, op, 0x18);
		}
		if (!is_al_reg (&op->operands[0])) {
			return process_group_1 (a, data, op);
		}
	}
	return process_1byte_op (a, data, op, 0x18);
}

static int opbswap(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	if (op->operands[0].type & OT_REGALL) {
		if (op->operands[0].reg == X86R_UNDEFINED) {
			return -1;
		}

		if (op->operands[0].type & OT_QWORD) {
			data[l++] = 0x48;
			data[l++] = 0x0f;
			data[l++] = 0xc8 + op->operands[0].reg;
		} else if (op->operands[0].type & OT_DWORD) {
			data[l++] = 0x0f;
			data[l++] = 0xc8 + op->operands[0].reg;
		} else {
			return -1;
		}
	}
	return l;
}

static int opcall(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	int immediate = 0;
	int offset = 0;
	int mod = 0;

	if (op->operands[0].type & OT_GPREG) {
		if (op->operands[0].reg == X86R_UNDEFINED) {
			return -1;
		}
		if (a->bits == 64 && op->operands[0].extended) {
			data[l++] = 0x41;
		}
		data[l++] = 0xff;
		mod = 3;
		data[l++] = mod << 6 | 2 << 3 | op->operands[0].reg;
	} else if (op->operands[0].type & OT_MEMORY) {
		if (op->operands[0].regs[0] == X86R_UNDEFINED) {
			return -1;
		}
		data[l++] = 0xff;
		offset = op->operands[0].offset * op->operands[0].offset_sign;
		if (offset) {
			mod = 1;
			if (offset > 127 || offset < -128) {
				mod = 2;
			}
		}
		data[l++] = mod << 6 | 2 << 3 | op->operands[0].regs[0];
		if (mod) {
			data[l++] = offset;
			if (mod == 2) {
				data[l++] = offset >> 8;
				data[l++] = offset >> 16;
				data[l++] = offset >> 24;
			}
		}
	} else {
		ut64 instr_offset = a->pc;
		data[l++] = 0xe8;
		immediate = op->operands[0].immediate * op->operands[0].sign;
		immediate -= instr_offset + 5;
		data[l++] = immediate;
		data[l++] = immediate >> 8;
		data[l++] = immediate >> 16;
		data[l++] = immediate >> 24;
	}
	return l;
}

static int opcmov(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	int mod_byte = 0;
	int offset = 0;

	if (op->operands[0].type & OT_MEMORY ||
	    op->operands[1].type & OT_CONSTANT) {
		return -1;
	}

	data[l++] = 0x0f;
	char *cmov = op->mnemonic + 4;
	if (!strcmp (cmov, "o")) {
		data[l++] = 0x40;
	} else if (!strcmp (cmov, "no")) {
		data [l++] = 0x41;
	} else if (!strcmp (cmov, "b") ||
	           !strcmp (cmov, "c") ||
	           !strcmp (cmov, "nae")) {
		data [l++] = 0x42;
	} else if (!strcmp (cmov, "ae") ||
	           !strcmp (cmov, "nb") ||
		   !strcmp (cmov, "nc")) {
		data [l++] = 0x43;
	} else if (!strcmp (cmov, "e") ||
                   !strcmp (cmov, "z")) {
		data [l++] = 0x44;
	} else if (!strcmp (cmov, "ne") ||
	           !strcmp (cmov, "nz")) {
		data [l++] = 0x45;
        } else if (!strcmp (cmov, "be") ||
	           !strcmp (cmov, "na")) {
		data [l++] = 0x46;
        } else if (!strcmp (cmov, "a") ||
	           !strcmp (cmov, "nbe")) {
		data [l++] = 0x47;
	} else if (!strcmp (cmov, "s")) {
		data [l++] = 0x48;
        } else if (!strcmp (cmov, "ns")) {
		data [l++] = 0x49;
        } else if (!strcmp (cmov, "p") ||
	           !strcmp (cmov, "pe")) {
		data [l++] = 0x4a;
        } else if (!strcmp (cmov, "np") ||
	           !strcmp (cmov, "po")) {
		data [l++] = 0x4b;
        } else if (!strcmp (cmov, "l") ||
	           !strcmp (cmov, "nge")) {
		data [l++] = 0x4c;
        } else if (!strcmp (cmov, "ge") ||
	           !strcmp (cmov, "nl")) {
		data [l++] = 0x4d;
        } else if (!strcmp (cmov, "le") ||
	           !strcmp (cmov, "ng")) {
		data [l++] = 0x4e;
        } else if (!strcmp (cmov, "g") ||
	           !strcmp (cmov, "nle")) {
		data [l++] = 0x4f;
        }

	if (op->operands[0].type & OT_REGALL) {
		if (op->operands[1].type & OT_MEMORY) {
			if (op->operands[1].scale[0] > 1) {
				if (op->operands[1].regs[1] != X86R_UNDEFINED) {
					data[l++] = op->operands[0].reg << 3 | 4;
					data[l++] = getsib (op->operands[1].scale[0]) << 6 |
                                                            op->operands[1].regs[0] << 3 |
                                                            op->operands[1].regs[1];
					return l;
				}
				offset = op->operands[1].offset * op->operands[1].offset_sign;

				if (op->operands[1].scale[0] == 2 && offset) {
					data[l++] = 0x40 | op->operands[0].reg << 3 | 4; // 4 = SIB
				} else {
					data[l++] = op->operands[0].reg << 3 | 4; // 4 = SIB
				}


				if (op->operands[1].scale[0] == 2) {
					data[l++] = op->operands[1].regs[0] << 3 | op->operands[1].regs[0];

				} else {
					data[l++] = getsib (op->operands[1].scale[0]) << 6 |
                                                            op->operands[1].regs[0] << 3 | 5;
				}

				if (offset) {
					data[l++] = offset;
					if (offset < ST8_MIN || offset > ST8_MAX) {
						data[l++] = offset >> 8;
						data[l++] = offset >> 16;
						data[l++] = offset >> 24;
					}
				}
				return l;
			}
			if (op->operands[1].regs[1] != X86R_UNDEFINED) {
				data[l++] = op->operands[0].reg << 3 | 4;
				data[l++] = op->operands[1].regs[1] << 3 | op->operands[1].regs[0];
				return l;
			}

			offset = op->operands[1].offset * op->operands[1].offset_sign;
			if (op->operands[1].offset || op->operands[1].regs[0] == X86R_EBP) {
				mod_byte = 1;
			}
			if (offset < ST8_MIN || offset > ST8_MAX) {
				mod_byte = 2;
			}

			data[l++] = mod_byte << 6 | op->operands[0].reg << 3 | op->operands[1].regs[0];

			if (mod_byte) {
				data[l++] = offset;
				if (mod_byte == 2) {
					data[l++] = offset >> 8;
					data[l++] = offset >> 16;
					data[l++] = offset >> 24;
				}
			}
		} else {
			data[l++] = 0xc0 | op->operands[0].reg << 3 | op->operands[1].reg;
		}
	}

	return l;
}

static int opmovx(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	int word = 0;
	char *movx = op->mnemonic + 3;

	if (!(op->operands[0].type & OT_REGTYPE && op->operands[1].type & OT_MEMORY)) {
		return -1;
	}
	if (op->operands[1].type & OT_WORD) {
		word = 1;
	}

	data[l++] = 0x0f;
	if (!strcmp (movx, "zx")) {
		data[l++] = 0xb6 + word;
	} else if (!strcmp (movx, "sx")) {
		data[l++] = 0xbe + word;
	}
	data[l++] = op->operands[0].reg << 3 | op->operands[1].regs[0];
	if (op->operands[1].regs[0] == X86R_ESP) {
		data[l++] = 0x24;
	}

	return l;
}

static int opaam(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	int immediate = op->operands[0].immediate * op->operands[0].sign;
	data[l++] = 0xd4;
	if (immediate == 0) {
		data[l++] = 0x0a;
	} else if (immediate < 256 && immediate > -129) {
		data[l++] = immediate;
	}
	return l;
}

static int opdec(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	if (op->operands[1].type) {
		eprintf ("Error: Invalid operands\n");
		return -1;
	}
	if (op->operands[0].type & OT_BYTE) {
		data[l++] = 0xfe;
		if (op->operands[0].type & OT_MEMORY) {
			data[l++] = 0x1 << 3 | op->operands[0].regs[0];
		} else {
			data[l++] = 0x19 << 3 | op->operands[0].reg;
		}
	} else {
		if (op->operands[0].type & OT_MEMORY) {
			data[l++] = 0xff;
			data[l++] = 0x1 << 3 | op->operands[0].regs[0];
		} else {
			if (a->bits == 32) {
				data[l++] = 0x48 | op->operands[0].reg;
			} else if (a->bits == 64) {
				data[l++] = 0x48;
				data[l++] = 0xff;
				data[l++] = 0xc8 | op->operands[0].reg;
			}
		}
	}
	return l;
}

static int opidiv(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	int offset = 0;
	st64 immediate = 0;

	if ( op->operands[0].type & OT_QWORD ) {
		data[l++] = 0x48;
	}
	switch (op->operands_count) {
	case 1:
		if ( op->operands[0].type & OT_WORD ) {
			data[l++] = 0x66;
		}
		if (op->operands[0].type & OT_BYTE) {
			data[l++] = 0xf6;
		} else {
			data[l++] = 0xf7;
		}
		if (op->operands[0].type & OT_MEMORY) {
			data[l++] = 0x38 | op->operands[0].regs[0];
		} else {
			data[l++] = 0xf8 | op->operands[0].reg;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opdiv(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	int offset = 0;
	st64 immediate = 0;

	if ( op->operands[0].type & OT_QWORD ) {
		data[l++] = 0x48;
	}
	switch (op->operands_count) {
	case 1:
		if ( op->operands[0].type & OT_WORD ) {
			data[l++] = 0x66;
		}
		if (op->operands[0].type & OT_BYTE) {
			data[l++] = 0xf6;
		} else {
			data[l++] = 0xf7;
		}
		if (op->operands[0].type & OT_MEMORY) {
			data[l++] = 0x30 | op->operands[0].regs[0];
		} else {
			data[l++] = 0xf0 | op->operands[0].reg;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opimul(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	int offset = 0;
	st64 immediate = 0;

	if ( op->operands[0].type & OT_QWORD ) {
		data[l++] = 0x48;
	}
	switch (op->operands_count) {
	case 1:
		if ( op->operands[0].type & OT_WORD ) {
			data[l++] = 0x66;
		}
		if (op->operands[0].type & OT_BYTE) {
			data[l++] = 0xf6;
		} else {
			data[l++] = 0xf7;
		}
		if (op->operands[0].type & OT_MEMORY) {
			data[l++] = 0x28 | op->operands[0].regs[0];
		} else {
			data[l++] = 0xe8 | op->operands[0].reg;
		}
		break;
	case 2:
		if (op->operands[0].type & OT_GPREG) {
			if (op->operands[1].type & OT_CONSTANT) {
				if (op->operands[1].immediate == -1) {
					eprintf ("Error: Immediate exceeds max\n");
					return -1;
				}
				immediate = op->operands[1].immediate * op->operands[1].sign;
				if (op->operands[0].type & OT_GPREG) {
					if (immediate >= 128) {
						data[l++] = 0x69;
					} else {
						data[l++] = 0x6b;
					}
					data[l++] = 0xc0 | op->operands[0].reg << 3 | op->operands[0].reg;
					data[l++] = immediate;
					if (immediate >= 128) {
						data[l++] = immediate >> 8;
						data[l++] = immediate >> 16;
						data[l++] = immediate >> 24;
					}
					if (a->bits == 64 && immediate > UT32_MAX) {
						data[l++] = immediate >> 32;
						data[l++] = immediate >> 40;
						data[l++] = immediate >> 48;
						data[l++] = immediate >> 56;
					}
				}
			} else if (op->operands[1].type & OT_MEMORY) {
				data[l++] = 0x0f;
				data[l++] = 0xaf;
				if (op->operands[1].regs[0] != X86R_UNDEFINED) {
					offset = op->operands[1].offset * op->operands[1].offset_sign;
					if (offset != 0) {
						if (offset >= 128 || offset <= -128) {
							data[l] = 0x80;
						} else {
							data[l] = 0x40;
						}
						data[l++] |= op->operands[0].reg << 3 | op->operands[1].regs[0];
						data[l++] = offset;
						if (offset >= 128 || offset <= -128) {
							data[l++] = offset >> 8;
							data[l++] = offset >> 16;
							data[l++] = offset >> 24;
						}
					} else {
						if (op->operands[1].regs[1] != X86R_UNDEFINED) {
							data[l++] = 0x04 | op->operands[0].reg << 3;
							data[l++] = op->operands[1].regs[1] << 3 | op->operands[1].regs[0];
						} else {
							data[l++] = op->operands[0].reg << 3 | op->operands[1].regs[0];
						}
					}
				} else {
					immediate = op->operands[1].immediate * op->operands[1].sign;
					data[l++] = op->operands[0].reg << 3 | 0x5;
					data[l++] = immediate;
					data[l++] = immediate >> 8;
					data[l++] = immediate >> 16;
					data[l++] = immediate >> 24;
				}
			} else if (op->operands[1].type & OT_GPREG) {
				data[l++] = 0x0f;
				data[l++] = 0xaf;
				data[l++] = 0xc0 | op->operands[0].reg << 3 | op->operands[1].reg;
			}
		}
		break;
	case 3:
		if (op->operands[0].type & OT_GPREG &&
		    (op->operands[1].type & OT_GPREG || op->operands[1].type & OT_MEMORY) &&
		    op->operands[2].type & OT_CONSTANT) {
				data[l++] = 0x6b;
				if (op->operands[1].type & OT_MEMORY) {
					if (op->operands[1].regs[1] != X86R_UNDEFINED) {
						data[l++] = 0x04 | op->operands[0].reg << 3;
						data[l++] = op->operands[1].regs[0] |  op->operands[1].regs[1] << 3;
					} else {
						offset = op->operands[1].offset * op->operands[1].offset_sign;
						if (offset != 0) {
							if (offset >= 128 || offset <= -128) {
								data[l] = 0x80;
							} else {
								data[l] = 0x40;
							}
							data[l++] |= op->operands[0].reg << 3;
							data[l++] = offset;
							if (offset >= 128 || offset <= -128) {
								data[l++] = offset >> 8;
								data[l++] = offset >> 16;
								data[l++] = offset >> 24;
							}
						} else {
							data[l++] = 0x00 | op->operands[0].reg << 3 | op->operands[1].regs[0];
						}
					}
				} else {
					data[l++] = 0xc0 | op->operands[0].reg << 3 | op->operands[1].reg;
				}
				immediate = op->operands[2].immediate * op->operands[2].sign;
				data[l++] = immediate;
				if (immediate >= 128 || immediate <= -128) {
					data[l++] = immediate >> 8;
					data[l++] = immediate >> 16;
					data[l++] = immediate >> 24;
				}
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opin(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	st32 immediate = 0;
	if (op->operands[1].reg == X86R_DX) {
		if (op->operands[0].reg == X86R_AL &&
			op->operands[0].type & OT_BYTE) {
			data[l++] = 0xec;
			return l;
		}
		if (op->operands[0].reg == X86R_AX &&
			op->operands[0].type & OT_WORD) {
			data[l++] = 0x66;
			data[l++] = 0xed;
			return l;
		}
		if (op->operands[0].reg == X86R_EAX &&
			op->operands[0].type & OT_DWORD) {
			data[l++] = 0xed;
			return l;
		}
	} else if (op->operands[1].type & OT_CONSTANT) {
		immediate = op->operands[1].immediate * op->operands[1].sign;
		if (immediate > 255 || immediate < -128) {
			return -1;
		}
		if (op->operands[0].reg == X86R_AL &&
			op->operands[0].type & OT_BYTE) {
			data[l++] = 0xe4;
		} else if (op->operands[0].reg == X86R_AX &&
				   op->operands[0].type & OT_BYTE) {
			data[l++] = 0x66;
			data[l++] = 0xe5;
		} else if (op->operands[0].reg == X86R_EAX &&
				   op->operands[0].type & OT_DWORD) {
			data[l++] = 0xe5;
		}
		data[l++] = immediate;
	}
	return l;
}

static int opclflush(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	if (op->operands[0].type & OT_MEMORY) {
		data[l++] = 0x0f;
		data[l++] = 0xae;
		data[l++] = (7 << 3) | op->operands[0].regs[0];
	}
	return l;
}

static int opinc(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	if (a->bits == 64) {
		if (op->operands[0].type & OT_GPREG) {
			data[l++] = 0x48;
			data[l++] = 0xff;
			data[l++] = 0xc0 | op->operands[0].reg;
		}
		return l;
	}
	if (op->operands[0].type & OT_REGALL) {
		if (op->operands[0].type & OT_BYTE) {
			data[l++] = 0xfe;
			data[l++] = 0xc0 | op->operands[0].reg;
		} else {
			data[l++] = 0x40 | op->operands[0].reg;
		}
	} else {
		if (op->operands[0].type & OT_BYTE) {
			data[l++] = 0xfe;
		} else {
			data[l++] = 0xff;
		}
		data[l++] = op->operands[0].regs[0];
	}
	return l;
}

static int opint(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	if (op->operands[0].type & OT_CONSTANT) {
		st32 immediate = op->operands[0].immediate * op->operands[0].sign;
		if (immediate <= 255 && immediate >= -128) {
			data[l++] = 0xcd;
			data[l++] = immediate;
		}
	}
	return l;
}

static int opjc(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	bool is_short = op->is_short;
	int immediate = op->operands[0].immediate * op->operands[0].sign;
	if (is_short && (immediate > ST8_MAX || immediate < ST8_MIN)) {
		return l;
	}
	immediate -= a->pc;
	if (!strcmp (op->mnemonic, "jmp")) {
		if (op->operands[0].type & OT_GPREG) {
			data[l++] = 0xff;
			if (op->operands[0].type & OT_MEMORY) {
				if (op->operands[0].offset) {
					int offset = op->operands[0].offset * op->operands[0].offset_sign;
					if (offset >= 128 || offset <= -129) {
						data[l] = 0xa0;
					} else {
						data[l] = 0x60;
					}
					data[l++] |= op->operands[0].regs[0];
					data[l++] = offset;
					if (op->operands[0].offset >= 0x80) {
						data[l++] = offset >> 8;
						data[l++] = offset >> 16;
						data[l++] = offset >> 24;
					}
				} else {
					data[l++] = 0x20 | op->operands[0].regs[0];
				}
			} else {
				data[l++] = 0xe0 | op->operands[0].reg;
			}
		} else {
			if (-0x80 <= (immediate - 2) && (immediate - 2) <= 0x7f) {
					/* relative byte address */
					data[l++] = 0xeb;
					data[l++] = immediate - 2;
				} else {
					/* relative address */
					immediate -= 5;
					data[l++] = 0xe9;
					data[l++] = immediate;
					data[l++] = immediate >> 8;
					data[l++] = immediate >> 16;
					data[l++] = immediate >> 24;
				}
		}
		return l;
	}
	if (immediate <= 0x81 && immediate > -0x7f) {
		is_short = true;
	}
	if (a->bits == 16 && (immediate > 0x81 || immediate < -0x7e)) {
		data[l++] = 0x66;
		is_short = false;
		immediate --;
	}

	if (!is_short) {data[l++] = 0x0f;}
	if (!strcmp (op->mnemonic, "ja") ||
            !strcmp (op->mnemonic, "jnbe")) {
		data[l++] = 0x87;
	} else if (!strcmp (op->mnemonic, "jae") ||
                   !strcmp (op->mnemonic, "jnb") ||
                   !strcmp (op->mnemonic, "jnc")) {
		data[l++] = 0x83;
	} else if (!strcmp (op->mnemonic, "jz") ||
                   !strcmp (op->mnemonic, "je")) {
		data[l++] = 0x84;
	} else if (!strcmp (op->mnemonic, "jb") ||
                   !strcmp (op->mnemonic, "jnae") ||
                   !strcmp (op->mnemonic, "jc")) {
		data[l++] = 0x82;
	} else if (!strcmp (op->mnemonic, "jbe") ||
                   !strcmp (op->mnemonic, "jna")) {
		data[l++] = 0x86;
	} else if (!strcmp (op->mnemonic, "jg") ||
                   !strcmp (op->mnemonic, "jnle")) {
		data[l++] = 0x8f;
	} else if (!strcmp (op->mnemonic, "jge") ||
                   !strcmp (op->mnemonic, "jnl")) {
		data[l++] = 0x8d;
	} else if (!strcmp (op->mnemonic, "jl") ||
                   !strcmp (op->mnemonic, "jnge")) {
		data[l++] = 0x8c;
	} else if (!strcmp (op->mnemonic, "jle") ||
	           !strcmp (op->mnemonic, "jng")) {
		data[l++] = 0x8e;
	} else if (!strcmp (op->mnemonic, "jne") ||
                   !strcmp (op->mnemonic, "jnz")) {
		data[l++] = 0x85;
	} else if (!strcmp (op->mnemonic, "jno")) {
		data[l++] = 0x81;
	} else if (!strcmp (op->mnemonic, "jnp") ||
                   !strcmp (op->mnemonic, "jpo")) {
		data[l++] = 0x8b;
	} else if (!strcmp (op->mnemonic, "jns")) {
		data[l++] = 0x89;
	} else if (!strcmp (op->mnemonic, "jo")) {
		data[l++] = 0x80;
	} else if (!strcmp (op->mnemonic, "jp") ||
                   !strcmp(op->mnemonic, "jpe")) {
		data[l++] = 0x8a;
	} else if (!strcmp (op->mnemonic, "js") ||
                   !strcmp (op->mnemonic, "jz")) {
		data[l++] = 0x88;
	}
	if (is_short) {
		data[l-1] -= 0x10;
	}

	immediate -= is_short ? 2 : 6;
	data[l++] = immediate;
	if (!is_short) {
		data[l++] = immediate >> 8;
		data[l++] = immediate >> 16;
		data[l++] = immediate >> 24;
	}
	return l;
}

static int oplea(RAsm *a, ut8 *data, const Opcode *op){
	int l =0;
	int mod = 0;
	st32 offset = 0;
	int reg = 0;
	int rm = 0;
	if (op->operands[0].type & OT_REGALL &&
	    op->operands[1].type & OT_MEMORY) {
		if (a->bits == 64) {
			data[l++] = 0x48;
		}
		data[l++] = 0x8d;
		if (op->operands[1].regs[0] == X86R_UNDEFINED) {
			int high = 0xff00 & op->operands[1].offset;
			data[l++] = op->operands[0].reg << 3 | 5;
			data[l++] = op->operands[1].offset;
			data[l++] = high >> 8;
			data[l++] = op->operands[1].offset >> 16;
			data[l++] = op->operands[1].offset >> 24;
			return l;
		} else {
			reg = op->operands[0].reg;
			rm = op->operands[1].regs[0];

			offset = op->operands[1].offset * op->operands[1].offset_sign;
			if (offset != 0 || op->operands[1].regs[0] == X86R_EBP) {
				mod = 1;
				if (offset >= 128 || offset < -128) {
					mod = 2;
				}
				data[l++] = mod << 6 | reg << 3 | rm;
				if (op->operands[1].regs[0] == X86R_ESP) {
					data[l++] = 0x24;
				}
				data[l++] = offset;
				if (mod == 2) {
					data[l++] = offset >> 8;
					data[l++] = offset >> 16;
					data[l++] = offset >> 24;
				}
			} else {
				data[l++] = op->operands[0].reg << 3 | op->operands[1].regs[0];
				if (op->operands[1].regs[0] == X86R_ESP) {
					data[l++] = 0x24;
				}
			}

		}
	}
	return l;
}

static int oples(RAsm *a, ut8* data, const Opcode *op) {
	int l = 0;
	int offset = 0;
	int mod = 0;

	if (op->operands[1].type & OT_MEMORY) {
		data[l++] = 0xc4;
		if (op->operands[1].type & OT_GPREG) {
			offset = op->operands[1].offset * op->operands[1].offset_sign;
			if (offset) {
				mod = 1;
				if (offset > 128 || offset < -128) {
					mod = 2;
				}
			}
			data[l++] = mod << 6 | op->operands[0].reg << 3 | op->operands[1].regs[0];
			if (mod) {
				data[l++] = offset;
				if (mod > 1) {
					data[l++] = offset >> 8;
					data[l++] = offset >> 16;
					data[l++] = offset >> 24;
				}
			}
		} else {
			offset = op->operands[1].offset * op->operands[1].offset_sign;
			data[l++] = 0x05;
			data[l++] = offset;
			data[l++] = offset >> 8;
			data[l++] = offset >> 16;
			data[l++] = offset >> 24;
		}
	}
	return l;
}

static int opmov(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	long offset = 0;
	int mod = 0;
	int base = 0;
	int rex = 0;
	ut64 immediate = 0;
	if (op->operands[1].type & OT_CONSTANT) {
		if (!op->operands[1].is_good_flag) {
			return -1;
		}
		if (op->operands[1].immediate == -1) {
			return -1;
		}
		immediate = op->operands[1].immediate * op->operands[1].sign;
		if (op->operands[0].type & OT_GPREG && !(op->operands[0].type & OT_MEMORY)) {
			if (a->bits == 64 && ((op->operands[0].type & OT_QWORD) | (op->operands[1].type & OT_QWORD))) {
				if (!(op->operands[1].type & OT_CONSTANT) && op->operands[1].extended) {
					data[l++] = 0x49;
				} else {
					data[l++] = 0x48;
				}
			} else if (op->operands[0].extended) {
				data[l++] = 0x41;
			}
			if (op->operands[0].type & OT_WORD) {
				data[l++] = 0x66;
			}
			if (op->operands[0].type & OT_BYTE) {
				data[l++] = 0xb0 | op->operands[0].reg;
				data[l++] = immediate;
			} else {
				if (a->bits == 64 &&
					((op->operands[0].type & OT_QWORD) |
					(op->operands[1].type & OT_QWORD)) &&
					immediate < UT32_MAX) {
						data[l++] = 0xc7;
				 		data[l++] = 0xc0 | op->operands[0].reg;
				} else {
					data[l++] = 0xb8 | op->operands[0].reg;
				}
				data[l++] = immediate;
				data[l++] = immediate >> 8;
				if (!(op->operands[0].type & OT_WORD)) {
					data[l++] = immediate >> 16;
					data[l++] = immediate >> 24;
				}
				if (a->bits == 64 && immediate > UT32_MAX) {
					data[l++] = immediate >> 32;
					data[l++] = immediate >> 40;
					data[l++] = immediate >> 48;
					data[l++] = immediate >> 56;
				}
			}
		} else if (op->operands[0].type & OT_MEMORY) {
			if (a->bits == 64) {
				if (op->operands[0].extended) {
					if (op->operands[0].reg < 0) {
						return -1;
					}
					data[l++] = 0x41;
					data[l++] = 0xc6;
					// For r12 and r13
					if (op->operands[0].reg == 4) {
						data[l++] = 0x04;
						data[l++] = 0x24;
					} else if (op->operands[0].reg == 5) {
						data[l++] = 0x45;
						data[l++] = 0x00;
					} else {
						data[l++] = op->operands[0].reg;
					}
					data[l++] = op->operands[1].immediate;
					return l;
				} else if (!(op->operands[0].type & OT_BYTE) &&
				           !(op->operands[0].type & OT_QWORD)) {
					data[l++] = 0x67;
				} else if (op->operands[0].type & OT_QWORD) {
					// The operand is a QWORD PTR memory access, so we want a
					// REX prefix with a set W bit.
					data[l++] = 0x48;
				}
			}
			if (op->operands[0].type & (OT_DWORD | OT_QWORD)) {
				data[l++] = 0xc7;
			} else if (op->operands[0].type & OT_BYTE) {
				data[l++] = 0xc6;
			} else if (op->operands[0].type & OT_WORD) {
				data[l++] = 0x66;
			}
			offset = op->operands[0].offset * op->operands[0].offset_sign;

			if (op->operands[0].scale[0] > 1) {
				int s = op->operands[0].scale[0];
				// Check for power of 2 as valid sib
				if (!(s & (s - 1))) {
					return -1;
				}
				data[l++] = 0x04;
				data[l++] = getsib (s) << 6 | op->operands[0].regs[0] << 3 | 5;
				data[l++] = offset;
				data[l++] = offset >> 8;
				data[l++] = offset >> 16;
				data[l++] = offset >> 24;
				data[l++] = immediate;
				if (op->operands[0].type & (OT_DWORD | OT_QWORD)) {
					data[l++] = immediate >> 8;
					data[l++] = immediate >> 16;
					data[l++] = immediate >> 24;
				}
				return l;
			}

			if (offset) {
				mod = (offset > 128 || offset < -129) ? 0x2 : 0x1;
			}

			//if (op->operands[0].regs[0] == X86R_EBP) mod = 0x2;
			if (op->operands[0].regs[1] != X86R_UNDEFINED) {
				data[l++] = 0x44;
				if (op->operands[0].regs[1] == X86R_ESP) {
					data[l++] = 0x4 | op->operands[0].regs[0] << 3;
				} else {
					data[l++] = op->operands[0].regs[1] << 3 | op->operands[0].regs[0];
				}
			} else {
				if (op->operands[0].regs[0] == X86R_UNDEFINED) {
					data[l++] = 0x5;
					mod = 0x02;
				} else if (op->operands[0].scale[0] < 2) {
					data[l++] = mod << 6 | op->operands[0].regs[0];
				}

				if (op->operands[0].regs[0] == X86R_ESP) {
					data[l++] = 0x24;
				}
				if (op->operands[0].regs[0] == X86R_EBP && !offset) {
					data[l++] = 0x00;
				}
			}
			if (offset) {
				data[l++] = offset;
			}
			if (mod == 2) {
				data[l++] = offset >> 8;
				data[l++] = offset >> 16;
				data[l++] = offset >> 24;
			}
			data[l++] = immediate;
			if (op->operands[0].type & (OT_DWORD | OT_QWORD)) {
				data[l++] = immediate >> 8;
				data[l++] = immediate >> 16;
				data[l++] = immediate >> 24;
			}
		}
	} else if (op->operands[1].type & OT_REGALL &&
			 !(op->operands[1].type & OT_MEMORY)) {
		if (op->operands[0].type & OT_CONSTANT) {
			return -1;
		}
		if (op->operands[0].type & OT_REGTYPE & OT_SEGMENTREG &&
		    op->operands[1].type & OT_REGTYPE & OT_SEGMENTREG) {
				return -1;
		}
		// Check reg sizes match
		if (op->operands[0].type & OT_REGTYPE && op->operands[1].type & OT_REGTYPE) {
			if (!((op->operands[0].type & ALL_SIZE) &
			(op->operands[1].type & ALL_SIZE))) {
				return -1;
			}
		}

		if (a->bits == 64) {
			if (op->operands[0].extended) {
				rex = 1;
			}
			if (op->operands[1].extended) {
				rex += 4;
			}
			if (op->operands[1].type & OT_QWORD) {
				if (!(op->operands[0].type & OT_QWORD)) {
					data[l++] = 0x67;
					data[l++] = 0x48;
				}
			}
			if (op->operands[1].type & OT_QWORD &&
				op->operands[0].type & OT_QWORD) {
				data[l++] = 0x48 | rex;
			}
		} else if (op->operands[0].extended && op->operands[1].extended) {
			data[l++] = 0x45;
		}
		offset = op->operands[0].offset * op->operands[0].offset_sign;
		if (op->operands[1].type & OT_REGTYPE & OT_SEGMENTREG) {
			data[l++] = 0x8c;
		} else {
			if (op->operands[0].type & OT_WORD) {
				data[l++] = 0x66;
			}
			data[l++] = (op->operands[0].type & OT_BYTE) ? 0x88 : 0x89;
		}

		if (op->operands[0].scale[0] > 1) {
				data[l++] = op->operands[1].reg << 3 | 4;
				if (op->operands[0].scale[0] > 2) {
					data[l++] = getsib (op->operands[0].scale[0]) << 6 |
										op->operands[0].regs[0] << 3 | 5;

					data[l++] = offset;
					data[l++] = offset >> 8;
					data[l++] = offset >> 16;
					data[l++] = offset >> 24;
				}
				return l;
			}

		if (!(op->operands[0].type & OT_MEMORY)) {
			if (op->operands[0].reg == X86R_UNDEFINED ||
				op->operands[1].reg == X86R_UNDEFINED) {
				return -1;
			}
			mod = 0x3;
			data[l++] = mod << 6 | op->operands[1].reg << 3 | op->operands[0].reg;
		} else if (op->operands[0].regs[0] == X86R_UNDEFINED) {
			data[l++] = op->operands[1].reg << 3 | 0x5;
			data[l++] = offset;
			data[l++] = offset >> 8;
			data[l++] = offset >> 16;
			data[l++] = offset >> 24;
		} else {
			if (op->operands[0].type & OT_MEMORY) {
				if (op->operands[0].regs[1] != X86R_UNDEFINED) {
					data[l++] = op->operands[1].reg << 3 | 0x4;
					data[l++] = op->operands[0].regs[1] << 3 | op->operands[0].regs[0];
					return l;
				}
				if (offset) {
					mod = (offset > 128 || offset < -129) ? 0x2 : 0x1;
				}
				if (op->operands[0].regs[0] == X86R_EBP) {
					mod = 0x2;
				}
				data[l++] = mod << 6 | op->operands[1].reg << 3 | op->operands[0].regs[0];
				if (op->operands[0].regs[0] == X86R_ESP) {
					data[l++] = 0x24;
				}
				if (offset) {
					data[l++] = offset;
				}
				if (mod == 2) {
					// warning C4293: '>>': shift count negative or too big, undefined behavior
					data[l++] = offset >> 8;
					data[l++] = offset >> 16;
					data[l++] = offset >> 24;
				}
			}
		}
	} else if (op->operands[1].type & OT_MEMORY) {
		if (op->operands[0].type & OT_MEMORY) {
			return -1;
		}
		offset = op->operands[1].offset * op->operands[1].offset_sign;
		if (op->operands[0].reg == X86R_EAX && op->operands[1].regs[0] == X86R_UNDEFINED) {
			if (a->bits == 64) {
				data[l++] = 0x48;
			}
			if (op->operands[0].type & OT_BYTE) {
				data[l++] = 0xa0;
			} else {
				data[l++] = 0xa1;
			}
			data[l++] = offset;
			data[l++] = offset >> 8;
			data[l++] = offset >> 16;
			data[l++] = offset >> 24;
			if (a->bits == 64) {
				data[l++] = offset >> 32;
				data[l++] = offset >> 40;
				data[l++] = offset >> 48;
				data[l++] = offset >> 54;
			}
			return l;
		}
		if (op->operands[0].type & OT_BYTE && a->bits == 64 && op->operands[1].regs[0]) {
			if (op->operands[1].regs[0] >= X86R_R8 &&
			    op->operands[0].reg < 4) {
				data[l++] = 0x41;
				data[l++] = 0x8a;
				data[l++] = op->operands[0].reg << 3 | (op->operands[1].regs[0] - 8);
				return l;
			}
			return -1;
		}

		if (op->operands[1].type & OT_REGTYPE & OT_SEGMENTREG) {
			if (op->operands[1].scale[0] == 0) return -1;
			data[l++] = SEG_REG_PREFIXES[op->operands[1].regs[0]];
			data[l++] = 0x8b;
			data[l++] = op->operands[0].reg << 3 | 0x5;
			data[l++] = offset;
			data[l++] = offset >> 8;
			data[l++] = offset >> 16;
			data[l++] = offset >> 24;
			return l;
		}

		if (a->bits == 64) {
			if (op->operands[0].type & OT_QWORD) {
				if (!(op->operands[1].type & OT_QWORD)) {
					if (op->operands[1].regs[0] != -1) {
						data[l++] = 0x67;
					}
					data[l++] = 0x48;
				}
			} else if (!(op->operands[1].type & OT_QWORD)) {
				data[l++] = 0x67;
			}
			if (op->operands[1].type & OT_QWORD &&
				op->operands[0].type & OT_QWORD) {
				data[l++] = 0x48;
			}
		}

		if (op->operands[0].type & OT_WORD) {
			data[l++] = 0x66;
			data[l++] = op->operands[1].type & OT_BYTE ? 0x8a : 0x8b;
		} else {
			data[l++] = (op->operands[1].type & OT_BYTE ||
				op->operands[0].type & OT_BYTE) ?
				0x8a : 0x8b;
		}

		if (op->operands[1].regs[0] == X86R_UNDEFINED) {
			if (a->bits == 64) {
				data[l++] = op->operands[0].reg << 3 | 0x4;
				data[l++] = 0x25;
			} else {
				data[l++] = op->operands[0].reg << 3 | 0x5;
			}
			data[l++] = offset;
			data[l++] = offset >> 8;
			data[l++] = offset >> 16;
			data[l++] = offset >> 24;
		} else {
			if (op->operands[1].scale[0] > 1) {
				data[l++] = op->operands[0].reg << 3 | 4;

				if (op->operands[1].scale[0] > 2) {
					base = 5;
				}
				if (base) {
					data[l++] = getsib (op->operands[1].scale[0]) << 6 | op->operands[1].regs[0] << 3 | base;
				} else {
					data[l++] = getsib (op->operands[1].scale[0]) << 3 | op->operands[1].regs[0];
				}
				if (offset || base) {
					data[l++] = offset;
					data[l++] = offset >> 8;
					data[l++] = offset >> 16;
					data[l++] = offset >> 24;
				}
				return l;
			}
			if (op->operands[1].regs[1] != X86R_UNDEFINED) {
				data[l++] = op->operands[0].reg << 3 | 0x4;
				data[l++] = op->operands[1].regs[1] << 3 | op->operands[1].regs[0];
				return l;
			}

			if (offset || op->operands[1].regs[0] == X86R_EBP) {
				mod = 0x2;
				if (op->operands[1].offset > 127) {
					mod = 0x4;
				}
			}
			if (a->bits == 64 && offset && op->operands[0].type & OT_QWORD) {
				if (op->operands[1].regs[0] == X86R_RIP) {
					data[l++] = 0x5;
				} else {
					if (op->operands[1].offset > 127) {
						data[l++] = 0x80 | op->operands[0].reg << 3 | op->operands[1].regs[0];
					} else {
						data[l++] = 0x40 | op->operands[1].regs[0];
					}
				}
				if (op->operands[1].offset > 127) {
					mod = 0x1;
				}
			} else {
				if (op->operands[1].regs[0] == X86R_EIP) {
					data[l++] = 0x0d;
				} else {
					data[l++] = mod << 5 | op->operands[0].reg << 3 | op->operands[1].regs[0];
				}
			}
			if (op->operands[1].regs[0] == X86R_ESP) {
				data[l++] = 0x24;
			}
			if (mod >= 0x2) {
				data[l++] = offset;
				if (op->operands[1].offset > 128) {
					data[l++] = offset >> 8;
					data[l++] = offset >> 16;
					data[l++] = offset >> 24;
				}
			} else if (a->bits == 64 && offset) {
				data[l++] = offset;
				if (op->operands[1].offset > 127) {
					data[l++] = offset >> 8;
					data[l++] = offset >> 16;
					data[l++] = offset >> 24;
				}
			}
		}
	}
	return l;
}

static int opmul(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	int offset = 0;
	st64 immediate = 0;

	if ( op->operands[0].type & OT_QWORD ) {
		data[l++] = 0x48;
	}
	switch (op->operands_count) {
	case 1:
		if ( op->operands[0].type & OT_WORD ) {
			data[l++] = 0x66;
		}
		if (op->operands[0].type & OT_BYTE) {
			data[l++] = 0xf6;
		} else {
			data[l++] = 0xf7;
		}
		if (op->operands[0].type & OT_MEMORY) {
			data[l++] = 0x20 | op->operands[0].regs[0];
		} else {
			data[l++] = 0xe0 | op->operands[0].reg;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int oppop(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	int offset = 0;
	int mod = 0;
	if (op->operands[0].type & OT_GPREG) {
		if (op->operands[0].type & OT_MEMORY) {
			return -1;
		}
		if (op->operands[0].type & OT_REGTYPE & OT_SEGMENTREG) {
			ut8 base;
			if (op->operands[0].reg & X86R_FS) {
				data[l++] = 0x0f;
				base = 0x81;
			} else {
				base = 0x7;
			}
			data[l++] = base + (8 * op->operands[0].reg);
		} else {
			ut8 base = 0x58;
			data[l++] = base + op->operands[0].reg;
		}
	} else if (op->operands[0].type & OT_MEMORY) {
		data[l++] = 0x8f;
		offset = op->operands[0].offset * op->operands[0].offset_sign;
		if (offset != 0 || op->operands[0].regs[0] == X86R_EBP) {
			mod = 1;
			if (offset >= 128 || offset < -128) {
				mod = 2;
			}
			data[l++] = mod << 6 | op->operands[0].regs[0];
			if (op->operands[0].regs[0] == X86R_ESP) {
				data[l++] = 0x24;
			}
			data[l++] = offset;
			if (mod == 2) {
				data[l++] = offset >> 8;
				data[l++] = offset >> 16;
				data[l++] = offset >> 24;
			}
		} else {
			data[l++] = op->operands[0].regs[0];
			if (op->operands[0].regs[0] == X86R_ESP) {
				data[l++] = 0x24;
			}
		}

	}
	return l;
}

static int oppush(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	int mod = 0;
	st32 immediate = 0;;
	st32 offset = 0;
	if (op->operands[0].type & OT_GPREG &&
	    !(op->operands[0].type & OT_MEMORY)) {
		if (op->operands[0].type & OT_REGTYPE & OT_SEGMENTREG) {
			ut8 base;
			if (op->operands[0].reg & X86R_FS) {
				data[l++] = 0x0f;
				base = 0x80;
			} else {
				base = 0x6;
			}
			data[l++] = base + (8 * op->operands[0].reg);
		} else {
			if (op->operands[0].extended && a->bits == 64) {
				data[l++] = 0x41;
			}
			ut8 base = 0x50;
			data[l++] = base + op->operands[0].reg;
		}
	} else if (op->operands[0].type & OT_MEMORY) {
		data[l++] = 0xff;
		offset = op->operands[0].offset * op->operands[0].offset_sign;
		mod = 0;
		if (offset != 0 || op->operands[0].regs[0] == X86R_EBP) {
			mod = 1;
			if (offset >= 128 || offset < -128) {
				mod = 2;
			}
			data[l++] = mod << 6 | 6 << 3 | op->operands[0].regs[0];
			if (op->operands[0].regs[0] == X86R_ESP) {
				data[l++] = 0x24;
			}
			data[l++] = offset;
			if (mod == 2) {
				data[l++] = offset >> 8;
				data[l++] = offset >> 16;
				data[l++] = offset >> 24;
			}
		} else {
			mod = 3;
			data[l++] = mod << 4 | op->operands[0].regs[0];
			if (op->operands[0].regs[0] == X86R_ESP) {
				data[l++] = 0x24;
			}
		}
	} else {
		immediate = op->operands[0].immediate * op->operands[0].sign;
		if (immediate >= 128 || immediate < -128) {
			data[l++] = 0x68;
			data[l++] = immediate;
			data[l++] = immediate >> 8;
			data[l++] = immediate >> 16;
			data[l++] = immediate >> 24;
		} else {
			data[l++] = 0x6a;
			data[l++] = immediate;
		}
	}
	return l;
}

static int opout(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	st32 immediate = 0;
	if (op->operands[0].reg == X86R_DX) {
		if (op->operands[1].reg == X86R_AL && op->operands[1].type & OT_BYTE) {
			data[l++] = 0xec;
			return l;
		}
		if (op->operands[1].reg == X86R_AX && op->operands[1].type & OT_WORD) {
			data[l++] = 0x66;
			data[l++] = 0xed;
			return l;
		}
		if (op->operands[1].reg == X86R_EAX && op->operands[1].type & OT_DWORD) {
			data[l++] = 0xed;
			return l;
		}
	} else if (op->operands[0].type & OT_CONSTANT) {
		immediate = op->operands[0].immediate * op->operands[0].sign;
		if (immediate > 255 || immediate < -128) {
			return -1;
		}
		if (op->operands[0].reg == X86R_AL && op->operands[1].type & OT_BYTE) {
			data[l++] = 0xe6;
		} else if (op->operands[0].reg == X86R_AX && op->operands[0].type & OT_BYTE) {
			data[l++] = 0x66;
			data[l++] = 0xe7;
		} else if (op->operands[1].reg == X86R_EAX && op->operands[1].type & OT_DWORD) {
			data[l++] = 0xe7;
		}
		data[l++] = immediate;
	}
	return l;
}

static int oploop(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	data[l++] = 0xe2;
	st8 delta = op->operands[0].immediate - a->pc - 2;
	data[l++] = (ut8)delta;
	return l;
}

static int opret(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	int immediate = 0;
	if (a->bits == 16) {
		data[l++] = 0xc3;
		return l;
	}
	if (op->operands[0].type == OT_UNKNOWN) {
		data[l++] = 0xc3;
	} else if (op->operands[0].type & (OT_CONSTANT | OT_WORD)) {
		data[l++] = 0xc2;
		immediate = op->operands[0].immediate * op->operands[0].sign;
		data[l++] = immediate;
		data[l++] = immediate << 8;
	}
	return l;
}

static int opretf(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	st32 immediate = 0;
	if (op->operands[0].type & OT_CONSTANT) {
		immediate = op->operands[0].immediate * op->operands[0].sign;
		data[l++] = 0xca;
		data[l++] = immediate;
		data[l++] = immediate >> 8;
	} else if (op->operands[0].type == OT_UNKNOWN) {
		data[l++] = 0xcb;
	}
	return l;
}

static int opstos(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	if (!strcmp(op->mnemonic, "stosw")) {
		data[l++] = 0x66;
	}
	if (!strcmp(op->mnemonic, "stosb")) {
		data[l++] = 0xaa;
	} else if (!strcmp(op->mnemonic, "stosw")) {
		data[l++] = 0xab;
	} else if (!strcmp(op->mnemonic, "stosd")) {
		data[l++] = 0xab;
	}
	return l;
}

static int opset(RAsm *a, ut8 *data, const Opcode *op) {
	if (!(op->operands[0].type & (OT_GPREG | OT_BYTE))) {return -1;}
	int l = 0;
	int mod = 0;
	int reg = op->operands[0].regs[0];

	data[l++] = 0x0f;
	if (!strcmp (op->mnemonic, "seto")) {
		data[l++] = 0x90;
	} else if (!strcmp (op->mnemonic, "setno")) {
		data[l++] = 0x91;
	} else if (!strcmp (op->mnemonic, "setb") ||
			  !strcmp (op->mnemonic, "setnae") ||
			  !strcmp (op->mnemonic, "setc")) {
		data[l++] = 0x92;
	} else if (!strcmp (op->mnemonic, "setnb") ||
			   !strcmp (op->mnemonic, "setae") ||
			   !strcmp (op->mnemonic, "setnc")) {
		data[l++] = 0x93;
	} else if (!strcmp (op->mnemonic, "setz") ||
			   !strcmp (op->mnemonic, "sete")) {
		data[l++] = 0x94;
	} else if (!strcmp (op->mnemonic, "setnz") ||
			   !strcmp (op->mnemonic, "setne")) {
		data[l++] = 0x95;
	} else if (!strcmp (op->mnemonic, "setbe") ||
			   !strcmp (op->mnemonic, "setna")) {
		data[l++] = 0x96;
	} else if (!strcmp (op->mnemonic, "setnbe") ||
			   !strcmp (op->mnemonic, "seta")) {
		data[l++] = 0x97;
	} else if (!strcmp (op->mnemonic, "sets")) {
		data[l++] = 0x98;
	} else if (!strcmp (op->mnemonic, "setns")) {
		data[l++] = 0x99;
	} else if (!strcmp (op->mnemonic, "setp") ||
			   !strcmp (op->mnemonic, "setpe")) {
		data[l++] = 0x9a;
	} else if (!strcmp (op->mnemonic, "setnp") ||
			   !strcmp (op->mnemonic, "setpo")) {
		data[l++] = 0x9b;
	} else if (!strcmp (op->mnemonic, "setl") ||
			   !strcmp (op->mnemonic, "setnge")) {
		data[l++] = 0x9c;
	} else if (!strcmp (op->mnemonic, "setnl") ||
			   !strcmp (op->mnemonic, "setge")) {
		data[l++] = 0x9d;
	} else if (!strcmp (op->mnemonic, "setle") ||
			   !strcmp (op->mnemonic, "setng")) {
		data[l++] = 0x9e;
	} else if (!strcmp (op->mnemonic, "setnle") ||
			   !strcmp (op->mnemonic, "setg")) {
		data[l++] = 0x9f;
	} else {
		return -1;
	}
	if (!(op->operands[0].type & OT_MEMORY)) {
		mod = 3;
		reg = op->operands[0].reg;
	}
	data[l++] = mod << 6 | reg;
	return l;
}

static int optest(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	if (!op->operands[0].type || !op->operands[1].type) {
		eprintf ("Error: Invalid operands\n");
		return -1;
	}
	if (a->bits == 64) {
		if (op->operands[0].type & OT_MEMORY ||
			op->operands[1].type & OT_MEMORY) {
			data[l++] = 0x67;
		}
		if (op->operands[0].type & OT_QWORD &&
			op->operands[1].type & OT_QWORD) {
			if (op->operands[0].extended &&
			    op->operands[1].extended) {
					data[l++] = 0x4d;
				} else {
					data[l++] = 0x48;
				}
		}
	}

	if (op->operands[1].type & OT_CONSTANT) {
		if (op->operands[0].type & OT_BYTE) {
			data[l++] = 0xf6;
			data[l++] = op->operands[0].regs[0];
			data[l++] = op->operands[1].reg;
			return l;
		}
		data[l++] = 0xf7;
		if (op->operands[0].type & OT_MEMORY) {
			data[l++] = 0x00 | op->operands[0].regs[0];
		} else {
			data[l++] = 0xc0 | op->operands[0].reg;
		}
		data[l++] = op->operands[1].reg >> 0;
		data[l++] = op->operands[1].reg >> 8;
		data[l++] = op->operands[1].reg >> 16;
		data[l++] = op->operands[1].reg >> 24;
		return l;
	}
	if (op->operands[0].type & OT_BYTE ||
		op->operands[1].type & OT_BYTE) {
		data[l++] = 0x84;
	} else {
		data[l++] = 0x85;
	}
	if (op->operands[0].type & OT_MEMORY) {
		data[l++] = 0x00 | op->operands[1].reg << 3 | op->operands[0].regs[0];
	} else {
		if (op->operands[1].type & OT_MEMORY) {
			data[l++] = 0x00 | op->operands[0].reg << 3 | op->operands[1].regs[0];
		} else {
			data[l++] = 0xc0 | op->operands[1].reg << 3 | op->operands[0].reg;
		}
	}
	return l;
}

static int opxchg(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	int mod_byte = 0;
	int reg = 0;
	int rm = 0;
	st32 offset = 0;

	if (op->operands[0].type & OT_MEMORY || op->operands[1].type & OT_MEMORY) {
		data[l++] = 0x87;
		if (op->operands[0].type & OT_MEMORY) {
			rm = op->operands[0].regs[0];
			offset = op->operands[0].offset * op->operands[0].offset_sign;
			reg = op->operands[1].reg;
		} else if (op->operands[1].type & OT_MEMORY) {
			rm = op->operands[1].regs[0];
			offset = op->operands[1].offset * op->operands[1].offset_sign;
			reg = op->operands[0].reg;
		}
		if (offset) {
			mod_byte = 1;
			if (offset < ST8_MIN || offset > ST8_MAX) {
				mod_byte = 2;
			}
		}
	} else {
		if (op->operands[0].reg == X86R_EAX &&
			op->operands[1].type & OT_GPREG) {
			data[l++] = 0x90 + op->operands[1].reg;
			return l;
		} else if (op->operands[1].reg == X86R_EAX &&
				   op->operands[0].type & OT_GPREG) {
			data[l++] = 0x90 + op->operands[0].reg;
			return l;
		} else if (op->operands[0].type & OT_GPREG &&
				   op->operands[1].type & OT_GPREG) {
			mod_byte = 3;
			data[l++] = 0x87;
			reg = op->operands[1].reg;
			rm = op->operands[0].reg;
		}
	}
	data[l++] = mod_byte << 6 | reg << 3 | rm;
	if (mod_byte > 0 && mod_byte < 3) {
		data[l++] = offset;
		if (mod_byte == 2) {
			data[l++] = offset >> 8;
			data[l++] = offset >> 16;
			data[l++] = offset >> 24;
		}
	}
	return l;
}

static int opcdqe(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	if (a->bits == 64) {
		data[l++] = 0x48;
	}
	data[l++] = 0x98;
	return l;
}

static int opfcmov(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	char* fcmov = op->mnemonic + strlen("fcmov");
	switch (op->operands_count) {
	case 2:
		if ( op->operands[0].type & OT_FPUREG & ~OT_REGALL && op->operands[0].reg == 0 &&
		     op->operands[1].type & OT_FPUREG & ~OT_REGALL ) {
			if ( !strcmp( fcmov, "b" ) ) {
				data[l++] = 0xda;
				data[l++] = 0xc0 | op->operands[1].reg;
			} else if ( !strcmp( fcmov, "e" ) ) {
				data[l++] = 0xda;
				data[l++] = 0xc8 | op->operands[1].reg;
			} else if ( !strcmp( fcmov, "be" ) ) {
				data[l++] = 0xda;
				data[l++] = 0xd0 | op->operands[1].reg;
			} else if ( !strcmp( fcmov, "u" ) ) {
				data[l++] = 0xda;
				data[l++] = 0xd8 | op->operands[1].reg;
			} else if ( !strcmp( fcmov, "nb" ) ) {
				data[l++] = 0xdb;
				data[l++] = 0xc0 | op->operands[1].reg;
			} else if ( !strcmp( fcmov, "ne" ) ) {
				data[l++] = 0xdb;
				data[l++] = 0xc8 | op->operands[1].reg;
			} else if ( !strcmp( fcmov, "nbe" ) ) {
				data[l++] = 0xdb;
				data[l++] = 0xd0 | op->operands[1].reg;
			} else if ( !strcmp( fcmov, "nu" ) ) {
				data[l++] = 0xdb;
				data[l++] = 0xd8 | op->operands[1].reg;
			} else {
				return -1;
			}
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opffree(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_FPUREG & ~OT_REGALL)  {
			data[l++] = 0xdd;
			data[l++] = 0xc0 | op->operands[0].reg;
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfrstor(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if (op->operands[0].type & OT_MEMORY) {
			data[l++] = 0xdd;
			data[l++] = 0x20 | op->operands[0].regs[0];
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfxch(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 0:
		data[l++] = 0xd9;
		data[l++] = 0xc9;
		break;
	case 1:
		if (op->operands[0].type & OT_FPUREG & ~OT_REGALL) {
			data[l++] = 0xd9;
			data[l++] = 0xc8 | op->operands[0].reg;
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfucom(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if ( op->operands[0].type & OT_FPUREG & ~OT_REGALL ) {
			data[l++] = 0xdd;
			data[l++] = 0xe0 | op->operands[0].reg;
		} else {
			return -1;
		}
		break;
	case 0:
		data[l++] = 0xdd;
		data[l++] = 0xe1;
		break;
	default:
		return -1;
	}
	return l;
}

static int opfucomp(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if ( op->operands[0].type & OT_FPUREG & ~OT_REGALL ) {
			data[l++] = 0xdd;
			data[l++] = 0xe8 | op->operands[0].reg;
		} else {
			return -1;
		}
		break;
	case 0:
		data[l++] = 0xdd;
		data[l++] = 0xe9;
		break;
	default:
		return -1;
	}
	return l;
}

static int opfaddp(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 2:
		if ( op->operands[0].type & OT_FPUREG & ~OT_REGALL &&
		     op->operands[1].type & OT_FPUREG & ~OT_REGALL && op->operands[1].reg == 0 ) {
			data[l++] = 0xde;
			data[l++] = 0xc0 | op->operands[0].reg;
		} else {
			return -1;
		}
		break;
	case 0:
		data[l++] = 0xde;
		data[l++] = 0xc1;
		break;
	default:
		return -1;
	}
	return l;
}

static int opfiadd(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if ( op->operands[0].type & OT_MEMORY ) {
			if ( op->operands[0].type & OT_WORD ) {
				data[l++] = 0xde;
				data[l++] = 0x00 | op->operands[0].regs[0];
			} else if ( op->operands[0].type & OT_DWORD ) {
				data[l++] = 0xda;
				data[l++] = 0x00 | op->operands[0].regs[0];
			} else {
				return -1;
			}
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfadd(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if ( op->operands[0].type & OT_MEMORY ) {
			if ( op->operands[0].type & OT_QWORD ) {
				data[l++] = 0xdc;
				data[l++] = 0x00 | op->operands[0].regs[0];
			} else if ( op->operands[0].type & OT_DWORD ) {
				data[l++] = 0xd8;
				data[l++] = 0x00 | op->operands[0].regs[0];
			} else {
				return -1;
			}
		} else {
			return -1;
		}
		break;
	case 2:
		if ( op->operands[0].type & OT_FPUREG & ~OT_REGALL && op->operands[0].reg == 0 &&
		     op->operands[1].type & OT_FPUREG & ~OT_REGALL ) {
			data[l++] = 0xd8;
			data[l++] = 0xc0 | op->operands[1].reg;
		} else if ( op->operands[0].type & OT_FPUREG & ~OT_REGALL &&
			    op->operands[1].type & OT_FPUREG & ~OT_REGALL && op->operands[1].reg == 0 ) {
			data[l++] = 0xdc;
			data[l++] = 0xc0 | op->operands[0].reg;
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opficom(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if ( op->operands[0].type & OT_MEMORY ) {
			if ( op->operands[0].type & OT_WORD ) {
				data[l++] = 0xde;
				data[l++] = 0x10 | op->operands[0].regs[0];
			} else if ( op->operands[0].type & OT_DWORD ) {
				data[l++] = 0xda;
				data[l++] = 0x10 | op->operands[0].regs[0];
			} else {
				return -1;
			}
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opficomp(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if ( op->operands[0].type & OT_MEMORY ) {
			if ( op->operands[0].type & OT_WORD ) {
				data[l++] = 0xde;
				data[l++] = 0x18 | op->operands[0].regs[0];
			} else if ( op->operands[0].type & OT_DWORD ) {
				data[l++] = 0xda;
				data[l++] = 0x18 | op->operands[0].regs[0];
			} else {
				return -1;
			}
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfild(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if ( op->operands[0].type & OT_MEMORY ) {
			if ( op->operands[0].type & OT_WORD ) {
				data[l++] = 0xdf;
				data[l++] = 0x00 | op->operands[0].regs[0];
			} else if ( op->operands[0].type & OT_DWORD ) {
				data[l++] = 0xdb;
				data[l++] = 0x00 | op->operands[0].regs[0];
			} else if ( op->operands[0].type & OT_QWORD ) {
				data[l++] = 0xdf;
				data[l++] = 0x28 | op->operands[0].regs[0];
			} else {
				return -1;
			}
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfldcw(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if ( op->operands[0].type & (OT_MEMORY | OT_WORD) ) {
			data[l++] = 0xd9;
			data[l++] = 0x28 | op->operands[0].regs[0];
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfldenv(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if ( op->operands[0].type & OT_MEMORY ) {
			data[l++] = 0xd9;
			data[l++] = 0x20 | op->operands[0].regs[0];
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfbld(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if ( op->operands[0].type & (OT_MEMORY | OT_TBYTE) ) {
			data[l++] = 0xdf;
			data[l++] = 0x20 | op->operands[0].regs[0];
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfbstp(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if ( op->operands[0].type & (OT_MEMORY | OT_TBYTE) ) {
			data[l++] = 0xdf;
			data[l++] = 0x30 | op->operands[0].regs[0];
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfxrstor(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if ( op->operands[0].type & OT_MEMORY ) {
			data[l++] = 0x0f;
			data[l++] = 0xae;
			data[l++] = 0x08 | op->operands[0].regs[0];
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

static int opfxsave(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	switch (op->operands_count) {
	case 1:
		if ( op->operands[0].type & OT_MEMORY ) {
			data[l++] = 0x0f;
			data[l++] = 0xae;
			data[l++] = 0x00 | op->operands[0].regs[0];
		} else {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return l;
}

typedef struct lookup_t {
	char mnemonic[12];
	int only_x32;
	int (*opdo)(RAsm*, ut8*, const Opcode*);
	ut64 opcode;
	int size;
} LookupTable;

LookupTable oplookup[] = {
	{"aaa", 0, NULL, 0x37, 1},
	{"aad", 0, NULL, 0xd50a, 2},
	{"aam", 0, opaam, 0},
	{"aas", 0, NULL, 0x3f, 1},
	{"adc", 0, &opadc, 0},
	{"add", 0, &opadd, 0},
	{"adx", 0, NULL, 0xd4, 1},
	{"amx", 0, NULL, 0xd5, 1},
	{"and", 0, &opand, 0},
	{"bswap", 0, &opbswap, 0},
	{"call", 0, &opcall, 0},
	{"cbw", 0, NULL, 0x6698, 2},
	{"cdq", 0, NULL, 0x99, 1},
	{"cdqe", 0, &opcdqe, 0},
	{"cwde", 0, &opcdqe, 0},
	{"clc", 0, NULL, 0xf8, 1},
	{"cld", 0, NULL, 0xfc, 1},
	{"clflush", 0, &opclflush, 0},
	{"clgi", 0, NULL, 0x0f01dd, 3},
	{"cli", 0, NULL, 0xfa, 1},
	{"clts", 0, NULL, 0x0f06, 2},
	{"cmc", 0, NULL, 0xf5, 1},
	{"cmovo", 0, &opcmov, 0},
	{"cmovno", 0, &opcmov, 0},
	{"cmovb", 0, &opcmov, 0},
	{"cmovc", 0, &opcmov, 0},
	{"cmovnae", 0, &opcmov, 0},
	{"cmovae", 0, &opcmov, 0},
	{"cmovnb", 0, &opcmov, 0},
	{"cmovnc", 0, &opcmov, 0},
	{"cmove", 0, &opcmov, 0},
	{"cmovz", 0, &opcmov, 0},
	{"cmovne", 0, &opcmov, 0},
	{"cmovnz", 0, &opcmov, 0},
	{"cmovbe", 0, &opcmov, 0},
	{"cmovna", 0, &opcmov, 0},
	{"cmova", 0, &opcmov, 0},
	{"cmovnbe", 0, &opcmov, 0},
	{"cmovne", 0, &opcmov, 0},
	{"cmovnz", 0, &opcmov, 0},
	{"cmovs", 0, &opcmov, 0},
	{"cmovns", 0, &opcmov, 0},
	{"cmovp", 0, &opcmov, 0},
	{"cmovpe", 0, &opcmov, 0},
	{"cmovnp", 0, &opcmov, 0},
	{"cmovpo", 0, &opcmov, 0},
	{"cmovl", 0, &opcmov, 0},
	{"cmovnge", 0, &opcmov, 0},
	{"cmovge", 0, &opcmov, 0},
	{"cmovnl", 0, &opcmov, 0},
	{"cmovle", 0, &opcmov, 0},
	{"cmovng", 0, &opcmov, 0},
	{"cmovg", 0, &opcmov, 0},
	{"cmovnle", 0, &opcmov, 0},
	{"cmp", 0, &opcmp, 0},
	{"cmpsb", 0, NULL, 0xa6, 1},
	{"cmpsd", 0, NULL, 0xa7, 1},
	{"cmpsw", 0, NULL, 0x66a7, 2},
	{"cpuid", 0, NULL, 0x0fa2, 2},
	{"cwd", 0, NULL, 0x6699, 2},
	{"cwde", 0, NULL, 0x98, 1},
	{"daa", 0, NULL, 0x27, 1},
	{"das", 0, NULL, 0x2f, 1},
	{"dec", 0, &opdec, 0},
	{"div", 0, &opdiv, 0},
	{"emms", 0, NULL, 0x0f77, 2},
	{"f2xm1", 0, NULL, 0xd9f0, 2},
	{"fabs", 0, NULL, 0xd9e1, 2},
	{"fadd", 0, &opfadd, 0},
	{"faddp", 0, &opfaddp, 0},
	{"fbld", 0, &opfbld, 0},
	{"fbstp", 0, &opfbstp, 0},
	{"fchs", 0, NULL, 0xd9e0, 2},
	{"fclex", 0, NULL, 0x9bdbe2, 3},
	{"fcmovb", 0, &opfcmov, 0},
	{"fcmove", 0, &opfcmov, 0},
	{"fcmovbe", 0, &opfcmov, 0},
	{"fcmovu", 0, &opfcmov, 0},
	{"fcmovnb", 0, &opfcmov, 0},
	{"fcmovne", 0, &opfcmov, 0},
	{"fcmovnbe", 0, &opfcmov, 0},
	{"fcmovnu", 0, &opfcmov, 0},
	{"fcos", 0, NULL, 0xd9ff, 2},
	{"fdecstp", 0, NULL, 0xd9f6, 2},
	{"femms", 0, NULL, 0x0f0e, 2},
	{"ffree", 0, &opffree, 0},
	{"fiadd", 0, &opfiadd, 0},
	{"ficom", 0, &opficom, 0},
	{"ficomp", 0, &opficomp, 0},
	{"fild", 0, &opfild, 0},
	{"fincstp", 0, NULL, 0xd9f7, 2},
	{"finit", 0, NULL, 0x9bdbe3, 3},
	{"fld1", 0, NULL, 0xd9e8, 2},
	{"fldcw", 0, &opfldcw, 0},
	{"fldenv", 0, &opfldenv, 0},
	{"fldl2t", 0, NULL, 0xd9e9, 2},
	{"fldl2e", 0, NULL, 0xd9ea, 2},
	{"fldlg2", 0, NULL, 0xd9ec, 2},
	{"fldln2", 0, NULL, 0xd9ed, 2},
	{"fldpi", 0, NULL, 0xd9eb, 2},
	{"fldz", 0, NULL, 0xd9ee, 2},
	{"fnclex", 0, NULL, 0xdbe2, 2},
	{"fninit", 0, NULL, 0xdbe3, 2},
	{"fnop", 0, NULL, 0xd9d0, 2},
	{"fpatan", 0, NULL, 0xd9f3, 2},
	{"fprem", 0, NULL, 0xd9f8, 2},
	{"fprem1", 0, NULL, 0xd9f5, 2},
	{"fptan", 0, NULL, 0xd9f2, 2},
	{"frndint", 0, NULL, 0xd9fc, 2},
	{"frstor", 0, &opfrstor, 0},
	{"fscale", 0, NULL, 0xd9fd, 2},
	{"fsin", 0, NULL, 0xd9fe, 2},
	{"fsincos", 0, NULL, 0xd9fb, 2},
	{"fsqrt", 0, NULL, 0xd9fa, 2},
	{"ftst", 0, NULL, 0xd9e4, 2},
	{"fucom", 0, &opfucom, 0},
	{"fucomp", 0, &opfucomp, 0},
	{"fucompp", 0, NULL, 0xdae9, 2},
	{"fwait", 0, NULL, 0x9b, 1},
	{"fxam", 0, NULL, 0xd9e5, 2},
	{"fxch", 0, &opfxch, 0},
	{"fxrstor", 0, &opfxrstor, 0},
	{"fxsave", 0, &opfxsave, 0},
	{"fxtract", 0, NULL, 0xd9f4, 2},
	{"fyl2x", 0, NULL, 0xd9f1, 2},
	{"fyl2xp1", 0, NULL, 0xd9f9, 2},
	{"getsec", 0, NULL, 0x0f37, 2},
	{"hlt", 0, NULL, 0xf4, 1},
	{"idiv", 0, &opidiv, 0},
	{"imul", 0, &opimul, 0},
	{"in", 0, &opin, 0},
	{"inc", 0, &opinc, 0},
	{"ins", 0, NULL, 0x6d, 1},
	{"insb", 0, NULL, 0x6c, 1},
	{"insd", 0, NULL, 0x6d, 1},
	{"insw", 0, NULL, 0x666d, 2},
	{"int", 0, &opint, 0},
	{"int1", 0, NULL, 0xf1, 1},
	{"int3", 0, NULL, 0xcc, 1},
	{"into", 0, NULL, 0xce, 1},
	{"invd", 0, NULL, 0x0f08, 2},
	{"iret", 0, NULL, 0x66cf, 2},
	{"iretd", 0, NULL, 0xcf, 1},
	{"ja", 0, &opjc, 0},
	{"jae", 0, &opjc, 0},
	{"jb", 0, &opjc, 0},
	{"jbe", 0, &opjc, 0},
	{"jc", 0, &opjc, 0},
	{"je", 0, &opjc, 0},
	{"jg", 0, &opjc, 0},
	{"jge", 0, &opjc, 0},
	{"jl", 0, &opjc, 0},
	{"jle", 0, &opjc, 0},
	{"jmp", 0, &opjc, 0},
	{"jna", 0, &opjc, 0},
	{"jnae", 0, &opjc, 0},
	{"jnb", 0, &opjc, 0},
	{"jnbe", 0, &opjc, 0},
	{"jnc", 0, &opjc, 0},
	{"jne", 0, &opjc, 0},
	{"jng", 0, &opjc, 0},
	{"jnge", 0, &opjc, 0},
	{"jnl", 0, &opjc, 0},
	{"jnle", 0, &opjc, 0},
	{"jno", 0, &opjc, 0},
	{"jnp", 0, &opjc, 0},
	{"jns", 0, &opjc, 0},
	{"jnz", 0, &opjc, 0},
	{"jo", 0, &opjc, 0},
	{"jp", 0, &opjc, 0},
	{"jpe", 0, &opjc, 0},
	{"jpo", 0, &opjc, 0},
	{"js", 0, &opjc, 0},
	{"jz", 0, &opjc, 0},
	{"lahf", 0, NULL, 0x9f},
	{"lea", 0, &oplea, 0},
	{"leave", 0, NULL, 0xc9, 1},
	{"les", 0, &oples, 0},
	{"lfence", 0, NULL, 0x0faee8, 3},
	{"lodsb", 0, NULL, 0xac, 1},
	{"lodsd", 0, NULL, 0xad, 1},
	{"lodsw", 0, NULL, 0x66ad, 2},
	{"mfence", 0, NULL, 0x0faef0, 3},
	{"monitor", 0, NULL, 0x0f01c8, 3},
	{"mov", 0, &opmov, 0},
	{"movsb", 0, NULL, 0xa4, 1},
	{"movsd", 0, NULL, 0xa5, 1},
	{"movsw", 0, NULL, 0x66a5, 2},
	{"movzx", 0, &opmovx, 0},
	{"movsx", 0, &opmovx, 0},
	{"mul", 0, &opmul, 0},
	{"mwait", 0, NULL, 0x0f01c9, 3},
	{"nop", 0, NULL, 0x90, 1},
	{"not", 0, &opnot, 0},
	{"or", 0, &opor, 0},
	{"out", 0, &opout, 0},
	{"outsb", 0, NULL, 0x6e, 1},
	{"outs", 0, NULL, 0x6f, 1},
	{"outsd", 0, NULL, 0x6f, 1},
	{"outsw", 0, NULL, 0x666f, 2},
	{"pop", 0, &oppop, 0},
	{"popa", 1, NULL, 0x61, 1},
	{"popad", 1, NULL, 0x61, 1},
	{"popal", 1, NULL, 0x61, 1},
	{"popaw", 1, NULL, 0x6661, 2},
	{"popfd", 1, NULL, 0x9d, 1},
	{"prefetch", 0, NULL, 0x0f0d, 2},
	{"push", 0, &oppush, 0},
	{"pusha", 1, NULL, 0x60, 1},
	{"pushad", 1, NULL, 0x60, 1},
	{"pushal", 1, NULL, 0x60, 1},
	{"pushfd", 0, NULL, 0x9c, 1},
	{"rcl", 0, &process_group_2, 0},
	{"rcr", 0, &process_group_2, 0},
	{"rep", 0, &oprep, 0},
	{"repe", 0, &oprep, 0},
	{"repne", 0, &oprep, 0},
	{"repz", 0, &oprep, 0},
	{"repnz", 0, &oprep, 0},
	{"rdmsr", 0, NULL, 0x0f32, 2},
	{"rdpmc", 0, NULL, 0x0f33, 2},
	{"rdtsc", 0, NULL, 0x0f31, 2},
	{"rdtscp", 0, NULL, 0x0f01f9, 3},
	{"ret", 0, &opret, 0},
	{"loop", 0, &oploop, 0},
	{"retf", 0, &opretf, 0},
	{"retw", 0, NULL, 0x66c3, 2},
	{"rol", 0, &process_group_2, 0},
	{"ror", 0, &process_group_2, 0},
	{"rsm", 0, NULL, 0x0faa, 2},
	{"sahf", 0, NULL, 0x9e, 1},
	{"sal", 0, &process_group_2, 0},
	{"salc", 0, NULL, 0xd6, 1},
	{"sar", 0, &process_group_2, 0},
	{"sbb", 0, &opsbb, 0},
	{"scasb", 0, NULL, 0xae, 1},
	{"scasd", 0, NULL, 0xaf, 1},
	{"scasw", 0, NULL, 0x66af, 2},
	{"seto", 0, &opset, 0},
	{"setno", 0, &opset, 0},
	{"setb", 0, &opset, 0},
	{"setnae", 0, &opset, 0},
	{"setc", 0, &opset, 0},
	{"setnb", 0, &opset, 0},
	{"setae", 0, &opset, 0},
	{"setnc", 0, &opset, 0},
	{"setz", 0, &opset, 0},
	{"sete", 0, &opset, 0},
	{"setnz", 0, &opset, 0},
	{"setne", 0, &opset, 0},
	{"setbe", 0, &opset, 0},
	{"setna", 0, &opset, 0},
	{"setnbe", 0, &opset, 0},
	{"seta", 0, &opset, 0},
	{"sets", 0, &opset, 0},
	{"setns", 0, &opset, 0},
	{"setp", 0, &opset, 0},
	{"setpe", 0, &opset, 0},
	{"setnp", 0, &opset, 0},
	{"setpo", 0, &opset, 0},
	{"setl", 0, &opset, 0},
	{"setnge", 0, &opset, 0},
	{"setnl", 0, &opset, 0},
	{"setge", 0, &opset, 0},
	{"setle", 0, &opset, 0},
	{"setng", 0, &opset, 0},
	{"setnle", 0, &opset, 0},
	{"setg", 0, &opset, 0},
	{"sfence", 0, NULL, 0x0faef8, 3},
	{"shl", 0, &process_group_2, 0},
	{"shr", 0, &process_group_2, 0},
	{"stc", 0, NULL, 0xf9, 1},
	{"std", 0, NULL, 0xfd, 1},
	{"stgi", 0, NULL, 0x0f01dc, 3},
	{"sti", 0, NULL, 0xfb, 1},
	{"stosb", 0, &opstos, 0},
	{"stosd", 0, &opstos, 0},
	{"stosw", 0, &opstos, 0},
	{"sub", 0, &opsub, 0},
	{"swapgs", 0, NULL, 0x0f1ff8, 3},
	{"syscall", 0, NULL, 0x0f05, 2},
	{"sysenter", 0, NULL, 0x0f34, 2},
	{"sysexit", 0, NULL, 0x0f35, 2},
	{"sysret", 0, NULL, 0x0f07, 2},
	{"ud2", 0, NULL, 0x0f0b, 2},
	{"vmcall", 0, NULL, 0x0f01c1, 3},
	{"vmlaunch", 0, NULL, 0x0f01c2, 3},
	{"vmload", 0, NULL, 0x0f01da, 3},
	{"vmmcall", 0, NULL, 0x0f01d9, 3},
	{"vmresume", 0, NULL, 0x0f01c3, 3},
	{"vmrun", 0, NULL, 0x0f01d8, 3},
	{"vmsave", 0, NULL, 0x0f01db, 3},
	{"vmxoff", 0, NULL, 0x0f01c4, 3},
	{"vzeroall", 0, NULL, 0xc5fc77, 3},
	{"vzeroupper", 0, NULL, 0xc5f877, 3},
	{"wait", 0, NULL, 0x9b, 1},
	{"wbinvd", 0, NULL, 0x0f09, 2},
	{"wrmsr", 0, NULL, 0x0f30, 2},
	{"xchg", 0, &opxchg, 0},
	{"xgetbv", 0, NULL, 0x0f01d0, 3},
	{"xlatb", 0, NULL, 0xd7, 1},
	{"xor", 0, &opxor, 0},
	{"xsetbv", 0, NULL, 0x0f01d1, 3},
	{"test", 0, &optest, 0},
	{"null", 0, NULL, 0, 0}
};

static x86newTokenType getToken(const char *str, size_t *begin, size_t *end) {
	// Skip whitespace
	while (isspace ((int)str[*begin]))
		++(*begin);

	if (!str[*begin]) {                // null byte
		*end = *begin;
		return TT_EOF;
	} else if (isalpha ((int)str[*begin])) {   // word token
		*end = *begin;
		while (isalnum ((int)str[*end]))
			++(*end);
		return TT_WORD;
	} else if (isdigit ((int)str[*begin])) {   // number token
		*end = *begin;
		while (isalnum ((int)str[*end]))     // accept alphanumeric characters, because hex.
			++(*end);
		return TT_NUMBER;
	} else {                             // special character: [, ], +, *, ...
		*end = *begin + 1;
		return TT_SPECIAL;
	}
}

/**
 * Get the register at position pos in str. Increase pos afterwards.
 */
static Register parseReg(RAsm *a, const char *str, size_t *pos, ut32 *type) {
	int i;
	// Must be the same order as in enum register_t
	const char *regs[] = { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip", NULL };
	const char *regsext[] = { "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d", NULL };
	const char *regs8[] = { "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh", NULL };
	const char *regs16[] = { "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", NULL };
	const char *regs64[] = { "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "rip", NULL};
	const char *regs64ext[] = { "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", NULL };
	const char *sregs[] = { "es", "cs", "ss", "ds", "fs", "gs", NULL};

	// Get token (especially the length)
	size_t nextpos, length;
	const char *token;
	getToken (str, pos, &nextpos);
	token = str + *pos;
	length = nextpos - *pos;
	*pos = nextpos;

	// General purpose registers
	if (length == 3 && token[0] == 'e') {
		for (i = 0; regs[i]; i++)
			if (!strncasecmp (regs[i], token, length)) {
				*type = (OT_GPREG & OT_REG (i)) | OT_DWORD;
				return i;
			}
	}
	if (length == 2 && (token[1] == 'l' || token[1] == 'h')) {
		for (i = 0; regs8[i]; i++)
			if (!strncasecmp (regs8[i], token, length)) {
				*type = (OT_GPREG & OT_REG (i)) | OT_BYTE;
				return i;
			}
	}
	if (length == 2) {
		for (i = 0; regs16[i]; i++) {
			if (!strncasecmp (regs16[i], token, length)) {
				*type = (OT_GPREG & OT_REG (i)) | OT_WORD;
				return i;
			}
		}
		// This isn't working properly yet
		for (i = 0; sregs[i]; i++) {
			if (!strncasecmp (sregs[i], token, length)) {
				*type = (OT_SEGMENTREG & OT_REG (i)) | OT_WORD;
				return i;
			}
		}
	}
	if (token[0] == 'r') {
		for (i = 0; regs64[i]; i++) {
			if (!strncasecmp (regs64[i], token, length)) {
				*type = (OT_GPREG & OT_REG (i)) | OT_QWORD;
				a->bits = 64;
				return i;
			}
		}
		for (i = 0; regs64ext[i]; i++) {
			if (!strncasecmp (regs64ext[i], token, length)) {
				*type = (OT_GPREG & OT_REG (i)) | OT_QWORD;
				a->bits = 64;
				return i + 8;
			}
		}
		for (i = 0; regsext[i]; i++) {
			if (!strncasecmp (regsext[i], token, length)) {
				*type = (OT_GPREG & OT_REG (i)) | OT_DWORD;
				a->bits = 32;
				return i + 8;
			}
		}
	}

	// Extended registers
	if (!strncasecmp ("st", token, 2)) {
		*type = (OT_FPUREG & ~OT_REGALL);
		*pos = 3;
	}
	if (!strncasecmp ("mm", token, 2)) {
		*type = (OT_MMXREG & ~OT_REGALL);
		*pos = 3;
	}
	if (!strncasecmp ("xmm", token, 3)) {
		*type = (OT_XMMREG & ~OT_REGALL);
		*pos = 4;
	}

	// Now read number, possibly with parantheses
	if (*type & (OT_FPUREG | OT_MMXREG | OT_XMMREG) & ~OT_REGALL) {
		Register reg = X86R_UNDEFINED;

		// pass by '(',if there is one
		if (getToken (str, pos, &nextpos) == TT_SPECIAL && str[*pos] == '(') {
			*pos = nextpos;
		}

		// read number
		// const int maxreg = (a->bits == 64) ? 15 : 7;
		if (getToken (str, pos, &nextpos) != TT_NUMBER ||
				(reg = getnum (a, str + *pos)) > 7) {
			if ((int)reg > 15) {
				eprintf ("Too large register index!\n");
				return X86R_UNDEFINED;
			} else {
				reg -= 8;
			}
		}

		*pos = nextpos;

		// pass by ')'
		if (getToken (str, pos, &nextpos) == TT_SPECIAL && str[*pos] == ')') {
			*pos = nextpos;
		}
		// Safety to prevent a shift bigger than 31. Reg
		// should never be > 8 anyway
		if (reg > 7) {
			eprintf ("Too large register index!\n");
			return X86R_UNDEFINED;
		}
		*type |= (OT_REG(reg) & ~OT_REGTYPE);
		return reg;
	}

	return X86R_UNDEFINED;
}

static void parse_segment_offset(RAsm *a, const char *str, size_t *pos,
								Operand *op, int reg_index) {
	int nextpos = *pos;
	char *c = strchr (str + nextpos, ':');
	if (c) {
		nextpos ++; // Skip the ':'
		c = strchr (str + nextpos, '[');
		if (c) {nextpos ++;} // Skip the '['

		// Assign registers to match behaviour of OT_MEMORY type
		op->regs[reg_index] = op->reg;
		op->type |= OT_MEMORY;
		op->offset_sign = 1;
		char *p = strchr (str + nextpos, '-');
		if (p) {
			op->offset_sign = -1;
			nextpos ++;
		}
		op->scale[reg_index] = getnum (a, str + nextpos);
		op->offset = op->scale[reg_index];
	}
}
// Parse operand
static int parseOperand(RAsm *a, const char *str, Operand *op, bool isrepop) {
	size_t pos, nextpos = 0;
	x86newTokenType last_type;
	int size_token = 1;
	bool explicit_size = false;
	int reg_index = 0;
	// Reset type
	op->type = 0;
	// Consume tokens denoting the operand size
	while (size_token) {
		pos = nextpos;
		last_type = getToken (str, &pos, &nextpos);

		// Token may indicate size: then skip
		if (!strncasecmp (str + pos, "ptr", 3))
			continue;
		else if (!strncasecmp (str + pos, "byte", 4)) {
			op->type |= OT_MEMORY | OT_BYTE;
			explicit_size = true;
		} else if (!strncasecmp (str + pos, "word", 4)) {
			op->type |= OT_MEMORY | OT_WORD;
			explicit_size = true;
		} else if (!strncasecmp (str + pos, "dword", 5)) {
			op->type |= OT_MEMORY | OT_DWORD;
			explicit_size = true;
		} else if (!strncasecmp (str + pos, "qword", 5)) {
			op->type |= OT_MEMORY | OT_QWORD;
			explicit_size = true;
		} else if (!strncasecmp (str + pos, "oword", 5)) {
			op->type |= OT_MEMORY | OT_OWORD;
			explicit_size = true;
		} else if (!strncasecmp (str + pos, "tbyte", 5)) {
			op->type |= OT_MEMORY | OT_TBYTE;
			explicit_size = true;
		} else	// the current token doesn't denote a size
			size_token = 0;
	}

	// Next token: register, immediate, or '['
	if (str[pos] == '[') {
		// Don't care about size, if none is given.
		if (!op->type) op->type = OT_MEMORY;

		// At the moment, we only accept plain linear combinations:
		// part := address | [factor *] register
		// address := part {+ part}*
		op->offset = op->scale[0] = op->scale[1] = 0;

		ut64 temp = 1;
		Register reg = X86R_UNDEFINED;
		while (str[pos] != ']') {
			pos = nextpos;
			if (!str[pos]) {
				break;
			}
			last_type = getToken (str, &pos, &nextpos);

			if (last_type == TT_SPECIAL) {
				if (str[pos] == '+' || str[pos] == '-' || str[pos] == ']') {
					if (reg != X86R_UNDEFINED) {
						op->regs[reg_index] = reg;
						op->scale[reg_index] = temp;
						++reg_index;
					} else {
						op->offset += temp;
						op->regs[reg_index] = X86R_UNDEFINED;
					}

					temp = 1;
					reg = X86R_UNDEFINED;
				} else if (str[pos] == '*') {
					// go to ], + or - to get scale

					// Something to do here?
					// Seems we are just ignoring '*' or assuming it implicitly.
				}
			}
			else if (last_type == TT_WORD) {
				ut32 reg_type = 0;

				// We can't multiply registers
				if (reg != X86R_UNDEFINED) {
					op->type = 0;	// Make the result invalid
				}

				// Reset nextpos: parseReg wants to parse from the beginning
				nextpos = pos;
				reg = parseReg (a, str, &nextpos, &reg_type);
				op->extended = false;
				if (reg > 7) {
					op->extended = true;
					op->reg = reg - 8;
				}
				if (reg_type & OT_REGTYPE & OT_SEGMENTREG) {
					op->reg = reg;
					op->type = reg_type;
					parse_segment_offset (a, str, &nextpos, op, reg_index);
					return nextpos;
				}

				// Still going to need to know the size if not specified
				if (!explicit_size) {
					op->type |= reg_type;
				}
				// Addressing only via general purpose registers
				if (!(reg_type & OT_GPREG)) {
					op->type = 0;	// Make the result invalid
				}
			}
			else {
				char *p = strchr (str, '+');
				op->offset_sign = 1;
				if (!p) {
					p = strchr (str, '-');
					if (p) {
						op->offset_sign = -1;
					}
				}
				// If there's a scale, we don't want to parse out the
				// scale with the offset (scale + offset) otherwise the scale
				// will be the sum of the two. This splits the numbers
				char *tmp;
				tmp = malloc (strlen (str + pos) + 1);
				strcpy (tmp, str + pos);
				strtok (tmp, "+-");
				st64 read = getnum (a, tmp);
				free (tmp);
				temp *= read;
			}
		}
	} else if (last_type == TT_WORD) {   // register
		nextpos = pos;
		RFlagItem *flag;
		op->reg = parseReg (a, str, &nextpos, &op->type);

		op->extended = false;
		if (op->reg > 7) {
			op->extended = true;
			op->reg -= 8;
		}
		if (op->type & OT_REGTYPE & OT_SEGMENTREG) {
			parse_segment_offset (a, str, &nextpos, op, reg_index);
			return nextpos;
		}
		if (op->reg == X86R_UNDEFINED) {
			op->is_good_flag = false;
			if (a->num && a->num->value == 0) {
				if (isrepop) {
					strncpy (op->rep_op, str, MAX_REPOP_LENGTH - 1);
					op->rep_op[MAX_REPOP_LENGTH - 1] = '\0';
				}
				return nextpos;
			}
			op->type = OT_CONSTANT;
			RCore *core = a->num? (RCore *)(a->num->userptr): NULL;
			if (core && (flag = r_flag_get (core->flags, str))) {
				op->is_good_flag = true;
			}

			char *p = strchr (str, '-');
			if (p) {
				op->sign = -1;
				str = ++p;
			}
			op->immediate = getnum (a, str);
		} else if (op->reg < X86R_UNDEFINED) {
			strncpy (op->rep_op, str, MAX_REPOP_LENGTH - 1);
			op->rep_op[MAX_REPOP_LENGTH - 1] = '\0';
		}
	} else {                             // immediate
		// We don't know the size, so let's just set no size flag.
		op->type = OT_CONSTANT;
		op->sign = 1;
		char *p = strchr (str, '-');
		if (p) {
			op->sign = -1;
			str = ++p;
		}
		op->immediate = getnum (a, str);
	}

	return nextpos;
}

static int parseOpcode(RAsm *a, const char *op, Opcode *out) {
	out->has_bnd = false;
	bool isrepop = false;
	if (!strncmp (op, "bnd ", 4)) {
		out->has_bnd = true;
		op += 4;
	}
	char *args = strchr (op, ' ');
	out->mnemonic = args ? r_str_ndup (op, args - op) : strdup (op);
	out->operands[0].type = out->operands[1].type = 0;
	out->operands[0].extended = out->operands[1].extended = false;
	out->operands[0].reg = out->operands[0].regs[0] = out->operands[0].regs[1] = X86R_UNDEFINED;
	out->operands[1].reg = out->operands[1].regs[0] = out->operands[1].regs[1] = X86R_UNDEFINED;
	out->operands[0].immediate = out->operands[1].immediate = 0;
	out->operands[0].sign = out->operands[1].sign = 1;
	out->operands[0].is_good_flag = out->operands[1].is_good_flag = true;
	out->is_short = false;
	out->operands_count = 0;
	if (args) {
		args++;
	} else {
		return 1;
	}
	if (!strncasecmp (args, "short", 5)) {
		out->is_short = true;
		args += 5;
	}
	if (!strncmp (out->mnemonic, "rep", 3)) {
		isrepop = true;
	}
	parseOperand (a, args, &(out->operands[0]), isrepop);
	out->operands_count = 1;
	while (out->operands_count <= MAX_OPERANDS) {
		args = strchr (args, ',');
		if (!args) {
			break;
		}
		args++;
		parseOperand (a, args, &(out->operands[out->operands_count]), isrepop);
		out->operands_count++;
	}
	return 0;
}

static ut64 getnum(RAsm *a, const char *s) {
	if (!s) return 0;
	if (*s == '$') s++;
	return r_num_math (a->num, s);
}

static int oprep(RAsm *a, ut8 *data, const Opcode *op) {
	int l = 0;
	LookupTable *lt_ptr;
	int retval;
	if (!strcmp (op->mnemonic, "rep") ||
	    !strcmp (op->mnemonic, "repe") ||
	    !strcmp (op->mnemonic, "repz")) {
		data[l++] = 0xf3;
	} else if (!strcmp (op->mnemonic, "repne") ||
	           !strcmp (op->mnemonic, "repnz")) {
		data[l++] = 0xf2;
	}
	Opcode instr = {0};
	parseOpcode (a, op->operands[0].rep_op, &instr);

	for (lt_ptr = oplookup; strcmp (lt_ptr->mnemonic, "null"); lt_ptr++) {
		if (!strcasecmp (instr.mnemonic, lt_ptr->mnemonic)) {
			if (lt_ptr->opcode > 0) {
				if (lt_ptr->only_x32 && a->bits == 64) {
					return -1;
				}
				ut8 *ptr = (ut8 *)&lt_ptr->opcode;
				int i = 0;
				for (; i < lt_ptr->size; i++) {
					data[i + l] = ptr[lt_ptr->size - (i + 1)];
				}
				return l + lt_ptr->size;
			} else {
				if (lt_ptr->opdo) {
					data += l;
					if (instr.has_bnd) {
						data[l] = 0xf2;
						data++;
					}
					retval = lt_ptr->opdo (a, data, &instr);
					// if op supports bnd then the first byte will
					// be 0xf2.
					if (instr.has_bnd) {
						retval++;
					}
					return l + retval;
				}
				break;
			}
		}
	}
	return -1;
}

static int assemble(RAsm *a, RAsmOp *ao, const char *str) {
	ut8 *data = ao->buf;
	char op[128];
	LookupTable *lt_ptr;
	int retval = -1;
	Opcode instr = {0};

	strncpy (op, str, sizeof (op) - 1);
	op[sizeof (op) - 1] = '\0';
	parseOpcode (a, op, &instr);
	for (lt_ptr = oplookup; strcmp (lt_ptr->mnemonic, "null"); lt_ptr++) {
		if (!strcasecmp (instr.mnemonic, lt_ptr->mnemonic)) {
			if (lt_ptr->opcode > 0) {
				if (!lt_ptr->only_x32 || a->bits != 64) {
					ut8 *ptr = (ut8 *)&lt_ptr->opcode;
					int i = 0;
					for (; i < lt_ptr->size; i++) {
						data[i] = ptr[lt_ptr->size - (i + 1)];
					}
					retval = lt_ptr->size;
				}
			} else {
				if (lt_ptr->opdo) {
					if (instr.has_bnd) {
						data[0] = 0xf2;
						data ++;
					}
					retval = lt_ptr->opdo (a, data, &instr);
					// if op supports bnd then the first byte will
					// be 0xf2.
					if (instr.has_bnd) {
						retval++;
					}
				}
			}
			break;
		}
	}
	free (instr.mnemonic);
	return retval;
}

RAsmPlugin r_asm_plugin_x86_nz = {
	.name = "x86.nz",
	.desc = "x86 handmade assembler",
	.license = "LGPL3",
	.arch = "x86",
	.bits = 16 | 32 | 64,
	.endian = R_SYS_ENDIAN_LITTLE,
	.assemble = &assemble };

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_x86_nz,
	.version = R2_VERSION
};
#endif
