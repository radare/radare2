/* radare - LGPL - Copyright 2015-2017 - pancake */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <r_util.h>

typedef enum optype_t {
	ARM_REG = 0, ARM_CONSTANT, ARM_FP
} OpType;

typedef enum regtype_t {
	ARM_UNDEFINED = -1,
	ARM_GPR = 0, ARM_SP, ARM_PC, ARM_SIMD 
} RegType;

typedef struct operand_t {
	OpType type;
	union {
		struct {
			int reg;
			RegType reg_type;
		};
		struct {
			ut64 immediate;
			int sign;
		};
	};
} Operand;

typedef struct Opcode_t {
	char *mnemonic;
	ut32 op[3];
	size_t op_len;
	ut8 opcode[3];
	int operands_count;
	Operand operands[3];
} ArmOp;

static ut32 mov(const char *str, int k, ArmOp *op) {
#if 1
	ut32 data = UT32_MAX;
	printf ("mmmm %s] [%d]\n", op->mnemonic, strlen (op->mnemonic));
	if (strlen (op->mnemonic) == 3) {
		printf ("plog\n");
		if (op->operands[0].type == ARM_REG) {
			if (op->operands[1].type == ARM_REG) {
				data = 0xE00300AA | op->operands[1].reg << 8;
			} else {
				data = k | op->operands[1].immediate << 29;
			}
			data |=  op->operands[0].reg << 24;
		} else if (op->operands[0].type == ARM_CONSTANT) {
			return data;
		}
	} else {
		data = k;
		printf ("%d %d\n", op->operands[0].reg, op->operands[1].reg);
		data |= (op->operands[0].reg << 24); // arg(0)
		data |= ((op->operands[1].reg & 7) << 29); // arg(1)
		data |= (((op->operands[1].reg >> 3) & 0xff) << 16); // arg(1)
		data |= ((op->operands[1].reg >> 10) << 7); // arg(1)
	}
	return data;
#else
printf ("str %s\n", str);
	ut32 op = UT32_MAX;
	const char *op1 = strchr (str, ' ') + 1;
	char *comma = strchr (str, ',');
	comma[0] = '\0';
	const char *op2 = (comma[1]) == ' ' ? comma + 2 : comma + 1;

	int n = (int)r_num_math (NULL, op1 + 1);
	int w = (int)r_num_math (NULL, op2);
	if (!strncmp (str, "mov x", 5)) {
		// TODO handle values > 32
		if (n >= 0 && n < 32) {
			if (op2[0] == 'x') {
				w = (int)r_num_math (NULL, op2 + 1);
				k = 0xE00300AA;
				op = k | w << 8;
			} else {
				op = k | w << 29;
			}
		}
		op |= n << 24;
	} else if (!strncmp (str, "mov", 3) && strlen (str) > 5) {
		if (n >= 0 && n < 32 && comma) {
			op = k;
			op |= (n << 24); // arg(0)
			op |= ((w & 7) << 29); // arg(1)
			op |= (((w >> 3) & 0xff) << 16); // arg(1)
			op |= ((w >> 10) << 7); // arg(1)
		}
	}
	return op;
#endif
}

static ut32 branch_reg(const char *str, ut64 addr, int k) {
	ut32 op = UT32_MAX;
	const char *operand = strchr (str, 'x');
	if (!operand) {
		return -1;
	}
	operand++;
	int n = (int)r_num_math (NULL, operand);
	if (n < 0 || n > 31) {
		return -1;
	}
	n = n << 5;
	int h = n >> 8;
	n &= 0xff;
	op = k;
	op |= n << 24;
	op |= h << 16;
	return op;
}

static ut32 branch(const char *str, ut64 addr, int k) {
	ut32 op = UT32_MAX;
	const char *operand = strchr (str, ' ');
	if (operand) {
		operand++;
		int n = (int)r_num_math (NULL, operand);

		if (n & 0x3 || n > 0x7ffffff) {
			/* return -1 */
		} else {
			n -= addr;
			n = n >> 2;
			int t = n >> 24;
			int h = n >> 16;
			int m = (n & 0xff00) >> 8;
			n &= 0xff;
			op = k;
			op |= n << 24;
			op |= m << 16;
			op |= h << 8;
			op |= t;
		}
	}
	return op;
}

#include "armass64_const.h"

static ut32 msrk(const char *arg) {
	int i;
	ut32 r = 0;
	ut32 v = r_num_get (NULL, arg);
	arg = r_str_chop_ro (arg);
	if (!v) {
		for (i = 0; msr_const[i].name; i++) {
			if (!strncasecmp (arg, msr_const[i].name, strlen (msr_const[i].name))) {
				v = msr_const[i].val;
				break;
			}
		}
		if (!v) {
			return UT32_MAX;
		}
	}
	ut32 a = ((v >> 12) & 0xf) << 1;
	ut32 b = ((v & 0xfff) >> 3) & 0xff;
	r |= a << 8;
	r |= b << 16;
	return r;
}

static ut32 msr(const char *str, int w) {
	const char *comma = strchr (str, ',');
	ut32 op = UT32_MAX;
	if (comma) {
		ut32 r, b;
		/* handle swapped args */
		if (w) {
			char *reg = strchr (str, 'x');
			if (!reg) {
				return op;
			}
			r = atoi (reg + 1);
			b = msrk (comma + 1);
		} else {
			char *reg = strchr (comma + 1, 'x');
			if (!reg) {
				return op;
			}
			r = atoi (reg + 1);
			b = msrk (str + 4);
		}
		op = (r << 24) | b | 0xd5;
		if (w) {
			/* mrs */
			op |= 0x2000;
		}
	}
	return op;
}

static bool exception(ut32 *op, const char *arg, ut32 type) {
	int n = (int)r_num_math (NULL, arg);
	n /= 8;
	*op = type;
	*op += ((n & 0xff) << 16);
	*op += ((n >> 8) << 8);
	return *op != -1;
}

static bool arithmetic (ut32 *op, const char *str, int type) {
	char *c = strchr (str + 5, 'x');
	if (c) {
		char *c2 = strchr (c + 1, ',');
		if (c2) {
			int r0 = atoi (str + 5);
			int r1 = atoi (c + 1);
			ut64 n = r_num_math (NULL, c2 + 1);
			*op = type;
			*op += r0 << 24;
			*op += (r1 & 7) << (24 + 5);
			*op += (r1 >> 3) << 16;
			*op += (n & 0x3f) << 18;
			*op += (n >> 6) << 8;
		}
	}
	return *op != -1;
}

static bool parseOperands(char* str, ArmOp *op) {
	char *t = strdup (str);
	int operand = 0;
	char *token = t;
	char *x;
	while (token[0] != '\0') {
		switch (token[0]) {
			case ' ':
				token ++;
				continue;
				break;
			case 'x':
				x = strchr (token, ',');
				if (x) {
					x[0] = '\0';
				}
				op->operands_count ++;
				op->operands[operand].type = ARM_REG;
				op->operands[operand].reg = r_num_math (NULL, token + 1);
			
			break;
			case 'v':
				x = strchr (token, ',');
				if (x) {
					x[0] = '\0';
				}
				op->operands_count ++;
				op->operands[operand].type = ARM_FP;
				op->operands[operand].reg = r_num_math (NULL, token + 1);
			
			break;
			case '-':
				op->operands[operand].sign = -1;
			default:
				x = strchr (token, ',');
				if (x) {
					x[0] = '\0';
				}
				op->operands_count ++;
				op->operands[operand].type = ARM_CONSTANT;
				op->operands[operand].immediate = r_num_math (NULL, token);
				
			break;			
		}	
		if (x == '\0') {
			free (t);
			return true;
		}
		token = ++x;
		operand ++;
			
	} 
	free (t);
	return true;
}

static bool parseOpcode(const char *str, ArmOp *op) {
	char *in = strdup (str);
	char *space = strchr (in, ' ');
	space[0] = '\0';
	op->mnemonic = in;
	space ++;
	parseOperands (space, op);
	return true;

}	


bool arm64ass(const char *str, ut64 addr, ut32 *op) {
	ArmOp ops = {0};
	parseOpcode (str, &ops);
	/* TODO: write tests for this and move out the regsize logic into the mov */
	if (!strncmp (str, "movk w", 6)) {
		return mov (str, 0x8072, &ops) != -1;
	}
	if (!strncmp (str, "movk x", 6)) {
		return mov (str, 0x80f2, &ops) != -1;
	}
	if (!strncmp (str, "movn x", 6)) {
		return mov (str, 0x8092, &ops) != -1;
	}
	if (!strncmp (str, "movn w", 6)) {
		*op = mov (str, 0x8012, &ops);
		return *op != -1;
	}
	if (!strncmp (str, "movz x", 6)) {
		*op = mov (str, 0x80d2, &ops);
		return *op != -1;
	}
	if (!strncmp (str, "movz ", 5)) { // w
		*op = mov (str, 0x8052, &ops);
		return *op != -1;
	}
	if (!strncmp (str, "mov x", 5)) { // w
		*op = mov (str, 0x80d2, &ops);
		return *op != -1;
	}
	if (!strncmp (str, "sub x", 5)) { // w
		return arithmetic (op, str, 0xd1);
	}
	if (!strncmp (str, "add x", 5)) { // w
		return arithmetic (op, str, 0x91);
	}
	if (!strncmp (str, "adr x", 5)) { // w
		int regnum = atoi (str + 5);
		char *arg = strchr (str + 5, ',');
		ut64 at = 0LL;
		if (arg) {
			at = r_num_math (NULL, arg + 1);
			// XXX what about negative values?
			at = at - addr;
			at /= 4;
		}
		*op = 0x00000010;
		*op += 0x01000000 * regnum;
		ut8 b0 = at;
		ut8 b1 = (at >> 3) & 0xff;
		ut8 b2 = (at >> (8 + 7)) & 0xff;
		*op += b0 << 29;
		*op += b1 << 16;
		*op += b2 << 24;
		return *op != -1;
	}
	if (!strcmp (str, "nop")) {
		*op = 0x1f2003d5;
		return *op != -1;
	}
	if (!strcmp (str, "ret")) {
		*op = 0xc0035fd6;
		return true;
	}
	if (!strncmp (str, "msr ", 4)) {
		*op = msr (str, 0);
		if (*op != UT32_MAX) {
			return true;
		}
	}
	if (!strncmp (str, "mrs ", 4)) {
		*op = msr (str, 1);
		if (*op != UT32_MAX) {
			return true;
		}
	}
	if (!strncmp (str, "svc ", 4)) { // system level exception
		return exception (op, str + 4, 0x010000d4);
	}
	if (!strncmp (str, "hvc ", 4)) { // hypervisor level exception
		return exception (op, str + 4, 0x020000d4);
	}
	if (!strncmp (str, "smc ", 4)) { // secure monitor exception
		return exception (op, str + 4, 0x040000d4);
	}
	if (!strncmp (str, "brk ", 4)) { // breakpoint
		return exception (op, str + 4, 0x000020d4);
	}
	if (!strncmp (str, "hlt ", 4)) { // halt
		return exception (op, str + 4, 0x000040d4);
	}
	if (!strncmp (str, "b ", 2)) {
		*op = branch (str, addr, 0x14);
		return *op != -1;
	}
	if (!strncmp (str, "bl ", 3)) {
		*op = branch (str, addr, 0x94);
		return *op != -1;
	}
	if (!strncmp (str, "br x", 4)) {
		*op = branch_reg (str, addr, 0x1fd6);
		return *op != -1;
	}
	if (!strncmp (str, "blr x", 4)) {
		*op = branch_reg (str, addr, 0x3fd6);
		return *op != -1;
	}
	return false;
}
