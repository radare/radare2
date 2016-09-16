/* radare - LGPL - Copyright 2011-2016 - pancake, Roc Valles, condret */

#if 0
http://www.atmel.com/images/atmel-0856-avr-instruction-set-manual.pdf
https://en.wikipedia.org/wiki/Atmel_AVR_instruction_set
#endif

#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

// hack to get avr disasm in anal, this must be fixed by merging both worlds
#include "../asm/arch/avr/disasm.c"

#define	AVR_SOFTCAST(x,y) (x+(y*0x100))

typedef struct _cpu_models_tag_ {
	char *model;
	int pc_bits;
	int pc_mask;
	int pc_size;
	int eeprom_size;
} CPU_MODEL;

typedef void (*inst_handler_t) (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu);

typedef struct _opcodes_tag_ {
	char *name;
	int mask;
	int selector;
	inst_handler_t handler;
	int cycles;
	int size;
	int type;
} OPCODE_DESC;

#define CPU_MODEL_DECL(model, pc_bits, eeprom_sz)			\
	{								\
		model,							\
		(pc_bits),						\
		(~((~0) << (pc_bits))), 				\
		((pc_bits) >> 3) + (((pc_bits) & 0x07) ? 1 : 0),	\
		eeprom_sz						\
	}

#define INST_HANDLER(OPCODE_NAME)	static void _inst__ ## OPCODE_NAME (RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len, int *fail, CPU_MODEL *cpu)
#define INST_DECL(OP, M, SL, C, SZ, T)	{ #OP, (M), (SL), _inst__ ## OP, (C), (SZ), R_ANAL_OP_TYPE_ ## T }
#define INST_LAST			{ "unknown", 0, 0, (void *) 0, 2, 1, R_ANAL_OP_TYPE_UNK      }

#define INST_CALL(OPCODE_NAME)		_inst__ ## OPCODE_NAME (anal, op, addr, buf, len, fail, cpu)
#define INST_INVALID			{ *fail = 1; return; }
#define INST_ASSERT(x)			{ if (!(x)) { INST_INVALID; } }

CPU_MODEL cpu_models[] = {
	CPU_MODEL_DECL ("ATmega48",   11, 512),
	CPU_MODEL_DECL ("ATmega8",    12, 512),
	CPU_MODEL_DECL ("ATmega88",   12, 512),
	CPU_MODEL_DECL ("ATmega168",  13, 512),
	CPU_MODEL_DECL ("ATmega640",  16, 512),
	CPU_MODEL_DECL ("ATmega1280", 16, 512),
	CPU_MODEL_DECL ("ATmega1281", 16, 512),
	CPU_MODEL_DECL ("ATmega2560", 22, 512),
	CPU_MODEL_DECL ("ATmega2561", 22, 512),
	CPU_MODEL_DECL ((char *) 0,   16, 512)
};

INST_HANDLER (cp) {
	// CP Rd, Rr
	int r = (buf[0]        & 0x0f) | ((buf[1] << 3) & 0x10);
	int d = ((buf[0] >> 4) & 0x0f) | ((buf[1] << 4) & 0x10);
	r_strbuf_setf (
		&op->esil,
		"r%d,r%d,==,"			// compare Rr vs Rd
		","				// clean stack result
		"$z,zf,=,"			// zero flag (zf)
		"r%d,r%d,^,0x08,&,!,!,hf,=,"	// half carry flag (hf)
		"r%d,r%d,^,0x80,&,!,!,cf,=,"	// carry flag (cf)
		"$o,vf,=,"			// overflow flag (vf)
		"r%d,r%d,-,0x80,&,!,!,nf,=,"	// neg flg: result's MSB is set
		"vf,nf,^,sf,=",			// sign flag: xor(vf, nf)
		r, d, r, d, r, d, r, d);
		//"r%d,r%d,==,"			// compare Rr vs Rd
		//"$z,zf,=,"			// zero flag (zf)
		//"$b3,hf,=,"			// half carry flag (hf)
		//"$b8,cf,=,"			// carry flag (cf)
		//"$o,vf,=,"			// overflow flag (vf)
		//"r%d,r%d,-,0x80,&,!,!,nf,=,"	// neg flg: result's MSB is set
		//"vf,nf,^,sf,=",			// sign flag: xor(vf, nf)
}

INST_HANDLER (cpc) {
	int r = (buf[0]        & 0x0f) | ((buf[1] << 3) & 0x10);
	int d = ((buf[0] >> 4) & 0x0f) | ((buf[1] << 4) & 0x10);
	r_strbuf_setf (
		&op->esil,
		"r%d,cf,r%d,-,0xff,&,-,"	// ((Rd - C) & 0xff) - Rr
		"0x80,&,!,!,nf,=,"		// nef flg: result's MSB is set
		"r%d,cf,r%d,-,0xff,&,==,"	// ((Rd - C) & 0xff) == Rr
		"$z,zf,=,"			// zero flag
		"$b8,cf,=,"			// carry flag
		"$b3,hf,=,"			// half carry flag
		"$o,vf,=,"			// overflow flag
		"vf,nf,^,sf,=",			// sign flag : xor(vf, nf)
		r, d, r, d);
}

// ALIAS: Opcode (clr) when Rra and Rrb are the same
INST_HANDLER (eor) {
	int d = ((buf[0] & 0xf0) >> 4) | ((buf[1] & 1) << 4);
	int r = (buf[0] & 0xf) | ((buf[1] & 2) << 3);
	r_strbuf_setf (&op->esil, "r%d,r%d,^=,$z,zf,=,r%d,0x80,&,!,!,nf,=,nf,sf,=,0,vf,=", r, d, d);
}

INST_HANDLER (movw) {
	int d = (buf[0] & 0xf0) >> 3;
	int r = (buf[0] & 0x0f) << 1;
	r_strbuf_setf (&op->esil, "r%d,r%d,=,r%d,r%d,=", r, d, r + 1, d + 1);
}

INST_HANDLER (nop) {
}

INST_HANDLER (out) {
	int r = ((buf[0] >> 4) & 0x0f) | ((buf[1] & 0x01) << 4);
	int v = (buf[0] & 0x0f) | (((buf[1] >> 1) & 0x03) << 4);
	op->type2 = 1;
	op->val = v;
	switch (v) {
	case 0x3f: /* SREG */ r_strbuf_setf (&op->esil, "r%d,sreg,=", r); break;
	case 0x3e: /* SPH  */ r_strbuf_setf (&op->esil, "r%d,sph,=",  r); break;
	case 0x3d: /* SPL  */ r_strbuf_setf (&op->esil, "r%d,spl,=",  r); break;
	default:
		r_strbuf_setf (&op->esil, "2,$");
	}
}

INST_HANDLER (rcall) {
	ut32 offset;

	// target offset
	offset = ((((buf[1] & 0xf) << 8) | buf[0]) + 1) << 1;
	if (offset & 0x100)
		offset |= 0xfffff000;
	op->jump = op->addr + offset;
	op->fail = 0;

	// cycles!
	if (!strncasecmp (anal->cpu, "ATtiny", 6)) {
		op->cycles = 4;	// ATtiny is always slow
	} else {
		// PC size decides required runtime!
		op->cycles = cpu->pc_bits <= 16 ? 3 : 4;
		if (strncasecmp (anal->cpu, "ATxmega", 7))
			op->cycles--;	// ATxmega optimizes one cycle
	}

	r_strbuf_setf (
		&op->esil,
		"pc,"			// esil is already pointing to the
					// next instruction (@ret)
		"sp,-%d,+,"		//   and dec by (PC_SIZE-1) SP
		"_sram,+,"              //   and point to the SRAM!
		"=[%d],"		// store ret@ in stack
		"sp,-%d,+,"		// decrement stack pointer
		"sp,=,"			// store SP
		"%d,pc,=",		// jump!
		cpu->pc_size - 1, cpu->pc_size,
		cpu->pc_size, op->jump);
}

INST_HANDLER (ret) {
	if (cpu->pc_size > 2) {	// if we have a bus bigger than 16 bit
		op->cycles++;	// (i.e. a 22-bit bus), add one extra cycle
	}
	op->eob = true;

	r_strbuf_setf (
		&op->esil,
		"sp,"			// load stack pointer
		"sp,1,+,"		//   and inc by 1 SP
		"_sram,+,"              //   and point to the SRAM!
		"[%d],"			// read ret@ from the stack
		"pc,=,"			// update PC with [SP]
		"sp,%d,+,"		// post increment stack pointer
		"sp,=,",		// store incremented SP
		cpu->pc_size, cpu->pc_size);
}

INST_HANDLER (reti) {
	INST_CALL (ret);

	//XXX: There are not privileged instructions in ATMEL/AVR
	// op->family = R_ANAL_OP_FAMILY_PRIV;

	// RETI: The I-bit is cleared by hardware after an interrupt
	// has occurred, and is set by the RETI instruction to enable
	// subsequent interrupts
	r_strbuf_append (&op->esil, ",1,if,=");
}

INST_HANDLER (rjmp) {
	ut32 offset;

	op->fail = 0;

	offset = (buf[0] + (buf[1] << 8)) & 0xfff;
	if (offset & 0x800) {
		offset |= 0xfffff000;
	}
	offset++;
	offset <<= 1;
	op->jump = op->addr + offset;

	r_strbuf_setf (&op->esil, "%"PFMT64d",pc,=", op->jump);
}

INST_HANDLER (st) {
	// check op
	INST_ASSERT ((buf[0] & 0xf) != 0xf);

	// esil
	r_strbuf_setf (				// leave on stack the target
		&op->esil, "r%d,",		// register
		((buf[1] & 0x01) << 4) | ((buf[0] >> 4) & 0x0f));
	if ((buf[0] & 0xf) == 0xe) {		// do I need to preincrement X?
		r_strbuf_appendf ( &op->esil, "1,x,+,x,=,");
	}
	r_strbuf_appendf (
		&op->esil, "x,_sram,+,=[1]");	// write byte @X
	if ((buf[0] & 0xf) == 0xd) {		// do I need to postinc X?
		r_strbuf_appendf (&op->esil, ",1,x,+,x,=");
	}
}

OPCODE_DESC opcodes[] = {
	//         op     mask    select  cycles  size type
	INST_DECL (cp,    0xfc00, 0x1400, 1,      2,   CMP   ),
	INST_DECL (cpc,   0xfc00, 0x0400, 1,      2,   CMP   ),
	INST_DECL (eor,   0xfc00, 0x2400, 1,      2,   XOR   ),
	INST_DECL (movw,  0xff00, 0x0100, 1,      2,   MOV   ),
	INST_DECL (nop,   0xffff, 0x0000, 1,      2,   NOP   ),
	INST_DECL (out,   0xf800, 0xb800, 1,      2,   IO    ),
	INST_DECL (rcall, 0xf000, 0xd000, 0,      2,   CALL  ),
	INST_DECL (ret,   0xffff, 0x9508, 4,      2,   RET   ),
	INST_DECL (reti,  0xffff, 0x9518, 4,      2,   RET   ),
	INST_DECL (rjmp,  0xf000, 0xc000, 2,      2,   JMP   ),
	INST_DECL (st,    0xf00c, 0x900c, 2,      2,   STORE ),
	INST_LAST
};

static ut64 rjmp_dest(ut64 addr, const ut8* b) {
	uint16_t data = (b[0] + (b[1] << 8)) & 0xfff;
	ut32 op = data;
	op <<= 1;
	if (op & 0x1000) {
		short val = (~op) & 0xfff;
		return (ut64) (addr - val + 1);
	}
	return addr + op + 2;
}

static int avr_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	int imm = 0, imm2 = 0, d, r, k;
	ut8 kbuf[4];
	ut16 ins = AVR_SOFTCAST (buf[0], buf[1]);
	char *arg, str[32];
	CPU_MODEL *cpu;
	OPCODE_DESC *opcode_desc;

	if (!op) {
		return 2;
	}
	memset (op, '\0', sizeof (RAnalOp));
	op->addr = addr;
	op->type = R_ANAL_OP_TYPE_UNK;
	op->ptr = UT64_MAX;
	op->val = UT64_MAX;
	op->jump = UT64_MAX;
	op->fail = UT64_MAX;
	op->refptr = 0;
	op->nopcode = 1; // Necessary??
	op->size = 2;    // by default most opcodes are 2 bytes len
	op->cycles = 1;  // by default most opcodes only use 1 cpu cycle
	op->family = R_ANAL_OP_FAMILY_CPU;
	r_strbuf_init (&op->esil);
	arg = strchr (str, ' ');
	if (arg) {
		arg++;
		imm = (int)r_num_get (NULL, arg);
		arg = strchr (arg, ',');
		if (arg) {
			arg++;
			imm2 = (int)r_num_get (NULL, arg);
		}
	}
	op->delay = 0;
	op->type = R_ANAL_OP_TYPE_UNK;

	// select cpu info
	for (cpu = cpu_models; cpu->model; cpu++) {
		if (!strcasecmp (anal->cpu, cpu->model)) {
			break;
		}
	}

	// set memory layout registers
	if (anal->esil) {
		r_anal_esil_reg_write (anal->esil, "_eeprom", (1 << cpu->pc_bits));
		r_anal_esil_reg_write (anal->esil, "_sram",   (1 << cpu->pc_bits) + cpu->eeprom_size);
	}

	// process opcode
	for (opcode_desc = opcodes; opcode_desc->handler; opcode_desc++) {
		if ((ins & opcode_desc->mask) == opcode_desc->selector) {
			int fail = 0;

			// copy default cycles/size values
			op->cycles = opcode_desc->cycles;
			op->size = opcode_desc->size;

			// handle opcode
			opcode_desc->handler (anal, op, addr, buf, len, &fail, cpu);
			if (fail) {
				goto INVALID_OP;
			}
			if (op->cycles <= 0) {
				eprintf ("opcode %s @%"PFMT64x" returned 0 cycles.\n", opcode_desc->name, op->addr);
			}

			return op->size;
		}
	}

	// old and slow implementation
	// NOTE: This block should collapse along time... it depends on
	// avrdis which does not seem the most efficient and easy way
	// to emulate the CPU details :P
	op->size = avrdis (str, addr, buf, len);
	if (str[0] == 'l') {
		op->type = R_ANAL_OP_TYPE_LOAD;
	} else if (str[0] == 's') {
		op->type = R_ANAL_OP_TYPE_SUB;
	} else if (!strncmp (str, "inv", 3)) {
		op->type = R_ANAL_OP_TYPE_ILL;
	} else if (!strncmp (str, "ser ", 4)) {
		op->type = R_ANAL_OP_TYPE_MOV;
	} else if (!strncmp (str, "and", 3)) {
		op->type = R_ANAL_OP_TYPE_AND;
	} else if (!strncmp (str, "mul", 3)) {
		op->type = R_ANAL_OP_TYPE_MUL;
	} else if (!strncmp (str, "in ", 3)) {
		op->type = R_ANAL_OP_TYPE_IO;
		op->type2 = 0;
		op->val = imm2;
	} else if (!strncmp (str, "push ", 5)) {
		op->type = R_ANAL_OP_TYPE_PUSH;
	}
	k = (buf[0] & 0xf) + ((buf[1] & 0xf) << 4);
	d = ((buf[0] & 0xf0) >> 4) + 16;
	if ((buf[1] & 0xf0) == 0xe0) {		//LDI
		op->type = R_ANAL_OP_TYPE_LOAD;
		op->cycles = 1;
		r_strbuf_setf (&op->esil, "0x%x,r%d,=", k, d);
	}
	if ((buf[1] & 0xf0) == 0x30) {		//CPI
		op->type = R_ANAL_OP_TYPE_CMP;
		op->cycles = 1;
		r_strbuf_setf (&op->esil, "0x%x,r%d,==,$z,zf,=,$b3,HF,=,$b8,CF,=$o,VF,=,0x%x,r%d,-,0x80,&,!,!,NF,=,VF,NF,^,SF,=", k, d, k, d);		//check VF here
	}
	d = ((buf[0] & 0xf0) >> 4) | ((buf[1] & 1) << 4);
	r = (buf[0] & 0xf) | ((buf[1] & 2) << 3);
	if ((buf[1] & 0xec) == 12) {		//ADD + ADC
		op->type = R_ANAL_OP_TYPE_ADD;
		op->cycles = 1;
		if (buf[1] & 0x10)
			r_strbuf_setf (&op->esil, "r%d,r%d,+=,$c7,CF,=,$c3,HF,=,$o,VF,=,r%d,r%d,=,$z,zf,=,r%d,0x80,&,!,!,NF,=,VF,NF,^,SF,=", r, d, d, d, d);
		else	r_strbuf_setf (&op->esil, "r%d,NUM,r%d,CF,+=,r%d,r%d,+=,$c7,CF,=,$c3,HF,=,$o,VF,=,r%d,r%d,=,$z,zf,=,r%d,0x80,&,!,!,NF,=,VF,NF,^,SF,=,r%d,=", r, r, r, d, d, d, r);
	}
	if ((buf[1] & 0xec) == 8) {             //SUB + SBC
		op->type = R_ANAL_OP_TYPE_SUB;
		op->cycles = 1;
		if (buf[1] & 0x10)
			r_strbuf_setf (&op->esil, "r%d,r%d,-=,$b8,CF,=,$b3,HF,=,$o,VF,=,r%d,r%d,=,$z,zf,=,r%d,0x80,&,!,!,NF,=,VF,NF,^,SF,=", r, d, d, d, d);
		else	r_strbuf_setf (&op->esil, "r%d,NUM,r%d,CF,+=,r%d,r%d,-=,$b8,CF,=,$b3,HF,=,$o,VF,=,r%d,r%d,=,$z,zf,=,r%d,0x80,&,!,!,NF,=,VF,NF,^,SF,=,r%d,=", r, r, r, d, d, d, r);
	}
	switch (buf[1] & 0xfc) {
	case 0x10:	//CPSE
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->type2 = R_ANAL_OP_TYPE_CMP;
		anal->iob.read_at (anal->iob.io, addr+2, kbuf, 4);
		op->fail = addr + 2;
		op->jump = op->fail + avrdis (str, op->fail, kbuf, 4);
		op->failcycles = 1;
		op->cycles = ((op->jump - op->fail) == 4) ? 3 : 2;
		r_strbuf_setf (&op->esil, "r%d,r%d,==,$z,?{,0x%"PFMT64x",PC,=,}", r, d, op->jump);
		break;
	case 0x20:	//AND
		op->type = R_ANAL_OP_TYPE_AND;
		op->cycles = 1;
		r_strbuf_setf (&op->esil, "r%d,r%d,&=,$z,zf,=,r%d,0x80,&,!,!,NF,=,NF,SF,=,0,VF,=", r, d, d);
		break;
	case 0x28:	//OR
		op->type = R_ANAL_OP_TYPE_OR;
		op->cycles = 1;
		r_strbuf_setf (&op->esil, "r%d,r%d,|=,$z,zf,=,r%d,0x80,&,!,!,NF,=,NF,SF,=,0,VF,=", r, d, d);
		break;
	case 0x2c:	//MOV
		op->type = R_ANAL_OP_TYPE_MOV;
		op->cycles = 1;
		r_strbuf_setf (&op->esil, "r%d,r%d,=", r, d);
		break;
	}
	if ((buf[1] & 0xfe) == 0x92) {
		switch (buf[0] & 0xf) {
		case 4:		//XCH
			op->type = R_ANAL_OP_TYPE_XCHG;
			op->cycles = 2;
			r_strbuf_setf (&op->esil, "r%d,Z,^=[1],Z,[1],r%d,^=,r%d,Z,^=[1]", d, d, d);
			break;
		case 5:		//LAS
			op->type = R_ANAL_OP_TYPE_LOAD;
			op->cycles = 2;
			r_strbuf_setf (&op->esil, "r%d,Z,[1],|,Z,[1],r%d,=,Z,=[1]", d, d);
			break;
		case 6:		//LAC
			op->type = R_ANAL_OP_TYPE_LOAD;
			op->cycles = 2;
			r_strbuf_setf (&op->esil, "r%d,Z,[1],&,Z,[1],-,Z,[1],r%d,=,Z,=[1]", d, d);
			break;
		case 7:		//LAT
			op->type = R_ANAL_OP_TYPE_LOAD;
			op->cycles = 2;
			r_strbuf_setf (&op->esil, "r%d,Z,[1],^,Z,[1],r%d,=,Z,=[1]", d, d);
			break;
		}
	}
	if ((buf[1] & 0xfe) == 0x94) {
		switch (buf[0] & 0xf) {
		case 0:		//COM
			op->type = R_ANAL_OP_TYPE_CPL;
			op->cycles = 1;
			r_strbuf_setf (&op->esil, "r%d,0xff,-,r%d,=,$z,zf,=,r%d,0x80,&,!,!,NF,=,NF,SF,=,0,VF,=,1,CF,=", d, d, d);
			break;
		case 1:		//NEG
			op->type = R_ANAL_OP_TYPE_CPL;
			op->cycles = 1;
			r_strbuf_setf (&op->esil, "r%d,NUM,0,r%d,=,r%d,-=,$b3,HF,=,$b8,CF,=,CF,!,zf,=,r%d,0x80,&,!,!,NF,=,r%d,0x80,==,$z,VF,=,NF,VF,^,SF,=", d, d, d, d);	//Hack for accessing internal vars
			break;
		case 2:		//SWAP
			op->type = R_ANAL_OP_TYPE_ROL;
			op->cycles = 1;
			r_strbuf_setf (&op->esil, "4,r%d,0xf,&,<<,4,r%d,0xf0,&,>>,|,r%d,=", d, d, d);
			break;
		case 3:		//INC
			op->type = R_ANAL_OP_TYPE_ADD;
			op->cycles = 1;
			r_strbuf_setf (&op->esil, "r%d,1,+,0xff,&,r%d,=,$z,zf,=,r%d,0x80,&,!,!,NF,=,r%d,0x80,==,$z,VF,=,NF,VF,^,SF,=", d, d, d, d);
			break;
		case 5:		//ASR
			op->type = R_ANAL_OP_TYPE_SAR;
			op->cycles = 1;
			r_strbuf_setf (&op->esil, "r%d,1,&,CF,=,1,r%d,>>,0x80,r%d,&,|,r%d,=,$z,zf,=,r%d,0x80,&,NF,=,CF,NF,^,VF,=,NF,VF,^,SF,=", d, d, d, d, d);
			break;
		case 6: 	//LSR
			op->type = R_ANAL_OP_TYPE_SHR;
			op->cycles = 1;
			r_strbuf_setf (&op->esil, "r%d,1,&,CF,=,1,r%d,>>=,$z,zf,=,0,NF,=,CF,VF,=,CF,SF,=", d, d);
			break;
		case 7:		//ROR
			op->type = R_ANAL_OP_TYPE_ROR;
			op->cycles = 1;
			r_strbuf_setf (&op->esil, "CF,NF,=,r%d,1,&,7,CF,<<,1,r%d,>>,|,r%d,=,$z,zf,=,CF,=,NF,CF,^,VF,=,NF,VF,^,SF,=", d, d, d);
			break;
		case 10:	//DEC
			op->type = R_ANAL_OP_TYPE_SUB;
			op->cycles = 1;
			r_strbuf_setf (&op->esil, "1,r%d,-=,$z,zf,=,r%d,0x80,&,NF,=,r%d,0x80,==,$z,VF,=,NF,VF,^,SF,=", d, d, d);
			break;
		case 11:
			if (d < 16) {	//DES
				op->type = R_ANAL_OP_TYPE_CRYPTO;
				op->cycles = 1;		//redo this
				r_strbuf_setf (&op->esil, "%d,des", d);
			}
			break;
		}
	}
	// 0xf0 - 0xf7 BR
	if ((buf[1] >= 0xf0 && buf[1] <= 0xf8)) {
		// int cond = (buf[0] & 7);
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = imm;
		op->fail = addr + 2;
		return op->size;
	}
	if ((buf[1] >= 0xc0 && buf[1] <= 0xcf)) { // rjmp
		op->type = R_ANAL_OP_TYPE_JMP; // relative jump
		ut64 dst = rjmp_dest (addr, buf);
		op->jump = dst;
		op->fail = UT64_MAX;
		r_strbuf_setf (&op->esil, "%"PFMT64d",PC,=", dst);
		return op->size;
	}
	switch (buf[1]) {
	case 0x96: // ADIW
		op->type = R_ANAL_OP_TYPE_ADD;
		op->cycles = 2;
		break;
	case 0x97: // SBIW
		op->type = R_ANAL_OP_TYPE_SUB;
//		r_strbuf_setf (&op->esil, ",", dst);
		op->cycles = 2;
		break;
	case 0x98: // SBI
	case 0x9a: // CBI
		op->type = R_ANAL_OP_TYPE_IO;
		op->cycles = 2; // 1 for atTiny
		break;
	case 0x99: // SBIC
	case 0x9b: // SBIS
		op->type = R_ANAL_OP_TYPE_CMP;
		op->type2 = R_ANAL_OP_TYPE_CJMP;
		op->failcycles = 1;
		break;
	}
	if (!memcmp (buf, "\x0e\x94", 2)) {
		op->addr = addr;
		op->type = R_ANAL_OP_TYPE_CALL; // call (absolute)
		op->fail = (op->addr)+4;
		// override even if len<4 wtf
		len = 4;
		if (len>3) {
			memcpy (kbuf, buf+2, 2);
			op->size = 4;
			//anal->iob.read_at (anal->iob.io, addr+2, kbuf, 2);
			op->jump = AVR_SOFTCAST (kbuf[0],kbuf[1])*2;
		} else {
			op->size = 0;
			return -1;
			return op->size;		//WTF
		}
		//eprintf("addr: %x inst: %x dest: %x fail:%x\n", op->addr, *ins, op->jump, op->fail);
	}
	if (((buf[1] & 0xfe) == 0x94) && ((buf[0] & 0x0e) == 0x0c)) {
		op->addr = addr;
		op->type = R_ANAL_OP_TYPE_CJMP; // breq, jmp (absolute)
		op->fail = op->addr + 4;
		anal->iob.read_at (anal->iob.io, addr + 2, kbuf, 2);
		// TODO: check return value
		op->jump = AVR_SOFTCAST (kbuf[0], kbuf[1]) * 2;
		//eprintf("addr: %x inst: %x dest: %x fail:%x\n", op->addr, *ins, op->jump, op->fail);
	}

	return op->size;

INVALID_OP:
	// An unknown or invalid option has appeared.
	//  -- Throw pokeball!
	op->type = R_ANAL_OP_TYPE_UNK;
	op->family = R_ANAL_OP_FAMILY_UNKNOWN;
	op->size = 2;
	op->cycles = 1;
	// launch esil trap (for communicating upper layers about this weird
	// and stinky situation
	r_strbuf_set (&op->esil, "1,$");

	return op->size;
}

static int avr_custom_des (RAnalEsil *esil) {
	char *round;
	ut64 key, text;
	int r, enc;
	if (!esil || !esil->anal || !esil->anal->reg) {
		return false;
	}
	round = r_anal_esil_pop (esil);
	if (!round) {
		return false;
	}
	if (!r_anal_esil_get_parm (esil, round, &key)) {
		free (round);
		return false;
	}
	free (round);
	r = (int)key;
	r_anal_esil_reg_read (esil, "hf", &key, NULL);
	enc = (int)key;
	r_anal_esil_reg_read (esil, "deskey", &key, NULL);
	r_anal_esil_reg_read (esil, "text", &text, NULL);
//	eprintf ("des - key: 0x%"PFMT64x" - text: 0x%"PFMT64x" - round: %d - %s\n", key, text, r, enc ? "decrypt" : "encrypt");
	key = r_des_get_roundkey (key, r, enc);
	text = r_des_round (text, key);
	r_anal_esil_reg_write (esil, "text", text);
	return true;
}

static int esil_avr_init (RAnalEsil *esil) {
	if (!esil)
		return false;
	r_anal_esil_set_op (esil, "des", avr_custom_des);

	return true;
}

static int esil_avr_fini (RAnalEsil *esil) {
	return true;
}

static int set_reg_profile(RAnal *anal) {
	const char *p =
		"=PC	pcl\n"
		"=SP	sp\n"
// explained in http://www.nongnu.org/avr-libc/user-manual/FAQ.html
// and http://www.avrfreaks.net/forum/function-calling-convention-gcc-generated-assembly-file
		"=A0	r25\n"
		"=A1	r24\n"
		"=A2	r23\n"
		"=A3	r22\n"
		"=R0	r24\n"
#if 0
PC: 16- or 22-bit program counter
SP: 8- or 16-bit stack pointer
SREG: 8-bit status register
RAMPX, RAMPY, RAMPZ, RAMPD and EIND:
#endif
// 8bit registers x 32
		"gpr	r0	.8	0	0\n"
		"gpr	r1	.8	1	0\n"
		"gpr	r2	.8	2	0\n"
		"gpr	r3	.8	3	0\n"
		"gpr	r4	.8	4	0\n"
		"gpr	r5	.8	5	0\n"
		"gpr	r6	.8	6	0\n"
		"gpr	r7	.8	7	0\n"
		"gpr	text	.64	0	0\n"
		"gpr	r8	.8	8	0\n"
		"gpr	r9	.8	9	0\n"
		"gpr	r10	.8	10	0\n"
		"gpr	r11	.8	11	0\n"
		"gpr	r12	.8	12	0\n"
		"gpr	r13	.8	13	0\n"
		"gpr	r14	.8	14	0\n"
		"gpr	r15	.8	15	0\n"
		"gpr	deskey	.64	8	0\n"
		"gpr	r16	.8	16	0\n"
		"gpr	r17	.8	17	0\n"
		"gpr	r18	.8	18	0\n"
		"gpr	r19	.8	19	0\n"
		"gpr	r20	.8	20	0\n"
		"gpr	r21	.8	21	0\n"
		"gpr	r22	.8	22	0\n"
		"gpr	r23	.8	23	0\n"
		"gpr	r24	.8	24	0\n"
		"gpr	r25	.8	25	0\n"
		"gpr	r26	.8	26	0\n"
		"gpr	r27	.8	27	0\n"
		"gpr	r28	.8	28	0\n"
		"gpr	r29	.8	29	0\n"
		"gpr	r30	.8	30	0\n"
		"gpr	r31	.8	31	0\n"

// 16 bit overlapped registers for memory addressing
		"gpr	x	.16	26	0\n"
		"gpr	y	.16	28	0\n"
		"gpr	z	.16	30	0\n"
// program counter
// NOTE: program counter size in AVR depends on the CPU model. It seems that
// the PC may range from 16 bits to 22 bits.
		"gpr	pc	.32	32	0\n"
		"gpr	pcl	.16	32	0\n"
		"gpr	pch	.16	34	0\n"
// special purpose registers
		"gpr	sp	.16	36	0\n"
		"gpr	spl	.8	36	0\n"
		"gpr	sph	.8	37	0\n"
// status bit register (SREG)
		"gpr	sreg	.8	38	0\n"
		"gpr	cf	.1	38.0	0\n" // Carry. This is a borrow flag on subtracts.
		"gpr	zf	.1	38.1	0\n" // Zero. Set to 1 when an arithmetic result is zero.
		"gpr	nf	.1	38.2	0\n" // Negative. Set to a copy of the most significant bit of an arithmetic result.
		"gpr	vf	.1	38.3	0\n" // Overflow flag. Set in case of two's complement overflow.
		"gpr	sf	.1	38.4	0\n" // Sign flag. Unique to AVR, this is always (N ^ V) (xor), and shows the true sign of a comparison.
		"gpr	hf	.1	38.5	0\n" // Half carry. This is an internal carry from additions and is used to support BCD arithmetic.
		"gpr	tf	.1	38.6	0\n" // Bit copy. Special bit load and bit store instructions use this bit.
		"gpr	if	.1	38.7	0\n" // Interrupt flag. Set when interrupts are enabled.
// 8bit segment registers to be added to X, Y, Z to get 24bit offsets
		"gpr	rampx	.8	39	0\n"
		"gpr	rampy	.8	40	0\n"
		"gpr	rampz	.8	41	0\n"
		"gpr	rampd	.8	42	0\n"
		"gpr	eind	.8	43	0\n"
// memory mapping emulator registers
		"gpr	_eeprom	.32	44	0\n"
		"gpr	_sram	.32	48	0\n"
		;

	return r_reg_set_profile_string (anal->reg, p);
}

static int archinfo(RAnal *anal, int q) {
	if (q == R_ANAL_ARCHINFO_ALIGN)
		return 2;
	if (q == R_ANAL_ARCHINFO_MAX_OP_SIZE)
		return 4;
	if (q == R_ANAL_ARCHINFO_MIN_OP_SIZE)
		return 2;
	return 2; // XXX
}

RAnalPlugin r_anal_plugin_avr = {
	.name = "avr",
	.desc = "AVR code analysis plugin",
	.license = "LGPL3",
	.arch = "avr",
	.esil = true,
	.archinfo = archinfo,
	.bits = 8 | 16, // 24 big regs conflicts
	.op = &avr_op,
	.set_reg_profile = &set_reg_profile,
	.esil_init = esil_avr_init,
	.esil_fini = esil_avr_fini,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_avr,
	.version = R2_VERSION
};
#endif
