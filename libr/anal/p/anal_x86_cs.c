/* radare2 - LGPL - Copyright 2013-2014 - pancake */

#include <r_anal.h>
#include <r_lib.h>
#include <capstone.h>
#include <x86.h>

#define USE_ITER_API 0

#if CS_API_MAJOR < 2
#error Old Capstone not supported
#endif

#define esilprintf(op, fmt, arg...) r_strbuf_setf (&op->esil, fmt, ##arg)
#define INSOP(n) insn->detail->x86.operands[n]

static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	csh handle;
#if USE_ITER_API
	static
#endif
	cs_insn *insn = NULL;
	int mode = (a->bits==64)? CS_MODE_64: 
		(a->bits==32)? CS_MODE_32:
		(a->bits==16)? CS_MODE_16: 0;
	int n, ret = cs_open (CS_ARCH_X86, mode, &handle);
	memset (op, '\0', sizeof (RAnalOp));
	op->type = R_ANAL_OP_TYPE_NULL;
	op->jump = UT64_MAX;
	op->fail = UT64_MAX;
	op->ptr = op->val = UT64_MAX;
	op->src[0] = NULL;
	op->src[1] = NULL;
	op->size = 0;
	op->delay = 0;
	r_strbuf_init (&op->esil);
	if (ret == CS_ERR_OK) {
		cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);
		// capstone-next
#if USE_ITER_API
		{
			ut64 naddr = addr;
			size_t size = len;
			if (insn == NULL)
				insn = cs_malloc (handle);
			n = cs_disasm_iter (handle, (const uint8_t**)&buf, &size, (uint64_t*)&naddr, insn);
		}
#else
		n = cs_disasm (handle, (const ut8*)buf, len, addr, 1, &insn);
#endif
		if (n<1) {
			op->type = R_ANAL_OP_TYPE_ILL;
		} else {
			int rs = a->bits/8;
			const char *pc = (a->bits==16)?"ip":
				(a->bits==32)?"eip":"rip";
			const char *sp = (a->bits==16)?"sp":
				(a->bits==32)?"esp":"rsp";
			op->size = insn->size;
			op->prefix = 0;
			switch (insn->detail->x86.prefix[0]) {
			case X86_PREFIX_REPNE:
				op->prefix |= R_ANAL_OP_PREFIX_REPNE;
			case X86_PREFIX_REP:
				op->prefix |= R_ANAL_OP_PREFIX_REP;
			case X86_PREFIX_LOCK:
				op->prefix |= R_ANAL_OP_PREFIX_LOCK;
			}
			switch (insn->id) {
			case X86_INS_FNOP:
			case X86_INS_NOP:
				op->type = R_ANAL_OP_TYPE_NOP;
				if (a->decode)
					esilprintf (op, "");
				break;
			case X86_INS_HLT:
				op->type = R_ANAL_OP_TYPE_TRAP;
				break;
			case X86_INS_CLI:
			case X86_INS_STI:
			case X86_INS_CLC:
			case X86_INS_STC:
				break;
			case X86_INS_MOV:
			case X86_INS_MOVZX:
			case X86_INS_MOVABS:
			case X86_INS_MOVHPD:
			case X86_INS_MOVHPS:
			case X86_INS_MOVLPD:
			case X86_INS_MOVLPS:
			case X86_INS_MOVBE:
			case X86_INS_MOVSB:
			case X86_INS_MOVSD:
			case X86_INS_MOVSQ:
			case X86_INS_MOVSS:
			case X86_INS_MOVSW:
			case X86_INS_MOVD:
			case X86_INS_MOVQ:
			case X86_INS_MOVDQ2Q:
				{
				op->type = R_ANAL_OP_TYPE_MOV;
				switch (INSOP(0).type) {
				case X86_OP_MEM:
					op->ptr = INSOP(0).mem.disp;
					op->refptr = INSOP(0).size;
					if (INSOP(0).mem.base == X86_REG_RIP) {
						op->ptr += addr + insn->size;
					}
				default:
					break;
				}
				switch (INSOP(1).type) {
				case X86_OP_MEM:
					op->ptr = INSOP(1).mem.disp;
					op->refptr = INSOP(1).size;
					if (INSOP(1).mem.base == X86_REG_RIP) {
						op->ptr += addr + insn->size;
					}
					break;
				case X86_OP_IMM:
					if (INSOP(1).imm > 10)
						op->ptr = INSOP(1).imm;
					break;
				default:
					break;
				}
				}
				break;
			case X86_INS_CMP:
			case X86_INS_VCMP:
			case X86_INS_CMPPD:
			case X86_INS_CMPPS:
			case X86_INS_CMPSW:
			case X86_INS_CMPSD:
			case X86_INS_CMPSQ:
			case X86_INS_CMPSB:
			case X86_INS_CMPSS:
			case X86_INS_TEST:
				op->type = R_ANAL_OP_TYPE_CMP;
				switch (INSOP(0).type) {
				case X86_OP_MEM:
					op->ptr = INSOP(0).mem.disp;
					op->refptr = INSOP(0).size;
					if (INSOP(0).mem.base == X86_REG_RIP) {
						op->ptr += addr + insn->size;
					}
					break;
				default:
					switch (INSOP(1).type) {
					case X86_OP_MEM:
						op->ptr = INSOP(1).mem.disp;
						op->refptr = INSOP(1).size;
						if (INSOP(1).mem.base == X86_REG_RIP) {
							op->ptr += addr + insn->size;
						}
						break;
					case X86_OP_IMM:
						op->ptr = INSOP(1).imm;
						break;
					default:
						break;
					}
					break;
				}
				break;
			case X86_INS_LEA:
				op->type = R_ANAL_OP_TYPE_LEA;
				switch (INSOP(1).type) {
				case X86_OP_MEM:
					op->ptr = INSOP(1).mem.disp;
				default:
					break;
				}
				break;
			case X86_INS_ENTER:
			case X86_INS_PUSH:
			case X86_INS_PUSHAW:
			case X86_INS_PUSHAL:
			case X86_INS_PUSHF:
				op->type = R_ANAL_OP_TYPE_PUSH;
				switch (INSOP(0).type) {
				case X86_OP_IMM:
					op->ptr = INSOP(0).imm;
				default:
					break;
				}
				break;
			case X86_INS_LEAVE:
			case X86_INS_POP:
			case X86_INS_POPAW:
			case X86_INS_POPAL:
			case X86_INS_POPF:
			case X86_INS_POPCNT:
				op->type = R_ANAL_OP_TYPE_POP;
				break;
			case X86_INS_RET:
			case X86_INS_RETF:
			case X86_INS_IRET:
			case X86_INS_IRETD:
			case X86_INS_IRETQ:
			case X86_INS_SYSRET:
				op->type = R_ANAL_OP_TYPE_RET;
				if (a->decode)
					esilprintf (op, "%s,[%d],%s,=,%d,%s,+=",
						sp, rs, pc, rs, sp);
				break;
			case X86_INS_INT1:
			case X86_INS_INT3:
			case X86_INS_INTO:
			case X86_INS_INT:
			case X86_INS_VMCALL:
			case X86_INS_VMMCALL:
			case X86_INS_SYSCALL:
				op->type = R_ANAL_OP_TYPE_TRAP;
				if (a->decode)
					esilprintf (op, "%d,$", (int)INSOP(0).imm);
				break;
			case X86_INS_JL:
			case X86_INS_JLE:
			case X86_INS_JA:
			case X86_INS_JAE:
			case X86_INS_JB:
			case X86_INS_JBE:
			case X86_INS_JCXZ:
			case X86_INS_JECXZ:
			case X86_INS_JO:
			case X86_INS_JNO:
			case X86_INS_JS:
			case X86_INS_JNS:
			case X86_INS_JP:
			case X86_INS_JNP:
			case X86_INS_JE:
			case X86_INS_JNE:
			case X86_INS_JG:
			case X86_INS_JGE:
				op->type = R_ANAL_OP_TYPE_CJMP;
				op->jump = INSOP(0).imm;
				op->fail = addr+op->size;
				if (a->decode) {
					if (INSOP(0).type==X86_OP_IMM) {
// TODO
					}
				}
				break;
			case X86_INS_CALL:
			case X86_INS_LCALL:
				if (INSOP(0).type==X86_OP_IMM) {
					op->type = R_ANAL_OP_TYPE_CALL;
					// TODO: what if UCALL?
					// TODO: use imm_size
					op->jump = INSOP(0).imm;
					op->fail = addr+op->size;
				} else {
					op->type = R_ANAL_OP_TYPE_UCALL;
				}
				break;
			case X86_INS_JMP:
			case X86_INS_LJMP:
				// TODO: what if UJMP?
				if (INSOP(0).type == X86_OP_IMM) {
					op->jump = INSOP(0).imm;
					op->type = R_ANAL_OP_TYPE_JMP;
					if (a->decode) {
						ut64 dst = INSOP(0).imm;
						esilprintf (op, "0x%"PFMT64x",%s,=", dst, pc);
					}
				} else {
					op->type = R_ANAL_OP_TYPE_UJMP;
				}
				break;
			case X86_INS_IN:
			case X86_INS_INSW:
			case X86_INS_INSD:
			case X86_INS_INSB:
			case X86_INS_OUT:
			case X86_INS_OUTSB:
			case X86_INS_OUTSD:
			case X86_INS_OUTSW:
				op->type = R_ANAL_OP_TYPE_IO;
				break;
			case X86_INS_VXORPD:
			case X86_INS_VXORPS:
			case X86_INS_VPXORD:
			case X86_INS_VPXORQ:
			case X86_INS_VPXOR:
			case X86_INS_KXORW:
			case X86_INS_PXOR:
			case X86_INS_XOR:
				op->type = R_ANAL_OP_TYPE_XOR;
				break;
			case X86_INS_OR:
				op->type = R_ANAL_OP_TYPE_OR;
				break;
			case X86_INS_SUB:
			case X86_INS_DEC:
			case X86_INS_PSUBB:
			case X86_INS_PSUBW:
			case X86_INS_PSUBD:
			case X86_INS_PSUBQ:
			case X86_INS_PSUBSB:
			case X86_INS_PSUBSW:
			case X86_INS_PSUBUSB:
			case X86_INS_PSUBUSW:
				op->type = R_ANAL_OP_TYPE_SUB;
				break;
			case X86_INS_AND:
			case X86_INS_ANDN:
			case X86_INS_ANDPD:
			case X86_INS_ANDPS:
			case X86_INS_ANDNPD:
			case X86_INS_ANDNPS:
				op->type = R_ANAL_OP_TYPE_AND;
				break;
			case X86_INS_DIV:
				op->type = R_ANAL_OP_TYPE_DIV;
				break;
			case X86_INS_MUL:
				op->type = R_ANAL_OP_TYPE_MUL;
				break;
			case X86_INS_INC:
			case X86_INS_ADD:
			case X86_INS_FADD:
			case X86_INS_ADDPD:
				op->type = R_ANAL_OP_TYPE_ADD;
				break;
			}
		}
#if !USE_ITER_API
		cs_free (insn, n);
#endif
		cs_close (&handle);
	}
	return op->size;
}

RAnalPlugin r_anal_plugin_x86_cs = {
	.name = "x86",
	.desc = "Capstone X86 analysis",
	.esil = R_TRUE,
	.license = "BSD",
	.arch = R_SYS_ARCH_X86,
	.bits = 16|32|64,
	.op = &analop,
	//.set_reg_profile = &set_reg_profile,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_x86_cs
};
#endif
