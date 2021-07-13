/* radare - LGPL - Copyright 2010-2020 - pancake, nibble */

#include <r_anal.h>
#include <r_util.h>
#include <r_list.h>

R_API RAnalOp *r_anal_op_new(void) {
	RAnalOp *op = R_NEW (RAnalOp);
	r_anal_op_init (op);
	return op;
}

R_API RList *r_anal_op_list_new(void) {
	RList *list = r_list_new ();
	if (list) {
		list->free = &r_anal_op_free;
	}
	return list;
}

R_API void r_anal_op_init(RAnalOp *op) {
	if (op) {
		memset (op, 0, sizeof (*op));
		op->addr = UT64_MAX;
		op->jump = UT64_MAX;
		op->fail = UT64_MAX;
		op->ptr = UT64_MAX;
		op->refptr = 0;
		op->val = UT64_MAX;
		op->disp = UT64_MAX;
	}
}

R_API bool r_anal_op_fini(RAnalOp *op) {
	if (!op) {
		return false;
	}
	r_anal_value_free (op->src[0]);
	r_anal_value_free (op->src[1]);
	r_anal_value_free (op->src[2]);
	op->src[0] = NULL;
	op->src[1] = NULL;
	op->src[2] = NULL;
	r_anal_value_free (op->dst);
	op->dst = NULL;
	r_list_free (op->access);
	op->access = NULL;
	r_strbuf_fini (&op->opex);
	r_strbuf_fini (&op->esil);
	r_anal_switch_op_free (op->switch_op);
	op->switch_op = NULL;
	R_FREE (op->mnemonic);
	return true;
}

R_API void r_anal_op_free(void *_op) {
	if (!_op) {
		return;
	}
	r_anal_op_fini (_op);
	memset (_op, 0, sizeof (RAnalOp));
	free (_op);
}

static int defaultCycles(RAnalOp *op) {
	switch (op->type) {
	case R_ANAL_OP_TYPE_PUSH:
	case R_ANAL_OP_TYPE_POP:
	case R_ANAL_OP_TYPE_STORE:
	case R_ANAL_OP_TYPE_LOAD:
		return 2;
	case R_ANAL_OP_TYPE_LEA:
	case R_ANAL_OP_TYPE_MOV:
	case R_ANAL_OP_TYPE_NOP:
		return 1;
	case R_ANAL_OP_TYPE_TRAP:
	case R_ANAL_OP_TYPE_SWI:
		return 4;
	case R_ANAL_OP_TYPE_SYNC:
		return 4;
	case R_ANAL_OP_TYPE_RET:
	case R_ANAL_OP_TYPE_JMP:
	case R_ANAL_OP_TYPE_RJMP:
	case R_ANAL_OP_TYPE_CALL:
		return 4;
	default:
		return 1;
	}
}

R_API int r_anal_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
	r_anal_op_init (op);
	r_return_val_if_fail (anal && op && len > 0, -1);

	int ret = R_MIN (2, len);
	if (len > 0 && anal->cur && anal->cur->op) {
		//use core binding to set asm.bits correctly based on the addr
		//this is because of the hassle of arm/thumb
		if (anal && anal->coreb.archbits) {
			anal->coreb.archbits (anal->coreb.core, addr);
		}
		if (anal->pcalign && addr % anal->pcalign) {
			op->type = R_ANAL_OP_TYPE_ILL;
			op->addr = addr;
			// eprintf ("Unaligned instruction for %d bits at 0x%"PFMT64x"\n", anal->bits, addr);
			op->size = 1;
			return -1;
		}
		ret = anal->cur->op (anal, op, addr, data, len, mask);
		if (ret < 1) {
			op->type = R_ANAL_OP_TYPE_ILL;
		}
		/* special case some conditionals */
		if (op->type & R_ANAL_OP_TYPE_COND && op->cond == R_ANAL_COND_AL) {
			/* Always conditional. */
			op->cond = 0;
			op->type &= ~R_ANAL_OP_TYPE_COND;
		} else if (op->type & R_ANAL_OP_TYPE_COND && op->cond == R_ANAL_COND_NV) {
			/* Never conditional. */
			op->cond = 0;
			op->type = R_ANAL_OP_TYPE_NOP;
		}
		op->addr = addr;
		/* consider at least 1 byte to be part of the opcode */
		if (op->nopcode < 1) {
			op->nopcode = 1;
		}
	} else if (!memcmp (data, "\xff\xff\xff\xff", R_MIN (4, len))) {
		op->type = R_ANAL_OP_TYPE_ILL;
	} else {
		op->type = R_ANAL_OP_TYPE_MOV;
		if (op->cycles == 0) {
			op->cycles = defaultCycles (op);
		}
	}
	if (!op->mnemonic && (mask & R_ANAL_OP_MASK_DISASM)) {
		if (anal->verbose) {
			eprintf ("Warning: unhandled R_ANAL_OP_MASK_DISASM in r_anal_op\n");
		}
        }
	if (mask & R_ANAL_OP_MASK_HINT) {
		RAnalHint *hint = r_anal_hint_get (anal, addr);
		if (hint) {
			r_anal_op_hint (op, hint);
			r_anal_hint_free (hint);
		}
	}
	return ret;
}

R_API RAnalOp *r_anal_op_copy(RAnalOp *op) {
	RAnalOp *nop = R_NEW0 (RAnalOp);
	if (!nop) {
		return NULL;
	}
	*nop = *op;
	if (op->mnemonic) {
		nop->mnemonic = strdup (op->mnemonic);
		if (!nop->mnemonic) {
			free (nop);
			return NULL;
		}
	} else {
		nop->mnemonic = NULL;
	}
	nop->src[0] = r_anal_value_copy (op->src[0]);
	nop->src[1] = r_anal_value_copy (op->src[1]);
	nop->src[2] = r_anal_value_copy (op->src[2]);
	nop->dst = r_anal_value_copy (op->dst);
	if (op->access) {
		RListIter *it;
		RAnalValue *val;
		RList *naccess = r_list_newf ((RListFree)r_anal_value_free);
		r_list_foreach (op->access, it, val) {
			r_list_append (naccess, r_anal_value_copy (val));
		}
		nop->access = naccess;
	}
	r_strbuf_init (&nop->esil);
	r_strbuf_copy (&nop->esil, &op->esil);
	return nop;
}

R_API bool r_anal_op_nonlinear(int t) {
	t &= R_ANAL_OP_TYPE_MASK;
	switch (t) {
	//call
	case R_ANAL_OP_TYPE_CALL:
	case R_ANAL_OP_TYPE_RCALL:
	case R_ANAL_OP_TYPE_ICALL:
	case R_ANAL_OP_TYPE_UCALL:
	case R_ANAL_OP_TYPE_IRCALL:
	case R_ANAL_OP_TYPE_UCCALL:
	// jmp
	case R_ANAL_OP_TYPE_JMP:
	case R_ANAL_OP_TYPE_MJMP:
	case R_ANAL_OP_TYPE_UJMP:
	case R_ANAL_OP_TYPE_CJMP:
	case R_ANAL_OP_TYPE_UCJMP:
	case R_ANAL_OP_TYPE_RJMP:
	case R_ANAL_OP_TYPE_IJMP:
	case R_ANAL_OP_TYPE_IRJMP:
	// trap| ill| unk
	case R_ANAL_OP_TYPE_TRAP:
	case R_ANAL_OP_TYPE_ILL:
	case R_ANAL_OP_TYPE_UNK:
	case R_ANAL_OP_TYPE_SWI:
	case R_ANAL_OP_TYPE_RET:
		return true;
	default:
		return false;
	}
}

R_API bool r_anal_op_ismemref(int t) {
	t &= R_ANAL_OP_TYPE_MASK;
	switch (t) {
	case R_ANAL_OP_TYPE_LOAD:
	case R_ANAL_OP_TYPE_MOV:
	case R_ANAL_OP_TYPE_STORE:
	case R_ANAL_OP_TYPE_LEA:
	case R_ANAL_OP_TYPE_CMP:
		return true;
	default:
		return false;
	}
}

static struct optype {
	int type;
	const char *name;
} optypes[] = {
	{ R_ANAL_OP_TYPE_IO, "io" },
	{ R_ANAL_OP_TYPE_ACMP, "acmp" },
	{ R_ANAL_OP_TYPE_ADD, "add" },
	{ R_ANAL_OP_TYPE_SYNC, "sync" },
	{ R_ANAL_OP_TYPE_AND, "and" },
	{ R_ANAL_OP_TYPE_CALL, "call" },
	{ R_ANAL_OP_TYPE_CCALL, "ccall" },
	{ R_ANAL_OP_TYPE_CJMP, "cjmp" },
	{ R_ANAL_OP_TYPE_MJMP, "mjmp" },
	{ R_ANAL_OP_TYPE_CMP, "cmp" },
	{ R_ANAL_OP_TYPE_IO, "cret" },
	{ R_ANAL_OP_TYPE_ILL, "ill" },
	{ R_ANAL_OP_TYPE_JMP, "jmp" },
	{ R_ANAL_OP_TYPE_LEA, "lea" },
	{ R_ANAL_OP_TYPE_LEAVE, "leave" },
	{ R_ANAL_OP_TYPE_LOAD, "load" },
	{ R_ANAL_OP_TYPE_NEW, "new" },
	{ R_ANAL_OP_TYPE_MOD, "mod" },
	{ R_ANAL_OP_TYPE_CMOV, "cmov" },
	{ R_ANAL_OP_TYPE_MOV, "mov" },
	{ R_ANAL_OP_TYPE_CAST, "cast" },
	{ R_ANAL_OP_TYPE_MUL, "mul" },
	{ R_ANAL_OP_TYPE_DIV, "div" },
	{ R_ANAL_OP_TYPE_NOP, "nop" },
	{ R_ANAL_OP_TYPE_NOT, "not" },
	{ R_ANAL_OP_TYPE_NULL  , "null" },
	{ R_ANAL_OP_TYPE_OR    , "or" },
	{ R_ANAL_OP_TYPE_POP   , "pop" },
	{ R_ANAL_OP_TYPE_PUSH  , "push" },
	{ R_ANAL_OP_TYPE_REP   , "rep" },
	{ R_ANAL_OP_TYPE_RET   , "ret" },
	{ R_ANAL_OP_TYPE_ROL   , "rol" },
	{ R_ANAL_OP_TYPE_ROR   , "ror" },
	{ R_ANAL_OP_TYPE_SAL   , "sal" },
	{ R_ANAL_OP_TYPE_SAR   , "sar" },
	{ R_ANAL_OP_TYPE_SHL   , "shl" },
	{ R_ANAL_OP_TYPE_SHR   , "shr" },
	{ R_ANAL_OP_TYPE_STORE , "store" },
	{ R_ANAL_OP_TYPE_SUB   , "sub" },
	{ R_ANAL_OP_TYPE_SWI   , "swi" },
	{ R_ANAL_OP_TYPE_CSWI  , "cswi" },
	{ R_ANAL_OP_TYPE_SWITCH, "switch" },
	{ R_ANAL_OP_TYPE_TRAP  , "trap" },
	{ R_ANAL_OP_TYPE_UCALL , "ucall" },
	{ R_ANAL_OP_TYPE_RCALL , "rcall" }, // needs to be changed
	{ R_ANAL_OP_TYPE_ICALL , "ucall" }, // needs to be changed
	{ R_ANAL_OP_TYPE_IRCALL, "ucall" }, // needs to be changed
	{ R_ANAL_OP_TYPE_UCCALL, "uccall" },
	{ R_ANAL_OP_TYPE_UCJMP , "ucjmp" },
	{ R_ANAL_OP_TYPE_UJMP  , "ujmp" },
	{ R_ANAL_OP_TYPE_RJMP  , "rjmp" }, // needs to be changed
	{ R_ANAL_OP_TYPE_IJMP  , "ujmp" }, // needs to be changed
	{ R_ANAL_OP_TYPE_IRJMP , "ujmp" }, // needs to be changed
	{ R_ANAL_OP_TYPE_UNK   , "unk" },
	{ R_ANAL_OP_TYPE_UPUSH , "upush" },
	{ R_ANAL_OP_TYPE_RPUSH , "rpush" },
	{ R_ANAL_OP_TYPE_XCHG  , "xchg" },
	{ R_ANAL_OP_TYPE_XOR   , "xor" },
	{ R_ANAL_OP_TYPE_CASE  , "case" },
	{ R_ANAL_OP_TYPE_CPL   , "cpl" },
	{ R_ANAL_OP_TYPE_CRYPTO, "crypto" },
	{0,NULL}
};

R_API int r_anal_optype_from_string(const char *type) {
	int i;
	for  (i = 0; optypes[i].name;i++) {
		if (!strcmp (optypes[i].name, type)) {
			return optypes[i].type;
		}
	}
	return -1;
}

R_API const char *r_anal_optype_to_string(int t) {
	bool once = true;
repeat:
	// TODO: delete
	switch (t) {
	case R_ANAL_OP_TYPE_IO    : return "io";
	case R_ANAL_OP_TYPE_ACMP  : return "acmp";
	case R_ANAL_OP_TYPE_ADD   : return "add";
	case R_ANAL_OP_TYPE_SYNC  : return "sync";
	case R_ANAL_OP_TYPE_AND   : return "and";
	case R_ANAL_OP_TYPE_CALL  : return "call";
	case R_ANAL_OP_TYPE_CCALL : return "ccall";
	case R_ANAL_OP_TYPE_CJMP  : return "cjmp";
	case R_ANAL_OP_TYPE_MJMP  : return "mjmp";
	case R_ANAL_OP_TYPE_CMP   : return "cmp";
	case R_ANAL_OP_TYPE_CRET  : return "cret";
	case R_ANAL_OP_TYPE_DIV   : return "div";
	case R_ANAL_OP_TYPE_ILL   : return "ill";
	case R_ANAL_OP_TYPE_JMP   : return "jmp";
	case R_ANAL_OP_TYPE_LEA   : return "lea";
	case R_ANAL_OP_TYPE_LEAVE : return "leave";
	case R_ANAL_OP_TYPE_LOAD  : return "load";
	case R_ANAL_OP_TYPE_NEW   : return "new";
	case R_ANAL_OP_TYPE_MOD   : return "mod";
	case R_ANAL_OP_TYPE_CMOV  : return "cmov";
	case R_ANAL_OP_TYPE_MOV   : return "mov";
	case R_ANAL_OP_TYPE_CAST  : return "cast";
	case R_ANAL_OP_TYPE_MUL   : return "mul";
	case R_ANAL_OP_TYPE_NOP   : return "nop";
	case R_ANAL_OP_TYPE_NOT   : return "not";
	case R_ANAL_OP_TYPE_NULL  : return "null";
	case R_ANAL_OP_TYPE_OR    : return "or";
	case R_ANAL_OP_TYPE_POP   : return "pop";
	case R_ANAL_OP_TYPE_PUSH  : return "push";
	case R_ANAL_OP_TYPE_RPUSH : return "rpush";
	case R_ANAL_OP_TYPE_REP   : return "rep";
	case R_ANAL_OP_TYPE_RET   : return "ret";
	case R_ANAL_OP_TYPE_ROL   : return "rol";
	case R_ANAL_OP_TYPE_ROR   : return "ror";
	case R_ANAL_OP_TYPE_SAL   : return "sal";
	case R_ANAL_OP_TYPE_SAR   : return "sar";
	case R_ANAL_OP_TYPE_SHL   : return "shl";
	case R_ANAL_OP_TYPE_SHR   : return "shr";
	case R_ANAL_OP_TYPE_STORE : return "store";
	case R_ANAL_OP_TYPE_SUB   : return "sub";
	case R_ANAL_OP_TYPE_SWI   : return "swi";
	case R_ANAL_OP_TYPE_CSWI  : return "cswi";
	case R_ANAL_OP_TYPE_SWITCH: return "switch";
	case R_ANAL_OP_TYPE_TRAP  : return "trap";
	case R_ANAL_OP_TYPE_UCALL : return "ucall";
	case R_ANAL_OP_TYPE_RCALL : return "rcall"; // needs to be changed
	case R_ANAL_OP_TYPE_ICALL : return "ucall"; // needs to be changed
	case R_ANAL_OP_TYPE_IRCALL: return "ucall"; // needs to be changed
	case R_ANAL_OP_TYPE_UCCALL: return "uccall";
	case R_ANAL_OP_TYPE_UCJMP : return "ucjmp";
	case R_ANAL_OP_TYPE_UJMP  : return "ujmp";
	case R_ANAL_OP_TYPE_RJMP  : return "rjmp"; // needs to be changed
	case R_ANAL_OP_TYPE_IJMP  : return "ujmp"; // needs to be changed
	case R_ANAL_OP_TYPE_IRJMP : return "ujmp"; // needs to be changed
	case R_ANAL_OP_TYPE_UNK   : return "unk";
	case R_ANAL_OP_TYPE_UPUSH : return "upush";
	case R_ANAL_OP_TYPE_XCHG  : return "xchg";
	case R_ANAL_OP_TYPE_XOR   : return "xor";
	case R_ANAL_OP_TYPE_CASE  : return "case";
	case R_ANAL_OP_TYPE_CPL   : return "cpl";
	case R_ANAL_OP_TYPE_CRYPTO: return "crypto";
	}
	if (once) {
		once = false;
		t &= R_ANAL_OP_TYPE_MASK; // ignore the modifier bits... we don't want this!
		goto repeat;
	}
	return "undefined";
}

R_API const char *r_anal_op_to_esil_string(RAnal *anal, RAnalOp *op) {
	return r_strbuf_get (&op->esil);
}

// TODO: use esil here?
R_API char *r_anal_op_to_string(RAnal *anal, RAnalOp *op) {
	RAnalBlock *bb;
	RAnalFunction *f;
	char *cstr, ret[128];
	char *r0 = r_anal_value_to_string (op->dst);
	char *a0 = r_anal_value_to_string (op->src[0]);
	char *a1 = r_anal_value_to_string (op->src[1]);
	if (!r0) {
		r0 = strdup ("?");
	}
	if (!a0) {
		a0 = strdup ("?");
	}
	if (!a1) {
		a1 = strdup ("?");
	}

	switch (op->type) {
	case R_ANAL_OP_TYPE_MOV:
		snprintf (ret, sizeof (ret), "%s = %s", r0, a0);
		break;
	case R_ANAL_OP_TYPE_CJMP:
		if ((bb = r_anal_bb_from_offset (anal, op->addr))) {
			cstr = r_anal_cond_to_string (bb->cond);
			snprintf (ret, sizeof (ret), "if (%s) goto 0x%"PFMT64x, cstr, op->jump);
			free (cstr);
		} else {
			snprintf (ret, sizeof (ret), "if (%s) goto 0x%"PFMT64x, "?", op->jump);
		}
		break;
	case R_ANAL_OP_TYPE_JMP:
		snprintf (ret, sizeof (ret), "goto 0x%"PFMT64x, op->jump);
		break;
	case R_ANAL_OP_TYPE_UJMP:
	case R_ANAL_OP_TYPE_RJMP:
	case R_ANAL_OP_TYPE_IJMP:
	case R_ANAL_OP_TYPE_IRJMP:
		snprintf (ret, sizeof (ret), "goto %s", r0);
		break;
	case R_ANAL_OP_TYPE_PUSH:
	case R_ANAL_OP_TYPE_UPUSH:
	case R_ANAL_OP_TYPE_RPUSH:
		snprintf (ret, sizeof (ret), "push %s", a0);
		break;
	case R_ANAL_OP_TYPE_POP:
		snprintf (ret, sizeof (ret), "pop %s", r0);
		break;
	case R_ANAL_OP_TYPE_UCALL:
	case R_ANAL_OP_TYPE_RCALL:
	case R_ANAL_OP_TYPE_ICALL:
	case R_ANAL_OP_TYPE_IRCALL:
		snprintf (ret, sizeof (ret), "%s()", r0);
		break;
	case R_ANAL_OP_TYPE_CALL:
		f = r_anal_get_fcn_in (anal, op->jump, R_ANAL_FCN_TYPE_NULL);
		if (f) {
			snprintf (ret, sizeof (ret), "%s()", f->name);
		} else {
			snprintf (ret, sizeof (ret), "0x%"PFMT64x"()", op->jump);
		}
		break;
	case R_ANAL_OP_TYPE_CCALL:
		f = r_anal_get_fcn_in (anal, op->jump, R_ANAL_FCN_TYPE_NULL);
		if ((bb = r_anal_bb_from_offset (anal, op->addr))) {
			cstr = r_anal_cond_to_string (bb->cond);
			if (f) {
				snprintf (ret, sizeof (ret), "if (%s) %s()", cstr, f->name);
			} else {
				snprintf (ret, sizeof (ret), "if (%s) 0x%" PFMT64x "()", cstr, op->jump);
			}
			free (cstr);
		} else {
			if (f) {
				snprintf (ret, sizeof (ret), "if (unk) %s()", f->name);
			} else {
				snprintf (ret, sizeof (ret), "if (unk) 0x%" PFMT64x "()", op->jump);
			}
		}
		break;
	case R_ANAL_OP_TYPE_ADD:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s += %s", r0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s + %s", r0, a0, a1);
		}
		break;
	case R_ANAL_OP_TYPE_SUB:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s -= %s", r0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s - %s", r0, a0, a1);
		}
		break;
	case R_ANAL_OP_TYPE_MUL:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s *= %s", r0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s * %s", r0, a0, a1);
		}
		break;
	case R_ANAL_OP_TYPE_DIV:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s /= %s", r0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s / %s", r0, a0, a1);
		}
		break;
	case R_ANAL_OP_TYPE_AND:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s &= %s", r0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s & %s", r0, a0, a1);
		}
		break;
	case R_ANAL_OP_TYPE_OR:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s |= %s", r0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s | %s", r0, a0, a1);
		}
		break;
	case R_ANAL_OP_TYPE_XOR:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s ^= %s", r0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s ^ %s", r0, a0, a1);
		}
		break;
	case R_ANAL_OP_TYPE_LEA:
		snprintf (ret, sizeof (ret), "%s -> %s", r0, a0);
		break;
	case R_ANAL_OP_TYPE_CMP:
		memcpy (ret, ";", 2);
		break;
	case R_ANAL_OP_TYPE_NOP:
		memcpy (ret, "nop", 4);
		break;
	case R_ANAL_OP_TYPE_RET:
		memcpy (ret, "ret", 4);
		break;
	case R_ANAL_OP_TYPE_CRET:
		if ((bb = r_anal_bb_from_offset (anal, op->addr))) {
			cstr = r_anal_cond_to_string (bb->cond);
			snprintf (ret, sizeof (ret), "if (%s) ret", cstr);
			free (cstr);
		} else {
			strcpy (ret, "if (unk) ret");
		}
		break;
	case R_ANAL_OP_TYPE_LEAVE:
		memcpy (ret, "leave", 6);
		break;
	case R_ANAL_OP_TYPE_MOD:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s %%= %s", r0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s %% %s", r0, a0, a1);
		}
		break;
	case R_ANAL_OP_TYPE_XCHG:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "tmp = %s; %s = %s; %s = tmp", r0, r0, a0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s ^ %s", r0, a0, a1);
		}
		break;
	case R_ANAL_OP_TYPE_ROL:
	case R_ANAL_OP_TYPE_ROR:
	case R_ANAL_OP_TYPE_SWITCH:
	case R_ANAL_OP_TYPE_CASE:
		eprintf ("Command not implemented.\n");
		free (r0);
		free (a0);
		free (a1);
		return NULL;
	default:
		free (r0);
		free (a0);
		free (a1);
		return NULL;
	}
	free (r0);
	free (a0);
	free (a1);
	return strdup (ret);
}

R_API const char *r_anal_stackop_tostring(int s) {
	switch (s) {
	case R_ANAL_STACK_NULL:
		return "null";
	case R_ANAL_STACK_NOP:
		return "nop";
	case R_ANAL_STACK_INC:
		return "inc";
	case R_ANAL_STACK_GET:
		return "get";
	case R_ANAL_STACK_SET:
		return "set";
	case R_ANAL_STACK_RESET:
		return "reset";
	}
	return "unk";
}

R_API const char *r_anal_op_family_to_string(int n) {
	switch (n) {
	case R_ANAL_OP_FAMILY_UNKNOWN: return "unk";
	case R_ANAL_OP_FAMILY_CPU: return "cpu";
	case R_ANAL_OP_FAMILY_SECURITY: return "sec";
	case R_ANAL_OP_FAMILY_FPU: return "fpu";
	case R_ANAL_OP_FAMILY_MMX: return "mmx";
	case R_ANAL_OP_FAMILY_SSE: return "sse";
	case R_ANAL_OP_FAMILY_PRIV: return "priv";
	case R_ANAL_OP_FAMILY_THREAD: return "thrd";
	case R_ANAL_OP_FAMILY_CRYPTO: return "crpt";
	case R_ANAL_OP_FAMILY_IO: return "io";
	case R_ANAL_OP_FAMILY_VIRT: return "virt";
	}
	return NULL;
}

R_API int r_anal_op_family_from_string(const char *f) {
	struct op_family {
		const char *name;
		int id;
	};
	static const struct op_family of[] = {
		{"cpu", R_ANAL_OP_FAMILY_CPU},
		{"fpu", R_ANAL_OP_FAMILY_FPU},
		{"mmx", R_ANAL_OP_FAMILY_MMX},
		{"sse", R_ANAL_OP_FAMILY_SSE},
		{"priv", R_ANAL_OP_FAMILY_PRIV},
		{"virt", R_ANAL_OP_FAMILY_VIRT},
		{"crpt", R_ANAL_OP_FAMILY_CRYPTO},
		{"io", R_ANAL_OP_FAMILY_IO},
		{"sec", R_ANAL_OP_FAMILY_SECURITY},
		{"thread", R_ANAL_OP_FAMILY_THREAD},
	};

	int i;
	for (i = 0; i < sizeof (of) / sizeof (of[0]); i ++) {
		if (!strcmp (f, of[i].name)) {
			return of[i].id;
		}
	}
	return R_ANAL_OP_FAMILY_UNKNOWN;
}

/* apply hint to op, return the number of hints applied */
R_API int r_anal_op_hint(RAnalOp *op, RAnalHint *hint) {
	int changes = 0;
	if (hint) {
		if (hint->val != UT64_MAX) {
			op->val = hint->val;
			changes++;
		}
		if (hint->type > 0) {
			op->type = hint->type;
			changes++;
		}
		if (hint->jump != UT64_MAX) {
			op->jump = hint->jump;
			changes++;
		}
		if (hint->fail != UT64_MAX) {
			op->fail = hint->fail;
			changes++;
		}
		if (hint->opcode) {
			/* XXX: this is not correct */
			free (op->mnemonic);
			op->mnemonic = strdup (hint->opcode);
			changes++;
		}
		if (hint->esil) {
			r_strbuf_set (&op->esil, hint->esil);
			changes++;
		}
		if (hint->size) {
			op->size = hint->size;
			changes++;
		}
	}
	return changes;
}

// returns the '33' in 'rax + 33'
// returns value for the given register name in specific address / range
// imho this should not iterate, should be just a helper to get that value
R_API int r_anal_op_reg_delta(RAnal *anal, ut64 addr, const char *name) {
	ut8 buf[32];
	anal->iob.read_at (anal->iob.io, addr, buf, sizeof (buf));
	RAnalOp op = { 0 };
	if (r_anal_op (anal, &op, addr, buf, sizeof (buf), R_ANAL_OP_MASK_ALL) > 0) {
		if (op.dst && op.dst->reg && op.dst->reg->name && (!name || !strcmp (op.dst->reg->name, name))) {
			if (op.src[0]) {
				return op.src[0]->delta;
			}
		}
	}
	return 0;
}
