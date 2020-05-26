/* radare - LGPL - Copyright 2010-2020 - nibble, alvaro, pancake */

#include <r_anal.h>
#include <r_parse.h>
#include <r_util.h>
#include <r_list.h>

#define READ_AHEAD 1
#define SDB_KEY_BB "bb.0x%"PFMT64x ".0x%"PFMT64x
// XXX must be configurable by the user
#define JMPTBLSZ 512
#define JMPTBL_LEA_SEARCH_SZ 64
#define JMPTBL_MAXFCNSIZE 4096
#define BB_ALIGN 0x10
#define MAX_SCAN_SIZE 0x7ffffff

/* speedup analysis by removing some function overlapping checks */
#define JAYRO_04 1

// 16 KB is the maximum size for a basic block
#define MAX_FLG_NAME_SIZE 64

#define FIX_JMP_FWD 0
#define D if (a->verbose)

// 64KB max size
// 256KB max function size
#define MAX_FCN_SIZE (1024 * 256)

#define DB a->sdb_fcns
#define EXISTS(x, ...) snprintf (key, sizeof (key) - 1, x, ## __VA_ARGS__), sdb_exists (DB, key)
#define SETKEY(x, ...) snprintf (key, sizeof (key) - 1, x, ## __VA_ARGS__);

typedef struct fcn_tree_iter_t {
	int len;
	RBNode *cur;
	RBNode *path[R_RBTREE_MAX_HEIGHT];
} FcnTreeIter;

R_API const char *r_anal_fcntype_tostring(int type) {
	switch (type) {
	case R_ANAL_FCN_TYPE_NULL: return "null";
	case R_ANAL_FCN_TYPE_FCN: return "fcn";
	case R_ANAL_FCN_TYPE_LOC: return "loc";
	case R_ANAL_FCN_TYPE_SYM: return "sym";
	case R_ANAL_FCN_TYPE_IMP: return "imp";
	case R_ANAL_FCN_TYPE_INT: return "int"; // interrupt
	case R_ANAL_FCN_TYPE_ROOT: return "root";
	}
	return "unk";
}

#if READ_AHEAD
static ut64 cache_addr = UT64_MAX;

// TODO: move into io :?
static int read_ahead(RAnal *anal, ut64 addr, ut8 *buf, int len) {
	static ut8 cache[1024];
	const int cache_len = sizeof (cache);

	if (len < 1) {
		return 0;
	}
	if (len > cache_len) {
		int a = anal->iob.read_at (anal->iob.io, addr, buf, len); // double read
		memcpy (cache, buf, cache_len);
		cache_addr = addr;
		return a;
	}

	ut64 addr_end = UT64_ADD_OVFCHK (addr, len)? UT64_MAX: addr + len;
	ut64 cache_addr_end = UT64_ADD_OVFCHK (cache_addr, cache_len)? UT64_MAX: cache_addr + cache_len;
	bool isCached = ((addr != UT64_MAX) && (addr >= cache_addr) && (addr_end < cache_addr_end));
	if (isCached) {
		memcpy (buf, cache + (addr - cache_addr), len);
	} else {
		anal->iob.read_at (anal->iob.io, addr, cache, sizeof (cache));
		memcpy (buf, cache, len);
		cache_addr = addr;
	}
	return len;
}
#else
static int read_ahead(RAnal *anal, ut64 addr, ut8 *buf, int len) {
	return anal->iob.read_at (anal->iob.io, addr, buf, len);
}
#endif

R_API void r_anal_fcn_invalidate_read_ahead_cache() {
#if READ_AHEAD
	cache_addr = UT64_MAX;
#endif
}

static int cmpaddr(const void *_a, const void *_b) {
	const RAnalBlock *a = _a, *b = _b;
	return a->addr > b->addr ? 1 : (a->addr < b->addr ? -1 : 0);
}

R_API int r_anal_function_resize(RAnalFunction *fcn, int newsize) {
	RAnal *anal = fcn->anal;
	RAnalBlock *bb;
	RListIter *iter, *iter2;

	r_return_val_if_fail (fcn, false);

	if (newsize < 1) {
		return false;
	}

	// XXX this is something we should probably do for all the archs
	bool is_arm = anal->cur->arch && !strncmp (anal->cur->arch, "arm", 3);
	if (is_arm) {
		return true;
	}

	ut64 eof = fcn->addr + newsize;
	r_list_foreach_safe (fcn->bbs, iter, iter2, bb) {
		if (bb->addr >= eof) {
			r_anal_function_remove_block (fcn, bb);
			continue;
		}
		if (bb->addr + bb->size >= eof) {
			r_anal_block_set_size (bb, eof - bb->addr);
		}
		if (bb->jump != UT64_MAX && bb->jump >= eof) {
			bb->jump = UT64_MAX;
		}
		if (bb->fail != UT64_MAX && bb->fail >= eof) {
			bb->fail = UT64_MAX;
		}
	}
	return true;
}

// Create a new 0-sized basic block inside the function
static RAnalBlock *fcn_append_basic_block(RAnal *anal, RAnalFunction *fcn, ut64 addr) {
	RAnalBlock *bb = r_anal_create_block (anal, addr, 0);
	if (!bb) {
		return NULL;
	}
	r_anal_function_add_block (fcn, bb);
	bb->parent_stackptr = fcn->stack;
	return bb;
}

#define gotoBeach(x) ret = x; goto beach;

static bool isInvalidMemory(RAnal *anal, const ut8 *buf, int len) {
	if (anal->opt.nonull > 0) {
		int i;
		const int count = R_MIN (len, anal->opt.nonull);
		for (i = 0; i < count; i++) {
			if (buf[i]) {
				break;
			}
		}
		if (i == count) {
			return true;
		}
	}
	return !memcmp (buf, "\xff\xff\xff\xff", R_MIN (len, 4));
}

static bool isSymbolNextInstruction(RAnal *anal, RAnalOp *op) {
	r_return_val_if_fail (anal && op && anal->flb.get_at, false);

	RFlagItem *fi = anal->flb.get_at (anal->flb.f, op->addr + op->size, false);
	return (fi && fi->name && (strstr (fi->name, "imp.") || strstr (fi->name, "sym.")
			|| strstr (fi->name, "entry") || strstr (fi->name, "main")));
}

static bool is_delta_pointer_table(RAnal *anal, RAnalFunction *fcn, ut64 addr, ut64 lea_ptr, ut64 *jmptbl_addr, RAnalOp *jmp_aop) {
	int i;
	ut64 dst;
	st32 jmptbl[64] = {0};
	/* check if current instruction is followed by an ujmp */
	ut8 buf[JMPTBL_LEA_SEARCH_SZ];
	RAnalOp *aop = jmp_aop;
	RAnalOp mov_aop = {0};
	RAnalOp add_aop = {0};

	read_ahead (anal, addr, (ut8*)buf, sizeof (buf));
	bool isValid = false;
	for (i = 0; i + 8 < JMPTBL_LEA_SEARCH_SZ; i++) {
		ut64 at = addr + i;
		int left = JMPTBL_LEA_SEARCH_SZ - i;
		int len = r_anal_op (anal, aop, at, buf + i, left, R_ANAL_OP_MASK_BASIC | R_ANAL_OP_MASK_HINT);
		if (len < 1) {
			len = 1;
		}
		if (aop->type == R_ANAL_OP_TYPE_UJMP || aop->type == R_ANAL_OP_TYPE_RJMP) {
			isValid = true;
			break;
		}
		if (aop->type == R_ANAL_OP_TYPE_MOV) {
			mov_aop = *aop;
		}
		if (aop->type == R_ANAL_OP_TYPE_ADD) {
			add_aop = *aop;
		}
		r_anal_op_fini (aop);
		i += len - 1;
	}
	if (!isValid) {
		return false;
	}

	// check if we have a msvc 19xx style jump table using rva table entries
	// lea reg1, [base_addr]
	// mov reg2, sword [reg1 + tbl_off*4 + tbl_loc_off]
	// add reg2, reg1
	// jmp reg2
	if (mov_aop.type && add_aop.type && mov_aop.addr < add_aop.addr && add_aop.addr < jmp_aop->addr
	    && mov_aop.disp && mov_aop.disp != UT64_MAX) {
		// disp in this case should be tbl_loc_off
		*jmptbl_addr += mov_aop.disp;
	}
#if 0
	// required for the last jmptbl.. but seems to work without it and breaks other tests
	if (mov_aop.type && mov_aop.ptr) {
		*jmptbl_addr += mov_aop.ptr;
		// absjmptbl
		lea_ptr = mov_aop.ptr;
	}
#endif
	/* check if jump table contains valid deltas */
	read_ahead (anal, *jmptbl_addr, (ut8 *)&jmptbl, 64);
	for (i = 0; i < 3; i++) {
		dst = lea_ptr + (st32)r_read_le32 (jmptbl);
		if (!anal->iob.is_valid_offset (anal->iob.io, dst, 0)) {
			return false;
		}
		if (dst > fcn->addr + JMPTBL_MAXFCNSIZE) {
			return false;
		}
		if (anal->opt.jmpabove && dst < (fcn->addr < JMPTBL_MAXFCNSIZE ? 0 : fcn->addr - JMPTBL_MAXFCNSIZE)) {
			return false;
		}
	}
	return true;
}

static ut64 try_get_cmpval_from_parents(RAnal * anal, RAnalFunction *fcn, RAnalBlock *my_bb, const char * cmp_reg) {
	r_return_val_if_fail (fcn && fcn->bbs && cmp_reg, UT64_MAX);
	RListIter *iter;
	RAnalBlock *tmp_bb;
	r_list_foreach (fcn->bbs, iter, tmp_bb) {
		if (tmp_bb->jump == my_bb->addr || tmp_bb->fail == my_bb->addr) {
			if (tmp_bb->cmpreg == cmp_reg) {
				return tmp_bb->cmpval;
			}
		}
	}
	return UT64_MAX;
}

static bool regs_exist(RAnalValue *src, RAnalValue *dst) {
	r_return_val_if_fail (src && dst, false);
	return src->reg && dst->reg && src->reg->name && dst->reg->name;
}

// 0 if not skipped; 1 if skipped; 2 if skipped before
static int skip_hp(RAnal *anal, RAnalFunction *fcn, RAnalOp *op, RAnalBlock *bb, ut64 addr,
                   char *tmp_buf, int oplen, int un_idx, int *idx) {
	// this step is required in order to prevent infinite recursion in some cases
	if ((addr + un_idx - oplen) == fcn->addr) {
		// use addr instead of op->addr to mark repeat
		if (!anal->flb.exist_at (anal->flb.f, "skip", 4, addr)) {
			snprintf (tmp_buf + 5, MAX_FLG_NAME_SIZE - 6, "%"PFMT64u, addr);
			anal->flb.set (anal->flb.f, tmp_buf, addr, oplen);
			fcn->addr += oplen;
			r_anal_block_relocate (bb, bb->addr + oplen, bb->size - oplen);
			*idx = un_idx;
			return 1;
		}
		return 2;
	}
	return 0;
}

static bool purity_checked(HtUP *ht, RAnalFunction *fcn) {
	bool checked;
	ht_up_find (ht, fcn->addr, &checked);
	return checked;
}

/*
 * Checks whether a given function is pure and sets its 'is_pure' field.
 * This function marks fcn 'not pure' if fcn, or any function called by fcn, accesses data
 * from outside, even if it only READS it.
 * Probably worth changing it in the future, so that it marks fcn 'impure' only when it
 * (or any function called by fcn) MODIFIES external data.
 */
static void check_purity(HtUP *ht, RAnalFunction *fcn) {
	RListIter *iter;
	RList *refs = r_anal_function_get_refs (fcn);
	RAnalRef *ref;
	ht_up_insert (ht, fcn->addr, NULL);
	fcn->is_pure = true;
	r_list_foreach (refs, iter, ref) {
		if (ref->type == R_ANAL_REF_TYPE_CALL || ref->type == R_ANAL_REF_TYPE_CODE) {
			RAnalFunction *called_fcn = r_anal_get_fcn_in (fcn->anal, ref->addr, 0);
			if (!called_fcn) {
				continue;
			}
			if (!purity_checked (ht, called_fcn)) {
				check_purity (ht, called_fcn);
			}
			if (!called_fcn->is_pure) {
				fcn->is_pure = false;
				break;
			}
		}
		if (ref->type == R_ANAL_REF_TYPE_DATA) {
			fcn->is_pure = false;
			break;
		}
	}
	r_list_free (refs);
}

typedef struct {
	ut64 op_addr;
	ut64 leaddr;
} leaddr_pair;

static RAnalBlock *bbget(RAnal *anal, ut64 addr, bool jumpmid) {
	RList *intersecting = r_anal_get_blocks_in (anal, addr);
	RListIter *iter;
	RAnalBlock *bb;

	RAnalBlock *ret = NULL;
	r_list_foreach (intersecting, iter, bb) {
		ut64 eaddr = bb->addr + bb->size;
		if (((bb->addr >= eaddr && addr == bb->addr)
		     || r_anal_block_contains (bb, addr))
		    && (!jumpmid || r_anal_block_op_starts_at (bb, addr))) {
			ret = bb;
			break;
		}
	}
	r_list_free (intersecting);
	return ret;
}

static bool fcn_takeover_block_recursive_cb(RAnalBlock *block, void *user) {
	RAnalFunction *our_fcn = user;
	r_anal_block_ref (block);
	while (!r_list_empty (block->fcns)) {
		RAnalFunction *other_fcn = r_list_first (block->fcns);
		r_anal_function_remove_block (other_fcn, block);
	}
	r_anal_function_add_block (our_fcn, block);
	r_anal_block_unref (block);
	return true;
}

// Remove block and all of its recursive successors from all its functions and add them only to fcn
static void fcn_takeover_block_recursive(RAnalFunction *fcn, RAnalBlock *start_block) {
	r_anal_block_recurse (start_block, fcn_takeover_block_recursive_cb, fcn);
}

static const char *retpoline_reg(RAnal *anal, ut64 addr) {
	RFlagItem *flag = anal->flag_get (anal->flb.f, addr);
	if (flag) {
		const char *token = "x86_indirect_thunk_";
		const char *thunk = strstr (flag->name, token);
		if (thunk) {
			return thunk + strlen (token);
		}
	}
#if 0
// TODO: implement following code analysis check for stripped binaries:
// 1) op(addr).type == CALL
// 2) call_dest = op(addr).addr
// 3) op(call_dest).type == STORE
// 4) op(call_dest + op(call_dest).size).type == RET
[0x00000a65]> pid 6
0x00000a65  sym.__x86_indirect_thunk_rax:
0x00000a65  .------- e807000000  call 0xa71
0x00000a6a  |              f390  pause
0x00000a6c  |            0faee8  lfence
0x00000a6f  |              ebf9  jmp 0xa6a
0x00000a71  `---->     48890424  mov qword [rsp], rax
0x00000a75                   c3  ret
#endif
	return NULL;
}

static void analyze_retpoline(RAnal *anal, RAnalOp *op) {
	if (anal->opt.retpoline) {
		const char *rr = retpoline_reg (anal, op->jump);
		if (rr) {
			op->type = R_ANAL_OP_TYPE_RJMP;
			op->reg = rr;
		}
	}
}

static inline bool op_is_set_bp(RAnalOp *op, const char *bp_reg, const char *sp_reg) {
	bool has_dst_reg = op->dst && op->dst->reg && op->dst->reg->name;
	bool has_src_reg = op->src[0] && op->src[0]->reg && op->src[0]->reg->name;
	if (has_dst_reg && has_src_reg) {
		return !strcmp (bp_reg, op->dst->reg->name) && !strcmp (sp_reg, op->src[0]->reg->name);
	}
	return false;
}

static int fcn_recurse(RAnal *anal, RAnalFunction *fcn, ut64 addr, ut64 len, int depth) {
	const int continue_after_jump = anal->opt.afterjmp;
	const int addrbytes = anal->iob.io ? anal->iob.io->addrbytes : 1;
	char *last_reg_mov_lea_name = NULL;
	RAnalBlock *bb = NULL;
	RAnalBlock *bbg = NULL;
	int ret = R_ANAL_RET_END, skip_ret = 0;
	bool overlapped = false;
	RAnalOp op = {0};
	int oplen, idx = 0;
	static ut64 cmpval = UT64_MAX; // inherited across functions, otherwise it breaks :?
	bool varset = false;
	struct {
		int cnt;
		int idx;
		int after;
		int pending;
		int adjust;
		int un_idx; // delay.un_idx
	} delay = {
		0
	};
	bool is_arm = anal->cur->arch && !strncmp (anal->cur->arch, "arm", 3);
	bool is_riscv = anal->cur->arch && !strcmp (anal->cur->arch, "riscv");
	char tmp_buf[MAX_FLG_NAME_SIZE + 5] = "skip";
	bool is_x86 = is_arm ? false: anal->cur->arch && !strncmp (anal->cur->arch, "x86", 3);
	bool is_amd64 = is_x86 ? fcn->cc && !strcmp (fcn->cc, "amd64") : false;
	bool is_dalvik = is_x86? false: anal->cur->arch && !strncmp (anal->cur->arch, "dalvik", 6);
	RRegItem *variadic_reg = NULL;
	if (is_amd64) {
		variadic_reg = r_reg_get (anal->reg, "rax", R_REG_TYPE_GPR);
	}
	bool has_variadic_reg = !!variadic_reg;
	const char *bp_reg = anal->reg->name[R_REG_NAME_BP];
	const char *sp_reg = anal->reg->name[R_REG_NAME_SP];
	bool has_stack_regs = bp_reg && sp_reg;

	if (r_cons_is_breaked ()) {
		return R_ANAL_RET_END;
	}
	if (anal->sleep) {
		r_sys_usleep (anal->sleep);
	}

	if (depth < 1) {
		if (anal->verbose) {
			eprintf ("Anal went too deep at address 0x%"PFMT64x ".\n", addr);
		}
		return R_ANAL_RET_ERROR; // MUST BE TOO DEEP
	}

	// check if address is readable //:
	if (!anal->iob.is_valid_offset (anal->iob.io, addr, 0)) {
		if (addr != UT64_MAX && !anal->iob.io->va) {
			if (anal->verbose) {
				eprintf ("Invalid address 0x%"PFMT64x ". Try with io.va=true\n", addr);
			}
		}
		return R_ANAL_RET_ERROR; // MUST BE TOO DEEP
	}

	RAnalFunction *fcn_at_addr = r_anal_get_function_at (anal, addr);
	if (fcn_at_addr && fcn_at_addr != fcn) {
		return R_ANAL_RET_ERROR; // MUST BE NOT FOUND
	}

	RAnalBlock *existing_bb = bbget (anal, addr, anal->opt.jmpmid && is_x86);
	if (existing_bb) {
		bool existing_in_fcn = r_list_contains (existing_bb->fcns, fcn);
		existing_bb = r_anal_block_split (existing_bb, addr);
		if (!existing_in_fcn && existing_bb) {
			if (existing_bb->addr == fcn->addr) {
				// our function starts directly there, so we steal what is ours!
				fcn_takeover_block_recursive (fcn, existing_bb);
			}
		}
		if (existing_bb) {
			r_anal_block_unref (existing_bb);
		}
		if (anal->opt.recont) {
			return R_ANAL_RET_END;
		}
		if (anal->verbose) {
			eprintf ("r_anal_fcn_bb() fails at 0x%"PFMT64x ".\n", addr);
		}
		return R_ANAL_RET_ERROR; // MUST BE NOT DUP
	}

	bb = fcn_append_basic_block (anal, fcn, addr);
	// we checked before whether there is a bb at addr, so the create should have succeeded
	r_return_val_if_fail (bb, R_ANAL_RET_ERROR);

	if (!anal->leaddrs) {
		anal->leaddrs = r_list_newf (free);
		if (!anal->leaddrs) {
			eprintf ("Cannot create leaddr list\n");
			gotoBeach (R_ANAL_RET_ERROR);
		}
	}
	static ut64 lea_jmptbl_ip = UT64_MAX;
	ut64 last_reg_mov_lea_val = UT64_MAX;
	bool last_is_reg_mov_lea = false;
	bool last_is_push = false;
	bool last_is_mov_lr_pc = false;
	ut64 last_push_addr = UT64_MAX;
	if (anal->limit && addr + idx < anal->limit->from) {
		gotoBeach (R_ANAL_RET_END);
	}
	RAnalFunction *tmp_fcn = r_anal_get_fcn_in (anal, addr, 0);
	if (tmp_fcn) {
		// Checks if var is already analyzed at given addr
		RList *list = r_anal_var_all_list (anal, tmp_fcn);
		if (!r_list_empty (list)) {
			varset = true;
		}
		r_list_free (list);
	}
	ut64 movdisp = UT64_MAX; // used by jmptbl when coded as "mov reg,[R*4+B]"
	ut8 buf[32]; // 32 bytes is enough to hold any instruction.
	int maxlen = len * addrbytes;
	if (is_dalvik) {
		bool skipAnalysis = false;
		if (!strncmp (fcn->name, "sym.", 4)) {
			if (!strncmp (fcn->name + 4, "imp.", 4)) {
				skipAnalysis = true;
			} else if (strstr (fcn->name, "field")) {
				skipAnalysis = true;
			}
		}
		if (skipAnalysis) {
			ret = 0;
			gotoBeach (R_ANAL_RET_END);
		}
	}
	if ((maxlen - (addrbytes * idx)) > MAX_SCAN_SIZE) {
		if (anal->verbose) {
			eprintf ("Warning: Skipping large memory region.\n");
		}
		maxlen = 0;
	}

	while (addrbytes * idx < maxlen) {
		if (!last_is_reg_mov_lea) {
			free (last_reg_mov_lea_name);
			last_reg_mov_lea_name = NULL;
		}
		if (anal->limit && anal->limit->to <= addr + idx) {
			break;
		}
repeat:
		if (r_cons_is_breaked ()) {
			break;
		}
		ut32 at_delta = addrbytes * idx;
		ut64 at = addr + at_delta;
		ut64 bytes_read = R_MIN (len - at_delta, sizeof (buf));
		ret = read_ahead (anal, at, buf, bytes_read);

		if (ret < 0) {
			eprintf ("Failed to read\n");
			break;
		}
		if (isInvalidMemory (anal, buf, bytes_read)) {
			if (anal->verbose) {
				eprintf ("Warning: FFFF opcode at 0x%08"PFMT64x "\n", at);
			}
			gotoBeach (R_ANAL_RET_ERROR)
		}
		r_anal_op_fini (&op);
		if ((oplen = r_anal_op (anal, &op, at, buf, bytes_read, R_ANAL_OP_MASK_ESIL | R_ANAL_OP_MASK_VAL | R_ANAL_OP_MASK_HINT)) < 1) {
			if (anal->verbose) {
				eprintf ("Invalid instruction at 0x%"PFMT64x" with %d bits\n", at, anal->bits);
			}
			// gotoBeach (R_ANAL_RET_ERROR);
			// RET_END causes infinite loops somehow
			gotoBeach (R_ANAL_RET_END);
		}
		if (anal->opt.nopskip && fcn->addr == at) {
			RFlagItem *fi = anal->flb.get_at (anal->flb.f, addr, false);
			if (!fi || strncmp (fi->name, "sym.", 4)) {
				if ((addr + delay.un_idx - oplen) == fcn->addr) {
					if (r_anal_block_relocate (bb, bb->addr + oplen, bb->size - oplen)) {
						fcn->addr += oplen;
						idx = delay.un_idx;
						goto repeat;
					}
				}
			}
			switch (op.type & R_ANAL_OP_TYPE_MASK) {
			case R_ANAL_OP_TYPE_TRAP:
			case R_ANAL_OP_TYPE_ILL:
			case R_ANAL_OP_TYPE_NOP:
				if (r_anal_block_relocate (bb, at + op.size, bb->size)) {
					addr = at + op.size;
					fcn->addr = addr;
					goto repeat;
				}
			}
		}
		if (op.hint.new_bits) {
			r_anal_hint_set_bits (anal, op.jump, op.hint.new_bits);
		}
		if (idx > 0 && !overlapped) {
			bbg = bbget (anal, at, anal->opt.jmpmid && is_x86);
			if (bbg && bbg != bb) {
				bb->jump = at;
				if (anal->opt.jmpmid && is_x86) {
					// This happens when we purposefully walked over another block and overlapped it
					// and now we hit an offset where the instructions match again.
					// So we need to split the overwalked block.
					RAnalBlock *split = r_anal_block_split (bbg, at);
					r_anal_block_unref (split);
				}
				overlapped = true;
				if (anal->verbose) {
					eprintf ("Overlapped at 0x%08"PFMT64x "\n", at);
				}
			}
		}
		if (!overlapped) {
			ut64 newbbsize = bb->size + oplen;
			if (newbbsize > MAX_FCN_SIZE) {
				gotoBeach (R_ANAL_RET_ERROR);
			}
			r_anal_bb_set_offset (bb, bb->ninstr++, at - bb->addr);
			r_anal_block_set_size (bb, newbbsize);
			fcn->ninstr++;
		}
		if (anal->opt.trycatch) {
			const char *name = anal->coreb.getName (anal->coreb.core, at);
			if (name) {
				if (r_str_startswith (name, "try.") && r_str_endswith (name, ".from")) {
					char *handle = strdup (name);
					// handle = r_str_replace (handle, ".from", ".to", 0);
					ut64 from_addr = anal->coreb.numGet (anal->coreb.core, handle);
					handle = r_str_replace (handle, ".from", ".catch", 0);
					ut64 handle_addr = anal->coreb.numGet (anal->coreb.core, handle);
					bb->jump = at + oplen;
					if (from_addr != bb->addr) {
						bb->fail = handle_addr;
						ret = r_anal_fcn_bb (anal, fcn, handle_addr, depth);
						eprintf ("(%s) 0x%08"PFMT64x"\n", handle, handle_addr);
						if (bb->size == 0) {
							r_anal_function_remove_block (fcn, bb);
						}
						r_anal_block_unref (bb);
						bb = fcn_append_basic_block (anal, fcn, addr);
						if (!bb) {
							gotoBeach (R_ANAL_RET_ERROR);
						}
					}
				}
			}
		}
		idx += oplen;
		delay.un_idx = idx;
		if (anal->opt.delay && op.delay > 0 && !delay.pending) {
			// Handle first pass through a branch delay jump:
			// Come back and handle the current instruction later.
			// Save the location of it in `delay.idx`
			// note, we have still increased size of basic block
			// (and function)
			if (anal->verbose) {
				eprintf("Enter branch delay at 0x%08"PFMT64x ". bb->sz=%"PFMT64u"\n", at - oplen, bb->size);
			}
			delay.idx = idx - oplen;
			delay.cnt = op.delay;
			delay.pending = 1; // we need this in case the actual idx is zero...
			delay.adjust = !overlapped; // adjustment is required later to avoid double count
			continue;
		}

		if (delay.cnt > 0) {
			// if we had passed a branch delay instruction, keep
			// track of how many still to process.
			delay.cnt--;
			if (!delay.cnt) {
				if (anal->verbose) {
					eprintf("Last branch delayed opcode at 0x%08"PFMT64x ". bb->sz=%"PFMT64u"\n", addr + idx - oplen, bb->size);
				}
				delay.after = idx;
				idx = delay.idx;
				// At this point, we are still looking at the
				// last instruction in the branch delay group.
				// Next time, we will again be looking
				// at the original instruction that entered
				// the branch delay.
			}
		} else if (op.delay > 0 && delay.pending) {
			if (anal->verbose) {
				eprintf ("Revisit branch delay jump at 0x%08"PFMT64x ". bb->sz=%"PFMT64u"\n", addr + idx - oplen, bb->size);
			}
			// This is the second pass of the branch delaying opcode
			// But we also already counted this instruction in the
			// size of the current basic block, so we need to fix that
			if (delay.adjust) {
				r_anal_block_set_size (bb, (ut64)addrbytes * (ut64)delay.after);
				fcn->ninstr--;
				if (anal->verbose) {
					eprintf ("Correct for branch delay @ %08"PFMT64x " bb.addr=%08"PFMT64x " corrected.bb=%"PFMT64u" f.uncorr=%"PFMT64u"\n",
					addr + idx - oplen, bb->addr, bb->size, r_anal_function_linear_size (fcn));
				}
			}
			// Next time, we go to the opcode after the delay count
			// Take care not to use this below, use delay.un_idx instead ...
			idx = delay.after;
			delay.pending = delay.after = delay.idx = delay.adjust = 0;
		}
		// Note: if we got two branch delay instructions in a row due to an
		// compiler bug or junk or something it wont get treated as a delay
		switch (op.stackop) {
		case R_ANAL_STACK_INC:
			if (R_ABS (op.stackptr) < 8096) {
				fcn->stack += op.stackptr;
				if (fcn->stack > fcn->maxstack) {
					fcn->maxstack = fcn->stack;
				}
			}
			bb->stackptr += op.stackptr;
			break;
		case R_ANAL_STACK_RESET:
			bb->stackptr = 0;
			break;
		default:
			break;
		}
		if (op.ptr && op.ptr != UT64_MAX && op.ptr != UT32_MAX) {
			// swapped parameters wtf
			r_anal_xrefs_set (anal, op.addr, op.ptr, R_ANAL_REF_TYPE_DATA);
		}
		analyze_retpoline (anal, &op);
		switch (op.type & R_ANAL_OP_TYPE_MASK) {
		case R_ANAL_OP_TYPE_CMOV:
		case R_ANAL_OP_TYPE_MOV:
			last_is_reg_mov_lea = false;
			if (is_arm) { // mov lr, pc
				const char *esil = r_strbuf_get (&op.esil);
				if (!r_str_cmp (esil, "pc,lr,=", -1)) {
					last_is_mov_lr_pc = true;
				}
			}
			if (has_stack_regs && op_is_set_bp (&op, bp_reg, sp_reg)) {
				fcn->bp_off = fcn->stack;
			}
			// Is this a mov of immediate value into a register?
			if (op.dst && op.dst->reg && op.dst->reg->name && op.val > 0 && op.val != UT64_MAX) {
				free (last_reg_mov_lea_name);
				if ((last_reg_mov_lea_name = strdup (op.dst->reg->name))) {
					last_reg_mov_lea_val = op.val;
					last_is_reg_mov_lea = true;
				}
			}
			// skip mov reg, reg
			if (anal->opt.jmptbl) {
				if (op.scale && op.ireg) {
					movdisp = op.disp;
				}
			}
			if (anal->opt.hpskip && regs_exist (op.src[0], op.dst)
			&& !strcmp (op.src[0]->reg->name, op.dst->reg->name)) {
				skip_ret = skip_hp (anal, fcn, &op, bb, addr, tmp_buf, oplen, delay.un_idx, &idx);
				if (skip_ret == 1) {
					goto repeat;
				}
				if (skip_ret == 2) {
					gotoBeach (R_ANAL_RET_END);
				}
			}
			break;
		case R_ANAL_OP_TYPE_LEA:
			last_is_reg_mov_lea = false;
			// if first byte in op.ptr is 0xff, then set leaddr assuming its a jumptable
			{
				ut8 buf[4];
				anal->iob.read_at (anal->iob.io, op.ptr, buf, sizeof (buf));
				if ((buf[2] == 0xff || buf[2] == 0xfe) && buf[3] == 0xff) {
					leaddr_pair *pair = R_NEW (leaddr_pair);
					if (!pair) {
						eprintf ("Cannot create leaddr_pair\n");
						gotoBeach (R_ANAL_RET_ERROR);
					}
					pair->op_addr = op.addr;
					pair->leaddr = op.ptr; // XXX movdisp is dupped but seems to be trashed sometimes(?), better track leaddr separately
					r_list_append (anal->leaddrs, pair);
				}
				if (has_stack_regs && op_is_set_bp (&op, bp_reg, sp_reg)) {
					fcn->bp_off = fcn->stack - op.src[0]->delta;
				}
				if (op.dst && op.dst->reg && op.dst->reg->name && op.ptr > 0 && op.ptr != UT64_MAX) {
					free (last_reg_mov_lea_name);
					if ((last_reg_mov_lea_name = strdup (op.dst->reg->name))) {
						last_reg_mov_lea_val = op.ptr;
						last_is_reg_mov_lea = true;
					}
				}
			}
			// skip lea reg,[reg]
			if (anal->opt.hpskip && regs_exist (op.src[0], op.dst)
			&& !strcmp (op.src[0]->reg->name, op.dst->reg->name)) {
				skip_ret = skip_hp (anal, fcn, &op, bb, at, tmp_buf, oplen, delay.un_idx, &idx);
				if (skip_ret == 1) {
					goto repeat;
				}
				if (skip_ret == 2) {
					gotoBeach (R_ANAL_RET_END);
				}
			}
			if (anal->opt.jmptbl) {
				RAnalOp jmp_aop = {0};
				ut64 jmptbl_addr = op.ptr;
				if (is_delta_pointer_table (anal, fcn, op.addr, op.ptr, &jmptbl_addr, &jmp_aop)) {
					ut64 table_size, default_case = 0;
					// we require both checks here since try_get_jmptbl_info uses
					// BB info of the final jmptbl jump, which is no present with
					// is_delta_pointer_table just scanning ahead
					// try_get_delta_jmptbl_info doesn't work at times where the
					// lea comes after the cmp/default case cjmp, which can be
					// handled with try_get_jmptbl_info
					if (try_get_jmptbl_info (anal, fcn, jmp_aop.addr, bb, &table_size, &default_case)
						|| try_get_delta_jmptbl_info (anal, fcn, jmp_aop.addr, op.addr, &table_size, &default_case)) {
						ret = try_walkthrough_jmptbl (anal, fcn, bb, depth, jmp_aop.addr, jmptbl_addr, op.ptr, 4, table_size, default_case, 4);
						if (ret) {
							lea_jmptbl_ip = jmp_aop.addr;
						}
					}
				}
				r_anal_op_fini (&jmp_aop);
			}
			break;
		case R_ANAL_OP_TYPE_LOAD:
			if (anal->opt.loads) {
				if (anal->iob.is_valid_offset (anal->iob.io, op.ptr, 0)) {
					r_meta_set (anal, R_META_TYPE_DATA, op.ptr, 4, "");
				}
			}
			break;
			// Case of valid but unused "add [rax], al"
		case R_ANAL_OP_TYPE_ADD:
			if (anal->opt.ijmp) {
				if ((op.size + 4 <= bytes_read) && !memcmp (buf + op.size, "\x00\x00\x00\x00", 4)) {
					r_anal_block_set_size (bb, bb->size - oplen);
					op.type = R_ANAL_OP_TYPE_RET;
					gotoBeach (R_ANAL_RET_END);
				}
			}
			break;
		case R_ANAL_OP_TYPE_ILL:
			gotoBeach (R_ANAL_RET_END);
		case R_ANAL_OP_TYPE_TRAP:
			gotoBeach (R_ANAL_RET_END);
		case R_ANAL_OP_TYPE_NOP:
			// do nothing, because the nopskip goes before this switch
			break;
		case R_ANAL_OP_TYPE_JMP:
			if (op.jump == UT64_MAX) {
				gotoBeach (R_ANAL_RET_END);
			}
			{
				RFlagItem *fi = anal->flb.get_at (anal->flb.f, op.jump, false);
				if (fi && strstr (fi->name, "imp.")) {
					gotoBeach (R_ANAL_RET_END);
				}
			}
			if (r_cons_is_breaked ()) {
				gotoBeach (R_ANAL_RET_END);
			}
			if (anal->opt.jmpref) {
				(void) r_anal_xrefs_set (anal, op.addr, op.jump, R_ANAL_REF_TYPE_CODE);
			}
			if (!anal->opt.jmpabove && (op.jump < fcn->addr)) {
				gotoBeach (R_ANAL_RET_END);
			}
			if (r_anal_noreturn_at (anal, op.jump)) {
				gotoBeach (R_ANAL_RET_END);
			}
			{
				bool must_eob = true;
				RIOMap *map = anal->iob.map_get (anal->iob.io, addr);
				if (map) {
					must_eob = (op.jump < map->itv.addr || op.jump >= map->itv.addr + map->itv.size);
				}
				if (must_eob) {
					op.jump = UT64_MAX;
					gotoBeach (R_ANAL_RET_END);
				}
			}
#if FIX_JMP_FWD
			bb->jump = op.jump;
			bb->fail = UT64_MAX;
			FITFCNSZ ();
			gotoBeach (R_ANAL_RET_END);
#else
			if (!overlapped) {
				bb->jump = op.jump;
				bb->fail = UT64_MAX;
			}
			ret = r_anal_fcn_bb (anal, fcn, op.jump, depth);
			int tc = anal->opt.tailcall;
			if (tc) {
				// eprintf ("TAIL CALL AT 0x%llx\n", op.addr);
				int diff = op.jump - op.addr;
				if (tc < 0) {
					ut8 buf[32];
					(void)anal->iob.read_at (anal->iob.io, op.jump, (ut8 *) buf, sizeof (buf));
					if (r_anal_is_prelude (anal, buf, sizeof (buf))) {
						fcn_recurse (anal, fcn, op.jump, anal->opt.bb_max_size, depth - 1);
					}
				} else if (R_ABS (diff) > tc) {
					(void) r_anal_xrefs_set (anal, op.addr, op.jump, R_ANAL_REF_TYPE_CALL);
					fcn_recurse (anal, fcn, op.jump, anal->opt.bb_max_size, depth - 1);
					gotoBeach (R_ANAL_RET_END);
				}
			}
			goto beach;
#endif
			break;
		case R_ANAL_OP_TYPE_SUB:
			if (op.val != UT64_MAX && op.val > 0) {
				// if register is not stack
				cmpval = op.val;
			}
			break;
		case R_ANAL_OP_TYPE_CMP: {
			ut64 val = is_x86 ? op.val : op.ptr;
			if (val) {
				cmpval = val;
				bb->cmpval = cmpval;
				bb->cmpreg = op.reg;
			}
		}
			break;
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_MCJMP:
		case R_ANAL_OP_TYPE_RCJMP:
		case R_ANAL_OP_TYPE_UCJMP:
			if (anal->opt.cjmpref) {
				(void) r_anal_xrefs_set (anal, op.addr, op.jump, R_ANAL_REF_TYPE_CODE);
			}
			if (!overlapped) {
				bb->jump = op.jump;
				bb->fail = op.fail;
			}
			if (anal->opt.jmptbl) {
				if (op.ptr != UT64_MAX) {
					ut64 table_size, default_case;
					table_size = cmpval + 1;
					default_case = op.fail; // is this really default case?
					if (cmpval != UT64_MAX && default_case != UT64_MAX && (op.reg || op.ireg)) {
						if (op.ireg) {
							ret = try_walkthrough_jmptbl (anal, fcn, bb, depth, op.addr, op.ptr, op.ptr, anal->bits >> 3, table_size, default_case, ret);
						} else { // op.reg
							ret = walkthrough_arm_jmptbl_style (anal, fcn, bb, depth, op.addr, op.ptr, anal->bits >> 3, table_size, default_case, ret);
						}
						// check if op.jump and op.fail contain jump table location
						// clear jump address, because it's jump table location
						if (op.jump == op.ptr) {
							op.jump = UT64_MAX;
						} else if (op.fail == op.ptr) {
							op.fail = UT64_MAX;
						}
						cmpval = UT64_MAX;
					}
				}
			}
			int saved_stack = fcn->stack;
			if (continue_after_jump) {
				r_anal_fcn_bb (anal, fcn, op.jump, depth);
				fcn->stack = saved_stack;
				ret = r_anal_fcn_bb (anal, fcn, op.fail, depth);
				fcn->stack = saved_stack;
			} else {
				ret = r_anal_fcn_bb (anal, fcn, op.jump, depth);
				fcn->stack = saved_stack;
				ret = r_anal_fcn_bb (anal, fcn, op.fail, depth);
				fcn->stack = saved_stack;
				if (op.jump < fcn->addr) {
					if (!overlapped) {
						bb->jump = op.jump;
						bb->fail = UT64_MAX;
					}
					gotoBeach (R_ANAL_RET_END);
				}
			}

			// XXX breaks mips analysis too !op.delay
			// this will be all x86, arm (at least)
			// without which the analysis is really slow,
			// presumably because each opcode would get revisited
			// (and already covered by a bb) many times
			goto beach;
			// For some reason, branch delayed code (MIPS) needs to continue
			break;
		case R_ANAL_OP_TYPE_UCALL:
		case R_ANAL_OP_TYPE_RCALL:
		case R_ANAL_OP_TYPE_ICALL:
		case R_ANAL_OP_TYPE_IRCALL:
			/* call [dst] */
			// XXX: this is TYPE_MCALL or indirect-call
			(void) r_anal_xrefs_set (anal, op.addr, op.ptr, R_ANAL_REF_TYPE_CALL);

			if (r_anal_noreturn_at (anal, op.ptr)) {
				RAnalFunction *f = r_anal_get_function_at (anal, op.ptr);
				if (f) {
					f->is_noreturn = true;
				}
				gotoBeach (R_ANAL_RET_END);
			}
			break;
		case R_ANAL_OP_TYPE_CCALL:
		case R_ANAL_OP_TYPE_CALL:
			/* call dst */
			(void) r_anal_xrefs_set (anal, op.addr, op.jump, R_ANAL_REF_TYPE_CALL);

			if (r_anal_noreturn_at (anal, op.jump)) {
				RAnalFunction *f = r_anal_get_function_at (anal, op.jump);
				if (f) {
					f->is_noreturn = true;
				}
				gotoBeach (R_ANAL_RET_END);
			}
			break;
		case R_ANAL_OP_TYPE_UJMP:
		case R_ANAL_OP_TYPE_RJMP:
			if (is_arm && last_is_mov_lr_pc) {
				break;
			}
			/* fall through */
		case R_ANAL_OP_TYPE_MJMP:
		case R_ANAL_OP_TYPE_IJMP:
		case R_ANAL_OP_TYPE_IRJMP:
			// if the next instruction is a symbol
			if (anal->opt.ijmp && isSymbolNextInstruction (anal, &op)) {
				gotoBeach (R_ANAL_RET_END);
			}
			// switch statement
			if (anal->opt.jmptbl && lea_jmptbl_ip != op.addr) {
				// op.ireg since rip relative addressing produces way too many false positives otherwise
				// op.ireg is 0 for rip relative, "rax", etc otherwise
				if (op.ptr != UT64_MAX && op.ireg) { // direct jump
					ut64 table_size, default_case;
					if (try_get_jmptbl_info (anal, fcn, op.addr, bb, &table_size, &default_case)) {
						ret = try_walkthrough_jmptbl (anal, fcn, bb, depth, op.addr, op.ptr, op.ptr, anal->bits >> 3, table_size, default_case, ret);
					}
				} else if (op.ptr != UT64_MAX && op.reg) { // direct jump
					ut64 table_size, default_case;
					if (try_get_jmptbl_info (anal, fcn, op.addr, bb, &table_size, &default_case)) {
						ret = try_walkthrough_jmptbl (anal, fcn, bb, depth, op.addr, op.ptr, op.ptr, anal->bits >> 3, table_size, default_case, ret);
					}
				} else if (movdisp == 0) {
					ut64 jmptbl_base = UT64_MAX;
					ut64 lea_op_off = UT64_MAX;
					RListIter *lea_op_iter = NULL;
					RListIter *iter;
					leaddr_pair *pair;
					// find nearest candidate leaddr before op.addr
					r_list_foreach (anal->leaddrs, iter, pair) {
						if (pair->op_addr >= op.addr) {
							continue;
						}
						if (lea_op_off == UT64_MAX || lea_op_off > op.addr - pair->op_addr) {
							lea_op_off = op.addr - pair->op_addr;
							jmptbl_base = pair->leaddr;
							lea_op_iter = iter;
						}
					}
					if (lea_op_iter) {
						r_list_delete (anal->leaddrs, lea_op_iter);
					}
					ut64 table_size = cmpval + 1;
					ret = try_walkthrough_jmptbl (anal, fcn, bb, depth, op.addr, jmptbl_base, jmptbl_base, 4, table_size, -1, ret);
					cmpval = UT64_MAX;
				} else if (movdisp != UT64_MAX) {
					ut64 table_size, default_case;

					if (try_get_jmptbl_info (anal, fcn, op.addr, bb, &table_size, &default_case)) {
						op.ptr = movdisp;
						ret = try_walkthrough_jmptbl (anal, fcn, bb, depth, op.addr, op.ptr, op.ptr, anal->bits >> 3, table_size, default_case, ret);
					}
					movdisp = UT64_MAX;
				} else if (is_arm) {
					if (op.ptrsize == 1) { // TBB
						ut64 pred_cmpval = try_get_cmpval_from_parents(anal, fcn, bb, op.ireg);
						ut64 table_size = 0;
						if (pred_cmpval != UT64_MAX) {
							table_size += pred_cmpval;
						} else {
							table_size += cmpval;
						}
						ret = try_walkthrough_jmptbl (anal, fcn, bb, depth, op.addr, op.addr + op.size,
							op.addr + 4, 1, table_size, UT64_MAX, ret);
						// skip inlined jumptable
						idx += table_size;
					}
					if (op.ptrsize == 2) { // LDRH on thumb/arm
						ut64 pred_cmpval = try_get_cmpval_from_parents(anal, fcn, bb, op.ireg);
						int tablesize = 1;
						if (pred_cmpval != UT64_MAX) {
							tablesize += pred_cmpval;
						} else {
							tablesize += cmpval;
						}
						ret = try_walkthrough_jmptbl (anal, fcn, bb, depth, op.addr, op.addr + op.size,
							op.addr + 4, 2, tablesize, UT64_MAX, ret);
						// skip inlined jumptable
						idx += (tablesize * 2);
					}
				}
			}
			if (lea_jmptbl_ip == op.addr) {
				lea_jmptbl_ip = UT64_MAX;
			}
			if (anal->opt.ijmp) {
				if (continue_after_jump) {
					r_anal_fcn_bb (anal, fcn, op.jump, depth);
					ret = r_anal_fcn_bb (anal, fcn, op.fail, depth);
					if (overlapped) {
						goto analopfinish;
					}
				}
				if (r_anal_noreturn_at (anal, op.jump) || op.eob) {
					goto analopfinish;
				}
			} else {
analopfinish:
				if (op.type == R_ANAL_OP_TYPE_RJMP) {
					gotoBeach (R_ANAL_RET_NOP);
				} else {
					gotoBeach (R_ANAL_RET_END);
				}
			}
			break;
		/* fallthru */
		case R_ANAL_OP_TYPE_PUSH:
			last_is_push = true;
			last_push_addr = op.val;
			if (anal->iob.is_valid_offset (anal->iob.io, last_push_addr, 1)) {
				(void) r_anal_xrefs_set (anal, op.addr, last_push_addr, R_ANAL_REF_TYPE_DATA);
			}
			break;
		case R_ANAL_OP_TYPE_UPUSH:
			if ((op.type & R_ANAL_OP_TYPE_REG) && last_is_reg_mov_lea && op.src[0] && op.src[0]->reg
				&& op.src[0]->reg->name && !strcmp (op.src[0]->reg->name, last_reg_mov_lea_name)) {
				last_is_push = true;
				last_push_addr = last_reg_mov_lea_val;
				if (anal->iob.is_valid_offset (anal->iob.io, last_push_addr, 1)) {
					(void) r_anal_xrefs_set (anal, op.addr, last_push_addr, R_ANAL_REF_TYPE_DATA);
				}
			}
			break;
		case R_ANAL_OP_TYPE_RET:
			if (op.family == R_ANAL_OP_FAMILY_PRIV) {
				fcn->type = R_ANAL_FCN_TYPE_INT;
			}
			if (last_is_push && anal->opt.pushret) {
				op.type = R_ANAL_OP_TYPE_JMP;
				op.jump = last_push_addr;
				bb->jump = op.jump;
				ret = r_anal_fcn_bb (anal, fcn, op.jump, depth);
				goto beach;
			}
			if (!op.cond) {
				if (anal->verbose) {
					eprintf ("RET 0x%08"PFMT64x ". overlap=%s %"PFMT64u" %"PFMT64u"\n",
						addr + delay.un_idx - oplen, r_str_bool (overlapped),
						bb->size, r_anal_function_linear_size (fcn));
				}
				gotoBeach (R_ANAL_RET_END);
			}
			break;
		}
		if (has_stack_regs && (is_arm || is_riscv)) {
			if (op_is_set_bp (&op, bp_reg, sp_reg) && op.src[1]) {
				switch (op.type & R_ANAL_OP_TYPE_MASK) {
				case R_ANAL_OP_TYPE_ADD:
					fcn->bp_off = fcn->stack - op.src[1]->imm;
					break;
				case R_ANAL_OP_TYPE_SUB:
					fcn->bp_off = fcn->stack + op.src[1]->imm;
					break;
				}
			}
		}
		if (anal->opt.vars && !varset) {
			r_anal_extract_vars (anal, fcn, &op);
		}
		if (op.type != R_ANAL_OP_TYPE_MOV && op.type != R_ANAL_OP_TYPE_CMOV && op.type != R_ANAL_OP_TYPE_LEA) {
			last_is_reg_mov_lea = false;
		}
		if (op.type != R_ANAL_OP_TYPE_PUSH && op.type != R_ANAL_OP_TYPE_RPUSH) {
			last_is_push = false;
		}
		if (is_arm && op.type != R_ANAL_OP_TYPE_MOV) {
			last_is_mov_lr_pc = false;
		}
		if (has_variadic_reg && !fcn->is_variadic) {
			bool dst_is_variadic = op.dst && op.dst->reg && op.dst->reg->offset == variadic_reg->offset;
			bool op_is_cmp = (op.type == R_ANAL_OP_TYPE_CMP) || op.type == R_ANAL_OP_TYPE_ACMP;
			if (dst_is_variadic && !op_is_cmp) {
				has_variadic_reg = false;
			} else if (op_is_cmp) {
				if (op.src[0] && op.src[0]->reg && (op.dst->reg == op.src[0]->reg) && dst_is_variadic) {
					fcn->is_variadic = true;
				}
			}
		}
	}
beach:
	r_anal_op_fini (&op);
	R_FREE (last_reg_mov_lea_name);
	if (bb && bb->size == 0) {
		r_anal_function_remove_block (fcn, bb);
	}
	r_anal_block_unref (bb);
	return ret;
}

R_API int r_anal_fcn_bb(RAnal *anal, RAnalFunction *fcn, ut64 addr, int depth) {
	return fcn_recurse (anal, fcn, addr, anal->opt.bb_max_size, depth - 1);
}

R_API bool r_anal_check_fcn(RAnal *anal, ut8 *buf, ut16 bufsz, ut64 addr, ut64 low, ut64 high) {
	RAnalOp op = {
		0
	};
	int i, oplen, opcnt = 0, pushcnt = 0, movcnt = 0, brcnt = 0;
	if (r_anal_is_prelude (anal, buf, bufsz)) {
		return true;
	}
	for (i = 0; i < bufsz && opcnt < 10; i += oplen, opcnt++) {
		r_anal_op_fini (&op);
		if ((oplen = r_anal_op (anal, &op, addr + i, buf + i, bufsz - i, R_ANAL_OP_MASK_BASIC | R_ANAL_OP_MASK_HINT)) < 1) {
			return false;
		}
		switch (op.type) {
		case R_ANAL_OP_TYPE_PUSH:
		case R_ANAL_OP_TYPE_UPUSH:
		case R_ANAL_OP_TYPE_RPUSH:
			pushcnt++;
			break;
		case R_ANAL_OP_TYPE_MOV:
		case R_ANAL_OP_TYPE_CMOV:
			movcnt++;
			break;
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_CALL:
			if (op.jump < low || op.jump >= high) {
				return false;
			}
			brcnt++;
			break;
		case R_ANAL_OP_TYPE_UNK:
			return false;
		default:
			break;
		}
	}
	return (pushcnt + movcnt + brcnt > 5);
}

R_API void r_anal_trim_jmprefs(RAnal *anal, RAnalFunction *fcn) {
	RAnalRef *ref;
	RList *refs = r_anal_function_get_refs (fcn);
	RListIter *iter;
	const bool is_x86 = anal->cur->arch && !strcmp (anal->cur->arch, "x86"); // HACK

	r_list_foreach (refs, iter, ref) {
		if (ref->type == R_ANAL_REF_TYPE_CODE && r_anal_function_contains (fcn, ref->addr)
		    && (!is_x86 || !r_anal_function_contains (fcn, ref->at))) {
			r_anal_xrefs_deln (anal, ref->at, ref->addr, ref->type);
		}
	}
	r_list_free (refs);
}

R_API void r_anal_del_jmprefs(RAnal *anal, RAnalFunction *fcn) {
	RAnalRef *ref;
	RList *refs = r_anal_function_get_refs (fcn);
	RListIter *iter;

	r_list_foreach (refs, iter, ref) {
		if (ref->type == R_ANAL_REF_TYPE_CODE) {
			r_anal_xrefs_deln (anal, ref->at, ref->addr, ref->type);
		}
	}
	r_list_free (refs);
}

/* Does NOT invalidate read-ahead cache. */
R_API int r_anal_fcn(RAnal *anal, RAnalFunction *fcn, ut64 addr, ut64 len, int reftype) {
	RPVector *metas = r_meta_get_all_in(anal, addr, R_META_TYPE_ANY);
	void **it;
	r_pvector_foreach (metas, it) {
		RAnalMetaItem *meta = ((RIntervalNode *)*it)->data;
		switch (meta->type) {
		case R_META_TYPE_DATA:
		case R_META_TYPE_STRING:
		case R_META_TYPE_FORMAT:
			r_pvector_free (metas);
			return 0;
		default:
			break;
		}
	}
	r_pvector_free (metas);
	if (anal->opt.norevisit) {
		if (!anal->visited) {
			anal->visited = set_u_new ();
		}
		if (set_u_contains (anal->visited, addr)) {
			eprintf ("r_anal_fcn: anal.norevisit at 0x%08"PFMT64x" %c\n", addr, reftype);
			return R_ANAL_RET_END;
		}
		set_u_add (anal->visited, addr);
	} else {
		if (anal->visited) {
			set_u_free (anal->visited);
			anal->visited = NULL;
		}
	}
	/* defines fcn. or loc. prefix */
	fcn->type = (reftype == R_ANAL_REF_TYPE_CODE) ? R_ANAL_FCN_TYPE_LOC : R_ANAL_FCN_TYPE_FCN;
	if (fcn->addr == UT64_MAX) {
		fcn->addr = addr;
	}
	fcn->maxstack = 0;
	if (fcn->cc && !strcmp (fcn->cc, "ms")) {
		fcn->stack = fcn->maxstack = 0x28; // Shadow store for the first 4 args + Return addr
	}
	int ret = r_anal_fcn_bb (anal, fcn, addr, anal->opt.depth);
	if (ret < 0) {
		if (anal->verbose) {
			eprintf ("Failed to analyze basic block at 0x%"PFMT64x"\n", addr);
		}
	}
	if (anal->opt.endsize && ret == R_ANAL_RET_END && r_anal_function_realsize (fcn)) {   // cfg analysis completed
		RListIter *iter;
		RAnalBlock *bb;
		ut64 endaddr = fcn->addr;
		const bool is_x86 = anal->cur->arch && !strcmp (anal->cur->arch, "x86");

		// set function size as length of continuous sequence of bbs
		r_list_sort (fcn->bbs, &cmpaddr);
		r_list_foreach (fcn->bbs, iter, bb) {
			if (endaddr == bb->addr) {
				endaddr += bb->size;
			} else if ((endaddr < bb->addr && bb->addr - endaddr < BB_ALIGN)
			           || (anal->opt.jmpmid && is_x86 && endaddr > bb->addr
			               && bb->addr + bb->size > endaddr)) {
				endaddr = bb->addr + bb->size;
			} else {
				break;
			}
		}
#if JAYRO_04
		// fcn is not yet in anal => pass NULL
		r_anal_function_resize (fcn, endaddr - fcn->addr);
#endif
		r_anal_trim_jmprefs (anal, fcn);
	}
	return ret;
}

// XXX deprecate
R_API int r_anal_fcn_del_locs(RAnal *anal, ut64 addr) {
	RListIter *iter, *iter2;
	RAnalFunction *fcn, *f = r_anal_get_fcn_in (anal, addr, R_ANAL_FCN_TYPE_ROOT);
	if (!f) {
		return false;
	}
	r_list_foreach_safe (anal->fcns, iter, iter2, fcn) {
		if (fcn->type != R_ANAL_FCN_TYPE_LOC) {
			continue;
		}
		if (r_anal_function_contains (fcn, addr)) {
			r_anal_function_delete (fcn);
		}
	}
	r_anal_fcn_del (anal, addr);
	return true;
}

R_API int r_anal_fcn_del(RAnal *a, ut64 addr) {
	RAnalFunction *fcn;
	RListIter *iter, *iter_tmp;
	r_list_foreach_safe (a->fcns, iter, iter_tmp, fcn) {
		D eprintf ("fcn at %llx %llx\n", fcn->addr, addr);
		if (fcn->addr == addr) {
			r_anal_function_delete (fcn);
		}
	}
	return true;
}

R_API RAnalFunction *r_anal_get_fcn_in(RAnal *anal, ut64 addr, int type) {
	RList *list = r_anal_get_functions_in (anal, addr);
	RAnalFunction *ret = NULL;
	if (list && !r_list_empty (list)) {
		if (type == R_ANAL_FCN_TYPE_ROOT) {
			RAnalFunction *fcn;
			RListIter *iter;
			r_list_foreach (list, iter, fcn) {
				if (fcn->addr == addr) {
					ret = fcn;
					break;
				}
			}
		} else {
			ret = r_list_first (list);
		}
	}
	r_list_free (list);
	return ret;
}

R_API RAnalFunction *r_anal_get_fcn_in_bounds(RAnal *anal, ut64 addr, int type) {
	RAnalFunction *fcn, *ret = NULL;
	RListIter *iter;
	if (type == R_ANAL_FCN_TYPE_ROOT) {
		r_list_foreach (anal->fcns, iter, fcn) {
			if (addr == fcn->addr) {
				return fcn;
			}
		}
		return NULL;
	}
	r_list_foreach (anal->fcns, iter, fcn) {
		if (!type || (fcn && fcn->type & type)) {
			if (r_anal_function_contains (fcn, addr)) {
				return fcn;
			}
		}
	}
	return ret;
}

R_API RAnalFunction *r_anal_get_function_byname(RAnal *a, const char *name) {
	bool found = false;
	RAnalFunction *f = ht_pp_find (a->ht_name_fun, name, &found);
	if (f && found) {
		return f;
	}
	return NULL;
}

/* rename RAnalFunctionBB.add() */
R_API bool r_anal_fcn_add_bb(RAnal *a, RAnalFunction *fcn, ut64 addr, ut64 size, ut64 jump, ut64 fail, R_BORROW RAnalDiff *diff) {
	D eprintf ("Add bb\n");
	if (size == 0) { // empty basic blocks allowed?
		eprintf ("Warning: empty basic block at 0x%08"PFMT64x" is not allowed. pending discussion.\n", addr);
		r_warn_if_reached ();
		return false;
	}
	if (size > a->opt.bb_max_size) {
		eprintf ("Warning: can't allocate such big bb of %"PFMT64d" bytes at 0x%08"PFMT64x"\n", (st64)size, addr);
		r_warn_if_reached ();
		return false;
	}

	RAnalBlock *block = r_anal_get_block_at (a, addr);
	if (block) {
		r_anal_delete_block (block);
		block = NULL;
	}

	const bool is_x86 = a->cur->arch && !strcmp (a->cur->arch, "x86");
	// TODO fix this x86-ism
	if (is_x86) {
		r_anal_fcn_invalidate_read_ahead_cache ();
		fcn_recurse (a, fcn, addr, size, 1);
		block = r_anal_get_block_at (a, addr);
		if (block) {
			r_anal_block_set_size (block, size);
		}
	} else {
		block = r_anal_create_block (a, addr, size);
	}

	if (!block) {
		D eprintf ("Warning: r_anal_fcn_add_bb failed in fcn 0x%08"PFMT64x" at 0x%08"PFMT64x"\n", fcn->addr, addr);
		return false;
	}

	r_anal_function_add_block (fcn, block);

	block->jump = jump;
	block->fail = fail;
	block->fail = fail;
	if (diff) {
		if (!block->diff) {
			block->diff = r_anal_diff_new ();
		}
		if (block->diff) {
			block->diff->type = diff->type;
			block->diff->addr = diff->addr;
			if (diff->name) {
				R_FREE (block->diff->name);
				block->diff->name = strdup (diff->name);
			}
		}
	}
	return true;
}

R_API int r_anal_function_loops(RAnalFunction *fcn) {
	RListIter *iter;
	RAnalBlock *bb;
	ut32 loops = 0;
	r_list_foreach (fcn->bbs, iter, bb) {
		if (bb->jump != UT64_MAX && bb->jump < bb->addr) {
			loops ++;
		}
		if (bb->fail != UT64_MAX && bb->fail < bb->addr) {
			loops ++;
		}
	}
	return loops;
}

R_API int r_anal_function_complexity(RAnalFunction *fcn) {
/*
        CC = E - N + 2P
        E = the number of edges of the graph.
        N = the number of nodes of the graph.
        P = the number of connected components (exit nodes).
 */
	RAnal *anal = fcn->anal;
	int E = 0, N = 0, P = 0;
	RListIter *iter;
	RAnalBlock *bb;

	r_list_foreach (fcn->bbs, iter, bb) {
		N++; // nodes
		if ((!anal || anal->verbose) && bb->jump == UT64_MAX && bb->fail != UT64_MAX) {
			eprintf ("Warning: invalid bb jump/fail pair at 0x%08"PFMT64x" (fcn 0x%08"PFMT64x"\n", bb->addr, fcn->addr);
		}
		if (bb->jump == UT64_MAX && bb->fail == UT64_MAX) {
			P++; // exit nodes
		} else {
			E++; // edges
			if (bb->fail != UT64_MAX) {
				E++;
			}
		}
		if (bb->switch_op && bb->switch_op->cases) {
			E += r_list_length (bb->switch_op->cases);
		}
	}

	int result = E - N + (2 * P);
	if (result < 1 && (!anal || anal->verbose)) {
		eprintf ("Warning: CC = E(%d) - N(%d) + (2 * P(%d)) < 1 at 0x%08"PFMT64x"\n", E, N, P, fcn->addr);
	}
	// r_return_val_if_fail (result > 0, 0);
	return result;
}

// tfj and afsj call this function
R_API char *r_anal_function_get_json(RAnalFunction *function) {
	PJ *pj = pj_new ();
	RAnal *a = function->anal;
	char *args = strdup ("");
	char *sdb_ret = r_str_newf ("func.%s.ret", function->name);
	char *sdb_args = r_str_newf ("func.%s.args", function->name);
	// RList *args_list = r_list_newf ((RListFree) free);
	unsigned int i;
	const char *ret_type = sdb_const_get (a->sdb_types, sdb_ret, 0);
	const char *argc_str = sdb_const_get (a->sdb_types, sdb_args, 0);

	int argc = argc_str? atoi (argc_str): 0;

	pj_o (pj);
	pj_ks (pj, "name", function->name);
	const bool no_return = r_anal_noreturn_at_addr (a, function->addr);
	pj_kb (pj, "noreturn", no_return);
	pj_ks (pj, "ret", ret_type?ret_type: "void");
	if (function->cc) {
		pj_ks (pj, "cc", function->cc);
	}
	pj_k (pj, "args");
	pj_a (pj);
	for (i = 0; i < argc; i++) {
		pj_o (pj);
		char *sdb_arg_i = r_str_newf ("func.%s.arg.%d", function->name, i);
		char *arg_i = sdb_get (a->sdb_types, sdb_arg_i, 0);
		char *comma = strchr (arg_i, ',');
		if (comma) {
			*comma = 0;
			pj_ks (pj, "name", comma + 1);
			pj_ks (pj, "type", arg_i);
			const char *cc_arg = r_reg_get_name (a->reg, r_reg_get_name_idx (sdb_fmt ("A%d", i)));
			if (cc_arg) {
				pj_ks (pj, "cc", cc_arg);
			}
		}
		free (arg_i);
		free (sdb_arg_i);
		pj_end (pj);
	}
	pj_end (pj);
	free (sdb_args);
	free (sdb_ret);
	free (args);
	pj_end (pj);
	return pj_drain (pj);
}

R_API char *r_anal_function_get_signature(RAnalFunction *function) {
	RAnal *a = function->anal;
	const char *realname = NULL, *import_substring = NULL;

	RFlagItem *flag = a->flag_get (a->flb.f, function->addr);
	// Can't access R_FLAGS_FS_IMPORTS, since it is defined in r_core.h
	if (flag && flag->space && !strcmp (flag->space->name, "imports")) {
		// Get substring after last dot
		import_substring = r_str_rchr (function->name, NULL, '.');
		if (import_substring) {
			realname = import_substring + 1;
		}
	} else {
		realname = function->name;
	}

	char *ret = NULL, *args = strdup ("");
	char *sdb_ret = r_str_newf ("func.%s.ret", realname);
	char *sdb_args = r_str_newf ("func.%s.args", realname);
	// RList *args_list = r_list_newf ((RListFree) free);
	unsigned int i, j;
	const char *ret_type = sdb_const_get (a->sdb_types, sdb_ret, 0);
	const char *argc_str = sdb_const_get (a->sdb_types, sdb_args, 0);

	int argc = argc_str? atoi (argc_str): 0;

	for (i = 0; i < argc; i++) {
		char *sdb_arg_i = r_str_newf ("func.%s.arg.%d", realname, i);
		char *arg_i = sdb_get (a->sdb_types, sdb_arg_i, 0);
		// parse commas
		int arg_i_len = strlen (arg_i);
		for (j = 0; j < arg_i_len; j++) {
			if (j > 0 && arg_i[j] == ',') {
				if (arg_i[j - 1] == '*') {
					// remove whitespace
					memmove (arg_i + j, arg_i + j + 1, strlen (arg_i) - j);
				} else {
					arg_i[j] = ' ';
				}
			}
		}
		char *new_args = (i + 1 == argc)
			? r_str_newf ("%s%s", args, arg_i)
			: r_str_newf ("%s%s, ", args, arg_i);
		free (args);
		args = new_args;

		free (arg_i);
		free (sdb_arg_i);
	}
	ret = r_str_newf ("%s %s (%s);", ret_type? ret_type: "void", realname, args);

	free (sdb_args);
	free (sdb_ret);
	free (args);
	return ret;
}

/* set function signature from string */
R_API int r_anal_str_to_fcn(RAnal *a, RAnalFunction *f, const char *sig) {
	r_return_val_if_fail (a || f || sig, false);
	char *error_msg = NULL;
	const char *out = r_parse_c_string (a, sig, &error_msg);
	if (out) {
		r_anal_save_parsed_type (a, out);
	}
	if (error_msg) {
		eprintf ("%s", error_msg);
		free (error_msg);
	}

	return true;
}

R_API RAnalFunction *r_anal_fcn_next(RAnal *anal, ut64 addr) {
	RAnalFunction *fcni;
	RListIter *iter;
	RAnalFunction *closer = NULL;
	r_list_foreach (anal->fcns, iter, fcni) {
		// if (fcni->addr == addr)
		if (fcni->addr > addr && (!closer || fcni->addr < closer->addr)) {
			closer = fcni;
		}
	}
	return closer;
}

R_API int r_anal_fcn_count(RAnal *anal, ut64 from, ut64 to) {
	int n = 0;
	RAnalFunction *fcni;
	RListIter *iter;
	r_list_foreach (anal->fcns, iter, fcni) {
		if (fcni->addr >= from && fcni->addr < to) {
			n++;
		}
	}
	return n;
}

/* return the basic block in fcn found at the given address.
 * NULL is returned if such basic block doesn't exist. */
R_API RAnalBlock *r_anal_fcn_bbget_in(const RAnal *anal, RAnalFunction *fcn, ut64 addr) {
	r_return_val_if_fail (anal && fcn, NULL);
	if (addr == UT64_MAX) {
		return NULL;
	}
	const bool is_x86 = anal->cur->arch && !strcmp (anal->cur->arch, "x86");
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		if (addr >= bb->addr && addr < (bb->addr + bb->size)
			&& (!anal->opt.jmpmid || !is_x86 || r_anal_block_op_starts_at (bb, addr))) {
			return bb;
		}
	}
	return NULL;
}

R_API RAnalBlock *r_anal_fcn_bbget_at(RAnal *anal, RAnalFunction *fcn, ut64 addr) {
	r_return_val_if_fail (fcn && addr != UT64_MAX, NULL);
	RAnalBlock *b = r_anal_get_block_at (anal, addr);
	if (b) {
		return b;
	}
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		if (addr == bb->addr) {
			return bb;
		}
	}
	return NULL;
}

// compute the cyclomatic cost
R_API ut32 r_anal_function_cost(RAnalFunction *fcn) {
	RListIter *iter;
	RAnalBlock *bb;
	ut32 totalCycles = 0;
	if (!fcn) {
		return 0;
	}
	RAnal *anal = fcn->anal;
	r_list_foreach (fcn->bbs, iter, bb) {
		RAnalOp op;
		ut64 at, end = bb->addr + bb->size;
		ut8 *buf = malloc (bb->size);
		if (!buf) {
			continue;
		}
		(void)anal->iob.read_at (anal->iob.io, bb->addr, (ut8 *) buf, bb->size);
		int idx = 0;
		for (at = bb->addr; at < end;) {
			r_anal_op_init (&op);
			(void) r_anal_op (anal, &op, at, buf + idx, bb->size - idx, R_ANAL_OP_MASK_BASIC);
			if (op.size < 1) {
				op.size = 1;
			}
			idx += op.size;
			at += op.size;
			totalCycles += op.cycles;
			r_anal_op_fini (&op);
		}
		free (buf);
	}
	return totalCycles;
}

R_API int r_anal_function_count_edges(const RAnalFunction *fcn, R_NULLABLE int *ebbs) {
	r_return_val_if_fail (fcn, 0);
	RListIter *iter;
	RAnalBlock *bb;
	int edges = 0;
	if (ebbs) {
		*ebbs = 0;
	}
	r_list_foreach (fcn->bbs, iter, bb) {
		if (ebbs && bb->jump == UT64_MAX && bb->fail == UT64_MAX) {
			*ebbs = *ebbs + 1;
		} else {
			if (bb->jump != UT64_MAX) {
				edges ++;
			}
			if (bb->fail != UT64_MAX) {
				edges ++;
			}
		}
	}
	return edges;
}

R_API bool r_anal_function_purity(RAnalFunction *fcn) {
	if (fcn->has_changed) {
		HtUP *ht = ht_up_new (NULL, NULL, NULL);
		if (ht) {
			check_purity (ht, fcn);
			ht_up_free (ht);
		}
	}
	return fcn->is_pure;
}

static bool can_affect_bp(RAnal *anal, RAnalOp* op) {
	RAnalValue *dst = op->dst;
	RAnalValue *src = op->src[0];
	const char *opdreg = (dst && dst->reg) ? dst->reg->name : NULL;
	const char *opsreg = (src && src->reg) ? src->reg->name : NULL;
	const char *bp_name = anal->reg->name[R_REG_NAME_BP];
	bool is_bp_dst = opdreg && !dst->memref && !strcmp (opdreg, bp_name);
	bool is_bp_src = opsreg && !src->memref && !strcmp (opsreg, bp_name);
	if (op->type == R_ANAL_OP_TYPE_XCHG) {
		return is_bp_src || is_bp_dst;
	}
	return is_bp_dst;
}

/*
 * This function checks whether any operation in a given function may change bp (excluding "mov bp, sp"
 * and "pop bp" at the end).
 */
static void __anal_fcn_check_bp_use(RAnal *anal, RAnalFunction *fcn) {
	RListIter *iter;
	RAnalBlock *bb;
	char str_to_find[40] = "\"type\":\"reg\",\"value\":\"";
	char *pos;
	strncat (str_to_find, anal->reg->name[R_REG_NAME_BP], 39);
	if (!fcn) {
		return;
	}
	r_list_foreach (fcn->bbs, iter, bb) {
		RAnalOp op;
		ut64 at, end = bb->addr + bb->size;
		ut8 *buf = malloc (bb->size);
		if (!buf) {
			continue;
		}
		(void)anal->iob.read_at (anal->iob.io, bb->addr, (ut8 *) buf, bb->size);
		int idx = 0;
		for (at = bb->addr; at < end;) {
			r_anal_op (anal, &op, at, buf + idx, bb->size - idx, R_ANAL_OP_MASK_VAL | R_ANAL_OP_MASK_OPEX);
			if (op.size < 1) {
				op.size = 1;
			}
			switch (op.type) {
			case R_ANAL_OP_TYPE_MOV:
			case R_ANAL_OP_TYPE_LEA:
				if (can_affect_bp (anal, &op) && op.src[0] && op.src[0]->reg && op.src[0]->reg->name
				&& strcmp (op.src[0]->reg->name, anal->reg->name[R_REG_NAME_SP])) {
					fcn->bp_frame = false;
					r_anal_op_fini (&op);
					return;
				}
				break;
			case R_ANAL_OP_TYPE_ADD:
			case R_ANAL_OP_TYPE_AND:
			case R_ANAL_OP_TYPE_CMOV:
			case R_ANAL_OP_TYPE_NOT:
			case R_ANAL_OP_TYPE_OR:
			case R_ANAL_OP_TYPE_ROL:
			case R_ANAL_OP_TYPE_ROR:
			case R_ANAL_OP_TYPE_SAL:
			case R_ANAL_OP_TYPE_SAR:
			case R_ANAL_OP_TYPE_SHR:
			case R_ANAL_OP_TYPE_SUB:
			case R_ANAL_OP_TYPE_XOR:
			case R_ANAL_OP_TYPE_SHL:
// op.dst is not filled for these operations, so for now, check for bp as dst looks like this; in the future it may be just replaced with call to can_affect_bp
 				pos = op.opex.ptr ? strstr (op.opex.ptr, str_to_find) : NULL;
				if (pos && pos - op.opex.ptr < 60) {
					fcn->bp_frame = false;
					r_anal_op_fini (&op);
					return;
				}
				break;
			case R_ANAL_OP_TYPE_XCHG:
				if (op.opex.ptr && strstr (op.opex.ptr, str_to_find)) {
					fcn->bp_frame = false;
					r_anal_op_fini (&op);
					return;
    			}
				break;
			case R_ANAL_OP_TYPE_POP:
				break;
			default:
				break;
			}
			idx += op.size;
			at += op.size;
			r_anal_op_fini (&op);
		}
		free (buf);
	}
}

R_API void r_anal_function_check_bp_use(RAnalFunction *fcn) {
	r_return_if_fail (fcn);
	__anal_fcn_check_bp_use (fcn->anal, fcn);
}
