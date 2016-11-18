/* radare - Copyright 2014-2015 pancake */

#include <r_types.h>
#include <r_core.h>

#define MAXFCNSIZE 4096

#define Fbb(x) sdb_fmt(0,"bb.%"PFMT64x,x)
#define Fhandled(x) sdb_fmt(0, "handled.%"PFMT64x,x)
#define FbbTo(x) sdb_fmt(0,"bb.%"PFMT64x".to",x)

static ut64 getCrossingBlock(Sdb *db, const char *key, ut64 start, ut64 end) {
	ut64 block_start, block_end, addr_end = UT64_MAX;
	ut64 nearest_start = UT64_MAX;
	const char *s = sdb_const_get (db, key, NULL);
	const char *next = NULL;
	const char *ptr = NULL;
	if (!s) {
		return UT64_MAX;
	}
	ptr = s;
	do {
		const char *str = sdb_const_anext (ptr, &next);
		block_start = sdb_atoi (str);

		if (start == block_start) { // case 5
			return start;
		}

		block_end = sdb_num_get (db, Fbb(block_start), NULL);
		eprintf ("current : 0x%x end: 0x%x\n", block_start, block_end);
		if (block_end) {
			if (start > block_start && start < block_end) { // case 2
				// start is inside the block
				return block_start;
			}
			if (start < block_start && end >= block_end) {
				// crossing the start of the block
				if (nearest_start > block_start) {
					nearest_start = block_start;
				}
			}
		}
		ptr = next;
	} while (next);

	return nearest_start;
}

/*
 bb.<addr-of-basic-block>=<end-address-of-basic-block>
 bb.<addr-of-basic-block>.to=array,of,destination,addresses
*/

static int bbAdd(Sdb *db, ut64 from, ut64 to, ut64 jump, ut64 fail) {
	eprintf ("bb add: from: 0x%x to: 0x%x jump: 0x%x fail: 0x%x\n", from, to, jump, fail);
	ut64 block_end, block_start = getCrossingBlock (db, "bbs", from, to);
	int add = 1;
	if (block_start == UT64_MAX) {
		// add = 1;
	} else if (block_start == from) {
		// check if size is the same,
		eprintf ("basic block already analyzed\n");
		add = 0;
	} else {
		block_end = sdb_num_get (db, Fbb(block_start), NULL);
		/*
		   from = start address of new basic block
		   to = end address of new basic block
		   jump = destination basic block
		   fail = fallback jump of basic block
		   addr = previous closer basic block start address
		   addr_end = previous closer basic block start address
		 */
		// found a possible block
		if (from > block_start) {
			// from inside
			// RESIZE this
			eprintf ("block1 s: 0x%x e: 0x%x\n", block_start, from);
			sdb_num_set (db, Fbb(block_start), from, 0);
			sdb_num_set (db, FbbTo(block_start), from, 0);
			ut64 old_jump = sdb_array_get_num (db, FbbTo(block_start), 0, NULL);
			ut64 old_fail = sdb_array_get_num (db, FbbTo(block_start), 1, NULL);
			sdb_array_set_num (db, FbbTo(block_start), 0, from, 0);
			sdb_array_delete (db, FbbTo(block_start), 1, 0);
			if (old_jump != jump || old_fail != fail) {
				eprintf ("####### 0x%x has different childs\n", block_start);
				eprintf ("#### old_j = 0x%x new_j = 0x%x and old_f = 0x%x new_f = 0x%x\n", 
						old_jump, jump, old_fail, fail);
			}
			// new one:
			eprintf ("block2 s: 0x%x e: 0x%x\n", from, block_end);
		} else {
			// < the current runs into a known block
			// new one:
			to = block_start;
			jump = block_start;
			fail = UT64_MAX;
			eprintf ("block1 s: 0x%x e: 0x%x\n", from, block_start);
			eprintf ("block2 s: 0x%x e: 0x%x\n", block_start, block_end);
		}
	}
	if (add) {
		sdb_array_add_num (db, "bbs", from, 0);
		eprintf ("####### adding 0x%x\n", from);
		sdb_num_set (db, Fbb(from), to, 0);
		sdb_array_set_num (db, FbbTo(from), 0, jump, 0);
		sdb_array_set_num (db, FbbTo(from), 1, fail, 0);
		sdb_num_min (db, "min", from, 0);
		sdb_num_max (db, "max", to, 0);
	}
	return 0;
}

void addTarget(RCore *core, RStack *stack, Sdb *db, ut64 addr) {
	if (!sdb_num_get (db, Fhandled(addr), NULL)) {
		r_stack_push (stack, addr);
		sdb_num_set (db, Fhandled(addr), 1, 0);
	}
}

ut64 analyzeStackBased(RCore *core, Sdb *db, ut64 addr) {
#define addCall(x) sdb_array_add_num (db, "calls", x, 0);
#define addUcall(x) sdb_array_add_num (db, "ucalls", x, 0);
#define addUjmp(x) sdb_array_add_num (db, "ujmps", x, 0);
#define addCjmp(x) sdb_array_add_num (db, "cjmps", x, 0);
#define addRet(x) sdb_array_add_num (db, "rets", x, 0);
#define bbAddOpcode(x) sdb_array_insert_num (db, sdb_fmt (0, "bb.%"PFMT64x, addr+cur), -1, x, 0);
	ut64 oaddr = addr;
	RAnalOp *op;
	int cur = 0;
	bool block_end = false;
	RStack *stack = r_stack_new (10);
	if (!r_stack_push (stack, addr)) {
			eprintf ("Cannot push start address onto handling stack\n");
			return UT64_MAX;
	}
	while (!r_stack_is_empty (stack)) {
		block_end = false;
		addr = r_stack_pop (stack);
		eprintf ("Handling 0x%x\n", addr);
		cur = 0;
		while (!block_end) {
			op = r_core_anal_op (core, addr + cur);
			if (!op || !op->mnemonic) {
				eprintf ("Cannot analyze opcode at %"PFMT64d"\n", addr+cur);
				break;
			}
			eprintf ("0x%08"PFMT64x"  %s\n", addr + cur, op->mnemonic);
			if (op->mnemonic[0] == '?') {
				eprintf ("Cannot analyze opcode at %"PFMT64d"\n", addr+cur);
				break;
			}

			bbAddOpcode (addr+cur);
			switch (op->type) {
			case R_ANAL_OP_TYPE_NOP:
				// skip nops
				if (cur == 0) {
					eprintf ("NOPSKIP %d\n", op->size);
					cur -= op->size;
					addr += op->size;
					oaddr += op->size;
				}
				break;
			case R_ANAL_OP_TYPE_CALL:
				/* A call instruction implies that the destination
				 * is a new function unless the address is inside
				 * the same range than the current function */
				addCall (op->jump);
				// add call reference
				break;
			case R_ANAL_OP_TYPE_UCALL:
			case R_ANAL_OP_TYPE_ICALL:
			case R_ANAL_OP_TYPE_RCALL:
			case R_ANAL_OP_TYPE_IRCALL:
				/* unknown calls depend on ESIL or DEBUG tracing
				 * information to know the destination, we can mark
				 * those 'calls' for later adding tracepoints in
				 * there to record all possible destinations */
				addUcall (addr+cur);
				break;
			case R_ANAL_OP_TYPE_UJMP:
			case R_ANAL_OP_TYPE_RJMP:
			case R_ANAL_OP_TYPE_IJMP:
			case R_ANAL_OP_TYPE_IRJMP:
				/* an unknown jump use to go into computed destinations
				 * outside the current function, but it may result
				 * on an antidisasm trick */
				addUjmp (addr+cur);
				/* An unknown jump breaks the basic blocks */
				block_end = true; // XXX more investigation here
				break;
			case R_ANAL_OP_TYPE_TRAP:
				if (cur == 0) {
					// we skip leading int3 too?
					eprintf ("TRAPSKIP %d\n", op->size);
					cur -= op->size;
					addr += op->size;
					oaddr += op->size;
				} else {
					block_end = true;
				}
				break;
			case R_ANAL_OP_TYPE_RET:
				addRet (addr + cur);
				bbAdd (db, addr, addr + cur + op->size, UT64_MAX, UT64_MAX);
				block_end = true;
				break;
			case R_ANAL_OP_TYPE_CJMP:
				addCjmp (addr+cur);
				bbAdd (db, addr, addr + cur + op->size, op->jump, addr + cur + op->size);
				addTarget (core, stack, db, op->jump);
				addTarget (core, stack, db, addr + cur + op->size);
				block_end = true;
				break;
			case R_ANAL_OP_TYPE_JMP:
				addUjmp (addr+cur);
				bbAdd (db, addr, addr + cur + op->size, op->jump, UT64_MAX);
				addTarget (core, stack, db, op->jump);
				block_end = true;
				break;
			case R_ANAL_OP_TYPE_UNK:
			case R_ANAL_OP_TYPE_ILL:
				break;
			}
			cur += op->size;
			r_anal_op_free (op);
			op = NULL;
		}
	}

	r_stack_free (stack);
	return oaddr;
}

static ut64 getFunctionSize(Sdb *db) {
	ut64 min, max;
	char *c, *bbs = sdb_get (db, "bbs", NULL);
	int first = 1;
	sdb_aforeach (c, bbs) {
		ut64 addr = sdb_atoi (c);
		ut64 addr_end = sdb_num_get (db, Fbb(addr), NULL);
		if (first) {
			min = addr;
			max = addr_end;
			first = 0;
		} else {
			if (addr<min)
				min = addr;
			if (addr_end>max)
				max = addr_end;
		}
		sdb_aforeach_next (c);
	}
	free (bbs);
	return max - min;
}

static int analyzeFunction(RCore *core, ut64 addr) {
	Sdb *db = sdb_new0 ();
	RFlagItem *fi;
	char *function_label;
	bool hasnext = r_config_get_i (core->config, "anal.hasnext");
	if (!db) {
		eprintf ("Cannot create db\n");
		return false;
	}

	addr = analyzeStackBased (core, db, addr);
	if (addr == UT64_MAX) {
		eprintf ("Initial analysis failed\n");
		return false;
	}
	sdb_num_set (db, "addr", addr, 0);

	eprintf ("addr: %s\n", sdb_const_get (db, "addr", NULL));
	eprintf ("calls: %s\n", sdb_const_get (db, "calls", NULL));
	eprintf ("ucalls: %s\n", sdb_const_get (db, "ucalls", NULL));
	eprintf ("cjmps: %s\n", sdb_const_get (db, "cjmps", NULL));
	eprintf ("ujmps: %s\n", sdb_const_get (db, "ujmps", NULL));
	eprintf ("rets: %s\n", sdb_const_get (db, "rets", NULL));
	eprintf ("bbs: %s\n", sdb_const_get (db, "bbs", NULL));

	// fcnfit to get fcn size
	sdb_num_set (db, "size", getFunctionSize (db), 0);

	// receiving a possible flag to label the new function
	fi = r_flag_get_at (core->flags, addr);
	if (fi && fi->name && strncmp (fi->name, "sect", 4)) {
		function_label = strdup (fi->name);
	} else {
		function_label = r_str_newf ("fcn2.%08"PFMT64x, addr);
	}
	r_core_cmdf (core, "af+ 0x%08"PFMT64x" %d %s\n",
			sdb_num_get (db, "addr", NULL),
			(int)sdb_num_get (db, "size", NULL),
			function_label
		      );
	// list bbs
	{
		char *c, *bbs = sdb_get (db, "bbs", NULL);
		int first = 1;
		sdb_aforeach (c, bbs) {
			ut64 jump, fail;
			ut64 addr = sdb_atoi (c);
			ut64 addr_end = sdb_num_get (db, Fbb(addr), NULL);
			// check if call destination is inside the function boundaries
			eprintf ("BB 0x%08"PFMT64x" - 0x%08"PFMT64x"  %d\n",
				addr, addr_end, (int)(addr_end-addr));
			eprintf ("  -> %s\n", sdb_const_get (db, FbbTo (addr), 0));
			jump = sdb_array_get_num (db, FbbTo(addr), 0, NULL);
			fail = sdb_array_get_num (db, FbbTo(addr), 1, NULL);

			r_core_cmdf (core, "afb+ 0x%"PFMT64x" 0x%"PFMT64x" %d 0x%"PFMT64x" 0x%"PFMT64x,
				sdb_num_get (db, "addr", NULL),
				addr, (int)(addr_end-addr),
				jump, fail);
			sdb_aforeach_next (c);
		}
		free (bbs);
		free (function_label);
	}
	eprintf ("size: %s\n", sdb_const_get (db, "size", NULL));
	// analyze next calls
	{
		char *c, *calls = sdb_get (db, "calls", NULL);
		sdb_aforeach (c, calls) {
			ut64 addr = sdb_atoi (c);
			r_cons_printf ("a2f @ 0x%"PFMT64x"\n", addr);
			sdb_aforeach_next (c);
		}
		free (calls);
	}
	sdb_free (db);
	return true;
}

static int r_cmd_anal_call(void *user, const char *input) {
	RCore *core = (RCore *) user;
	if (!strncmp (input, "a2", 2)) {
		switch (input[2]) {
		case 'f':
			if (!analyzeFunction (core, core->offset)) {
				eprintf ("a2f: Failed to analyze function.\n");
			}
			break;
		default:
			eprintf ("Usage: a2f\n");
			eprintf ("a2f is the new (experimental) analysis engine\n");
			eprintf ("Use with caution.\n");
			break;
		}
		return true;
	}
	return false;
}

// PLUGIN Definition Info
RCorePlugin r_core_plugin_anal = {
	.name = "anal",
	.desc = "The reworked analysis from scratch thing",
	.license = "LGPL3",
	.call = r_cmd_anal_call,
	.deinit = NULL,
	.init = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_anal,
	.version = R2_VERSION
};
#endif
