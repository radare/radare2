/* radare - Apache 2.0 - Copyright 2013 - Adam Pridgen <dso@rice.edu || adam.pridgen@thecoverofnight.com> */

#include <r_anal.h>
#include <r_anal2.h>
#include <r_util.h>
#include <r_list.h>
#include <r_io.h>
#include "../config.h"

#define IFDBG if(0)


static void r_anal2_perform_pre_anal(RAnal *anal, RAnalInfos *state, ut64 addr);
static void r_anal2_perform_pre_anal_op_cb(RAnal *anal, RAnalInfos *state, ut64 addr);
static void r_anal2_perform_pre_anal_bb_cb(RAnal *anal, RAnalInfos *state, ut64 addr);
static void r_anal2_perform_pre_anal_fn_cb(RAnal *anal, RAnalInfos *state, ut64 addr);

static void r_anal2_perform_post_anal(RAnal *anal, RAnalInfos *state, ut64 addr);
static void r_anal2_perform_post_anal_op_cb(RAnal *anal, RAnalInfos *state, ut64 addr);
static void r_anal2_perform_post_anal_bb_cb(RAnal *anal, RAnalInfos *state, ut64 addr);
static void r_anal2_perform_post_anal_fn_cb(RAnal *anal, RAnalInfos *state, ut64 addr);


ut64 extract_code_op(ut64 ranal2_op_type);
ut64 extract_load_store_op(ut64 ranal2_op_type);
ut64 extract_unknown_op(ut64 ranal2_op_type);
ut64 extract_bin_op(ut64 ranal2_op_type);
 
static void r_anal2_perform_pre_anal(RAnal *anal, RAnalInfos *state, ut64 addr) {
	if (anal->cur && anal->cur->pre_anal) {
		anal->cur->pre_anal (anal, state, addr);
	}
}

static void r_anal2_perform_pre_anal_op_cb(RAnal *anal, RAnalInfos *state, ut64 addr) {
	if (anal->cur && anal->cur->pre_anal_op_cb) {
		anal->cur->pre_anal_op_cb (anal, state, addr);
	}
}

static void r_anal2_perform_pre_anal_bb_cb(RAnal *anal, RAnalInfos *state, ut64 addr) {
	if (anal->cur && anal->cur->pre_anal_bb_cb) {
		anal->cur->pre_anal_bb_cb (anal, state, addr);
	}
}

static void r_anal2_perform_pre_anal_fn_cb(RAnal *anal, RAnalInfos *state, ut64 addr) {
	if (anal->cur && anal->cur->pre_anal_fn_cb) {
		anal->cur->pre_anal_fn_cb (anal, state, addr);
	}
}

static void r_anal2_perform_post_anal_op_cb(RAnal *anal, RAnalInfos *state, ut64 addr) {
	if (anal->cur && anal->cur->post_anal_op_cb) {
		anal->cur->post_anal_op_cb (anal, state, addr);
	}
}

static void r_anal2_perform_post_anal_bb_cb(RAnal *anal, RAnalInfos *state, ut64 addr) {
	if (anal->cur && anal->cur->post_anal_bb_cb) {
		anal->cur->post_anal_bb_cb (anal, state, addr);
	}
}

static void r_anal2_perform_post_anal_fn_cb(RAnal *anal, RAnalInfos *state, ut64 addr) {
	if (anal->cur && anal->cur->post_anal_fn_cb) {
		anal->cur->post_anal_fn_cb (anal, state, addr);
	}
}

static void r_anal2_perform_post_anal(RAnal *anal, RAnalInfos *state, ut64 addr) {
	if (anal->cur && anal->cur->post_anal) {
		anal->cur->post_anal (anal, state, addr);
	}
}

R_API int r_anal2_bb_address_comparator(RAnalBlock *a, RAnalBlock *b){
	if (a->addr == b->addr)
		return 0;
	else if (a->addr < b->addr)
		return -1;
	// a->addr > b->addr
	return 1;
}

R_API int r_anal2_bb_head_comparator(RAnalBlock *a, RAnalBlock *b){
	if (a->head == b->head)
		return 0;
	else if (a->head < b->head )
		return -1;
	// a->head > b->head
	return 1;
}

R_API void r_anal2_clone_op_switch_to_bb (RAnalBlock *bb, RAnalOp *op) {
	RListIter *iter;
	RAnalCaseOp *caseop = NULL;

	if ( op->switch_op ) {
		bb->switch_op = r_anal_switch_op_init (op->switch_op->addr, 
											op->switch_op->min_val, 
											op->switch_op->max_val);

		r_list_foreach (op->switch_op->cases, iter, caseop) {
			r_anal_add_switch_op_case (bb->switch_op, caseop->addr, 
													caseop->value, caseop->jump);
		}
	}
}

R_API RAnalOp * r_anal2_get_op(RAnal *anal, RAnalInfos *state, ut64 addr) {
	RAnalOp *current_op = state->current_op;
	const ut8 * data;
	// current_op set in a prior stage
	if (current_op) return current_op;
	IFDBG eprintf("r_anal2_get_op: Parsing op @ 0x%08x", addr);
	if (!r_anal2_state_addr_is_valid(state, addr) || 
		anal->cur && (anal->cur->op == NULL && anal->cur->op_from_buffer == NULL) ) {
		state->done = 1;
		return NULL;
	}
	data = r_anal2_state_get_buf_by_addr(state, addr);
	
	if (anal->cur && anal->cur->op_from_buffer) {
		current_op = anal->cur->op_from_buffer (anal, addr, data,  r_anal2_state_get_len( state, addr) );	
	} else {
		current_op = r_anal_op_new();
		anal->cur->op (anal, current_op, addr, data,  r_anal2_state_get_len( state, addr) );	
	}
	
	state->current_op = current_op;
	return current_op;

}

R_API RAnalBlock * r_anal2_get_bb(RAnal *anal, RAnalInfos *state, ut64 addr) {
	RAnalBlock *current_bb = state->current_bb;
	RAnalOp *op = state->current_op;

	// current_bb set before in a pre-analysis stage.
	if (current_bb) return current_bb;
	IFDBG eprintf("r_anal2_get_bb: Parsing op @ 0x%08x", addr);

	if (r_anal2_state_addr_is_valid(state, addr) && op == NULL)
		op = r_anal2_get_op(anal, state, addr);

	if (op == NULL || !r_anal2_state_addr_is_valid(state, addr)) return NULL;
	
	current_bb = r_anal_bb_new ();
	r_anal2_bb_to_op(anal, state, current_bb, op);
	
	if (op->eob) current_bb->type |= R_ANAL_BB_TYPE_LAST;

	current_bb->op_sz = state->current_op->size;
	memcpy(current_bb->op_bytes, r_anal2_state_get_buf_by_addr(state, addr), current_bb->op_sz);

	state->current_bb = current_bb;

	return current_bb;
}

R_API void r_anal2_update_bb_cfg_head_tail( RAnalBlock *start, RAnalBlock * head, RAnalBlock * tail ) {
	RAnalBlock *bb = start;

	if (bb) {
		bb->head = head;
		bb->tail = tail;
	}

	if (bb->next){ 
		bb->head = head;
		bb->tail = tail;
		do {
			bb->next->prev = bb;
			bb = bb->next;
			bb->head = head;
			bb->tail = tail;
		}while (bb->next != NULL && !(bb->type & R_ANAL_BB_TYPE_TAIL));
	}
}

R_API RList * r_anal2_perform_analysis( RAnal *anal, RAnalInfos *state, ut64 addr) {
	if (anal->cur && anal->cur->analysis_algorithm)
		return anal->cur->analysis_algorithm (anal, state, addr);

	return r_anal2_recursive_descent (anal, state, addr);
}

R_API RList * r_anal2_recursive_descent( RAnal *anal, RAnalInfos *state, ut64 addr ) {
	ut64 offset = 0, 
		 len = r_anal2_state_get_len (state, addr);

	RAnalBlock *pcurrent_bb = state->current_bb, 
				*current_head = NULL, 
				*past_bb = NULL;
	RAnalOp * pcurrent_op = state->current_op;

	RList *bb_list = r_anal_bb_list_new ();
	
	if (state->done)
		return bb_list;

	state->current_bb = NULL;
	state->current_op = NULL;

	r_anal2_perform_pre_anal (anal, state, addr);
	
	while (!state->done && offset < len) {

		r_anal2_perform_pre_anal_fn_cb (anal, state, addr+offset);
		state->current_bb = r_anal2_state_search_bb (state, addr+offset);
		// check state for bb
		
		if (state->current_bb) {
			// TODO something special should happen here.
			offset += state->current_bb->op_sz;
			if (state->current_bb->type & R_ANAL_BB_TYPE_TAIL) {
				r_anal2_update_bb_cfg_head_tail (current_head->next, current_head, state->current_bb);
				state->done = 1;
			}
		}
	
		r_anal2_perform_pre_anal_op_cb (anal, state, addr+offset);
		if (state->done) break;

	   	r_anal2_get_op (anal, state, addr+offset);
		r_anal2_perform_post_anal_op_cb (anal, state, addr+offset);
		if (state->done) break;
		

		r_anal2_perform_pre_anal_bb_cb (anal, state, addr+offset);
		if (state->done) break;
		

		r_anal2_get_bb (anal, state, addr+offset);
		if ( current_head == NULL ) {
			current_head = state->current_bb;
			state->current_bb->type |= R_ANAL_BB_TYPE_HEAD;
		}
		
		if (past_bb) {
			past_bb->next = state->current_bb;
			state->current_bb->prev = past_bb;
		}

		past_bb = state->current_bb;
		
		if (state->current_bb->type & R_ANAL_BB_TYPE_TAIL) {
			r_anal2_update_bb_cfg_head_tail (current_head->next, current_head, state->current_bb);
		}
		r_anal2_perform_post_anal_bb_cb (anal, state, addr+offset);
		if (state->done) {
			break;
		}

		offset += state->current_bb->op_sz;
		state->bytes_consumed += state->current_bb->op_sz;

		r_anal2_state_insert_bb (state, state->current_bb);
		r_anal2_perform_post_anal_fn_cb (anal, state, addr+offset);

		r_list_append (bb_list, state->current_bb);
		r_anal_op_free (state->current_op);
		
		state->current_op = NULL;
		state->current_bb = NULL;
	}
	
	r_anal_bb_free (state->current_bb);
	r_anal_op_free (state->current_op);
	r_anal2_perform_post_anal (anal, state, addr);
	state->current_op = pcurrent_op;
	state->current_bb = pcurrent_bb;
	return bb_list;
}

R_API void r_anal2_bb_to_op(RAnal *anal, RAnalInfos *state, RAnalBlock *bb, RAnalOp *op) {
	ut64 cnd_jmp = (R_ANAL2_COND_OP | R_ANAL2_CODEOP_JMP);
	bb->addr = op->addr;
	bb->size = op->size;
	bb->type2 = op->type2;
	bb->type = r_anal2_map_anal2_to_anal_bb_type ( op->type2 );
	bb->fail = (op->type2 & cnd_jmp) == cnd_jmp ? op->fail : UT64_MAX;
	bb->jump = (op->type2 & R_ANAL2_CODEOP_JMP) == R_ANAL2_CODEOP_JMP ? op->fail : UT64_MAX;
	bb->conditional = R_ANAL2_COND_OP & op->type2 ? R_ANAL_OP_TYPE_COND : 0;

	if (op->eob) bb->type |= R_ANAL_BB_TYPE_LAST;
	r_anal2_clone_op_switch_to_bb (bb, op);	
}

R_API ut32 r_anal2_map_anal2_to_anal_bb_type (ut64 ranal2_op_type) {
	ut32 bb_type = 0;
	ut64 conditional = R_ANAL2_COND_OP & ranal2_op_type ? R_ANAL_OP_TYPE_COND : 0;
	ut64 code_op_val = ranal2_op_type & (R_ANAL2_CODE_OP | 0x1FF);

	if (conditional) {
		bb_type |= R_ANAL_BB_TYPE_COND;
	}

	if (ranal2_op_type & R_ANAL2_LOAD_OP) {
		bb_type |= R_ANAL_BB_TYPE_LD;
	}

	if (ranal2_op_type & R_ANAL2_BIN_OP) {
		bb_type |= R_ANAL_BB_TYPE_BINOP;
	}

	if (ranal2_op_type & R_ANAL2_LOAD_OP) {
		bb_type |= R_ANAL_BB_TYPE_LD;
	}
	
	if (ranal2_op_type & R_ANAL2_STORE_OP) {
		bb_type |= R_ANAL_BB_TYPE_ST;
	}
	/* mark bb with a comparison */
	if (ranal2_op_type & R_ANAL2_BINOP_CMP) {
		bb_type |= R_ANAL_BB_TYPE_CMP;   
	}
	
	/* change in control flow here */
	if (code_op_val & R_ANAL2_CODEOP_JMP) {
		bb_type |= R_ANAL_BB_TYPE_JMP;
		bb_type |= R_ANAL_BB_TYPE_TAIL;  
	
	} else if (code_op_val & R_ANAL2_CODEOP_CALL) {
		bb_type |= R_ANAL_BB_TYPE_CALL;
		bb_type |= R_ANAL_BB_TYPE_TAIL;
	
	} else if ( code_op_val & R_ANAL2_CODEOP_SWITCH) {
		
		bb_type |= R_ANAL_BB_TYPE_SWITCH;
		bb_type |= R_ANAL_BB_TYPE_TAIL;
	
	} else if (code_op_val & R_ANAL2_CODEOP_LEAVE || 
				code_op_val & R_ANAL2_CODEOP_RET ) {
		
		bb_type |= R_ANAL_BB_TYPE_RET;
		bb_type |= R_ANAL_BB_TYPE_LAST;
		bb_type |= R_ANAL_BB_TYPE_TAIL;
	}

	if ( ranal2_op_type  & R_ANAL2_UNK_OP && code_op_val & R_ANAL2_CODEOP_JMP) 
		bb_type |= R_ANAL_BB_TYPE_FOOT;

	if ( conditional && code_op_val & R_ANAL2_CODEOP_JMP) 
		bb_type |= R_ANAL_BB_TYPE_BODY;

	return bb_type;
}

R_API int r_anal2_is_op_type_eop(ut64 x) {
	ut8 result = (x & R_ANAL2_CODE_OP) ? 1 : 0;
	IFDBG {
		eprintf ( "optype is leave: 0x%02x\n", result && (x == R_ANAL2_CODEOP_LEAVE));
		eprintf ( "optype is ret: 0x%02x\n", result && (x == R_ANAL2_CODEOP_RET));
		eprintf ( "optype is jmp: 0x%02x\n", result && (x == R_ANAL2_CODEOP_JMP));
		eprintf ( "optype is switch: 0x%02x\n", result && (x == R_ANAL2_CODEOP_SWITCH));
	}
	return result && 
			( (x & R_ANAL2_CODEOP_LEAVE) == R_ANAL2_CODEOP_LEAVE || 
			 (x & R_ANAL2_CODEOP_RET) == R_ANAL2_CODEOP_RET || 
			 (x & R_ANAL2_CODEOP_JMP) == R_ANAL2_CODEOP_JMP || 
			 (x & R_ANAL2_CODEOP_SWITCH) == R_ANAL2_CODEOP_SWITCH);
}

ut64 extract_code_op(ut64 ranal2_op_type) {
	ut64 conditional = R_ANAL2_COND_OP & ranal2_op_type ? R_ANAL_OP_TYPE_COND : 0;
	ut64 code_op_val = ranal2_op_type & (R_ANAL2_CODE_OP | 0x1FF);
	switch (code_op_val) {
		case R_ANAL2_CODEOP_CALL : return conditional | R_ANAL_OP_TYPE_CALL;
		case R_ANAL2_CODEOP_JMP  : return conditional | R_ANAL_OP_TYPE_JMP;
		case R_ANAL2_CODEOP_RET  : return conditional | R_ANAL_OP_TYPE_RET;
		case R_ANAL2_CODEOP_LEAVE: return R_ANAL_OP_TYPE_LEAVE;
		case R_ANAL2_CODEOP_SWI  : return R_ANAL_OP_TYPE_SWI;
		case R_ANAL2_CODEOP_TRAP : return R_ANAL_OP_TYPE_TRAP;
		case R_ANAL2_CODEOP_SWITCH: return R_ANAL_OP_TYPE_SWITCH;	
	}
	return R_ANAL_OP_TYPE_UNK;
}


ut64 extract_load_store_op(ut64 ranal2_op_type) {
	if ( (ranal2_op_type & R_ANAL2_LDST_OP_PUSH) == R_ANAL2_LDST_OP_PUSH) 
		return R_ANAL_OP_TYPE_PUSH;
	if ( (ranal2_op_type & R_ANAL2_LDST_OP_POP) == R_ANAL2_LDST_OP_POP )  
		return R_ANAL_OP_TYPE_POP;
	if ( (ranal2_op_type & R_ANAL2_LDST_OP_MOV) == R_ANAL2_LDST_OP_MOV)  
		return R_ANAL_OP_TYPE_MOV;
	if ( (ranal2_op_type & R_ANAL2_LDST_OP_EFF_ADDR) == R_ANAL2_LDST_OP_EFF_ADDR) 
		return R_ANAL_OP_TYPE_LEA;
	return R_ANAL_OP_TYPE_UNK;
}


ut64 extract_unknown_op(ut64 ranal2_op_type) {

	if ( (ranal2_op_type & R_ANAL2_CODEOP_JMP) == R_ANAL2_CODEOP_JMP )  return R_ANAL_OP_TYPE_UJMP;
	if ( (ranal2_op_type & R_ANAL2_CODEOP_CALL) == R_ANAL2_CODEOP_CALL) return R_ANAL_OP_TYPE_UCALL;
	if ( (ranal2_op_type & R_ANAL2_LDST_OP_PUSH) == R_ANAL2_LDST_OP_PUSH) return R_ANAL_OP_TYPE_UPUSH;
	return R_ANAL_OP_TYPE_UNK;
}

ut64 extract_bin_op(ut64 ranal2_op_type) {
	
	ut64 bin_op_val = ranal2_op_type & (R_ANAL2_BIN_OP | 0x7FFFF);
	switch (bin_op_val) {
		case R_ANAL2_BINOP_XCHG:return R_ANAL_OP_TYPE_XCHG;
		case R_ANAL2_BINOP_CMP: return R_ANAL_OP_TYPE_CMP;
		case R_ANAL2_BINOP_ADD: return R_ANAL_OP_TYPE_ADD;
		case R_ANAL2_BINOP_SUB: return R_ANAL_OP_TYPE_SUB;
		case R_ANAL2_BINOP_MUL: return R_ANAL_OP_TYPE_MUL;
		case R_ANAL2_BINOP_DIV: return R_ANAL_OP_TYPE_DIV;
		case R_ANAL2_BINOP_SHR: return R_ANAL_OP_TYPE_SHR;
		case R_ANAL2_BINOP_SHL: return R_ANAL_OP_TYPE_SHR;
		case R_ANAL2_BINOP_SAL: return R_ANAL_OP_TYPE_SAL;
		case R_ANAL2_BINOP_SAR: return R_ANAL_OP_TYPE_SAR;
		case R_ANAL2_BINOP_OR : return R_ANAL_OP_TYPE_OR;
		case R_ANAL2_BINOP_AND: return R_ANAL_OP_TYPE_AND;
		case R_ANAL2_BINOP_XOR: return R_ANAL_OP_TYPE_XOR;
		case R_ANAL2_BINOP_NOT: return R_ANAL_OP_TYPE_NOT;
		case R_ANAL2_BINOP_MOD: return R_ANAL_OP_TYPE_MOD;
		case R_ANAL2_BINOP_ROR: return R_ANAL_OP_TYPE_ROR;
		case R_ANAL2_BINOP_ROL: return R_ANAL_OP_TYPE_ROL;
	}
	return R_ANAL_OP_TYPE_UNK;
}


R_API ut64 r_anal2_map_anal2_to_anal_op_type (ut64 ranal2_op_type) {

	switch (ranal2_op_type) {
		case R_ANAL2_NULL_OP: return R_ANAL_OP_TYPE_NULL;
		case R_ANAL2_NOP: return R_ANAL_OP_TYPE_NOP;
		case R_ANAL2_ILL_OP: return R_ANAL_OP_TYPE_ILL;
		default: break;
	}

	if ( ranal2_op_type & R_ANAL2_UNK_OP)
		return extract_unknown_op(ranal2_op_type);
	
	if ( ranal2_op_type & R_ANAL2_CODE_OP)
		return extract_code_op(ranal2_op_type);

	if ( ranal2_op_type & R_ANAL2_REP_OP) 
		return R_ANAL_OP_TYPE_REP | r_anal2_map_anal2_to_anal_op_type ( ranal2_op_type & ~R_ANAL2_REP_OP );
	
	if ( ranal2_op_type & (R_ANAL2_LOAD_OP | R_ANAL2_STORE_OP ))
		return extract_load_store_op(ranal2_op_type);

	if ( ranal2_op_type & R_ANAL2_BIN_OP)
		return extract_bin_op(ranal2_op_type);
   
	return R_ANAL_OP_TYPE_UNK;
}

