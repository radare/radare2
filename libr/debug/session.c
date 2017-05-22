/* radare - LGPL - Copyright 2017 - rkx1209 */
#include <r_debug.h>

R_API void r_debug_session_free(void *p) {
	free (p);
}

static int r_debug_session_lastid(RDebug *dbg) {
	return r_list_length (dbg->sessions);
}

R_API void r_debug_session_list(RDebug *dbg) {
	const char *comment;
	ut32 count = 0;
	RListIter *iterse, *itersn;
	RDebugSnap *snap;
	RDebugSnapDiff *diff;
	RDebugSession *session;
	r_list_foreach (dbg->sessions, iterse, session) {
		count = 0;
		dbg->cb_printf ("session:%2d\tat:0x%08"PFMT64x "\n", session->key.id, session->key.addr);
		r_list_foreach (session->memlist, itersn, diff) {
			snap = diff->base;
			comment = "";
			if (snap->comment && *snap->comment) {
				comment = snap->comment;
			}
			dbg->cb_printf ("\t- %d 0x%08"PFMT64x " - 0x%08"PFMT64x " size: %d (page: %d)  --  %s\n",
				count, snap->addr, snap->addr_end, snap->size, diff->page_off, comment);
			count++;
		}
	}
}

R_API bool r_debug_session_add(RDebug *dbg) {
	RDebugSession *session;
	RDebugSnap *snap;
	RDebugSnapDiff *diff;
	RListIter *iter, *tail;
	ut64 addr;
	int i;
	session = R_NEW0 (RDebugSession);
	if (!session) {
		return false;
	}

	addr = r_debug_reg_get (dbg, dbg->reg->name[R_REG_NAME_PC]);
	session->key = (RDebugKey) {
		addr, r_debug_session_lastid (dbg)
	};

	/* save current registers */
	r_debug_reg_sync (dbg, R_REG_TYPE_ALL, 0);
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		session->reg[i] = r_list_tail (dbg->reg->regset[i].pool);
	}
	r_reg_arena_push (dbg->reg);

	/* save memory snapshots */
	session->memlist = r_list_newf (r_debug_diff_free);

	r_debug_snap_all (dbg, R_IO_RW);

	r_list_foreach (dbg->snaps, iter, snap) {
		if (r_list_length (snap->history) > 0) {
			/* Diff history exists */
			tail = r_list_tail (snap->history);
			diff = (RDebugSnapDiff *)tail->data;
			r_list_append (session->memlist, diff);
		}
	}

	r_list_append (dbg->sessions, session);
	return true;
}

R_API void r_debug_session_set(RDebug *dbg, RDebugSession *session) {
	RDebugSnapDiff *diff;
	RRegArena *arena;
	RListIter *iter, *iterr;
	int i;
	/* Restore all regsiter values from the stack area pointed by session */
	r_debug_reg_sync (dbg, R_REG_TYPE_ALL, 0);
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		iterr = session->reg[i];
		arena = iterr->data;
		if (dbg->reg->regset[i].arena->bytes) {
			memcpy (dbg->reg->regset[i].arena->bytes, arena->bytes, arena->size);
		}
	}
	r_debug_reg_sync (dbg, R_REG_TYPE_ALL, 1);

	/* Restore all memory values from memory (diff) snapshots */
	r_list_foreach (session->memlist, iter, diff) {
		r_debug_diff_set (dbg, diff);
	}
}

R_API bool r_debug_session_set_idx(RDebug *dbg, int idx) {
	RDebugSession *session;
	RListIter *iter;
	ut32 count = 0;

	if (!dbg || idx < 0) {
		return false;
	}

	r_list_foreach (dbg->sessions, iter, session) {
		if (count == idx) {
			r_debug_session_set (dbg, session);
			return true;
		}
		count++;
	}
	return false;
}

R_API RDebugSession *r_debug_session_get(RDebug *dbg, ut64 addr) {
	RDebugSession *session;
	RListIter *iter;
	r_list_foreach_prev (dbg->sessions, iter, session) {
		if (session->key.addr != addr) {
			/* Sessions are saved along program flow. So key must be compared by "!=" not "<". *
			         ex. Some operations like, jmp, can go back to former address in normal program flow. */
			return session;
		}
	}
	return NULL;
}
