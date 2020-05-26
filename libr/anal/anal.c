/* radare - LGPL - Copyright 2009-2019 - pancake, nibble */

#include <r_anal.h>
#include <r_util.h>
#include <r_list.h>
#include <r_io.h>
#include <config.h>

R_LIB_VERSION(r_anal);

static RAnalPlugin *anal_static_plugins[] = {
	R_ANAL_STATIC_PLUGINS
};

R_API void r_anal_set_limits(RAnal *anal, ut64 from, ut64 to) {
	free (anal->limit);
	anal->limit = R_NEW0 (RAnalRange);
	if (anal->limit) {
		anal->limit->from = from;
		anal->limit->to = to;
	}
}

R_API void r_anal_unset_limits(RAnal *anal) {
	R_FREE (anal->limit);
}

static void meta_unset_for(REvent *ev, int type, void *user, void *data) {
	RSpaces *s = (RSpaces *)ev->user;
	RAnal *anal = container_of (s, RAnal, meta_spaces);
	RSpaceEvent *se = (RSpaceEvent *)data;
	r_meta_space_unset_for (anal, se->data.unset.space);
}

static void meta_count_for(REvent *ev, int type, void *user, void *data) {
	RSpaces *s = (RSpaces *)ev->user;
	RAnal *anal = container_of (s, RAnal, meta_spaces);
	RSpaceEvent *se = (RSpaceEvent *)data;
	se->res = r_meta_space_count_for (anal, se->data.count.space);
}

static void zign_unset_for(REvent *ev, int type, void *user, void *data) {
	RSpaces *s = (RSpaces *)ev->user;
	RAnal *anal = container_of (s, RAnal, zign_spaces);
	RSpaceEvent *se = (RSpaceEvent *)data;
	r_sign_space_unset_for (anal, se->data.unset.space);
}

static void zign_count_for(REvent *ev, int type, void *user, void *data) {
	RSpaces *s = (RSpaces *)ev->user;
	RAnal *anal = container_of (s, RAnal, zign_spaces);
	RSpaceEvent *se = (RSpaceEvent *)data;
	se->res = r_sign_space_count_for (anal, se->data.count.space);
}

static void zign_rename_for(REvent *ev, int type, void *user, void *data) {
	RSpaces *s = (RSpaces *)ev->user;
	RAnal *anal = container_of (s, RAnal, zign_spaces);
	RSpaceEvent *se = (RSpaceEvent *)data;
	r_sign_space_rename_for (anal, se->data.rename.space,
		se->data.rename.oldname, se->data.rename.newname);
}

void r_anal_hint_storage_init(RAnal *a);
void r_anal_hint_storage_fini(RAnal *a);

static void r_meta_item_fini(RAnalMetaItem *item) {
	free (item->str);
}

static void r_meta_item_free(void *_item) {
	if (_item) {
		RAnalMetaItem *item = _item;
		r_meta_item_fini (item);
		free (item);
	}
}

R_API RAnal *r_anal_new(void) {
	int i;
	RAnal *anal = R_NEW0 (RAnal);
	if (!anal) {
		return NULL;
	}
	if (!r_str_constpool_init (&anal->constpool)) {
		free (anal);
		return NULL;
	}
	anal->bb_tree = NULL;
	anal->ht_addr_fun = ht_up_new0 ();
	anal->ht_name_fun = ht_pp_new0 ();
	anal->os = strdup (R_SYS_OS);
	anal->esil_goto_limit = R_ANAL_ESIL_GOTO_LIMIT;
	anal->opt.nopskip = true; // skip nops in code analysis
	anal->opt.hpskip = false; // skip `mov reg,reg` and `lea reg,[reg]`
	anal->gp = 0LL;
	anal->sdb = sdb_new0 ();
	anal->cpp_abi = R_ANAL_CPP_ABI_ITANIUM;
	anal->opt.depth = 32;
	anal->opt.noncode = false; // do not analyze data by default
	r_spaces_init (&anal->meta_spaces, "CS");
	r_event_hook (anal->meta_spaces.event, R_SPACE_EVENT_UNSET, meta_unset_for, NULL);
	r_event_hook (anal->meta_spaces.event, R_SPACE_EVENT_COUNT, meta_count_for, NULL);

	r_spaces_init (&anal->zign_spaces, "zs");
	r_event_hook (anal->zign_spaces.event, R_SPACE_EVENT_UNSET, zign_unset_for, NULL);
	r_event_hook (anal->zign_spaces.event, R_SPACE_EVENT_COUNT, zign_count_for, NULL);
	r_event_hook (anal->zign_spaces.event, R_SPACE_EVENT_RENAME, zign_rename_for, NULL);
	anal->sdb_fcns = sdb_ns (anal->sdb, "fcns", 1);
	r_anal_hint_storage_init (anal);
	r_interval_tree_init (&anal->meta, r_meta_item_free);
	anal->sdb_types = sdb_ns (anal->sdb, "types", 1);
	anal->sdb_fmts = sdb_ns (anal->sdb, "spec", 1);
	anal->sdb_cc = sdb_ns (anal->sdb, "cc", 1);
	anal->sdb_zigns = sdb_ns (anal->sdb, "zigns", 1);
	anal->sdb_classes = sdb_ns (anal->sdb, "classes", 1);
	anal->sdb_classes_attrs = sdb_ns (anal->sdb_classes, "attrs", 1);
	anal->zign_path = strdup ("");
	anal->cb_printf = (PrintfCallback) printf;
	(void)r_anal_pin_init (anal);
	(void)r_anal_xrefs_init (anal);
	anal->diff_thbb = R_ANAL_THRESHOLDBB;
	anal->diff_thfcn = R_ANAL_THRESHOLDFCN;
	anal->syscall = r_syscall_new ();
	r_io_bind_init (anal->iob);
	r_flag_bind_init (anal->flb);
	anal->reg = r_reg_new ();
	anal->last_disasm_reg = NULL;
	anal->stackptr = 0;
	anal->lineswidth = 0;
	anal->fcns = r_list_newf (r_anal_function_free);
	anal->refs = r_anal_ref_list_new ();
	anal->leaddrs = NULL;
	r_anal_set_bits (anal, 32);
	anal->plugins = r_list_newf ((RListFree) r_anal_plugin_free);
	if (anal->plugins) {
		for (i = 0; anal_static_plugins[i]; i++) {
			r_anal_add (anal, anal_static_plugins[i]);
		}
	}
	return anal;
}

R_API void r_anal_plugin_free (RAnalPlugin *p) {
	if (p && p->fini) {
		p->fini (NULL);
	}
}

void __block_free_rb(RBNode *node, void *user);

R_API RAnal *r_anal_free(RAnal *a) {
	if (!a) {
		return NULL;
	}
	/* TODO: Free anals here */
	r_list_free (a->fcns);
	ht_up_free (a->ht_addr_fun);
	ht_pp_free (a->ht_name_fun);
	set_u_free (a->visited);
	r_anal_hint_storage_fini (a);
	r_interval_tree_fini (&a->meta);
	free (a->cpu);
	free (a->os);
	free (a->zign_path);
	r_list_free (a->plugins);
	r_rbtree_free (a->bb_tree, __block_free_rb, NULL);
	r_spaces_fini (&a->meta_spaces);
	r_spaces_fini (&a->zign_spaces);
	r_anal_pin_fini (a);
	r_list_free (a->refs);
	r_syscall_free (a->syscall);
	r_reg_free (a->reg);
	r_anal_op_free (a->queued);
	ht_up_free (a->dict_refs);
	ht_up_free (a->dict_xrefs);
	r_list_free (a->leaddrs);
	sdb_free (a->sdb);
	if (a->esil) {
		r_anal_esil_free (a->esil);
		a->esil = NULL;
	}
	free (a->last_disasm_reg);
	r_str_constpool_fini (&a->constpool);
	free (a);
	return NULL;
}

R_API void r_anal_set_user_ptr(RAnal *anal, void *user) {
	anal->user = user;
}

R_API int r_anal_add(RAnal *anal, RAnalPlugin *foo) {
	if (foo->init) {
		foo->init (anal->user);
	}
	r_list_append (anal->plugins, foo);
	return true;
}

R_API bool r_anal_use(RAnal *anal, const char *name) {
	RListIter *it;
	RAnalPlugin *h;

	if (anal) {
		bool change = anal->cur && strcmp (anal->cur->name, name);
		r_list_foreach (anal->plugins, it, h) {
			if (!h->name || strcmp (h->name, name)) {
				continue;
			}
#if 0
			// regression happening here for asm.emu
			if (anal->cur && anal->cur == h) {
				return true;
			}
#endif
			anal->cur = h;
			r_anal_set_reg_profile (anal);
			if (change) {
				r_anal_set_fcnsign (anal, NULL);
			}
			return true;
		}
	}
	return false;
}

R_API char *r_anal_get_reg_profile(RAnal *anal) {
	r_return_val_if_fail (anal, NULL);
	if (r_arch_lazysession_can_decode (anal->lsa)) {
		// XXX unnecessary strdup here
		return strdup (anal->lsa->session->info.regprofile);
	}
	return (anal->cur && anal->cur->get_reg_profile)
		? anal->cur->get_reg_profile (anal) : NULL;
}

// deprecate.. or at least reuse get_reg_profile...
R_API bool r_anal_set_reg_profile(RAnal *anal) {
	if (r_arch_lazysession_can_decode (anal->lsa)) {
		const char *r = anal->lsa->session->info.regprofile;
		r_reg_set_profile_string (anal->reg, r);
	}
	bool ret = false;
	if (anal && anal->cur && anal->cur->set_reg_profile) {
		ret = anal->cur->set_reg_profile (anal);
	} else {
		char *p = r_anal_get_reg_profile (anal);
		if (p && *p) {
			r_reg_set_profile_string (anal->reg, p);
			ret = true;
		}
		free (p);
	}
	return ret;
}

R_API bool r_anal_set_fcnsign(RAnal *anal, const char *name) {
	const char *dirPrefix = r_sys_prefix (NULL);
	const char *arch = (anal->cur && anal->cur->arch) ? anal->cur->arch : R_SYS_ARCH;
	const char *file = (name && *name)
		? sdb_fmt (R_JOIN_3_PATHS ("%s", R2_SDB_FCNSIGN, "%s.sdb"), dirPrefix, name)
		: sdb_fmt (R_JOIN_3_PATHS ("%s", R2_SDB_FCNSIGN, "%s-%s-%d.sdb"), dirPrefix,
			anal->os, arch, anal->bits);
	if (r_file_exists (file)) {
		sdb_close (anal->sdb_fcnsign);
		sdb_free (anal->sdb_fcnsign);
		anal->sdb_fcnsign = sdb_new (0, file, 0);
		sdb_ns_set (anal->sdb, "fcnsign", anal->sdb_fcnsign);
		return (anal->sdb_fcnsign != NULL);
	}
	return false;
}

R_API const char *r_anal_get_fcnsign(RAnal *anal, const char *sym) {
	return sdb_const_get (anal->sdb_fcnsign, sym, 0);
}

R_API bool r_anal_set_triplet(RAnal *anal, const char *os, const char *arch, int bits) {
	r_return_val_if_fail (anal, false);
	if (!os || !*os) {
		os = R_SYS_OS;
	}
	if (!arch || !*arch) {
		arch = anal->cur? anal->cur->arch: R_SYS_ARCH;
	}
	if (bits < 1) {
		bits = anal->bits;
	}
	free (anal->os);
	anal->os = strdup (os);
	r_anal_set_bits (anal, bits);
	return r_anal_use (anal, arch);
}

// copypasta from core/cbin.c
static void sdb_concat_by_path(Sdb *s, const char *path) {
	Sdb *db = sdb_new (0, path, 0);
	sdb_merge (s, db);
	sdb_close (db);
	sdb_free (db);
}

R_API bool r_anal_set_os(RAnal *anal, const char *os) {
	Sdb *types = anal->sdb_types;
	const char *dir_prefix = r_sys_prefix (NULL);
	const char *dbpath = sdb_fmt (R_JOIN_3_PATHS ("%s", R2_SDB_FCNSIGN, "types-%s.sdb"),
		dir_prefix, os);
	if (r_file_exists (dbpath)) {
		sdb_concat_by_path (types, dbpath);
	}
	return r_anal_set_triplet (anal, os, NULL, -1);
}

R_API bool r_anal_set_bits(RAnal *anal, int bits) {
	switch (bits) {
	case 8:
	case 16:
	case 27:
	case 32:
	case 64:
		if (anal->bits != bits) {
			anal->bits = bits;
			r_anal_set_fcnsign (anal, NULL);
			(void)r_anal_set_reg_profile (anal);
		}
		return true;
	}
	return false;
}

R_API void r_anal_set_cpu(RAnal *anal, const char *cpu) {
	free (anal->cpu);
	anal->cpu = cpu ? strdup (cpu) : NULL;
	int v = r_anal_archinfo (anal, R_ANAL_ARCHINFO_ALIGN);
	if (v != -1) {
		anal->pcalign = v;
	}
}

R_API int r_anal_set_big_endian(RAnal *anal, int bigend) {
	anal->big_endian = bigend;
	anal->reg->big_endian = bigend;
	return true;
}

R_API ut8 *r_anal_mask(RAnal *anal, int size, const ut8 *data, ut64 at) {
	RAnalOp *op = NULL;
	ut8 *ret = NULL;
	int oplen, idx = 0;

	if (!data) {
		return NULL;
	}

	if (anal->cur && anal->cur->anal_mask) {
		return anal->cur->anal_mask (anal, size, data, at);
	}

	if (!(op = r_anal_op_new ())) {
		return NULL;
	}

	if (!(ret = malloc (size))) {
		r_anal_op_free (op);
		return NULL;
	}

	memset (ret, 0xff, size);

	while (idx < size) {
		if ((oplen = r_anal_op (anal, op, at, data + idx, size - idx, R_ANAL_OP_MASK_BASIC)) < 1) {
			break;
		}
		if ((op->ptr != UT64_MAX || op->jump != UT64_MAX) && op->nopcode != 0) {
			memset (ret + idx + op->nopcode, 0, oplen - op->nopcode);
		}
		idx += oplen;
		at += oplen;
	}

	r_anal_op_free (op);

	return ret;
}

R_API void r_anal_trace_bb(RAnal *anal, ut64 addr) {
	RAnalBlock *bbi;
	RAnalFunction *fcni;
	RListIter *iter2;
	fcni = r_anal_get_fcn_in (anal, addr, 0);
	if (fcni) {
		r_list_foreach (fcni->bbs, iter2, bbi) {
			if (addr >= bbi->addr && addr < (bbi->addr + bbi->size)) {
				bbi->traced = true;
				break;
			}
		}
	}
}

R_API void r_anal_colorize_bb(RAnal *anal, ut64 addr, ut32 color) {
	RAnalBlock *bbi;
	bbi = r_anal_bb_from_offset (anal, addr);
	if (bbi) {
		bbi->colorize = color;
	}
}

R_API RList* r_anal_get_fcns (RAnal *anal) {
	// avoid received to free this thing
	anal->fcns->free = NULL;
	return anal->fcns;
}

R_API RAnalOp *r_anal_op_hexstr(RAnal *anal, ut64 addr, const char *str) {
	RAnalOp *op = R_NEW0 (RAnalOp);
	if (!op) {
		return NULL;
	}
	ut8 *buf = calloc (1, strlen (str) + 1);
	if (!buf) {
		free (op);
		return NULL;
	}
	int len = r_hex_str2bin (str, buf);
	r_anal_op (anal, op, addr, buf, len, R_ANAL_OP_MASK_BASIC);
	free (buf);
	return op;
}

R_API bool r_anal_op_is_eob(RAnalOp *op) {
	if (op->eob) {
		return true;
	}
	switch (op->type) {
	case R_ANAL_OP_TYPE_JMP:
	case R_ANAL_OP_TYPE_UJMP:
	case R_ANAL_OP_TYPE_RJMP:
	case R_ANAL_OP_TYPE_IJMP:
	case R_ANAL_OP_TYPE_IRJMP:
	case R_ANAL_OP_TYPE_CJMP:
	case R_ANAL_OP_TYPE_RET:
	case R_ANAL_OP_TYPE_TRAP:
		return true;
	default:
		return false;
	}
}

R_API int r_anal_purge (RAnal *anal) {
	sdb_reset (anal->sdb_fcns);
	r_anal_hint_clear (anal);
	r_interval_tree_fini (&anal->meta);
	r_interval_tree_init (&anal->meta, r_meta_item_free);
	sdb_reset (anal->sdb_types);
	sdb_reset (anal->sdb_zigns);
	sdb_reset (anal->sdb_classes);
	sdb_reset (anal->sdb_classes_attrs);
	r_list_free (anal->fcns);
	anal->fcns = r_list_newf (r_anal_function_free);
	r_list_free (anal->refs);
	anal->refs = r_anal_ref_list_new ();
	return 0;
}

R_API int r_anal_archinfo(RAnal *anal, int query) {
	r_return_val_if_fail (anal, -1);
	switch (query) {
	case R_ANAL_ARCHINFO_MIN_OP_SIZE:
	case R_ANAL_ARCHINFO_MAX_OP_SIZE:
	case R_ANAL_ARCHINFO_ALIGN:
		if (anal->cur && anal->cur->archinfo) {
			return anal->cur->archinfo (anal, query);
		}
		break;
	}
	return -1;
}

static int __nonreturn_print_commands(void *p, const char *k, const char *v) {
	RAnal *anal = (RAnal *)p;
	if (!strncmp (v, "func", strlen ("func") + 1)) {
		char *query = sdb_fmt ("func.%s.noreturn", k);
		if (sdb_bool_get (anal->sdb_types, query, NULL)) {
			anal->cb_printf ("tnn %s\n", k);
		}
	}
	if (!strncmp (k, "addr.", 5)) {
		anal->cb_printf ("tna 0x%s %s\n", k + 5, v);
	}
	return 1;
}

static int __nonreturn_print(void *p, const char *k, const char *v) {
	RAnal *anal = (RAnal *)p;
	if (!strncmp (k, "func.", 5) && strstr (k, ".noreturn")) {
		char *s = strdup (k + 5);
		char *d = strchr (s, '.');
		if (d) {
			*d = 0;
		}
		anal->cb_printf ("%s\n", s);
		free (s);
	}
	if (!strncmp (k, "addr.", 5)) {
		char *off;
		if (!(off = strdup (k + 5))) {
			return 1;
		}
		char *ptr = strstr (off, ".noreturn");
		if (ptr) {
			*ptr = 0;
			anal->cb_printf ("0x%s\n", off);
		}
		free (off);
	}
	return 1;
}

R_API void r_anal_noreturn_list(RAnal *anal, int mode) {
	switch (mode) {
	case 1:
	case '*':
	case 'r':
		sdb_foreach (anal->sdb_types, __nonreturn_print_commands, anal);
		break;
	default:
		sdb_foreach (anal->sdb_types, __nonreturn_print, anal);
		break;
	}
}

#define K_NORET_ADDR(x) sdb_fmt ("addr.%"PFMT64x".noreturn", x)
#define K_NORET_FUNC(x) sdb_fmt ("func.%s.noreturn", x)

R_API bool r_anal_noreturn_add(RAnal *anal, const char *name, ut64 addr) {
	const char *tmp_name = NULL;
	Sdb *TDB = anal->sdb_types;
	char *fnl_name = NULL;
	if (addr != UT64_MAX) {
		if (sdb_bool_set (TDB, K_NORET_ADDR (addr), true, 0)) {
			RAnalFunction *fcn = r_anal_get_function_at (anal, addr);
			if (fcn) {
				fcn->is_noreturn = true;
			}
			return true;
		}
	}
	if (name && *name) {
		tmp_name = name;
	} else {
		RAnalFunction *fcn = r_anal_get_fcn_in (anal, addr, -1);
		RFlagItem *fi = anal->flb.get_at (anal->flb.f, addr, false);
		if (!fcn && !fi) {
			eprintf ("Can't find Function at given address\n");
			return false;
		}
		tmp_name = fcn ? fcn->name: fi->name;
		if (fcn) {
			fcn->is_noreturn = true;
		}
	}
	if (r_type_func_exist (TDB, tmp_name)) {
		fnl_name = strdup (tmp_name);
	} else if (!(fnl_name = r_type_func_guess (TDB, (char *)tmp_name))) {
		if (addr == UT64_MAX) {
			if (name) {
				sdb_bool_set (TDB, K_NORET_FUNC (name), true, 0);
			} else {
				eprintf ("Can't find prototype for: %s\n", tmp_name);
			}
		} else {
			eprintf ("Can't find prototype for: %s\n", tmp_name);
		}
		//return false;
	}
	if (fnl_name) {
		sdb_bool_set (TDB, K_NORET_FUNC (fnl_name), true, 0);
		free (fnl_name);
	}
	return true;
}

R_API bool r_anal_noreturn_drop(RAnal *anal, const char *expr) {
	Sdb *TDB = anal->sdb_types;
	expr = r_str_trim_head_ro (expr);
	const char *fcnname = NULL;
	if (!strncmp (expr, "0x", 2)) {
		ut64 n = r_num_math (NULL, expr);
		sdb_unset (TDB, K_NORET_ADDR (n), 0);
		RAnalFunction *fcn = r_anal_get_fcn_in (anal, n, -1);
		if (!fcn) {
			// eprintf ("can't find function at 0x%"PFMT64x"\n", n);
			return false;
		}
		fcnname = fcn->name;
	} else {
		fcnname = expr;
	}
	sdb_unset (TDB, K_NORET_FUNC (fcnname), 0);
#if 0
	char *tmp;
	// unnsecessary checks, imho the noreturn db should be pretty simple to allow forward and custom declarations without having to define the function prototype before
	if (r_type_func_exist (TDB, fcnname)) {
		sdb_unset (TDB, K_NORET_FUNC (fcnname), 0);
		return true;
	} else if ((tmp = r_type_func_guess (TDB, (char *)fcnname))) {
		sdb_unset (TDB, K_NORET_FUNC (fcnname), 0);
		free (tmp);
		return true;
	}
	eprintf ("Can't find prototype for %s in types database", fcnname);
#endif
	return false;
}

static bool r_anal_noreturn_at_name(RAnal *anal, const char *name) {
	if (sdb_bool_get (anal->sdb_types, K_NORET_FUNC(name), NULL)) {
		return true;
	}
	char *tmp = r_type_func_guess (anal->sdb_types, (char *)name);
	if (tmp) {
		if (sdb_bool_get (anal->sdb_types, K_NORET_FUNC (tmp), NULL)) {
			free (tmp);
			return true;
		}
		free (tmp);
	}
	if (r_str_startswith (name, "reloc.")) {
		return r_anal_noreturn_at_name (anal, name + 6);
	}
	return false;
}

R_API bool r_anal_noreturn_at_addr(RAnal *anal, ut64 addr) {
	return sdb_bool_get (anal->sdb_types, K_NORET_ADDR (addr), NULL);
}

static bool noreturn_recurse(RAnal *anal, ut64 addr) {
	RAnalOp op = {0};
	ut8 bbuf[0x10] = {0};
	ut64 recurse_addr = UT64_MAX;
	if (!anal->iob.read_at (anal->iob.io, addr, bbuf, sizeof (bbuf))) {
		eprintf ("Couldn't read buffer\n");
		return false;
	}
	if (r_anal_op (anal, &op, addr, bbuf, sizeof (bbuf), R_ANAL_OP_MASK_BASIC | R_ANAL_OP_MASK_VAL) < 1) {
		return false;
	}
	switch (op.type & R_ANAL_OP_TYPE_MASK) {
	case R_ANAL_OP_TYPE_JMP:
		if (op.jump == UT64_MAX) {
			recurse_addr = op.ptr;
		} else {
			recurse_addr = op.jump;
		}
		break;
	case R_ANAL_OP_TYPE_UCALL:
	case R_ANAL_OP_TYPE_RCALL:
	case R_ANAL_OP_TYPE_ICALL:
	case R_ANAL_OP_TYPE_IRCALL:
		recurse_addr = op.ptr;
		break;
	case R_ANAL_OP_TYPE_CCALL:
	case R_ANAL_OP_TYPE_CALL:
		recurse_addr = op.jump;
		break;
	}
	if (recurse_addr == UT64_MAX || recurse_addr == addr) {
		return false;
	}
	return r_anal_noreturn_at (anal, recurse_addr);
}

R_API bool r_anal_noreturn_at(RAnal *anal, ut64 addr) {
	if (!addr || addr == UT64_MAX) {
		return false;
	}
	if (r_anal_noreturn_at_addr (anal, addr)) {
		return true;
	}
	/* XXX this is very slow */
	RAnalFunction *f = r_anal_get_function_at (anal, addr);
	if (f) {
		if (r_anal_noreturn_at_name (anal, f->name)) {
			return true;
		}
	}
	RFlagItem *fi = anal->flag_get (anal->flb.f, addr);
	if (fi) {
		if (r_anal_noreturn_at_name (anal, fi->realname ? fi->realname : fi->name)) {
			return true;
		}
	}
	if (anal->recursive_noreturn) {
		return noreturn_recurse (anal, addr);
	}
	return false;
}

R_API void r_anal_bind(RAnal *anal, RAnalBind *b) {
	if (b) {
		b->anal = anal;
		b->get_fcn_in = r_anal_get_fcn_in;
		b->get_hint = r_anal_hint_get;
	}
}

R_API RList *r_anal_preludes(RAnal *anal) {
	if (anal->cur && anal->cur->preludes ) {
		return anal->cur->preludes (anal);
	}
	return NULL;
}

R_API bool r_anal_is_prelude(RAnal *anal, const ut8 *data, int len) {
	RList *l = r_anal_preludes (anal);
	if (l) {
		RSearchKeyword *kw;
		RListIter *iter;
		r_list_foreach (l, iter, kw) {
			int ks = kw->keyword_length;
			if (len >= ks && !memcmp (data, kw->bin_keyword, ks)) {
				r_list_free (l);
				return true;
			}
		}
		r_list_free (l);
	}
	return false;
}
