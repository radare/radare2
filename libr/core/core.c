/* radare2 - LGPL - Copyright 2009-2020 - pancake */

#include <r_core.h>
#include <r_socket.h>
#include <config.h>
#include <r_arch.h>
#include <r_util.h>
#if __UNIX__
#include <signal.h>
#endif

#define DB core->sdb

R_LIB_VERSION(r_core);

static ut64 letter_divs[R_CORE_ASMQJMPS_LEN_LETTERS - 1] = {
	R_CORE_ASMQJMPS_LETTERS * R_CORE_ASMQJMPS_LETTERS * R_CORE_ASMQJMPS_LETTERS * R_CORE_ASMQJMPS_LETTERS,
	R_CORE_ASMQJMPS_LETTERS * R_CORE_ASMQJMPS_LETTERS * R_CORE_ASMQJMPS_LETTERS,
	R_CORE_ASMQJMPS_LETTERS * R_CORE_ASMQJMPS_LETTERS,
	R_CORE_ASMQJMPS_LETTERS
};

extern bool r_core_is_project (RCore *core, const char *name);

static int on_fcn_new(RAnal *_anal, void* _user, RAnalFunction *fcn) {
	RCore *core = (RCore*)_user;
	const char *cmd = r_config_get (core->config, "cmd.fcn.new");
	if (cmd && *cmd) {
		ut64 oaddr = core->offset;
		ut64 addr = fcn->addr;
		r_core_seek (core, addr, true);
		r_core_cmd0 (core, cmd);
		r_core_seek (core, oaddr, true);
	}
	return 0;
}

static int on_fcn_delete (RAnal *_anal, void* _user, RAnalFunction *fcn) {
	RCore *core = (RCore*)_user;
	const char *cmd = r_config_get (core->config, "cmd.fcn.delete");
	if (cmd && *cmd) {
		ut64 oaddr = core->offset;
		ut64 addr = fcn->addr;
		r_core_seek (core, addr, true);
		r_core_cmd0 (core, cmd);
		r_core_seek (core, oaddr, true);
	}
	return 0;
}

static int on_fcn_rename(RAnal *_anal, void* _user, RAnalFunction *fcn, const char *oname) {
	RCore *core = (RCore*)_user;
	const char *cmd = r_config_get (core->config, "cmd.fcn.rename");
	if (cmd && *cmd) {
		// XXX: wat do with old name here?
		ut64 oaddr = core->offset;
		ut64 addr = fcn->addr;
		r_core_seek (core, addr, true);
		r_core_cmd0 (core, cmd);
		r_core_seek (core, oaddr, true);
	}
	return 0;
}

static void r_core_debug_breakpoint_hit(RCore *core, RBreakpointItem *bpi) {
	const char *cmdbp = r_config_get (core->config, "cmd.bp");
	const bool cmdbp_exists = (cmdbp && *cmdbp);
	const bool bpcmd_exists = (bpi->data && bpi->data[0]);
	const bool may_output = (cmdbp_exists || bpcmd_exists);
	if (may_output) {
		r_cons_push ();
	}
	if (cmdbp_exists) {
		r_core_cmd0 (core, cmdbp);
	}
	if (bpcmd_exists) {
		r_core_cmd0 (core, bpi->data);
	}
	if (may_output) {
		r_cons_flush ();
		r_cons_pop ();
	}
}

static void r_core_debug_syscall_hit(RCore *core) {
	const char *cmdhit = r_config_get (core->config, "cmd.onsyscall");

	if (cmdhit && cmdhit[0] != 0) {
		r_core_cmd0 (core, cmdhit);
		r_cons_flush ();
	}
}

struct getreloc_t {
        ut64 vaddr;
        int size;
};

static int getreloc_tree(const void *user, const RBNode *n, void *user2) {
        struct getreloc_t *gr = (struct getreloc_t *)user;
        const RBinReloc *r = container_of (n, const RBinReloc, vrb);
        if ((r->vaddr >= gr->vaddr) && (r->vaddr < (gr->vaddr + gr->size))) {
                return 0;
        }
        if (gr->vaddr > r->vaddr) {
                return 1;
        }
        if (gr->vaddr < r->vaddr) {
                return -1;
        }
        return 0;
}

// TODO: Use sdb in rbin to accelerate this
// we shuold use aligned reloc addresses instead of iterating all of them
R_API RBinReloc *r_core_getreloc(RCore *core, ut64 addr, int size) {
        if (size < 1 || addr == UT64_MAX) {
                return NULL;
        }
        RBNode *relocs = r_bin_get_relocs (core->bin);
        if (!relocs) {
                return NULL;
        }
        struct getreloc_t gr = { .vaddr = addr, .size = size };
        RBNode *res = r_rbtree_find (relocs, &gr, getreloc_tree, NULL);
        return res? container_of (res, RBinReloc, vrb): NULL;
}

/* returns the address of a jmp/call given a shortcut by the user or UT64_MAX
 * if there's no valid shortcut. When is_asmqjmps_letter is true, the string
 * should be of the form XYZWu, where XYZW are uppercase letters and u is a
 * lowercase one. If is_asmqjmps_letter is false, the string should be a number
 * between 1 and 9 included. */
R_API ut64 r_core_get_asmqjmps(RCore *core, const char *str) {
	if (!core->asmqjmps) {
		return UT64_MAX;
	}
	if (core->is_asmqjmps_letter) {
		int i, pos = 0;
		int len = strlen (str);
		for (i = 0; i < len - 1; i++) {
			if (!isupper ((ut8)str[i])) {
				return UT64_MAX;
			}
			pos *= R_CORE_ASMQJMPS_LETTERS;
			pos += str[i] - 'A' + 1;
		}
		if (!islower ((ut8)str[i])) {
			return UT64_MAX;
		}
		pos *= R_CORE_ASMQJMPS_LETTERS;
		pos += str[i] - 'a';
		if (pos < core->asmqjmps_count) {
			return core->asmqjmps[pos + 1];
		}
	} else if (str[0] > '0' && str[1] <= '9') {
		int pos = str[0] - '0';
		if (pos <= core->asmqjmps_count) {
			return core->asmqjmps[pos];
		}
	}
	return UT64_MAX;
}

/**
 * Takes addr and returns already saved shortcut or a new one
 * The returned buffer needs to be freed
 */
R_API char* r_core_add_asmqjmp(RCore *core, ut64 addr) {
	bool found = false;
	if (!core->asmqjmps) {
		return NULL;
	}
	if (core->is_asmqjmps_letter) {
		if (core->asmqjmps_count >= R_CORE_ASMQJMPS_MAX_LETTERS) {
			return NULL;
		}
		if (core->asmqjmps_count >= core->asmqjmps_size - 2) {
			core->asmqjmps = realloc (core->asmqjmps, core->asmqjmps_size * 2 * sizeof (ut64));
			if (!core->asmqjmps) {
				return NULL;
			}
			core->asmqjmps_size *= 2;
		}
	}
	if (core->asmqjmps_count < core->asmqjmps_size - 1) {
		int i = 0;
		char t[R_CORE_ASMQJMPS_LEN_LETTERS + 1] = {0};
		for (i = 0; i < core->asmqjmps_count + 1; i++) {
			if (core->asmqjmps[i] == addr) {
				found = true;
				break;
			}
		}
		if (!found) {
			i = ++core->asmqjmps_count;
			core->asmqjmps[i] = addr;
		}
		// This check makes pos never be <1, thefor not fill 't' with trash
		if (i < 1) {
			return NULL;
		}
		r_core_set_asmqjmps (core, t, sizeof (t), i);
		return strdup (t);
	}
	return NULL;
}

/* returns in str a string that represents the shortcut to access the asmqjmp
 * at position pos. When is_asmqjmps_letter is true, pos is converted into a
 * multiletter shortcut of the form XYWZu and returned (see r_core_get_asmqjmps
 * for more info). Otherwise, the shortcut is the string representation of pos. */
R_API void r_core_set_asmqjmps(RCore *core, char *str, size_t len, int pos) {
	if (core->is_asmqjmps_letter) {
		int i, j = 0;
		// if (pos > 0) {
			pos --;
		////  }
		for (i = 0; i < R_CORE_ASMQJMPS_LEN_LETTERS - 1; i++) {
			int div = pos / letter_divs[i];
			pos %= letter_divs[i];
			if (div > 0 && j < len) {
				str[j++] = 'A' + div - 1;
			}
		}
		if (j < len) {
			int div = pos % R_CORE_ASMQJMPS_LETTERS;
			str[j++] = 'a' + div;
		}
		str[j] = '\0';
	} else {
		snprintf (str, len, "%d", pos);
	}
}

static void setab(RCore *core, const char *arch, int bits) {
	if (arch) {
		r_config_set (core->config, "asm.arch", arch);
	}
	if (bits > 0) {
		r_config_set_i (core->config, "asm.bits", bits);
	}
}

static const char *getName(RCore *core, ut64 addr) {
	RFlagItem *item = r_flag_get_i (core->flags, addr);
	if (item) {
		if (core->flags->realnames) {
			return item->realname
				? item->realname: item->name;
		}
		return item->name;
	}
	return NULL;
}

static char *getNameDelta(RCore *core, ut64 addr) {
	RFlagItem *item = r_flag_get_at (core->flags, addr, true);
	if (item) {
		if (item->offset != addr) {
			return r_str_newf ("%s + %d", item->name, (int)(addr - item->offset));
		}
		return strdup (item->name);
	}
	return NULL;
}

static void archbits(RCore *core, ut64 addr) {
	r_core_seek_arch_bits (core, addr);
}

static int cfggeti(RCore *core, const char *k) {
	return r_config_get_i (core->config, k);
}

static const char *cfgget(RCore *core, const char *k) {
	return r_config_get (core->config, k);
}

static ut64 numget(RCore *core, const char *k) {
	return r_num_math (core->num, k);
}

static bool __isMapped(RCore *core, ut64 addr, int perm) {
	if (r_config_get_i (core->config, "cfg.debug")) {
		// RList *maps = core->dbg->maps;
		RDebugMap *map = NULL;
		RListIter *iter = NULL;

		r_list_foreach (core->dbg->maps, iter, map) {
			if (addr >= map->addr && addr < map->addr_end) {
				if (perm > 0) {
					if (map->perm & perm) {
						return true;
					}
				} else {
					return true;
				}
			}
		}

		return false;
	}

	return r_io_map_is_mapped (core->io, addr);
}

static bool __syncDebugMaps(RCore *core) {
	if (r_config_get_i (core->config, "cfg.debug")) {
		return r_debug_map_sync (core->dbg);
	}
	return false;
}

R_API int r_core_bind(RCore *core, RCoreBind *bnd) {
	bnd->core = core;
	bnd->bphit = (RCoreDebugBpHit)r_core_debug_breakpoint_hit;
	bnd->syshit = (RCoreDebugSyscallHit)r_core_debug_syscall_hit;
	bnd->cmd = (RCoreCmd)r_core_cmd0;
	bnd->cmdf = (RCoreCmdF)r_core_cmdf;
	bnd->cmdstr = (RCoreCmdStr)r_core_cmd_str;
	bnd->cmdstrf = (RCoreCmdStrF)r_core_cmd_strf;
	bnd->puts = (RCorePuts)r_cons_strcat;
	bnd->setab = (RCoreSetArchBits)setab;
	bnd->getName = (RCoreGetName)getName;
	bnd->getNameDelta = (RCoreGetNameDelta)getNameDelta;
	bnd->archbits = (RCoreSeekArchBits)archbits;
	bnd->cfggeti = (RCoreConfigGetI)cfggeti;
	bnd->cfgGet = (RCoreConfigGet)cfgget;
	bnd->numGet = (RCoreNumGet)numget;
	bnd->isMapped = (RCoreIsMapped)__isMapped;
	bnd->syncDebugMaps = (RCoreDebugMapsSync)__syncDebugMaps;
	return true;
}

R_API RCore *r_core_ncast(ut64 p) {
	return (RCore*)(size_t)p;
}

R_API RCore *r_core_cast(void *p) {
	return (RCore*)p;
}

static ut64 getref (RCore *core, int n, char t, int type) {
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
	RListIter *iter;
	RAnalRef *r;
	RList *list;
	int i = 0;
	if (!fcn) {
		return UT64_MAX;
	}
	if (t == 'r') {
		list = r_anal_function_get_refs (fcn);
	} else {
		list = r_anal_function_get_xrefs (fcn);
	}
	r_list_foreach (list, iter, r) {
		if (r->type == type) {
			if (i == n) {
				ut64 addr = r->addr;
				r_list_free (list);
				return addr;
			}
			i++;
		}
	}
	r_list_free (list);

	return UT64_MAX;
}

static ut64 bbInstructions(RAnalFunction *fcn, ut64 addr) {
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		if (R_BETWEEN (bb->addr, addr, bb->addr + bb->size - 1)) {
			return bb->ninstr;
		}
	}
	return UT64_MAX;
}

static ut64 bbBegin(RAnalFunction *fcn, ut64 addr) {
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		if (R_BETWEEN (bb->addr, addr, bb->addr + bb->size - 1)) {
			return bb->addr;
		}
	}
	return UT64_MAX;
}

static ut64 bbJump(RAnalFunction *fcn, ut64 addr) {
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		if (R_BETWEEN (bb->addr, addr, bb->addr + bb->size - 1)) {
			return bb->jump;
		}
	}
	return UT64_MAX;
}

static ut64 bbFail(RAnalFunction *fcn, ut64 addr) {
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		if (R_BETWEEN (bb->addr, addr, bb->addr + bb->size - 1)) {
			return bb->fail;
		}
	}
	return UT64_MAX;
}

static ut64 bbSize(RAnalFunction *fcn, ut64 addr) {
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		if (R_BETWEEN (bb->addr, addr, bb->addr + bb->size - 1)) {
			return bb->size;
		}
	}
	return 0;
}

static const char *str_callback(RNum *user, ut64 off, int *ok) {
	RFlag *f = (RFlag*)user;
	if (ok) {
		*ok = 0;
	}
	if (f) {
		RFlagItem *item = r_flag_get_i (f, off);
		if (item) {
			if (ok) {
				*ok = true;
			}
			return item->name;
		}
	}
	return NULL;
}

static ut64 num_callback(RNum *userptr, const char *str, int *ok) {
	RCore *core = (RCore *)userptr; // XXX ?
	RAnalFunction *fcn;
	char *ptr, *bptr, *out = NULL;
	RFlagItem *flag;
	RBinSection *s;
	RAnalOp op;
	ut64 ret = 0;

	if (ok) {
		*ok = false;
	}
	switch (*str) {
	case '.':
		if (str[1] == '.') {
			if (ok) {
				*ok = true;
			}
			return r_num_tail (core->num, core->offset, str + 2);
		}
		if (core->num->nc.curr_tok == '+') {
			ut64 off = core->num->nc.number_value.n;
			if (!off) {
				off = core->offset;
			}
			RAnalFunction *fcn = r_anal_get_function_at (core->anal, off);
			if (fcn) {
				if (ok) {
					*ok = true;
				}
				ut64 dst = r_anal_fcn_label_get (core->anal, fcn, str + 1);
				if (dst == UT64_MAX) {
					dst = fcn->addr;
				}
				st64 delta = dst - off;
				if (delta < 0) {
					core->num->nc.curr_tok = '-';
					delta = off - dst;
				}
				return delta;
			}
		}
		break;
	case '[':
{
		ut64 n = 0LL;
		int refsz = core->rasm->bits / 8;
		const char *p = NULL;
		if (strlen (str) > 5) {
			p = strchr (str + 5, ':');
		}
		if (p) {
			refsz = atoi (str + 1);
			str = p;
		}
		// push state
		if (str[0] && str[1]) {
			const char *q;
			char *o = strdup (str + 1);
			if (o) {
				q = r_num_calc_index (core->num, NULL);
				if (q) {
					if (r_str_replace_char (o, ']', 0)>0) {
						n = r_num_math (core->num, o);
						if (core->num->nc.errors) {
							return 0;
						}
						r_num_calc_index (core->num, q);
					}
				}
				free (o);
			}
		} else {
			return 0;
		}
		// pop state
		if (ok) {
			*ok = 1;
		}
		ut8 buf[sizeof (ut64)] = R_EMPTY;
		(void)r_io_read_at (core->io, n, buf, R_MIN (sizeof (buf), refsz));
		switch (refsz) {
		case 8:
			return r_read_ble64 (buf, core->print->big_endian);
		case 4:
			return r_read_ble32 (buf, core->print->big_endian);
		case 2:
			return r_read_ble16 (buf, core->print->big_endian);
		case 1:
			return r_read_ble8 (buf);
		default:
			eprintf ("Invalid reference size: %d (%s)\n", refsz, str);
			return 0LL;
		}
}
		break;
	case '$':
		if (ok) {
			*ok = 1;
		}
		// TODO: group analop-dependant vars after a char, so i can filter
		r_anal_op (core->anal, &op, core->offset, core->block, core->blocksize, R_ANAL_OP_MASK_BASIC);
		r_anal_op_fini (&op); // we don't need strings or pointers, just values, which are not nullified in fini
		// XXX the above line is assuming op after fini keeps jump, fail, ptr, val, size and r_anal_op_is_eob()
		switch (str[1]) {
		case '.': // can use pc, sp, a0, a1, ...
			return r_debug_reg_get (core->dbg, str + 2);
		case 'k': // $k{kv}
			if (str[2] != '{') {
				eprintf ("Expected '{' after 'k'.\n");
				break;
			}
			bptr = strdup (str + 3);
			ptr = strchr (bptr, '}');
			if (!ptr) {
				// invalid json
				free (bptr);
				break;
			}
			*ptr = '\0';
			ret = 0LL;
			out = sdb_querys (core->sdb, NULL, 0, bptr);
			if (out && *out) {
				if (strstr (out, "$k{")) {
					eprintf ("Recursivity is not permitted here\n");
				} else {
					ret = r_num_math (core->num, out);
				}
			}
			free (bptr);
			free (out);
			return ret;
			break;
		case '{': // ${ev} eval var
			bptr = strdup (str + 2);
			ptr = strchr (bptr, '}');
			if (ptr) {
				ptr[0] = '\0';
				ut64 ret = r_config_get_i (core->config, bptr);
				free (bptr);
				return ret;
			}
			// take flag here
			free (bptr);
			break;
		case 'c': // $c console width
			return r_cons_get_size (NULL);
		case 'r': // $r
			if (str[2] == '{') {
				bptr = strdup (str + 3);
				ptr = strchr (bptr, '}');
				if (!ptr) {
					free (bptr);
					break;
				}
				*ptr = 0;
				if (r_config_get_i (core->config, "cfg.debug")) {
					if (r_debug_reg_sync (core->dbg, R_REG_TYPE_GPR, false)) {
						RRegItem *r = r_reg_get (core->dbg->reg, bptr, -1);
						if (r) {
							free (bptr);
							return r_reg_get_value (core->dbg->reg, r);
						}
					}
				} else {
					RRegItem *r = r_reg_get (core->anal->reg, bptr, -1);
					if (r) {
						free (bptr);
						return r_reg_get_value (core->anal->reg, r);
					}
				}
				free (bptr);
				return 0; // UT64_MAX;
			} else {
				int rows;
				(void)r_cons_get_size (&rows);
				return rows;
			}
			break;
		case 'e': // $e
			if (str[2] == '{') { // $e{flag} flag off + size
				char *flagName = strdup (str + 3);
				int flagLength = strlen (flagName);
				if (flagLength > 0) {
					flagName[flagLength - 1] = 0;
				}
				RFlagItem *flag = r_flag_get (core->flags, flagName);
				free (flagName);
				if (flag) {
					return flag->offset + flag->size;
				}
				return UT64_MAX;
			}
			return r_anal_op_is_eob (&op);
		case 'j': // $j jump address
			return op.jump;
		case 'p': // $p
			return r_sys_getpid ();
		case 'P': // $P
			return core->dbg->pid > 0 ? core->dbg->pid : 0;
		case 'f': // $f jump fail address
			if (str[2] == 'l') { // $fl flag length
				RFlagItem *fi = r_flag_get_i (core->flags, core->offset);
				if (fi) {
					return fi->size;
				}
				return 0;
			}
			return op.fail;
		case 'm': // $m memref
			return op.ptr;
		case 'B': // $B base address
		case 'M': { // $M map address
				ut64 lower = UT64_MAX;
				ut64 size = 0LL;
				RIOMap *map = r_io_map_get (core->io, core->offset);
				if (map) {
					lower = r_itv_begin (map->itv);
					size = r_itv_size (map->itv);
				}

				if (str[1] == 'B') {
					/* clear lower bits of the lowest map address to define the base address */
					const int clear_bits = 16;
					lower >>= clear_bits;
					lower <<= clear_bits;
				}
				if (str[2] == 'M') {
					return size;
				}
				return (lower == UT64_MAX)? 0LL: lower;
			}
			break;
		case 'v': // $v immediate value
			return op.val;
		case 'l': // $l opcode length
			return op.size;
		case 'b': // $b
			return core->blocksize;
		case 's': // $s file size
			if (str[2] == '{') { // $s{flag} flag size
				bptr = strdup (str + 3);
				ptr = strchr (bptr, '}');
				if (!ptr) {
					// invalid json
					free (bptr);
					break;
				}
				*ptr = '\0';
				RFlagItem *flag = r_flag_get (core->flags, bptr);
				ret = flag? flag->size: 0LL; // flag
				free (bptr);
				free (out);
				return ret;
			} else if (core->file) {
				return r_io_fd_size (core->io, core->file->fd);
			}
			return 0LL;
		case 'w': // $w word size
			return r_config_get_i (core->config, "asm.bits") / 8;
		case 'S': // $S section offset
			{
				RBinObject *bo = r_bin_cur_object (core->bin);
				if (bo && (s = r_bin_get_section_at (bo, core->offset, true))) {
					return (str[2] == 'S'? s->size: s->vaddr);
				}
			}
			return 0LL;
		case 'D': // $D
			if (str[2] == 'B') { // $DD
				return r_debug_get_baddr (core->dbg, NULL);
			} else if (IS_DIGIT (str[2])) {
				return getref (core, atoi (str + 2), 'r', R_ANAL_REF_TYPE_DATA);
			} else {
				RDebugMap *map;
				RListIter *iter;
				r_list_foreach (core->dbg->maps, iter, map) {
					if (core->offset >= map->addr && core->offset < map->addr_end) {
						return (str[2] == 'D')? map->size: map->addr;
					}
				}
			}
			return 0LL; // maybe // return UT64_MAX;
		case '?': // $?
			return core->num->value; // rc;
		case '$': // $$ offset
			return str[2] == '$' ? core->prompt_offset : core->offset;
		case 'o': { // $o
			RBinSection *s = r_bin_get_section_at (r_bin_cur_object (core->bin), core->offset, true);
			return s ? core->offset - s->vaddr + s->paddr : core->offset;
			break;
		}
		case 'O': // $O
			  if (core->print->cur_enabled) {
				  return core->offset + core->print->cur;
			  }
			  return core->offset;
		case 'C': // $C nth call
			return getref (core, atoi (str + 2), 'r', R_ANAL_REF_TYPE_CALL);
		case 'J': // $J nth jump
			return getref (core, atoi (str + 2), 'r', R_ANAL_REF_TYPE_CODE);
		case 'X': // $X nth xref
			return getref (core, atoi (str + 2), 'x', R_ANAL_REF_TYPE_CALL);
		case 'F': // $F function size
			fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
			if (fcn) {
				switch (str[2]) {
				/* function bounds (uppercase) */
				case 'B': return fcn->addr; // begin
				case 'E': return r_anal_function_max_addr (fcn); // end
				case 'S': return (str[3]=='S') ? r_anal_function_realsize (fcn) : r_anal_function_linear_size (fcn);
				case 'I': return fcn->ninstr;
				/* basic blocks (lowercase) */
				case 'b': return bbBegin (fcn, core->offset);
				case 'e': return bbBegin (fcn, core->offset) + bbSize (fcn, core->offset);
				case 'i': return bbInstructions (fcn, core->offset);
				case 's': return bbSize (fcn, core->offset);
				case 'j': return bbJump (fcn, core->offset); // jump
				case 'f': return bbFail (fcn, core->offset); // fail
				}
				return fcn->addr;
			}
			return 0;
		}
		break;
	default:
		if (*str >= 'A') {
			// NOTE: functions override flags
			RAnalFunction *fcn = r_anal_get_function_byname (core->anal, str);
			if (fcn) {
				if (ok) {
					*ok = true;
				}
				return fcn->addr;
			}
#if 0
			ut64 addr = r_anal_fcn_label_get (core->anal, core->offset, str);
			if (addr != 0) {
				ret = addr;
			} else {
				...
			}
#endif
			if ((flag = r_flag_get (core->flags, str))) {
				ret = flag->offset;
				if (ok) {
					*ok = true;
				}
				return ret;
			}

			// check for reg alias
			struct r_reg_item_t *r = r_reg_get (core->dbg->reg, str, -1);
			if (!r) {
				int role = r_reg_get_name_idx (str);
				if (role != -1) {
					const char *alias = r_reg_get_name (core->dbg->reg, role);
					if (alias) {
						r = r_reg_get (core->dbg->reg, alias, -1);
						if (r) {
							if (ok) {
								*ok = true;
							}
							ret = r_reg_get_value (core->dbg->reg, r);
							return ret;
						}
					}
				}
			} else {
				if (ok) {
					*ok = true;
				}
				ret = r_reg_get_value (core->dbg->reg, r);
				return ret;
			}
		}
		break;
	}

	return ret;
}

R_API RCore *r_core_new() {
	RCore *c = R_NEW0 (RCore);
	if (c) {
		r_core_init (c);
	}
	return c;
}

/*-----------------------------------*/
#define radare_argc (sizeof (radare_argv) / sizeof(const char*) - 1)
#define ms_argc (sizeof (ms_argv) / sizeof (const char*) - 1)
static const char *ms_argv[] = {
	"?", "!", "ls", "cd", "cat", "get", "mount", "help", "q", "exit", NULL
};

static const char *radare_argv[] = {
	"whereis", "which", "ls", "rm", "mkdir", "pwd", "cat", "sort", "uniq", "join", "less", "exit", "quit",
	"#?", "#!", "#sha1", "#crc32", "#pcprint", "#sha256", "#sha512", "#md4", "#md5",
	"#!python", "#!vala", "#!pipe",
	"*?", "*", "$",
	"(", "(*", "(-", "()", ".?", ".", "..", "...", ".:", ".--", ".-", ".!", ".(", "./", ".*",
	"_?", "_",
	"=?", "=", "=<", "=!", "=+", "=-", "==", "=!=", "!=!", "=:", "=&:",
	"=g?", "=g", "=g!", "=h?", "=h", "=h-", "=h--", "=h*", "=h&", "=H?", "=H", "=H&",
	"<",
	"/?", "/", "/j", "/j!", "/j!x", "/+", "//", "/a", "/a1", "/ab", "/ad", "/aa", "/as", "/asl", "/at", "/atl", "/af", "/afl", "/ae", "/aej", "/ai", "/aij",
	"/c", "/ca", "/car", "/d", "/e", "/E", "/f", "/F", "/g", "/gg", "/h", "/ht", "/i", "/m", "/mb", "/mm",
	"/o", "/O", "/p", "/P", "/s", "/s*", "/r?", "/r", "/ra", "/rc", "/re", "/rr", "/rw", "/rc",
	"/R",
	"/v?", "/v", "/v1", "/v2", "/v4", "/v8",
	"/V?", "/V", "/V1", "/V2", "/V4", "/V8",
	"/w", "/wi", "/x", "/z",
	"!?", "!", "!!", "!!!", "!!!-", "!-", "!-*", "!=!",
	"a?", "a", "aa", "aa*",
	"aaa", "aab", "aac", "aac*", "aad", "aae", "aaf", "aaF", "aaFa", "aai", "aaij", "aan", "aang", "aao", "aap",
	"aar?", "aar", "aar*", "aarj", "aas", "aat", "aaT", "aau", "aav",
	"a8", "ab", "abb",
	"acl", "acll", "aclj", "acl*", "ac?", "ac", "ac-", "acn", "acv", "acvf", "acv-", "acb", "acb-", "acm", "acm-", "acmn",
	"aC?", "aC", "aCe", "ad", "ad4", "ad8", "adf", "adfg", "adt", "adk",
	"ae?", "ae??", "ae", "aea", "aeA", "aeaf", "aeAf", "aeC", "aec?", "aec", "aecs", "aecc", "aecu", "aecue",
	"aef", "aefa",
	"aei", "aeim", "aeip", "aek", "aek-", "aeli", "aelir", "aep?", "aep", "aep-", "aepc",
	"aer", "aets?", "aets", "aets+", "aes", "aesp", "aesb", "aeso", "aesou", "aess", "aesu", "aesue", "aetr", "aex",
	"af?", "af", "afr", "af+", "af-",
	"afa", "afan",
	"afb?", "afb", "afb.", "afb+", "afbb", "afbr", "afbi", "afbj", "afbe", "afB", "afbc", "afb=",
	"afB", "afC", "afCl", "afCc", "afc?", "afc", "afc=", "afcr", "afcrj", "afca", "afcf", "afcfj",
	"afck", "afcl", "afco", "afcR",
	"afd", "aff", "afF", "afi",
	"afl?", "afl", "afl+", "aflc", "aflj", "afll", "afllj", "aflm", "aflq", "aflqj", "afls",
	"afm", "afM", "afn?", "afna", "afns", "afnsj", "afl=",
	"afo", "afs", "afS", "aft?", "aft", "afu",
	"afv?", "afv", "afvr?", "afvr", "afvr*", "afvrj", "afvr-", "afvrg", "afvrs",
	"afvb?", "afvb", "afvbj", "afvb-", "afvbg", "afvbs",
	"afvs?", "afvs", "afvs*", "afvsj", "afvs-", "afvsg", "afvss",
	"afv*", "afvR", "afvW", "afva", "afvd", "afvn", "afvt", "afv-", "af*", "afx",
	"aF",
	"ag?", "ag", "aga", "agA", "agc", "agC", "agd", "agf", "agi", "agr", "agR", "agx", "agg", "ag-",
	"agn?", "agn", "agn-", "age?", "age", "age-",
	"agl", "agfl",
	"ah?", "ah", "ah.", "ah-", "ah*", "aha", "ahb", "ahc", "ahe", "ahf", "ahh", "ahi?", "ahi", "ahj", "aho",
	"ahp", "ahr", "ahs", "ahS", "aht",
	"ai", "aL", "an",
	"ao?", "ao", "aoj", "aoe", "aor", "aos", "aom", "aod", "aoda", "aoc", "ao*",
	"aO", "ap",
	"ar?", "ar", "ar0", "ara?", "ara", "ara+", "ara-", "aras", "arA", "arC", "arr", "arrj", "ar=",
	"arb", "arc", "ard", "arn", "aro", "arp?", "arp", "arpi", "arp.", "arpj", "arps",
	"ars", "art", "arw",
	"as?", "as", "asc", "asca", "asf", "asj", "asl", "ask",
	"av?", "av", "avj", "av*", "avr", "avra", "avraj", "avrr", "avrD",
	"at",
	"ax?", "ax", "ax*", "ax-", "ax-*", "axc", "axC", "axg", "axg*", "axgj", "axd", "axw", "axj", "axF",
	"axt", "axf", "ax.", "axff", "axffj", "axs",
	"b?", "b", "b+", "b-", "bf", "bm",
	"c?", "c", "c1", "c2", "c4", "c8", "cc", "ccd", "cf", "cg?", "cg", "cgf", "cgff", "cgfc", "cgfn", "cgo",
	"cu?", "cu", "cu1", "cu2", "cu4", "cu8", "cud",
	"cv", "cv1", "cv2", "cv4", "cv8",
	"cV", "cV1", "cV2", "cV4", "cV8",
	"cw?", "cw", "cw*", "cwr", "cwu",
	"cx", "cx*", "cX",
	"cl", "cls", "clear",
	"d?", "db ", "db-", "db-*", "db.", "dbj", "dbc", "dbC", "dbd", "dbe", "dbs", "dbf", "dbm", "dbn",
	"db?", "dbi", "dbi.", "dbix", "dbic", "dbie", "dbid", "dbis", "dbite", "dbitd", "dbits", "dbh", "dbh-",
	"dbt", "dbt*", "dbt=", "dbtv", "dbtj", "dbta", "dbte", "dbtd", "dbts", "dbx", "dbw",
	"dc?", "dc", "dca", "dcb", "dcc", "dccu", "dcf", "dck", "dcp", "dcr", "dcs", "dcs*", "dct", "dcu", "dcu.",
	"dd?", "dd", "dd-", "dd*", "dds", "ddd", "ddr", "ddw",
	"de",
	"dg",
	"dH",
	"di?", "di", "di*", "diq", "dij",
	"dk?", "dk", "dko", "dkj",
	"dL?", "dL", "dLq", "dLj",
	"dm?", "dm", "dm=", "dm.", "dm*", "dm-", "dmd",
	"dmh?", "dmh", "dmha", "dmhb", "dmhbg", "dmhc", "dmhf", "dmhg", "dmhi", "dmhm", "dmht",
	"dmi?", "dmi", "dmi*", "dmi.", "dmiv",
	"dmj",
	"dml?", "dml",
	"dmm?", "dmm", "dmm*", "dmm.", "dmmj",
	"dmp?", "dmp",
	"dms?", "dms", "dmsj", "dms*", "dms-", "dmsA", "dmsC", "dmsd", "dmsw", "dmsa", "dmsf", "dmst",
	"dmS", "dmS*",
	"do?", "do", "dor", "doo",
	"dp?", "dp", "dpj", "dpl", "dplj", "dp-", "dp=", "dpa", "dpc", "dpc*", "dpe", "dpf", "dpk", "dpn", "dptn", "dpt",
	"dr?", "dr", "drps", "drpj", "drr", "drrj", "drs", "drs+", "drs-", "drt", "drt*", "drtj", "drw", "drx", "drx-",
	".dr*", ".dr-",
	"ds?", "ds", "dsb", "dsf", "dsi", "dsl", "dso", "dsp", "dss", "dsu", "dsui", "dsuo", "dsue", "dsuf",
	"dt?", "dt", "dt%", "dt*", "dt+", "dt-", "dt=", "dtD", "dta", "dtc", "dtd", "dte", "dte-*", "dtei", "dtek",
	"dtg", "dtg*", "dtgi",
	"dtr",
	"dts?", "dts", "dts+", "dts-", "dtsf", "dtst", "dtsC", "dtt",
	"dw",
	"dx?", "dx", "dxa", "dxe", "dxr", "dxs",
	"e?", "e", "e-", "e*", "e!", "ec", "ee?", "ee", "?ed", "ed", "ej", "env", "er", "es" "et", "ev", "evj",
	"ec?", "ec", "ec*", "ecd", "ecr", "ecs", "ecj", "ecc", "eco", "ecp", "ecn",
	"ecH?", "ecH", "ecHi", "ecHw", "ecH-",
	"f?", "f", "f.", "f*", "f-", "f--", "f+", "f=", "fa", "fb", "fc?", "fc", "fC", "fd", "fe-", "fe",
	"ff", "fi", "fg", "fj",
	"fl", "fla", "fm", "fn", "fnj", "fo", "fO", "fr", "fR", "fR?",
	"fs?", "fs", "fs*", "fsj", "fs-", "fs+", "fs-.", "fsq", "fsm", "fss", "fss*", "fssj", "fsr",
	"ft?", "ft", "ftn", "fV", "fx", "fq",
	"fz?", "fz", "fz-", "fz.", "fz:", "fz*",
	"g?", "g", "gw", "gc", "gl?", "gl", "gs", "gi", "gp", "ge", "gr", "gS",
	"i?", "i", "ij", "iA", "ia", "ib", "ic", "icc", "iC",
	"id?", "id", "idp", "idpi", "idpi*", "idpd", "iD", "ie", "iee", "iE", "iE.",
	"ih", "iHH", "ii", "iI", "ik", "il", "iL", "im", "iM", "io", "iO?", "iO",
	"ir", "iR", "is", "is.", "iS", "iS.", "iS=", "iSS",
	"it", "iV", "iX", "iz", "izj", "izz", "izzz", "iz-", "iZ",
	"k?", "k", "ko", "kd", "ks", "kj",
	"l",
	"L?", "L", "L-", "Ll", "LL", "La", "Lc", "Ld", "Lh", "Li", "Lo",
	"m?", "m", "m*", "ml", "m-", "md", "mf?", "mf", "mg", "mo", "mi", "mp", "ms", "my",
	"o?", "o", "o-", "o--", "o+", "oa", "oa-", "oq", "o*", "o.", "o=",
	"ob?", "ob", "ob*", "obo", "obb", "oba", "obf", "obj", "obr", "ob-", "ob-*",
	"oc", "of", "oi", "oj", "oL", "om", "on",
	"oo?", "oo", "oo+", "oob", "ood", "oom", "oon", "oon+", "oonn", "oonn+",
	"op",  "ox",
	"p?", "p-", "p=", "p2", "p3", "p6?", "p6", "p6d", "p6e", "p8?", "p8", "p8f", "p8j",
	"pa?", "paD", "pad", "pade", "pae", "pA",
	"pb?", "pb", "pB", "pxb", "pB?",
	"pc?", "pc", "pc*", "pca", "pcA", "pcd", "pch", "pcj", "pcp", "pcs", "pcS", "pcw",
	"pC?", "pC", "pCa", "pCA", "pCc", "pCd", "pCD", "pCx", "pCw",
	"pd?", "pd", "pd--", "pD", "pda", "pdb", "pdc", "pdC", "pdf", "pdi", "pdj", "pdJ",
	"pdk", "pdl", "pdp", "pdr", "pdr.", "pdR", "pds?", "pds", "pdsb", "pdsf", "pdt",
	"pD",
	"pf?", "pf", "pf??", "pf???", "pf.", "pfj", "pfj.", "pf*", "pf*.", "pfd", "pfd.",
	"pfo", "pfq", "pfv", "pfv.", "pfs", "pfs.",
	"pF?", "pF", "pFa", "pFaq", "pFo", "pFp", "pFx",
	"pg?", "pg", "pg*", "pg-*",
	"ph?", "ph", "ph=",
	"pi?", "pi", "pia", "pib", "pid", "pie", "pif?", "pif", "pifc", "pifcj", "pifj", "pij", "pir",
	"pI?", "pI", "pIa", "pIb", "pId", "pIe", "pIf?", "pIf", "pIfc", "pIfcj", "pIfj", "pIj",	"pIr",
	"pj?", "pj", "pj.", "pj..",
	"pk?", "pk", "pK?", "pK",
	"pm?", "pm",
	"pq?", "pq", "pqi", "pqz",
	"pr?", "pr", "prc", "prl", "prx", "prg?", "prg", "prgi", "prgo", "prz",
	"ps?", "ps", "psb", "psi", "psj", "psp", "pss", "psu", "psw", "psW", "psx", "psz", "ps+",
	"pt?", "pt", "pt.", "ptd", "pth", "ptn",
	"pu?", "pu", "puw", "pU",
	"pv?", "pv", "pv1", "pv2", "pv4", "pv8", "pvz", "pvj", "pvh", "pv1j", "pv2j", "pv4j", "pv8j",
	"pv1h", "pv2h", "pv4h", "pv8h",
	"px?", "px", "px/", "px0", "pxa", "pxA?", "pxA", "pxb", "pxc", "pxd?", "pxd", "pxd2", "pxd4", "pxd8",
	"pxe", "pxf", "pxh", "pxH", "pxi", "pxl", "pxo", "pxq", "pxq", "pxQ", "pxQq", "pxr", "pxrj",
	"pxs", "pxt", "pxt*", "pxt.", "pxw", "pxW", "pxWq", "pxx", "pxX",
	"pz?", "pz", "pzp", "pzf", "pzs", "pz0", "pzF", "pze", "pzh",
	"P?", "P", "Pc", "Pd", "Pi", "Pn", "Pnj", "Po", "Ps", "PS", "P-",
	"q?", "q", "q!", "q!!", "q!!!", "qy", "qn", "qyy", "qyn", "qny", "qnn",
	"r?", "r", "r-", "r+", "rh",
	"s?", "s", "s:", "s-", "s-*", "s--", "s+", "s++", "sj", "s*", "s=", "s!", "s/", "s/x", "s.", "sa", "sb",
	"sC?", "sC", "sC*",
	"sf", "sf.", "sg", "sG", "sl?", "sl", "sl+", "sl-", "slc", "sll", "sn", "sp", "so", "sr", "ss",
	"t?", "t", "tj", "t*", "t-", "t-*", "ta", "tb", "tc", "te?", "te", "tej", "teb", "tec",
	"td?", "td", "td-", "tf", "tk", "tl", "tn", "to", "tos", "tp", "tpx", "ts?", "ts", "tsj", "ts*", "tsc", "tss",
	"tu?", "tu", "tuj", "tu*", "tuc", "tt?", "tt", "ttj", "ttc",
	"T?", "T", "T*", "T-", "Tl", "Tj", "Tm", "Ts", "TT", "T=", "T=.", "T=&",
	"u?", "u", "uw", "us", "uc",
	"v", "V", "v!", "vv", "vV", "vVV", "VV",
	"w?", "w", "w1+", "w1-", "w2+", "w2-", "w4+", "w4-", "w8+", "w8-",
	"w0", "w", "w6", "w6d", "w6e", "wa", "wa*", "waf", "wao?", "wao",
	"wA?", "wA", "wB", "wB-", "wc", "wcj", "wc-", "wc+", "wc*", "wcr", "wci", "wcp", "wcp*", "wcpi",
	"wd", "we?", "we", "wen", "weN", "wes", "wex", "weX",
	"wf?", "wf", "wff", "wfs", "wF", "wh", "wm",
	"wo?", "wo", "wo2", "wo4", "woa", "woA", "wod", "woD", "woe", "woE", "wol", "wom", "woo",
	"wop?", "wop", "wopD", "wopD*", "wopO",
	"wp?", "wp", "wr", "ws",
	"wt?", "wt", "wta", "wtf", "wtf!", "wtff", "wts",
	"wu",
	"wv?", "wv", "wv1", "wv2",  "wv4", "wv8",
	"ww",
	"wx?", "wx", "wxf", "wxs",
	"wz",
	"x?", "x", "x/", "x0", "xa", "xA?", "xA", "xb", "xc", "xd?", "xd", "xd2", "xd4", "xd8",
	"xe", "xf", "xh", "xH", "xi", "xl", "xo", "xq", "xq", "xQ", "xQq", "xr", "xrj",
	"xs", "xt", "xt*", "xt.", "xw", "xW", "xWq", "xx", "xX",
	"y?", "y", "yz", "yp", "yx", "ys", "yt", "ytf", "yf", "yfa", "yfx", "yw", "ywx", "yy",
	"z?", "z", "z*", "zj", "z-", "z-*",
	"za?", "za??", "za", "zaf", "zaF", "zg",
	"zo?", "zo", "zoz", "zos",
	"zf?", "zfd", "zfs", "zfz",
	"z/?", "z/", "z/*",
	"zc",
	"zs?", "zs", "zs-", "zs-*", "zs+", "zsr",
	"zi",
	"?", "?v", "?$?", "?@?", "?>?",
	NULL
};

static void autocomplete_mount_point (RLineCompletion *completion, RCore *core, const char *path) {
	RFSRoot *r;
	RListIter *iter;
	r_list_foreach (core->fs->roots, iter, r) {
		char *base = strdup (r->path);
		char *ls = (char *) r_str_lchr (base, '/');
		if (ls) {
			ls++;
			*ls = 0;
		}
		if (!strcmp (path, base)) {
			r_line_completion_push (completion, r->path);
		}
		free (base);
	}
}

static void autocomplete_ms_path(RLineCompletion *completion, RCore *core, const char *str, const char *path) {
	char *lpath = NULL, *dirname = NULL , *basename = NULL;
	char *p = NULL;
	char *pwd = (core->rfs && *(core->rfs->cwd)) ? *(core->rfs->cwd): ".";
	int n = 0;
	RList *list;
	RListIter *iter;
	RFSFile *file;
	r_return_if_fail (path);
	lpath = r_str_new (path);
	p = (char *)r_str_last (lpath, R_SYS_DIR);
	if (p) {
		*p = 0;
		if (p == lpath) { // /xxx
			dirname  = r_str_new ("/");
		} else if (lpath[0] == '.') { // ./xxx/yyy
			dirname = r_str_newf ("%s%s", pwd, R_SYS_DIR);
		} else if (lpath[0] == '/') { // /xxx/yyy
      			dirname = r_str_newf ("%s%s", lpath, R_SYS_DIR);
    		} else { // xxx/yyy
      			if (strlen (pwd) == 1) { // if pwd is root
        			dirname = r_str_newf ("%s%s%s", R_SYS_DIR, lpath, R_SYS_DIR);
      			} else {
				dirname = r_str_newf ("%s%s%s%s", pwd, R_SYS_DIR, lpath, R_SYS_DIR);
      			}
		}
		basename = r_str_new (p + 1);
	} else { // xxx
    		if (strlen (pwd) == 1) {
      			dirname = r_str_newf ("%s", R_SYS_DIR);
    		} else {
      			dirname = r_str_newf ("%s%s", pwd, R_SYS_DIR);
    		}
		basename = r_str_new (lpath);
	}

	if (!dirname || !basename) {
		goto out;
	}
	list= r_fs_dir (core->fs, dirname);
	n = strlen (basename);
	bool chgdir = !strncmp (str, "cd ", 3);
	if (list) {
		r_list_foreach (list, iter, file) {
			if (!file) {
				continue;
			}
			if (!basename[0] || !strncmp (file->name, basename, n))  {
				char *tmpstring = r_str_newf ("%s%s", dirname, file->name);
				if (r_file_is_directory (tmpstring)) {
					char *s = r_str_newf ("%s/", tmpstring);
					r_line_completion_push (completion, s);
					free (s);
				} else if (!chgdir) {
					r_line_completion_push (completion, tmpstring);
				}
				free (tmpstring);
			}
		}
		r_list_free (list);
	}
	autocomplete_mount_point (completion, core, path);
out:
	free (lpath);
	free (dirname);
	free (basename);
}

static void autocomplete_process_path(RLineCompletion *completion, const char *str, const char *path) {
	char *lpath = NULL, *dirname = NULL , *basename = NULL;
	char *home = NULL, *filename = NULL, *p = NULL;
	int n = 0;
	RList *list;
	RListIter *iter;

	if (!path) {
		goto out;
	}

	lpath = r_str_new (path);
#if __WINDOWS__
	r_str_replace_ch (lpath, '/', '\\', true);
#endif
	p = (char *)r_str_last (lpath, R_SYS_DIR);
	if (p) {
		*p = 0;
		if (p == lpath) { // /xxx
#if __WINDOWS__
			dirname = strdup ("\\.\\");
#else
			dirname = r_str_new (R_SYS_DIR);
#endif
		} else if (lpath[0] == '~' && lpath[1]) { // ~/xxx/yyy
			dirname = r_str_home (lpath + 2);
		} else if (lpath[0] == '~') { // ~/xxx
			if (!(home = r_str_home (NULL))) {
				goto out;
			}
			dirname = r_str_newf ("%s%s", home, R_SYS_DIR);
			free (home);
		} else if (lpath[0] == '.' || lpath[0] == R_SYS_DIR[0] ) { // ./xxx/yyy || /xxx/yyy
			dirname = r_str_newf ("%s%s", lpath, R_SYS_DIR);
		} else { // xxx/yyy
			char *fmt = ".%s%s%s";
#if __WINDOWS__
			if (strchr (path, ':')) {
				fmt = "%.0s%s%s";
			}
#endif
			dirname = r_str_newf (fmt, R_SYS_DIR, lpath, R_SYS_DIR);
		}
		basename = r_str_new (p + 1);
	} else { // xxx
		dirname = r_str_newf (".%s", R_SYS_DIR);
		basename = r_str_new (lpath);
	}

	if (!dirname || !basename) {
		goto out;
	}

	list= r_sys_dir (dirname);
	n = strlen (basename);
	bool chgdir = !strncmp (str, "cd ", 3);
	if (list) {
		r_list_foreach (list, iter, filename) {
			if (*filename == '.') {
				continue;
			}
			if (!basename[0] || !strncmp (filename, basename, n))  {
				char *tmpstring = r_str_newf ("%s%s", dirname, filename);
				if (r_file_is_directory (tmpstring)) {
					char *s = r_str_newf ("%s%s", tmpstring, R_SYS_DIR);
					r_line_completion_push (completion, s);
					free (s);
				} else if (!chgdir) {
					r_line_completion_push (completion, tmpstring);
				}
				free (tmpstring);
			}
		}
		r_list_free (list);
	}
out:
	free (lpath);
	free (dirname);
	free (basename);
}

static void autocompleteFilename(RLineCompletion *completion, RLineBuffer *buf, char **extra_paths, int narg) {
	char *args = NULL, *input = NULL;
	int n = 0, i = 0;
	char *pipe = strchr (buf->data, '>');
	if (pipe) {
		args = r_str_new (pipe + 1);
	} else {
		args = r_str_new (buf->data);
	}
	if (!args) {
		goto out;
	}

	n = r_str_word_set0 (args);
	if (n < narg) {
		goto out;
	}

	input = r_str_new (r_str_word_get0 (args, narg));
	if (!input) {
		goto out;
	}
	const char *tinput = r_str_trim_head_ro (input);

	autocomplete_process_path (completion, buf->data, tinput);

	if (input[0] == '/' || input[0] == '.' || !extra_paths) {
		goto out;
	}

	for (i = 0; extra_paths[i]; i ++) {
		char *s = r_str_newf ("%s%s%s", extra_paths[i], R_SYS_DIR, tinput);
		if (!s) {
			break;
		}
		autocomplete_process_path (completion, buf->data, s);
		free (s);
	}
out:
	free (args);
	free (input);
}

//TODO: make it recursive to handle nested struct
static int autocomplete_pfele (RCore *core, RLineCompletion *completion, char *key, char *pfx, int idx, char *ptr) {
	int i, ret = 0;
	int len = strlen (ptr);
	char* fmt = sdb_get (core->print->formats, key, NULL);
	if (fmt) {
		int nargs = r_str_word_set0_stack (fmt);
		if (nargs > 1) {
			for (i = 1; i < nargs; i++) {
				const char *arg = r_str_word_get0 (fmt, i);
				char *p = strchr (arg, '(');
				char *p2 = strchr (arg, ')');
				// remove '(' and ')' from fmt
				if (p && p2) {
					arg = p + 1;
					*p2 = '\0';
				}
				if (!len || !strncmp (ptr, arg, len)) {
					char *s = r_str_newf ("pf%s.%s.%s", pfx, key, arg);
					r_line_completion_push (completion, s);
					free (s);
				}
			}
		}
	}
	free (fmt);
	return ret;
}

#define ADDARG(x) if (!strncmp (buf->data+chr, x, strlen (buf->data+chr))) { r_line_completion_push (completion, x); }

static void autocomplete_default(R_NULLABLE RCore *core, RLineCompletion *completion, RLineBuffer *buf) {
	RCoreAutocomplete *a = core ? core->autocomplete : NULL;
	int i;
	if (a) {
		for (i = 0; i < a->n_subcmds; i++) {
			if (buf->data[0] == 0 || !strncmp (a->subcmds[i]->cmd, buf->data, a->subcmds[i]->length)) {
				r_line_completion_push (completion, a->subcmds[i]->cmd);
			}
		}
	} else {
		for (i = 0; i < radare_argc && radare_argv[i]; i++) {
			int length = strlen (radare_argv[i]);
			if (!strncmp (radare_argv[i], buf->data, length)) {
				r_line_completion_push (completion, radare_argv[i]);
			}
		}
	}
}

static void autocomplete_evals(RCore *core, RLineCompletion *completion, const char *str) {
	r_return_if_fail (str);
	RConfigNode *bt;
	RListIter *iter;
	char *tmp = strrchr (str, ' ');
	if (tmp) {
		str = tmp + 1;
	}
	int n = strlen (str);
	if (n < 1) {
		return;
	}
	r_list_foreach (core->config->nodes, iter, bt) {
		if (!strncmp (bt->name, str, n)) {
			r_line_completion_push (completion, bt->name);
		}
	}
}

static void autocomplete_project(RCore *core, RLineCompletion *completion, const char* str) {
	r_return_if_fail (str);
	char *foo, *projects_path = r_file_abspath (r_config_get (core->config, "dir.projects"));
	RList *list = r_sys_dir (projects_path);
	RListIter *iter;
	int n = strlen (str);
	if (projects_path) {
		r_list_foreach (list, iter, foo) {
			if (r_core_is_project (core, foo)) {
				if (!strncmp (foo, str, n)) {
					r_line_completion_push (completion, foo);
				}
			}
		}
		free (projects_path);
		r_list_free (list);
	}
}

static void autocomplete_minus(RCore *core, RLineCompletion *completion, const char *str) {
	r_return_if_fail (str);
	int count;
	int length = strlen (str);
	char **keys = r_cmd_alias_keys(core->rcmd, &count);
	if (!keys) {
		return;
	}
	int i;
	for (i = 0; i < count; i++) {
		if (!strncmp (keys[i], str, length)) {
			r_line_completion_push (completion, keys[i]);
		}
	}
}

static void autocomplete_breakpoints(RCore *core, RLineCompletion *completion, const char *str) {
	r_return_if_fail (str);
	RListIter *iter;
	RBreakpoint *bp = core->dbg->bp;
	RBreakpointItem *b;
	int n = strlen (str);
	r_list_foreach (bp->bps, iter, b) {
		char *addr = r_str_newf ("0x%"PFMT64x"", b->addr);
		if (!strncmp (addr, str, n)) {
			r_line_completion_push (completion, addr);
		}
		free (addr);
	}
}

static bool add_argv(RFlagItem *fi, void *user) {
	RLineCompletion *completion = user;
	r_line_completion_push (completion, fi->name);
	return true;
}

static void autocomplete_flags(RCore *core, RLineCompletion *completion, const char* str) {
	r_return_if_fail (str);
	int n = strlen (str);
	r_flag_foreach_prefix (core->flags, str, n, add_argv, completion);
}

// TODO: Should be refactored
static void autocomplete_sdb (RCore *core, RLineCompletion *completion, const char *str) {
	r_return_if_fail (core && completion && str);
	char *pipe = strchr (str, '>');
	Sdb *sdb = core->sdb;
	char *lpath = NULL, *p1 = NULL, *out = NULL, *p2 = NULL;
	char *cur_pos = NULL, *cur_cmd = NULL, *next_cmd = NULL;
	char *temp_cmd = NULL, *temp_pos = NULL, *key = NULL;
	if (pipe) {
		str = r_str_trim_head_ro (pipe + 1);
	}
	lpath = r_str_new (str);
	p1 = strchr (lpath, '/');
	if (p1) {
		*p1 = 0;
		char *ns = p1 + 1;
		p2 = strchr (ns, '/');
		if (!p2) { // anal/m
			char *tmp = p1 + 1;
			int n = strlen (tmp);
			out = sdb_querys (sdb, NULL, 0, "anal/**");
			if (!out) {
				return;
			}
			while (*out) {
				cur_pos = strchr (out, '\n');
				if (!cur_pos) {
					break;
				}
				cur_cmd = r_str_ndup (out, cur_pos - out);
				if (!strncmp (tmp, cur_cmd, n)) {
					char *cmplt = r_str_newf ("anal/%s/", cur_cmd);
					r_line_completion_push (completion, cmplt);
					free (cmplt);
				}
				out += cur_pos - out + 1;
			}

		} else { // anal/meta/*
			char *tmp = p2 + 1;
			int n = strlen (tmp);
			char *spltr = strchr (ns, '/');
			*spltr = 0;
			next_cmd = r_str_newf ("anal/%s/*", ns);
			out = sdb_querys (sdb, NULL, 0, next_cmd);
			if (!out) {
				free (lpath);
				return;
			}
			while (*out) {
				temp_pos = strchr (out, '\n');
				if (!temp_pos) {
					break;
				}
				temp_cmd = r_str_ndup (out, temp_pos - out); // contains the key=value pair
				key = strchr (temp_cmd, '=');
				*key = 0;
				if (!strncmp (tmp, temp_cmd, n)) {
					char *cmplt = r_str_newf ("anal/%s/%s", ns, temp_cmd);
					r_line_completion_push (completion, cmplt);
					free (cmplt);
				}
				out += temp_pos - out + 1;
			}
		}
	} else {
		int n = strlen (lpath);
		if (!strncmp (lpath, "anal", n)) {
			r_line_completion_push (completion, "anal/");
		}
	}
}

static void autocomplete_zignatures(RCore *core, RLineCompletion *completion, const char* msg) {
	r_return_if_fail (msg);
	int length = strlen (msg);
	RSpaces *zs = &core->anal->zign_spaces;
	RSpace *s;
	RSpaceIter it;

	r_spaces_foreach (zs, it, s) {
		if (!strncmp (msg, s->name, length)) {
			r_line_completion_push (completion, s->name);
		}
	}

	if (strlen (msg) == 0) {
		r_line_completion_push (completion, "*");
	}
}

static void autocomplete_flagspaces(RCore *core, RLineCompletion *completion, const char* msg) {
	r_return_if_fail (msg);
	int length = strlen (msg);
	RFlag *flag = core->flags;
	RSpaceIter it;
	RSpace *s;
	r_flag_space_foreach (flag, it, s) {
		if (!strncmp (msg, s->name, length)) {
			r_line_completion_push (completion, s->name);
		}
	}

	if (strlen (msg) == 0) {
		r_line_completion_push (completion, "*");
	}
}

static void autocomplete_functions (RCore *core, RLineCompletion *completion, const char* str) {
	r_return_if_fail (str);
	RListIter *iter;
	RAnalFunction *fcn;
	int n = strlen (str);
	r_list_foreach (core->anal->fcns, iter, fcn) {
		char *name = r_core_anal_fcn_name (core, fcn);
		if (!strncmp (name, str, n)) {
			r_line_completion_push (completion, name);
		}
		free (name);
	}
}

static void autocomplete_macro(RCore *core, RLineCompletion *completion, const char *str) {
	r_return_if_fail (str);
	RCmdMacroItem *item;
	RListIter *iter;
	char buf[1024];
	int n = strlen(str);
	r_list_foreach (core->rcmd->macro.macros, iter, item) {
		char *p = item->name;
		if (!*str || !strncmp (str, p, n)) {
			snprintf (buf, sizeof (buf), "%s%s)", str, p);
			r_line_completion_push (completion, buf);
		}
	}
}

static void autocomplete_file(RLineCompletion *completion, const char *str) {
	r_return_if_fail (str);
	char *pipe = strchr (str, '>');

	if (pipe) {
		str = r_str_trim_head_ro (pipe + 1);
	}
	if (str && !*str) {
		autocomplete_process_path (completion, str, "./");
	} else {
		autocomplete_process_path (completion, str, str);
	}

}

static void autocomplete_ms_file(RCore* core, RLineCompletion *completion, const char *str) {
	r_return_if_fail (str);
	char *pipe = strchr (str, '>');
	char *path = (core->rfs && *(core->rfs->cwd)) ? *(core->rfs->cwd): "/";
	if (pipe) {
		str = r_str_trim_head_ro (pipe + 1);
	}
	if (str && !*str) {
		autocomplete_ms_path (completion, core, str, path);
	} else {
		autocomplete_ms_path (completion, core, str, str);
	}
}

static void autocomplete_theme(RCore *core, RLineCompletion *completion, const char *str) {
	r_return_if_fail (str);
	int len = strlen (str);
	char *theme;
	RListIter *iter;
	RList *themes = r_core_list_themes (core);
	r_list_foreach (themes, iter, theme) {
		if (!len || !strncmp (str, theme, len)) {
			r_line_completion_push (completion, theme);
		}
	}
	r_list_free (themes);
}

static bool find_e_opts(RCore *core, RLineCompletion *completion, RLineBuffer *buf) {
	const char *pattern = "e (.*)=";
	RRegex *rx = r_regex_new (pattern, "e");
	const size_t nmatch = 2;
	RRegexMatch pmatch[2];
	bool ret = false;

	// required to get the new list of items to autocomplete for cmd.pdc at least
	r_core_config_update (core);

	if (r_regex_exec (rx, buf->data, nmatch, pmatch, 1)) {
		goto out;
	}
	int i;
	char *str = NULL, *sp;
	for (i = pmatch[1].rm_so; i < pmatch[1].rm_eo; i++) {
		str = r_str_appendch (str, buf->data[i]);
	}
	if (!str) {
		goto out;
	}
	if ((sp = strchr (str, ' '))) {
		// if the name contains a space, just null
		*sp = 0;
	}
	RConfigNode *node = r_config_node_get (core->config, str);
	if (sp) {
		// if nulled, then restore.
		*sp = ' ';
	}
	if (!node) {
		return false;
	}
	RListIter *iter;
	char *option;
	char *p = (char *) strchr (buf->data, '=');
	p = r_str_ichr (p + 1, ' ');
	int n = strlen (p);
	r_list_foreach (node->options, iter, option) {
		if (!strncmp (option, p, n)) {
			r_line_completion_push (completion, option);
		}
	}
	completion->opt = true;
	ret = true;

 out:
	r_regex_free (rx);
	return ret;
}

static bool find_autocomplete(RCore *core, RLineCompletion *completion, RLineBuffer *buf) {
	RCoreAutocomplete* child = NULL;
	RCoreAutocomplete* parent = core->autocomplete;
	const char* p = buf->data;
	if (!*p) {
		return false;
	}
	char arg[256];
	arg[0] = 0;
	while (*p) {
		const char* e = r_str_trim_head_wp (p);
		if (!e || (e - p) >= 256 || e == p) {
			return false;
		}
		memcpy (arg, p, e - p);
		arg[e - p] = 0;
		child = r_core_autocomplete_find (parent, arg, false);
		if (child && child->length < buf->length && p[child->length] == ' ') {
			// if is spaced then i can provide the
			// next subtree as suggestion..
			p = r_str_trim_head_ro (p + child->length);
			if (child->type == R_CORE_AUTOCMPLT_OPTN) {
				continue;
			}
			parent = child;
		} else {
			break;
		}
	}
	int i;
	/* if something went wrong this will prevent bad behavior */
	r_line_completion_clear (completion);
	switch (parent->type) {
	case R_CORE_AUTOCMPLT_SEEK:
		autocomplete_functions (core, completion, p);
	case R_CORE_AUTOCMPLT_FLAG:
		autocomplete_flags (core, completion, p);
		break;
	case R_CORE_AUTOCMPLT_FLSP:
		autocomplete_flagspaces (core, completion, p);
		break;
	case R_CORE_AUTOCMPLT_FCN:
		autocomplete_functions (core, completion, p);
		break;
	case R_CORE_AUTOCMPLT_ZIGN:
		autocomplete_zignatures (core, completion, p);
		break;
	case R_CORE_AUTOCMPLT_EVAL:
		autocomplete_evals (core, completion, p);
		break;
	case R_CORE_AUTOCMPLT_PRJT:
		autocomplete_project (core, completion, p);
		break;
	case R_CORE_AUTOCMPLT_MINS:
		autocomplete_minus (core, completion, p);
		break;
	case R_CORE_AUTOCMPLT_BRKP:
		autocomplete_breakpoints (core, completion, p);
		break;
	case R_CORE_AUTOCMPLT_MACR:
		autocomplete_macro (core, completion, p);
		break;
	case R_CORE_AUTOCMPLT_MS:
		autocomplete_ms_file(core, completion, p);
		break;
	case R_CORE_AUTOCMPLT_FILE:
		autocomplete_file (completion, p);
		break;
	case R_CORE_AUTOCMPLT_THME:
		autocomplete_theme (core, completion, p);
		break;
	case R_CORE_AUTOCMPLT_SDB:
		autocomplete_sdb (core, completion, p);
		break;
	case R_CORE_AUTOCMPLT_OPTN:
		// handled before
		break;
	default:
		if (r_config_get_i (core->config, "cfg.newtab")) {
			RCmdDescriptor *desc = &core->root_cmd_descriptor;
			for (i = 0; arg[i] && desc; i++) {
				ut8 c = arg[i];
				desc = c < R_ARRAY_SIZE (desc->sub) ? desc->sub[c] : NULL;
			}
			if (desc && desc->help_msg) {
				r_core_cmd_help (core, desc->help_msg);
				r_cons_flush ();
				return true;
			}
			// fallback to command listing
		}
		int length = strlen (arg);
		for (i = 0; i < parent->n_subcmds; i++) {
			if (!strncmp (arg, parent->subcmds[i]->cmd, length)) {
				r_line_completion_push (completion, parent->subcmds[i]->cmd);
			}
		}
		break;
	}
	return true;
}

R_API void r_core_autocomplete(R_NULLABLE RCore *core, RLineCompletion *completion, RLineBuffer *buf, RLinePromptType prompt_type) {
	if (!core) {
		autocomplete_default (core, completion, buf);
		return;
	}
	r_line_completion_clear (completion);
	char *pipe = strchr (buf->data, '>');
	char *ptr = strchr (buf->data, '@');
	if (pipe && strchr (pipe + 1, ' ') && buf->data + buf->index >= pipe) {
		autocompleteFilename (completion, buf, NULL, 1);
	} else if (ptr && strchr (ptr + 1, ' ') && buf->data + buf->index >= ptr) {
		int sdelta, n;
		ptr = (char *)r_str_trim_head_ro (ptr + 1);
		n = strlen (ptr);//(buf->data+sdelta);
		sdelta = (int)(size_t)(ptr - buf->data);
		r_flag_foreach_prefix (core->flags, buf->data + sdelta, n, add_argv, completion);
	} else if (!strncmp (buf->data, "#!pipe ", 7)) {
		if (strchr (buf->data + 7, ' ')) {
			autocompleteFilename (completion, buf, NULL, 2);
		} else {
			int chr = 7;
			ADDARG ("node");
			ADDARG ("vala");
			ADDARG ("ruby");
			ADDARG ("newlisp");
			ADDARG ("perl");
			ADDARG ("python");
		}
	} else if (!strncmp (buf->data, "ec ", 3)) {
		if (strchr (buf->data + 3, ' ')) {
			autocompleteFilename (completion, buf, NULL, 2);
		} else {
			int chr = 3;
			ADDARG("comment")
			ADDARG("usrcmt")
			ADDARG("args")
			ADDARG("fname")
			ADDARG("floc")
			ADDARG("fline")
			ADDARG("flag")
			ADDARG("label")
			ADDARG("help")
			ADDARG("flow")
			ADDARG("prompt")
			ADDARG("offset")
			ADDARG("input")
			ADDARG("invalid")
			ADDARG("other")
			ADDARG("b0x00")
			ADDARG("b0x7f")
			ADDARG("b0xff")
			ADDARG("math")
			ADDARG("bin")
			ADDARG("btext")
			ADDARG("push")
			ADDARG("pop")
			ADDARG("crypto")
			ADDARG("jmp")
			ADDARG("cjmp")
			ADDARG("call")
			ADDARG("nop")
			ADDARG("ret")
			ADDARG("trap")
			ADDARG("swi")
			ADDARG("cmp")
			ADDARG("reg")
			ADDARG("creg")
			ADDARG("num")
			ADDARG("mov")
			ADDARG("func_var")
			ADDARG("func_var_type")
			ADDARG("func_var_addr")
			ADDARG("widget_bg")
			ADDARG("widget_sel")
			ADDARG("ai.read")
			ADDARG("ai.write")
			ADDARG("ai.exec")
			ADDARG("ai.seq")
			ADDARG("ai.ascii")
			ADDARG("ai.unmap")
			ADDARG("graph.box")
			ADDARG("graph.box2")
			ADDARG("graph.box3")
			ADDARG("graph.box4")
			ADDARG("graph.true")
			ADDARG("graph.false")
			ADDARG("graph.trufae")
			ADDARG("graph.current")
			ADDARG("graph.traced")
			ADDARG("gui.cflow")
			ADDARG("gui.dataoffset")
			ADDARG("gui.background")
			ADDARG("gui.alt_background")
			ADDARG("gui.border")
		}
	} else if (!strncmp (buf->data, "pf.", 3)
	|| !strncmp (buf->data, "pf*.", 4)
	|| !strncmp (buf->data, "pfd.", 4)
	|| !strncmp (buf->data, "pfv.", 4)
	|| !strncmp (buf->data, "pfj.", 4)) {
		char pfx[2];
		int chr = (buf->data[2]=='.')? 3: 4;
		if (chr == 4) {
			pfx[0] = buf->data[2];
			pfx[1] = 0;
		} else {
			*pfx = 0;
		}
		SdbList *sls = sdb_foreach_list (core->print->formats, false);
		SdbListIter *iter;
		SdbKv *kv;
		int j = 0;
		ls_foreach (sls, iter, kv) {
			int len = strlen (buf->data + chr);
			int minlen = R_MIN (len,  strlen (sdbkv_key (kv)));
			if (!len || !strncmp (buf->data + chr, sdbkv_key (kv), minlen)) {
				char *p = strchr (buf->data + chr, '.');
				if (p) {
					j += autocomplete_pfele (core, completion, sdbkv_key (kv), pfx, j, p + 1);
					break;
				} else {
					char *s = r_str_newf ("pf%s.%s", pfx, sdbkv_key (kv));
					r_line_completion_push (completion, s);
					free (s);
				}
			}
		}
	} else if ((!strncmp (buf->data, "afvn ", 5))
	|| (!strncmp (buf->data, "afan ", 5))) {
		RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
		RList *vars;
		if (!strncmp (buf->data, "afvn ", 5)) {
			vars = r_anal_var_list (core->anal, fcn, R_ANAL_VAR_KIND_BPV);
		} else {
			vars = r_list_new (); // TODO wtf r_anal_var_list (core->anal, fcn, R_ANAL_VAR_KIND_ARG);
		}
		const char *f_ptr, *l_ptr;
		RAnalVar *var;
		int len = strlen (buf->data);

		f_ptr = r_sub_str_lchr (buf->data, 0, buf->index, ' ');
		f_ptr = f_ptr != NULL ? f_ptr + 1 : buf->data;
		l_ptr = r_sub_str_rchr (buf->data, buf->index, len, ' ');
		if (!l_ptr) {
			l_ptr = buf->data + len;
		}
		RListIter *iter;
		r_list_foreach (vars, iter, var) {
			if (!strncmp (f_ptr, var->name, l_ptr - f_ptr)) {
				r_line_completion_push (completion, var->name);
			}
		}
		r_list_free (vars);
	} else if (!strncmp (buf->data, "t ", 2)
	|| !strncmp (buf->data, "t- ", 3)) {
		SdbList *l = sdb_foreach_list (core->anal->sdb_types, true);
		SdbListIter *iter;
		SdbKv *kv;
		int chr = (buf->data[1] == ' ')? 2: 3;
		ls_foreach (l, iter, kv) {
			int len = strlen (buf->data + chr);
			if (!len || !strncmp (buf->data + chr, sdbkv_key (kv), len)) {
				if (!strcmp (sdbkv_value (kv), "type") || !strcmp (sdbkv_value (kv), "enum")
				|| !strcmp (sdbkv_value (kv), "struct")) {
					r_line_completion_push (completion, sdbkv_key (kv));
				}
			}
		}
		ls_free (l);
	} else if ((!strncmp (buf->data, "te ", 3))) {
		SdbList *l = sdb_foreach_list (core->anal->sdb_types, true);
		SdbListIter *iter;
		SdbKv *kv;
		int chr = 3;
		ls_foreach (l, iter, kv) {
			int len = strlen (buf->data + chr);
			if (!len || !strncmp (buf->data + chr, sdbkv_key (kv), len)) {
				if (!strcmp (sdbkv_value (kv), "enum")) {
					r_line_completion_push (completion, sdbkv_key (kv));
				}
			}
		}
		ls_free (l);
	} else if (!strncmp (buf->data, "$", 1)) {
		int i;
		for (i = 0; i < core->rcmd->aliases.count; i++) {
			const char *key = core->rcmd->aliases.keys[i];
			int len = strlen (buf->data);
			if (!len || !strncmp (buf->data, key, len)) {
				r_line_completion_push (completion, key);
			}
		}
	} else if (!strncmp (buf->data, "ts ", 3)
	|| !strncmp (buf->data, "ta ", 3)
	|| !strncmp (buf->data, "tp ", 3)
	|| !strncmp (buf->data, "tl ", 3)
	|| !strncmp (buf->data, "tpx ", 4)
	|| !strncmp (buf->data, "tss ", 4)
	|| !strncmp (buf->data, "ts* ", 4)) {
		SdbList *l = sdb_foreach_list (core->anal->sdb_types, true);
		SdbListIter *iter;
		SdbKv *kv;
		int chr = (buf->data[2] == ' ')? 3: 4;
		ls_foreach (l, iter, kv) {
			int len = strlen (buf->data + chr);
			const char *key = sdbkv_key (kv);
			if (!len || !strncmp (buf->data + chr, key, len)) {
				if (!strncmp (sdbkv_value (kv), "struct", strlen ("struct") + 1)) {
					r_line_completion_push (completion, key);
				}
			}
		}
		ls_free (l);
	} else if (!strncmp (buf->data, "zo ", 3)
	|| !strncmp (buf->data, "zoz ", 4)) {
		if (core->anal->zign_path && core->anal->zign_path[0]) {
			char *zignpath = r_file_abspath (core->anal->zign_path);
			char *paths[2] = { zignpath, NULL };
			autocompleteFilename (completion, buf, paths, 1);
			free (zignpath);
		} else {
			autocompleteFilename (completion, buf, NULL, 1);
		}
	} else if (find_e_opts (core, completion, buf)) {
		return;
	} else if (prompt_type == R_LINE_PROMPT_OFFSET) {
		autocomplete_flags (core, completion, buf->data);
	} else if (prompt_type == R_LINE_PROMPT_FILE) {
		autocomplete_file (completion, buf->data);
	} else if (!find_autocomplete (core, completion, buf)) {
		autocomplete_default (core, completion, buf);
	}
}

static int autocomplete(RLineCompletion *completion, RLineBuffer *buf, RLinePromptType prompt_type, void *user) {
	RCore *core = user;
	r_core_autocomplete (core, completion, buf, prompt_type);
	return true;
}

R_API int r_core_fgets(char *buf, int len) {
	const char *ptr;
	RLine *rli = r_line_singleton ();
	buf[0] = '\0';
	r_line_completion_set (&rli->completion, radare_argc, radare_argv);
 	rli->completion.run = autocomplete;
 	rli->completion.run_user = rli->user;
	ptr = r_line_readline ();
	if (!ptr) {
		return -1;
	}
	strncpy (buf, ptr, len - 1);
	buf[len - 1] = 0;
	return strlen (buf);
}

static const char *r_core_print_offname(void *p, ut64 addr) {
	RCore *c = (RCore*)p;
	RFlagItem *item = r_flag_get_i (c->flags, addr);
	return item ? item->name : NULL;
}

static int r_core_print_offsize(void *p, ut64 addr) {
	RCore *c = (RCore*)p;
	RFlagItem *item = r_flag_get_i (c->flags, addr);
	return item ? item->size: -1;
}

/**
 * Disassemble one instruction at specified address.
 */
static int __disasm(void *_core, ut64 addr) {
	RCore *core = _core;
	ut64 prevaddr = core->offset;

	r_core_seek (core, addr, true);
	int len = r_core_print_disasm_instructions (core, 0, 1);
	r_core_seek (core, prevaddr, true);

	return len;
}

static void update_sdb(RCore *core) {
	Sdb *d;
	RBinObject *o;
	if (!core) {
		return;
	}
	//SDB// anal/
	if (core->anal && core->anal->sdb) {
		sdb_ns_set (DB, "anal", core->anal->sdb);
	}
	//SDB// bin/
	if (core->bin && core->bin->sdb) {
		sdb_ns_set (DB, "bin", core->bin->sdb);
	}
	//SDB// bin/info
	o = r_bin_cur_object (core->bin);
	if (o) {
		sdb_ns_set (sdb_ns (DB, "bin", 1), "info", o->kv);
	}
	//sdb_ns_set (core->sdb, "flags", core->flags->sdb);
	//sdb_ns_set (core->sdb, "bin", core->bin->sdb);
	//SDB// syscall/
	if (core->rasm && core->rasm->syscall && core->rasm->syscall->db) {
		core->rasm->syscall->db->refs++;
		sdb_ns_set (DB, "syscall", core->rasm->syscall->db);
	}
	d = sdb_ns (DB, "debug", 1);
	if (core->dbg->sgnls) {
		core->dbg->sgnls->refs++;
		sdb_ns_set (d, "signals", core->dbg->sgnls);
	}
}

#define MINLEN 1
static int is_string (const ut8 *buf, int size, int *len) {
	int i;
	if (size < 1) {
		return 0;
	}
	if (size > 3 && buf[0] && !buf[1] && buf[2] && !buf[3]) {
		*len = 1; // XXX: TODO: Measure wide string length
		return 2; // is wide
	}
	for (i = 0; i < size; i++) {
		if (!buf[i] && i > MINLEN) {
			*len = i;
			return 1;
		}
		if (buf[i] == 10|| buf[i] == 13|| buf[i] == 9) {
			continue;
		}
		if (buf[i] < 32 || buf[i] > 127) {
			// not ascii text
			return 0;
		}
		if (!IS_PRINTABLE (buf[i])) {
			*len = i;
			return 0;
		}
	}
	*len = i;
	return 1;
}

static char *r_core_anal_hasrefs_to_depth(RCore *core, ut64 value, int depth);
R_API char *r_core_anal_hasrefs(RCore *core, ut64 value, bool verbose) {
	if (verbose) {
		const int hex_depth = r_config_get_i (core->config, "hex.depth");
		return r_core_anal_hasrefs_to_depth (core, value, hex_depth);
	}
	RFlagItem *fi = r_flag_get_i (core->flags, value);
	return fi? strdup (fi->name): NULL;
}

static char *r_core_anal_hasrefs_to_depth(RCore *core, ut64 value, int depth) {
	r_return_val_if_fail (core, NULL);
	if (depth < 1 || value == UT64_MAX) {
		return NULL;
	}
	RStrBuf *s = r_strbuf_new (NULL);
	char *mapname = NULL;
	RFlagItem *fi = r_flag_get_i (core->flags, value);
	ut64 type = r_core_anal_address (core, value);
	if (value && value != UT64_MAX) {
		RDebugMap *map = r_debug_map_get (core->dbg, value);
		if (map && map->name && map->name[0]) {
			mapname = strdup (map->name);
		}
	}
	if (mapname) {
		r_strbuf_appendf (s, " (%s)", mapname);
		R_FREE (mapname);
	}
	int bits = core->rasm->bits;
	switch (bits) {
	case 16: // umf, not in sync with pxr
		{
			st16 v = (st16)(value & UT16_MAX);
			st16 h = UT16_MAX / 0x100;
			if (v > -h && v < h) {
				r_strbuf_appendf (s," %hd", v);
			}
		}
		break;
	case 32:
		{
			st32 v = (st32)(value & 0xffffffff);
			st32 h = UT32_MAX / 0x10000;
			if (v > -h && v < h) {
				r_strbuf_appendf (s," %d", v);
			}
		}
		break;
	case 64:
		{
			st64 v = (st64)(value);
			st64 h = UT64_MAX / 0x1000000;
			if (v > -h && v < h) {
				r_strbuf_appendf (s," %"PFMT64d, v);
			}
		}
		break;
	}
	RBinSection *sect = value? r_bin_get_section_at (r_bin_cur_object (core->bin), value, true): NULL;
	if(! ((type&R_ANAL_ADDR_TYPE_HEAP)||(type&R_ANAL_ADDR_TYPE_STACK)) ) {
		// Do not repeat "stack" or "heap" words unnecessarily.
		if (sect && sect->name[0]) {
			r_strbuf_appendf (s," (%s)", sect->name);
		}
	}
	if (fi) {
		RRegItem *r = r_reg_get (core->dbg->reg, fi->name, -1);
		if (!r) {
			r_strbuf_appendf (s, " %s", fi->name);
		}
	}
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, value, 0);
	if (fcn) {
		r_strbuf_appendf (s, " %s", fcn->name);
	}
	if (type) {
		const char *c = r_core_anal_optype_colorfor (core, value, true);
		const char *cend = (c && *c) ? Color_RESET: "";
		if (!c) {
			c = "";
		}
		if (type & R_ANAL_ADDR_TYPE_HEAP) {
			r_strbuf_appendf (s, " %sheap%s", c, cend);
		} else if (type & R_ANAL_ADDR_TYPE_STACK) {
			r_strbuf_appendf (s, " %sstack%s", c, cend);
		}
		if (type & R_ANAL_ADDR_TYPE_PROGRAM) {
			r_strbuf_appendf (s, " %sprogram%s", c, cend);
		}
		if (type & R_ANAL_ADDR_TYPE_LIBRARY) {
			r_strbuf_appendf (s, " %slibrary%s", c, cend);
		}
		if (type & R_ANAL_ADDR_TYPE_ASCII) {
			r_strbuf_appendf (s, " %sascii%s ('%c')", c, cend, value);
		}
		if (type & R_ANAL_ADDR_TYPE_SEQUENCE) {
			r_strbuf_appendf (s, " %ssequence%s", c, cend);
		}
		if (type & R_ANAL_ADDR_TYPE_READ) {
			r_strbuf_appendf (s, " %sR%s", c, cend);
		}
		if (type & R_ANAL_ADDR_TYPE_WRITE) {
			r_strbuf_appendf (s, " %sW%s", c, cend);
		}
		if (type & R_ANAL_ADDR_TYPE_EXEC) {
			RAsmOp op;
			ut8 buf[32];
			r_strbuf_appendf (s, " %sX%s", c, cend);
			/* instruction disassembly */
			r_io_read_at (core->io, value, buf, sizeof (buf));
			r_asm_set_pc (core->rasm, value);
			r_asm_disassemble (core->rasm, &op, buf, sizeof (buf));
			r_strbuf_appendf (s, " '%s'", r_asm_op_get_asm (&op));
			/* get library name */
			{ // NOTE: dup for mapname?
				RDebugMap *map;
				RListIter *iter;
				r_list_foreach (core->dbg->maps, iter, map) {
					if ((value >= map->addr) &&
						(value<map->addr_end)) {
						const char *lastslash = r_str_lchr (map->name, '/');
						r_strbuf_appendf (s, " '%s'", lastslash?
							lastslash+1:map->name);
						break;
					}
				}
			}
		} else if (type & R_ANAL_ADDR_TYPE_READ) {
			ut8 buf[32];
			ut32 *n32 = (ut32 *)buf;
			ut64 *n64 = (ut64*)buf;
			r_io_read_at (core->io, value, buf, sizeof (buf));
			ut64 n = (core->rasm->bits == 64)? *n64: *n32;
			r_strbuf_appendf (s, " 0x%"PFMT64x, n);
		}
	}
	{
		ut8 buf[128], widebuf[256];
		const char *c = r_config_get_i (core->config, "scr.color")? core->cons->context->pal.ai_ascii: "";
		const char *cend = (c && *c) ? Color_RESET: "";
		int len, r;
		if (r_io_read_at (core->io, value, buf, sizeof (buf))) {
			buf[sizeof (buf) - 1] = 0;
			switch (is_string (buf, sizeof(buf), &len)) {
			case 1:
				r_strbuf_appendf (s, " (%s%s%s)", c, buf, cend);
				break;
			case 2:
				r = r_utf8_encode_str ((const RRune *)buf, widebuf,
						       sizeof (widebuf) - 1);
				if (r == -1) {
					eprintf ("Something was wrong with refs\n");
				} else {
					r_strbuf_appendf (s, " (%s%s%s)", c, widebuf, cend);
				}
				break;
			}
		}

	}
	if ((type & R_ANAL_ADDR_TYPE_READ) && !(type & R_ANAL_ADDR_TYPE_EXEC) && depth) {
		// Try to telescope further, but only several levels deep.
		ut8 buf[32];
		ut32 *n32 = (ut32 *)buf;
		ut64 *n64 = (ut64*)buf;
		r_io_read_at (core->io, value, buf, sizeof (buf));
		ut64 n = (core->rasm->bits == 64)? *n64: *n32;
		if(n != value) {
			char* rrstr = r_core_anal_hasrefs_to_depth (core, n, depth-1);
			if (rrstr) {
				if (rrstr[0]) {
					r_strbuf_appendf (s, " --> %s", rrstr);
				}
				free (rrstr);
			}
		}
	}
	free (mapname);
	return r_strbuf_drain (s);
}

R_API char *r_core_anal_get_comments(RCore *core, ut64 addr) {
	if (core) {
		const char *type = r_meta_get_string (core->anal, R_META_TYPE_VARTYPE, addr);
		const char *cmt = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr);
		if (type && cmt) {
			return r_str_newf ("%s %s", type, cmt);
		} else if (type) {
			return strdup (type);
		} else if (cmt) {
			return strdup (cmt);
		}
	}
	return NULL;
}

R_API const char *r_core_anal_optype_colorfor(RCore *core, ut64 addr, bool verbose) {
	ut64 type;
	if (!(core->print->flags & R_PRINT_FLAGS_COLOR)) {
		return NULL;
	}
	if (!r_config_get_i (core->config, "scr.color")) {
		return NULL;
	}
	type = r_core_anal_address (core, addr);
	if (type & R_ANAL_ADDR_TYPE_EXEC) {
		return core->cons->context->pal.ai_exec; //Color_RED;
	}
	if (type & R_ANAL_ADDR_TYPE_WRITE) {
		return core->cons->context->pal.ai_write; //Color_BLUE;
	}
	if (type & R_ANAL_ADDR_TYPE_READ) {
		return core->cons->context->pal.ai_read; //Color_GREEN;
	}
	if (type & R_ANAL_ADDR_TYPE_SEQUENCE) {
		return core->cons->context->pal.ai_seq; //Color_MAGENTA;
	}
	if (type & R_ANAL_ADDR_TYPE_ASCII) {
		return core->cons->context->pal.ai_ascii; //Color_YELLOW;
	}
	return NULL;
}

static void r_core_setenv (RCore *core) {
	char *e = r_sys_getenv ("PATH");
	char *h = r_str_home (R2_HOME_BIN);
	char *n = r_str_newf ("%s%s%s", h, R_SYS_ENVSEP, e);
	r_sys_setenv ("PATH", n);
	free (n);
	free (h);
	free (e);
}

static int mywrite(const ut8 *buf, int len) {
	return r_cons_memcat ((const char *)buf, len);
}

static bool exists_var(RPrint *print, ut64 func_addr, char *str) {
	char *name_key = sdb_fmt ("var.0x%"PFMT64x ".%d.%s", func_addr, 1, str);
	if (sdb_const_get_len (((RCore*)(print->user))->anal->sdb_fcns, name_key, NULL, 0)) {
		return true;
	}
	return false;
}

static bool r_core_anal_log(struct r_anal_t *anal, const char *msg) {
	RCore *core = anal->user;
	if (core->cfglog) {
		r_core_log_add (core, msg);
	}
	return true;
}

static bool r_core_anal_read_at(struct r_anal_t *anal, ut64 addr, ut8 *buf, int len) {
	return r_io_read_at (anal->iob.io, addr, buf, len);
}

static void r_core_break (RCore *core) {
}

static void *r_core_sleep_begin (RCore *core) {
	RCoreTask *task = r_core_task_self (&core->tasks);
	if (task) {
		r_core_task_sleep_begin (task);
	}
	return task;
}

static void r_core_sleep_end (RCore *core, void *user) {
	RCoreTask *task = (RCoreTask *)user;
	if (task) {
		r_core_task_sleep_end (task);
	}
}

static void __foreach(RCore *core, const char **cmds, int type) {
	int i;
	for (i = 0; cmds[i]; i++) {
		r_core_autocomplete_add (core->autocomplete, cmds[i], type, true);
	}
}

static void __init_autocomplete_default (RCore* core) {
	const char *fcns[] = {
		"afi", "afcf", "afn", NULL
	};
	const char *seeks[] = {
		"s", NULL
	};
	const char *flags[] = {
		"*", "s", "s+", "b", "f", "fg", "?", "?v", "ad", "bf", "c1", "db", "dbw",
		"f-", "fr", "tf", "/a", "/v", "/r", "/re", "aav", "aep", "aef", "afb",
		"afc", "axg", "axt", "axf", "dcu", "ag", "agfl", "aecu", "aesu", "aeim", NULL
	};
	const char *evals[] = {
		"e", "ee", "et", "e?", "e!", "ev", "evj", NULL
	};
	const char *breaks[] = {
		"db-", "dbc", "dbC", "dbd", "dbe", "dbs", "dbi", "dbte", "dbtd", "dbts", NULL
	};
	const char *files[] = {
		".", "..", ".*", "/F", "/m", "!", "!!", "#!c", "#!v", "#!cpipe", "#!vala",
		"#!rust", "#!zig", "#!pipe", "#!python", "aeli", "arp", "dmd", "drp", "o",
		"idp", "idpi", "L", "obf", "o+", "oc", "r2", "rabin2", "rasm2", "rahash2", "rax2",
		"rafind2", "cd", "on", "op", "wf", "rm", "wF", "wp", "Sd", "Sl", "to", "pm",
		"/m", "zos", "zfd", "zfs", "zfz", "cat", "wta", "wtf", "wxf", "dml", "vi",
		"less", "head", "tail", NULL
	};
	const char *projs[] = {
		"Pc", "Pd", "Pi", "Po", "Ps", "P-", NULL
	};
	const char *mounts[] = {
		"md", "mg", "mo", "ms", "mc", "mi", "mw", NULL
	};
	__foreach (core, flags, R_CORE_AUTOCMPLT_FLAG);
	__foreach (core, seeks, R_CORE_AUTOCMPLT_SEEK);
	__foreach (core, fcns, R_CORE_AUTOCMPLT_FCN);
	__foreach (core, evals, R_CORE_AUTOCMPLT_EVAL);
	__foreach (core, breaks, R_CORE_AUTOCMPLT_BRKP);
	__foreach (core, files, R_CORE_AUTOCMPLT_FILE);
	__foreach (core, projs, R_CORE_AUTOCMPLT_PRJT);
	__foreach (core, mounts, R_CORE_AUTOCMPLT_MS);

	r_core_autocomplete_add (core->autocomplete, "-", R_CORE_AUTOCMPLT_MINS, true);
	r_core_autocomplete_add (core->autocomplete, "zs", R_CORE_AUTOCMPLT_ZIGN, true);
	r_core_autocomplete_add (core->autocomplete, "fs", R_CORE_AUTOCMPLT_FLSP, true);
	r_core_autocomplete_add (
		r_core_autocomplete_add (core->autocomplete, "ls", R_CORE_AUTOCMPLT_DFLT, true),
		"-l", R_CORE_AUTOCMPLT_FILE, true);
	r_core_autocomplete_add (core->autocomplete, "eco", R_CORE_AUTOCMPLT_THME, true);
	r_core_autocomplete_add (core->autocomplete, "k", R_CORE_AUTOCMPLT_SDB, true);
	/* macros */
	r_core_autocomplete_add (core->autocomplete, ".(", R_CORE_AUTOCMPLT_MACR, true);
	r_core_autocomplete_add (core->autocomplete, "(-", R_CORE_AUTOCMPLT_MACR, true);
	/* just for hints */
	int i;
	for (i = 0; i < radare_argc && radare_argv[i]; i++) {
		if (!r_core_autocomplete_find (core->autocomplete, radare_argv[i], true)) {
			r_core_autocomplete_add (core->autocomplete, radare_argv[i], R_CORE_AUTOCMPLT_DFLT, true);
		}
	}
}

static void __init_autocomplete (RCore* core) {
	int i;
	core->autocomplete = R_NEW0 (RCoreAutocomplete);
	if (core->autocomplete_type == AUTOCOMPLETE_DEFAULT) {
		__init_autocomplete_default (core);
	} else if (core->autocomplete_type == AUTOCOMPLETE_MS) {
		r_core_autocomplete_add (core->autocomplete, "ls", R_CORE_AUTOCMPLT_MS, true);
		r_core_autocomplete_add (core->autocomplete, "cd", R_CORE_AUTOCMPLT_MS, true);
		r_core_autocomplete_add (core->autocomplete, "cat", R_CORE_AUTOCMPLT_MS, true);
		r_core_autocomplete_add (core->autocomplete, "get", R_CORE_AUTOCMPLT_MS, true);
		r_core_autocomplete_add (core->autocomplete, "mount", R_CORE_AUTOCMPLT_MS, true);
		for (i = 0; i < ms_argc && ms_argv[i]; i++) {
			if (!r_core_autocomplete_find (core->autocomplete, ms_argv[i], true)) {
				r_core_autocomplete_add (core->autocomplete, ms_argv[i], R_CORE_AUTOCMPLT_MS, true);
			}
		}
	}
}

static const char *colorfor_cb(void *user, ut64 addr, bool verbose) {
	return r_core_anal_optype_colorfor ((RCore *)user, addr, verbose);
}

static char *hasrefs_cb(void *user, ut64 addr, bool verbose) {
	return r_core_anal_hasrefs ((RCore *)user, addr, verbose);
}

static const char *get_section_name(void *user, ut64 addr) {
	return r_core_get_section_name ((RCore *)user, addr);
}

static char *get_comments_cb(void *user, ut64 addr) {
	return r_core_anal_get_comments ((RCore *)user, addr);
}

static void cb_event_handler(REvent *ev, int event_type, void *user, void *data) {
	RCore *core = (RCore *)ev->user;
	if (!core->log_events) {
		return;
	}
	REventMeta *rems = data;
	char *str = r_base64_encode_dyn (rems->string, -1);
	switch (event_type) {
	case R_EVENT_META_SET:
		switch (rems->type) {
		case 'C':
			r_core_log_add (ev->user, sdb_fmt (":add-comment 0x%08"PFMT64x" %s\n", rems->addr, str? str: ""));
			break;
		default:
			break;
		}
		break;
	case R_EVENT_META_DEL:
		switch (rems->type) {
		case 'C':
			r_core_log_add (ev->user, sdb_fmt (":del-comment 0x%08"PFMT64x, rems->addr));
			break;
		default:
			r_core_log_add (ev->user, sdb_fmt (":del-comment 0x%08"PFMT64x, rems->addr));
			break;
		}
		break;
	case R_EVENT_META_CLEAR:
		switch (rems->type) {
		case 'C':
			r_core_log_add (ev->user, sdb_fmt (":clear-comments 0x%08"PFMT64x, rems->addr));
			break;
		default:
			r_core_log_add (ev->user, sdb_fmt (":clear-comments 0x%08"PFMT64x, rems->addr));
			break;
		}
		break;
	default:
		// TODO
		break;
	}
	free (str);
}

static RFlagItem *core_flg_class_set(RFlag *f, const char *name, ut64 addr, ut32 size) {
	r_flag_space_push (f, R_FLAGS_FS_CLASSES);
	RFlagItem *res = r_flag_set (f, name, addr, size);
	r_flag_space_pop (f);
	return res;
}

static RFlagItem *core_flg_class_get(RFlag *f, const char *name) {
	r_flag_space_push (f, R_FLAGS_FS_CLASSES);
	RFlagItem *res = r_flag_get (f, name);
	r_flag_space_pop (f);
	return res;
}

static RFlagItem *core_flg_fcn_set(RFlag *f, const char *name, ut64 addr, ut32 size) {
	r_flag_space_push (f, R_FLAGS_FS_FUNCTIONS);
	RFlagItem *res = r_flag_set (f, name, addr, size);
	r_flag_space_pop (f);
	return res;
}

R_API void r_core_autocomplete_reload (RCore *core) {
	r_return_if_fail (core);
	r_core_autocomplete_free (core->autocomplete);
	__init_autocomplete (core);
}

R_API RFlagItem *r_core_flag_get_by_spaces(RFlag *f, ut64 off) {
	return r_flag_get_by_spaces (f, off,
		R_FLAGS_FS_FUNCTIONS,
		R_FLAGS_FS_SIGNS,
		R_FLAGS_FS_CLASSES,
		R_FLAGS_FS_SYMBOLS,
		R_FLAGS_FS_IMPORTS,
		R_FLAGS_FS_RELOCS,
		R_FLAGS_FS_STRINGS,
		R_FLAGS_FS_RESOURCES,
		R_FLAGS_FS_SYMBOLS_SECTIONS,
		R_FLAGS_FS_SECTIONS,
		R_FLAGS_FS_SEGMENTS,
		NULL);
}

#if __WINDOWS__
// XXX move to rcons?
static int win_eprintf(const char *format, ...) {
	va_list ap;
	va_start (ap, format);
	r_cons_win_vhprintf (STD_ERROR_HANDLE, false, format, ap);
	va_end (ap);
	return 0;
}
#endif

static int cb_arch_read_at(void *user, ut64 addr, R_OUT ut8 *buf, size_t len) {
	RCore *core = (RCore *)user;
	return r_io_read_at (core->io, addr, buf, len);
}

R_API bool r_core_init(RCore *core) {
	core->blocksize = R_CORE_BLOCKSIZE;
	core->block = (ut8 *)calloc (R_CORE_BLOCKSIZE + 1, 1);
	if (!core->block) {
		eprintf ("Cannot allocate %d byte(s)\n", R_CORE_BLOCKSIZE);
		/* XXX memory leak */
		return false;
	}
	r_core_setenv (core);
	core->ev = r_event_new (core);
	r_event_hook (core->ev, R_EVENT_ALL, cb_event_handler, NULL);
	core->max_cmd_depth = R_CONS_CMD_DEPTH + 1;
	core->sdb = sdb_new (NULL, "r2kv.sdb", 0); // XXX: path must be in home?
	core->lastsearch = NULL;
	core->cmdfilter = NULL;
	core->switch_file_view = 0;
	core->cmdremote = 0;
	core->incomment = false;
	core->config = NULL;
	core->http_up = false;
	core->use_tree_sitter_r2cmd = false;
	ZERO_FILL (core->root_cmd_descriptor);
	core->print = r_print_new ();
	core->ropchain = r_list_newf ((RListFree)free);
	r_core_bind (core, &(core->print->coreb));
	core->print->user = core;
	core->print->num = core->num;
	core->print->offname = r_core_print_offname;
	core->print->offsize = r_core_print_offsize;
	core->print->cb_printf = r_cons_printf;
#if __WINDOWS__
	core->print->cb_eprintf = win_eprintf;
#endif
	core->print->cb_color = r_cons_rainbow_get;
	core->print->write = mywrite;
	core->print->exists_var = exists_var;
	core->print->disasm = __disasm;
	core->print->colorfor = colorfor_cb;
	core->print->hasrefs = hasrefs_cb;
	core->print->get_comments = get_comments_cb;
	core->print->get_section_name = get_section_name;
	core->print->use_comments = false;
	core->rtr_n = 0;
	core->blocksize_max = R_CORE_BLOCKSIZE_MAX;
	r_core_task_scheduler_init (&core->tasks, core);
	core->watchers = r_list_new ();
	core->watchers->free = (RListFree)r_core_cmpwatch_free;
	core->scriptstack = r_list_new ();
	core->scriptstack->free = (RListFree)free;
	core->log = r_core_log_new ();
	core->times = R_NEW0 (RCoreTimes);
	core->vmode = false;
	core->printidx = 0;
	core->lastcmd = NULL;
	core->cmdlog = NULL;
	core->stkcmd = NULL;
	core->cmdqueue = NULL;
	core->cmdrepeat = true;
	core->yank_buf = r_buf_new ();
	core->num = r_num_new (&num_callback, &str_callback, core);
	core->egg = r_egg_new ();
	r_egg_setup (core->egg, R_SYS_ARCH, R_SYS_BITS, 0, R_SYS_OS);

	core->undos = r_list_newf ((RListFree)r_core_undo_free);
	core->fixedarch = false;
	core->fixedbits = false;

	/* initialize libraries */
	core->cons = r_cons_new ();
	if (core->cons->refcnt == 1) {
		core->cons = r_cons_singleton ();
		if (core->cons->line) {
			core->cons->line->user = core;
			core->cons->line->cb_editor = \
				(RLineEditorCb)&r_core_editor;
			core->cons->line->cb_fkey = core->cons->cb_fkey;
		}
#if __EMSCRIPTEN__
		core->cons->user_fgets = NULL;
#else
		core->cons->user_fgets = (void *)r_core_fgets;
#endif
		//r_line_singleton ()->user = (void *)core;
		r_line_hist_load (R2_HOME_HISTORY);
	}
	core->print->cons = core->cons;
	r_cons_bind (&core->print->consbind);

	// We save the old num ad user, in order to restore it after free
	core->lang = r_lang_new ();
	core->lang->cmd_str = (char *(*)(void *, const char *))r_core_cmd_str;
	core->lang->cmdf = (int (*)(void *, const char *, ...))r_core_cmdf;
	r_core_bind_cons (core);
	core->lang->cb_printf = r_cons_printf;
	r_lang_define (core->lang, "RCore", "core", core);
	r_lang_set_user_ptr (core->lang, core);
	{
		core->arch = r_arch_new ();
		// just move this into RCore
		RArchCallbacks *cbs = &core->arch->cbs;
		cbs->user = core;
		cbs->read_at = cb_arch_read_at;
		// .get_offset
		// .get_name
	}
	core->arch_pool = r_arch_sessionpool_new (core->arch);

	core->rasm->num = core->num;
	r_asm_set_user_ptr (core->rasm, core);

	core->rasm = r_asm_new ();
	core->rasm->num = core->num;
	core->rasm->lsd = r_arch_lazysession_new (core->arch_pool);
	core->rasm->lsa = r_arch_lazysession_new (core->arch_pool);
	r_asm_set_user_ptr (core->rasm, core);

	core->anal = r_anal_new ();
	core->anal->lsa = r_arch_lazysession_new (core->arch_pool);
	core->gadgets = r_list_newf ((RListFree)r_core_gadget_free);
	core->anal->ev = core->ev;
	core->anal->log = r_core_anal_log;
	core->anal->read_at = r_core_anal_read_at;
	core->anal->flag_get = r_core_flag_get_by_spaces;
	core->anal->cb.on_fcn_new = on_fcn_new;
	core->anal->cb.on_fcn_delete = on_fcn_delete;
	core->anal->cb.on_fcn_rename = on_fcn_rename;
	core->print->sdb_types = core->anal->sdb_types;
	core->rasm->syscall = r_syscall_ref (core->anal->syscall); // BIND syscall anal/asm
	r_anal_set_user_ptr (core->anal, core);
	core->anal->cb_printf = (void *) r_cons_printf;
	core->parser = r_parse_new ();
	r_anal_bind (core->anal, &(core->parser->analb));
	core->parser->varlist = r_anal_function_get_var_fields;
	/// XXX shouhld be using coreb
	r_parse_set_user_ptr (core->parser, core);
	core->bin = r_bin_new ();
	r_cons_bind (&core->bin->consb);
	// XXX we shuold use RConsBind instead of this hardcoded pointer
	core->bin->cb_printf = (PrintfCallback) r_cons_printf;
	r_bin_set_user_ptr (core->bin, core);
	core->io = r_io_new ();
	core->io->ff = 1;
	core->search = r_search_new (R_SEARCH_KEYWORD);
	r_io_undo_enable (core->io, 1, 0); // TODO: configurable via eval
	core->fs = r_fs_new ();
	core->flags = r_flag_new ();
	core->flags->cb_printf = r_cons_printf;
	core->graph = r_agraph_new (r_cons_canvas_new (1, 1));
	core->graph->need_reload_nodes = false;
	core->asmqjmps_size = R_CORE_ASMQJMPS_NUM;
	if (sizeof (ut64) * core->asmqjmps_size < core->asmqjmps_size) {
		core->asmqjmps_size = 0;
		core->asmqjmps = NULL;
	} else {
		core->asmqjmps = R_NEWS (ut64, core->asmqjmps_size);
	}

	r_bin_bind (core->bin, &(core->rasm->binb));
	r_bin_bind (core->bin, &(core->anal->binb));
	r_bin_bind (core->bin, &(core->anal->binb));

	r_io_bind (core->io, &(core->search->iob));
	r_io_bind (core->io, &(core->print->iob));
	r_io_bind (core->io, &(core->anal->iob));
	r_io_bind (core->io, &(core->fs->iob));
	r_cons_bind (&(core->fs->csb));
	r_core_bind (core, &(core->fs->cob));
	r_io_bind (core->io, &(core->bin->iob));
	r_flag_bind (core->flags, &(core->anal->flb));
	core->anal->flg_class_set = core_flg_class_set;
	core->anal->flg_class_get = core_flg_class_get;
	core->anal->flg_fcn_set = core_flg_fcn_set;
	r_anal_bind (core->anal, &(core->parser->analb));
	core->parser->flag_get = r_core_flag_get_by_spaces;
	core->parser->label_get = r_anal_fcn_label_at;

	r_core_bind (core, &(core->anal->coreb));

	core->file = NULL;
	core->files = r_list_newf ((RListFree)r_core_file_free);
	core->offset = 0LL;
	core->prompt_offset = 0LL;
	r_core_cmd_init (core);
	core->dbg = r_debug_new (true);

	r_io_bind (core->io, &(core->dbg->iob));
	r_io_bind (core->io, &(core->dbg->bp->iob));
	r_core_bind (core, &core->dbg->corebind);
	r_core_bind (core, &core->dbg->bp->corebind);
	r_core_bind (core, &core->io->corebind);
	core->dbg->anal = core->anal; // XXX: dupped instance.. can cause lost pointerz
	//r_debug_use (core->dbg, "native");
// XXX pushing uninitialized regstate results in trashed reg values
//	r_reg_arena_push (core->dbg->reg); // create a 2 level register state stack
//	core->dbg->anal->reg = core->anal->reg; // XXX: dupped instance.. can cause lost pointerz
	core->io->cb_printf = r_cons_printf;
	core->dbg->cb_printf = r_cons_printf;
	core->dbg->bp->cb_printf = r_cons_printf;
	core->dbg->ev = core->ev;
	// initialize config before any corebind
	r_core_config_init (core);

	r_core_loadlibs_init (core);
	//r_core_loadlibs (core);

	// TODO: get arch from r_bin or from native arch
	r_asm_use (core->rasm, R_SYS_ARCH);
	r_anal_use (core->anal, R_SYS_ARCH);
	if (R_SYS_BITS & R_SYS_BITS_64) {
		r_config_set_i (core->config, "asm.bits", 64);
	} else {
		if (R_SYS_BITS & R_SYS_BITS_32) {
			r_config_set_i (core->config, "asm.bits", 32);
		}
	}
	r_config_set (core->config, "asm.arch", R_SYS_ARCH);
	r_bp_use (core->dbg->bp, R_SYS_ARCH, core->anal->bits);
	update_sdb (core);
	{
		char *a = r_str_r2_prefix (R2_FLAGS);
		if (a) {
			char *file = r_str_newf ("%s/tags.r2", a);
			(void)r_core_run_script (core, file);
			free (file);
			free (a);
		}
	}
	r_core_anal_type_init (core);
	__init_autocomplete (core);
	return 0;
}

R_API void __cons_cb_fkey(RCore *core, int fkey) {
	char buf[32];
	snprintf (buf, sizeof (buf), "key.f%d", fkey);
	const char *v = r_config_get (core->config, buf);
	if (v && *v) {
		r_cons_printf ("%s\n", v);
		r_core_cmd0 (core, v);
		r_cons_flush ();
	}
}

R_API void r_core_bind_cons(RCore *core) {
	core->cons->num = core->num;
	core->cons->cb_fkey = (RConsFunctionKey)__cons_cb_fkey;
	core->cons->cb_editor = (RConsEditorCallback)r_core_editor;
	core->cons->cb_break = (RConsBreakCallback)r_core_break;
	core->cons->cb_sleep_begin = (RConsSleepBeginCallback)r_core_sleep_begin;
	core->cons->cb_sleep_end = (RConsSleepEndCallback)r_core_sleep_end;
	core->cons->cb_task_oneshot = (RConsQueueTaskOneshot) r_core_task_enqueue_oneshot;
	core->cons->user = (void*)core;
}

R_API void r_core_fini(RCore *c) {
	if (!c) {
		return;
	}
	r_core_task_break_all (&c->tasks);
	r_core_task_join (&c->tasks, NULL, -1);
	r_core_wait (c);
	/* TODO: it leaks as shit */
	//update_sdb (c);
	// avoid double free
	r_list_free (c->ropchain);
	r_event_free (c->ev);
	free (c->cmdlog);
	free (c->lastsearch);
	R_FREE (c->cons->pager);
	free (c->cmdqueue);
	free (c->lastcmd);
	free (c->stkcmd);
	r_list_free (c->visual.tabs);
	free (c->block);
	r_core_autocomplete_free (c->autocomplete);

	r_list_free (c->gadgets);
	r_list_free (c->undos);
	r_num_free (c->num);
	// TODO: sync or not? sdb_sync (c->sdb);
	// TODO: sync all dbs?
	//r_core_file_free (c->file);
	//c->file = NULL;
	R_FREE (c->table_query);
	r_list_free (c->files);
	r_list_free (c->watchers);
	r_list_free (c->scriptstack);
	r_core_task_scheduler_fini (&c->tasks);
	c->rcmd = r_cmd_free (c->rcmd);
	r_list_free (c->cmd_descriptors);
	c->anal = r_anal_free (c->anal);
	r_asm_free (c->rasm);
	c->rasm = NULL;
	c->print = r_print_free (c->print);
	c->bin = (r_bin_free (c->bin), NULL);
	c->lang = (r_lang_free (c->lang), NULL);
	c->dbg = (r_debug_free (c->dbg), NULL);
	r_io_free (c->io);
	r_config_free (c->config);
	/* after r_config_free, the value of I.teefile is trashed */
	/* rconfig doesnt knows how to deinitialize vars, so we
	should probably need to add a r_config_free_payload callback */
	r_cons_free ();
	r_cons_singleton ()->teefile = NULL; // HACK
	r_search_free (c->search);
	r_flag_free (c->flags);
	r_arch_free (c->arch);
	r_fs_free (c->fs);
	r_egg_free (c->egg);
	r_lib_free (c->lib);
	r_buf_free (c->yank_buf);
	r_agraph_free (c->graph);
	free (c->asmqjmps);
	sdb_free (c->sdb);
	r_core_log_free (c->log);
	r_parse_free (c->parser);
	free (c->times);
}

R_API void r_core_free(RCore *c) {
	if (c) {
		r_core_fini (c);
		free (c);
	}
}

R_API void r_core_prompt_loop(RCore *r) {
	int ret;
	do {
		int err = r_core_prompt (r, false);
		if (err < 1) {
			// handle ^D
			r->num->value = 0; // r.num->value will be read by r_main_radare2() after calling this fcn
			break;
		}
		/* -1 means invalid command, -2 means quit prompt loop */
		if ((ret = r_core_prompt_exec (r)) == -2) {
			break;
		}
	} while (ret != R_CORE_CMD_EXIT);
}

static int prompt_flag (RCore *r, char *s, size_t maxlen) {
	const char DOTS[] = "...";
	const RFlagItem *f = r_flag_get_at (r->flags, r->offset, false);
	if (!f) {
		return false;
	}
	if (f->offset < r->offset) {
		snprintf (s, maxlen, "%s + %" PFMT64u, f->name, r->offset - f->offset);
	} else {
		snprintf (s, maxlen, "%s", f->name);
	}
	if (strlen (s) > maxlen - sizeof (DOTS)) {
		s[maxlen - sizeof (DOTS) - 1] = '\0';
		strcat (s, DOTS);
	}
	return true;
}

static void prompt_sec(RCore *r, char *s, size_t maxlen) {
	const RBinSection *sec = r_bin_get_section_at (r_bin_cur_object (r->bin), r->offset, true);
	if (!sec) {
		return;
	}
	r_str_ncpy (s, sec->name, maxlen - 2);
	strcat (s, ":");
}

static void chop_prompt (const char *filename, char *tmp, size_t max_tmp_size) {
	size_t tmp_len, file_len;
	unsigned int OTHRSCH = 3;
	const char DOTS[] = "...";
	int w, p_len;

	w = r_cons_get_size (NULL);
	file_len = strlen (filename);
	tmp_len = strlen (tmp);
	p_len = R_MAX (0, w - 6);
	if (file_len + tmp_len + OTHRSCH >= p_len) {
		size_t dots_size = sizeof (DOTS);
		size_t chop_point = (size_t)(p_len - OTHRSCH - file_len - dots_size - 1);
		if (chop_point < (max_tmp_size - dots_size - 1)) {
			tmp[chop_point] = '\0';
			strncat (tmp, DOTS, dots_size);
		}
	}
}

static void set_prompt (RCore *r) {
	char tmp[128];
	char *filename = strdup ("");
	const char *cmdprompt = r_config_get (r->config, "cmd.prompt");
	const char *BEGIN = "";
	const char *END = "";
	const char *remote = "";

	if (cmdprompt && *cmdprompt) {
		r_core_cmd (r, cmdprompt, 0);
	}

	if (r_config_get_i (r->config, "scr.prompt.file")) {
		free (filename);
		filename = r_str_newf ("\"%s\"",
			r->io->desc ? r_file_basename (r->io->desc->name) : "");
	}
	if (r->cmdremote) {
		char *s = r_core_cmd_str (r, "s");
		r->offset = r_num_math (NULL, s);
		free (s);
		remote = "=!";
	}

	if (r_config_get_i (r->config, "scr.color")) {
		BEGIN = r->cons->context->pal.prompt;
		END = r->cons->context->pal.reset;
	}

	// TODO: also in visual prompt and disasm/hexdump ?
	if (r_config_get_i (r->config, "asm.segoff")) {
		ut32 a, b;
		unsigned int seggrn = r_config_get_i (r->config, "asm.seggrn");

		a = ((r->offset >> 16) << (16 - seggrn));
		b = (r->offset & 0xffff);
		snprintf (tmp, 128, "%04x:%04x", a, b);
	} else {
		char p[64], sec[32];
		int promptset = false;

		sec[0] = '\0';
		if (r_config_get_i (r->config, "scr.prompt.flag")) {
			promptset = prompt_flag (r, p, sizeof (p));
		}
		if (r_config_get_i (r->config, "scr.prompt.sect")) {
			prompt_sec (r, sec, sizeof (sec));
		}

		if (!promptset) {
			if (r->print->wide_offsets && r->dbg->bits & R_SYS_BITS_64) {
				snprintf (p, sizeof (p), "0x%016" PFMT64x, r->offset);
			} else {
				snprintf (p, sizeof (p), "0x%08" PFMT64x, r->offset);
			}
		}
		snprintf (tmp, sizeof (tmp), "%s%s", sec, p);
	}

	chop_prompt (filename, tmp, 128);
	char *prompt = r_str_newf ("%s%s[%s%s]>%s ", filename, BEGIN, remote,
		tmp, END);
	r_line_set_prompt (prompt ? prompt : "");

	R_FREE (filename);
	R_FREE (prompt);
}

R_API int r_core_prompt(RCore *r, int sync) {
	char line[4096];

	int rnv = r->num->value;
	set_prompt (r);
	int ret = r_cons_fgets (line, sizeof (line), 0, NULL);
	if (ret == -2) {
		return R_CORE_CMD_EXIT; // ^D
	}
	if (ret == -1) {
		return false; // FD READ ERROR
	}
	r->num->value = rnv;
	if (sync) {
		return r_core_prompt_exec (r);
	}
	free (r->cmdqueue);
	r->cmdqueue = strdup (line);
        if (r->scr_gadgets && *line && *line != 'q') {
                r_core_cmd0 (r, "pg");
        }
	r->num->value = r->rc;
	return true;
}

extern void r_core_echo(RCore *core, const char *input);

R_API int r_core_prompt_exec(RCore *r) {
	int ret = r_core_cmd (r, r->cmdqueue, true);
	r->rc = r->num->value;
	//int ret = r_core_cmd (r, r->cmdqueue, true);
	if (r->cons && r->cons->use_tts) {
		const char *buf = r_cons_get_buffer();
		r_sys_tts (buf, true);
		r->cons->use_tts = false;
	}
	r_cons_echo (NULL);
	r_cons_flush ();
	if (r->cons && r->cons->line && r->cons->line->zerosep) {
		r_cons_zero ();
	}
	return ret;
}

R_API int r_core_seek_size(RCore *core, ut64 addr, int bsize) {
	ut8 *bump;
	int ret = false;
	if (bsize < 0) {
		return false;
	}
	if (bsize == core->blocksize) {
		return true;
	}
	if (r_sandbox_enable (0)) {
		// TODO : restrict to filesize?
		if (bsize > 1024*32) {
			eprintf ("Sandbox mode restricts blocksize bigger than 32k\n");
			return false;
		}
	}
	if (bsize > core->blocksize_max) {
		eprintf ("Block size %d is too big\n", bsize);
		return false;
	}
	core->offset = addr;
	if (bsize < 1) {
		bsize = 1;
	} else if (core->blocksize_max && bsize>core->blocksize_max) {
		eprintf ("bsize is bigger than `bm`. dimmed to 0x%x > 0x%x\n",
			bsize, core->blocksize_max);
		bsize = core->blocksize_max;
	}
	bump = realloc (core->block, bsize + 1);
	if (!bump) {
		eprintf ("Oops. cannot allocate that much (%u)\n", bsize);
		ret = false;
	} else {
		ret = true;
		core->block = bump;
		core->blocksize = bsize;
		memset (core->block, 0xff, core->blocksize);
		r_core_block_read (core);
	}
	return ret;
}

R_API int r_core_block_size(RCore *core, int bsize) {
	return r_core_seek_size (core, core->offset, bsize);
}

R_API int r_core_seek_align(RCore *core, ut64 align, int times) {
	int inc = (times >= 0)? 1: -1;
	ut64 seek = core->offset;
	if (!align) {
		return false;
	}
	int diff = core->offset % align;
	if (!times) {
		diff = -diff;
	} else if (diff) {
		if (inc > 0) {
			diff += align-diff;
		} else {
			diff = -diff;
		}
		if (times) {
			times -= inc;
		}
	}
	while ((times*inc) > 0) {
		times -= inc;
		diff += (align * inc);
	}
	if (diff < 0 && -diff > seek) {
		seek = diff = 0;
	}
	return r_core_seek (core, seek + diff, true);
}

R_API char *r_core_op_str(RCore *core, ut64 addr) {
	RAsmOp op = {0};
	ut8 buf[64];
	r_asm_set_pc (core->rasm, addr);
	r_io_read_at (core->io, addr, buf, sizeof (buf));
	int ret = r_asm_disassemble (core->rasm, &op, buf, sizeof (buf));
	char *str = (ret > 0)? strdup (r_strbuf_get (&op.buf_asm)): NULL;
	r_asm_op_fini (&op);
	return str;
}

R_API RAnalOp *r_core_op_anal(RCore *core, ut64 addr, RAnalOpMask mask) {
	ut8 buf[64];
	RAnalOp *op = R_NEW (RAnalOp);
	r_io_read_at (core->io, addr, buf, sizeof (buf));
	r_anal_op (core->anal, op, addr, buf, sizeof (buf), mask);
	return op;
}

static void rap_break (void *u) {
	RIORap *rior = (RIORap*) u;
	if (u) {
		r_socket_close (rior->fd);
		rior->fd = NULL;
	}
}

// TODO: PLEASE move into core/io/rap? */
// TODO: use static buffer instead of mallocs all the time. it's network!
R_API bool r_core_serve(RCore *core, RIODesc *file) {
	// TODO: use r_socket_rap_server API instead of duplicating the logic
	ut8 cmd, flg, *ptr = NULL, buf[1024];
	int i, pipefd = -1;
	ut64 x;

	RIORap *rior = (RIORap *)file->data;
	if (!rior|| !rior->fd) {
		eprintf ("rap: cannot listen.\n");
		return false;
	}
	RSocket *fd = rior->fd;
	eprintf ("RAP Server started (rap.loop=%s)\n",
			r_config_get (core->config, "rap.loop"));
	r_cons_break_push (rap_break, rior);
reaccept:
	while (!r_cons_is_breaked ()) {
		RSocket *c = r_socket_accept (fd);
		if (!c) {
			break;
		}
		if (r_cons_is_breaked ()) {
			goto out_of_function;
		}
		if (!c) {
			eprintf ("rap: cannot accept\n");
			r_socket_free (c);
			goto out_of_function;
		}
		eprintf ("rap: client connected\n");
		for (;!r_cons_is_breaked ();) {
			if (!r_socket_read_block (c, &cmd, 1)) {
				eprintf ("rap: connection closed\n");
				if (r_config_get_i (core->config, "rap.loop")) {
					eprintf ("rap: waiting for new connection\n");
					r_socket_free (c);
					goto reaccept;
				}
				goto out_of_function;
			}
			switch ((ut8)cmd) {
			case RAP_PACKET_OPEN:
				r_socket_read_block (c, &flg, 1); // flags
				eprintf ("open (%d): ", cmd);
				r_socket_read_block (c, &cmd, 1); // len
				pipefd = -1;
				ptr = malloc (cmd + 1);
				//XXX cmd is ut8..so <256 if (cmd<RAP_PACKET_MAX)
				if (!ptr) {
					eprintf ("Cannot malloc in rmt-open len = %d\n", cmd);
				} else {
					ut64 baddr = r_config_get_i (core->config, "bin.laddr");
					r_socket_read_block (c, ptr, cmd);
					ptr[cmd] = 0;
					ut32 perm = R_PERM_R;
					if (flg & R_PERM_W) {
						perm |= R_PERM_W;
					}
					if (r_core_file_open (core, (const char *)ptr, perm, 0)) {
						int fd = r_io_fd_get_current (core->io);
						r_core_bin_load (core, NULL, baddr);
						r_io_map_add (core->io, fd, perm, 0, 0, r_io_fd_size (core->io, fd));
						if (core->file) {
							pipefd = fd;
						} else {
							pipefd = -1;
						}
						eprintf ("(flags: %d) len: %d filename: '%s'\n",
							flg, cmd, ptr); //config.file);
					} else {
						pipefd = -1;
						eprintf ("Cannot open file (%s)\n", ptr);
						r_socket_close (c);
						if (r_config_get_i (core->config, "rap.loop")) {
							eprintf ("rap: waiting for new connection\n");
							r_socket_free (c);
							goto reaccept;
						}
						goto out_of_function; //XXX: Close connection and goto accept
					}
				}
				buf[0] = RAP_PACKET_OPEN | RAP_PACKET_REPLY;
				r_write_be32 (buf + 1, pipefd);
				r_socket_write (c, buf, 5);
				r_socket_flush (c);
				R_FREE (ptr);
				break;
			case RAP_PACKET_READ:
				r_socket_read_block (c, (ut8*)&buf, 4);
				i = r_read_be32 (buf);
				ptr = (ut8 *)malloc (i + core->blocksize + 5);
				if (ptr) {
					r_core_block_read (core);
					ptr[0] = RAP_PACKET_READ | RAP_PACKET_REPLY;
					if (i > RAP_PACKET_MAX) {
						i = RAP_PACKET_MAX;
					}
					if (i > core->blocksize) {
						r_core_block_size (core, i);
					}
					if (i + 128 < core->blocksize) {
						r_core_block_size (core, i);
					}
					r_write_be32 (ptr + 1, i);
					memcpy (ptr + 5, core->block, i); //core->blocksize);
					r_socket_write (c, ptr, i + 5);
					r_socket_flush (c);
					R_FREE (ptr);
				} else {
					eprintf ("Cannot read %d byte(s)\n", i);
					r_socket_free (c);
					// TODO: reply error here
					goto out_of_function;
				}
				break;
			case RAP_PACKET_CMD:
				{
				char *cmd = NULL, *cmd_output = NULL;
				char bufr[8], *bufw = NULL;
				ut32 cmd_len = 0;
				int i;

				/* read */
				r_socket_read_block (c, (ut8*)&bufr, 4);
				i = r_read_be32 (bufr);
				if (i > 0 && i < RAP_PACKET_MAX) {
					if ((cmd = malloc (i + 1))) {
						r_socket_read_block (c, (ut8*)cmd, i);
						cmd[i] = '\0';
						int scr_interactive = r_config_get_i (core->config, "scr.interactive");
						r_config_set_i (core->config, "scr.interactive", 0);
						cmd_output = r_core_cmd_str (core, cmd);
						r_config_set_i (core->config, "scr.interactive", scr_interactive);
						free (cmd);
					} else {
						eprintf ("rap: cannot malloc\n");
					}
				} else {
					eprintf ("rap: invalid length '%d'\n", i);
				}
				/* write */
				if (cmd_output) {
					cmd_len = strlen (cmd_output) + 1;
				} else {
					cmd_output = strdup ("");
					cmd_len = 0;
				}
#if DEMO_SERVER_SENDS_CMD_TO_CLIENT
				static bool once = true;
				/* TODO: server can reply a command request to the client only here */
				if (once) {
					const char *cmd = "pd 4";
					int cmd_len = strlen (cmd) + 1;
					ut8 *b = malloc (cmd_len + 5);
					b[0] = RAP_PACKET_CMD;
					r_write_be32 (b + 1, cmd_len);
					strcpy ((char *)b+ 5, cmd);
					r_socket_write (c, b, 5 + cmd_len);
					r_socket_flush (c);

					/* read response */
					r_socket_read_block (c, b, 5);
					if (b[0] == (RAP_PACKET_CMD | RAP_PACKET_REPLY)) {
						ut32 n = r_read_be32 (b + 1);
						eprintf ("REPLY %d\n", n);
						if (n > 0) {
							ut8 *res = calloc (1, n);
							r_socket_read_block (c, res, n);
							eprintf ("RESPONSE(%s)\n", (const char *)res);
							free (res);
						}
					}
					r_socket_flush (c);
					free (b);
					once = false;
				}
#endif
				bufw = malloc (cmd_len + 5);
				bufw[0] = (ut8) (RAP_PACKET_CMD | RAP_PACKET_REPLY);
				r_write_be32 (bufw + 1, cmd_len);
				memcpy (bufw + 5, cmd_output, cmd_len);
				r_socket_write (c, bufw, cmd_len+5);
				r_socket_flush (c);
				free (bufw);
				free (cmd_output);
				break;
				}
			case RAP_PACKET_WRITE:
				r_socket_read_block (c, buf, 4);
				x = r_read_at_be32 (buf, 0);
				ptr = malloc (x);
				r_socket_read_block (c, ptr, x);
				int ret = r_core_write_at (core, core->offset, ptr, x);
				buf[0] = RAP_PACKET_WRITE | RAP_PACKET_REPLY;
				r_write_be32 (buf + 1, ret);
				r_socket_write (c, buf, 5);
				r_socket_flush (c);
				R_FREE (ptr);
				break;
			case RAP_PACKET_SEEK:
				r_socket_read_block (c, buf, 9);
				x = r_read_at_be64 (buf, 1);
				if (buf[0] == 2) {
					if (core->file) {
						x = r_io_fd_size (core->io, core->file->fd);
					} else {
						x = 0;
					}
				} else {
					if (buf[0] == 0) {
						r_core_seek (core, x, true); //buf[0]);
					}
					x = core->offset;
				}
				buf[0] = RAP_PACKET_SEEK | RAP_PACKET_REPLY;
				r_write_be64 (buf + 1, x);
				r_socket_write (c, buf, 9);
				r_socket_flush (c);
				break;
			case RAP_PACKET_CLOSE:
				// XXX : proper shutdown
				r_socket_read_block (c, buf, 4);
				i = r_read_be32 (buf);
				{
				//FIXME: Use r_socket_close
				int ret = close (i);
				r_write_be32 (buf + 1, ret);
				buf[0] = RAP_PACKET_CLOSE | RAP_PACKET_REPLY;
				r_socket_write (c, buf, 5);
				r_socket_flush (c);
				}
				break;
			default:
				if (cmd == 'G') {
					// silly http emulation over rap://
					char line[256] = {0};
					char *cmd = line;
					r_socket_read_block (c, (ut8*)line, sizeof (line));
					if (!strncmp (line, "ET /cmd/", 8)) {
						cmd = line + 8;
						char *http = strstr (cmd, "HTTP");
						if (http) {
							*http = 0;
							http--;
							if (*http == ' ') {
								*http = 0;
							}
						}
						r_str_uri_decode (cmd);
						char *res = r_core_cmd_str (core, cmd);
						if (res) {
							r_socket_printf (c, "HTTP/1.0 %d %s\r\n%s"
									"Connection: close\r\nContent-Length: %d\r\n\r\n",
									200, "OK", "", -1); // strlen (res));
							r_socket_write (c, res, strlen (res));
							free (res);
						}
						r_socket_flush (c);
						r_socket_close (c);
					}
				} else {
					eprintf ("[rap] unknown command 0x%02x\n", cmd);
					r_socket_close (c);
					R_FREE (ptr);
				}
				if (r_config_get_i (core->config, "rap.loop")) {
					eprintf ("rap: waiting for new connection\n");
					r_socket_free (c);
					goto reaccept;
				}
				goto out_of_function;
			}
		}
		eprintf ("client: disconnected\n");
		r_socket_free (c);
	}
out_of_function:
	r_cons_break_pop ();
	return false;
}

R_API int r_core_search_cb(RCore *core, ut64 from, ut64 to, RCoreSearchCallback cb) {
	int ret, len = core->blocksize;
	ut8 *buf = malloc (len);
	if (!buf) {
		eprintf ("Cannot allocate blocksize\n");
		return false;
	}
	while (from < to) {
		ut64 delta = to-from;
		if (delta < len) {
			len = (int)delta;
		}
		if (!r_io_read_at (core->io, from, buf, len)) {
			eprintf ("Cannot read at 0x%"PFMT64x"\n", from);
			break;
		}
		for (ret = 0; ret < len;) {
			int done = cb (core, from, buf+ret, len-ret);
			if (done < 1) { /* interrupted */
				free (buf);
				return false;
			}
			ret += done;
		}
		from += len;
	}
	free (buf);
	return true;
}

R_API char *r_core_editor(const RCore *core, const char *file, const char *str) {
	const bool interactive = r_cons_is_interactive ();
	const char *editor = r_config_get (core->config, "cfg.editor");
	char *name = NULL, *ret = NULL;
	int fd;

	if (!interactive || !editor || !*editor) {
		return NULL;
	}
	bool readonly = false;
	if (file && *file != '*') {
		name = strdup (file);
		fd = r_sandbox_open (file, O_RDWR, 0644);
		if (fd == -1) {
			fd = r_sandbox_open (file, O_RDWR | O_CREAT, 0644);
			if (fd == -1) {
				fd = r_sandbox_open (file, O_RDONLY, 0644);
				readonly = true;
			}
		}
	} else {
		fd = r_file_mkstemp (file, &name);
	}
	if (fd == -1) {
		free (name);
		return NULL;
	}
	if (readonly) {
		eprintf ("Opening in read-only\n");
	} else {
		if (str) {
			write (fd, str, strlen (str));
		}
	}
	close (fd);

	if (name && (!editor || !*editor || !strcmp (editor, "-"))) {
		RCons *cons = r_cons_singleton ();
		void *tmp = cons->cb_editor;
		cons->cb_editor = NULL;
		r_cons_editor (name, NULL);
		cons->cb_editor = tmp;
	} else {
		if (editor && name) {
			r_sys_cmdf ("%s '%s'", editor, name);
		}
	}
	size_t len = 0;
	ret = name? r_file_slurp (name, &len): 0;
	if (ret) {
		if (len && ret[len - 1] == '\n') {
			ret[len - 1] = 0; // chop
		}
		if (!file) {
			r_file_rm (name);
		}
	}
	free (name);
	return ret;
}

/* weak getters */
R_API RCons *r_core_get_cons (RCore *core) {
	return core->cons;
}

R_API RConfig *r_core_get_config (RCore *core) {
	return core->config;
}

R_API RBin *r_core_get_bin (RCore *core) {
	return core->bin;
}

R_API RBuffer *r_core_syscallf (RCore *core, const char *name, const char *fmt, ...) {
	char str[1024];
	RBuffer *buf;
	va_list ap;
	va_start (ap, fmt);

	vsnprintf (str, sizeof (str), fmt, ap);
	buf = r_core_syscall (core, name, str);

	va_end (ap);
	return buf;
}

R_API RBuffer *r_core_syscall (RCore *core, const char *name, const char *args) {
	RBuffer *b = NULL;
	char code[1024];
	int num;

	//arch check
	if (strcmp (core->anal->cur->arch, "x86")) {
		eprintf ("architecture not yet supported!\n");
		return 0;
	}

	num = r_syscall_get_num (core->anal->syscall, name);

	//bits check
	switch (core->rasm->bits) {
	case 32:
		if (strcmp (name, "setup") && !num ) {
			eprintf ("syscall not found!\n");
			return 0;
		}
		break;
	case 64:
		if (strcmp (name, "read") && !num ) {
			eprintf ("syscall not found!\n");
			return 0;
		}
		break;
	default:
		eprintf ("syscall not found!\n");
		return 0;
	}

	snprintf (code, sizeof (code),
		"sc@syscall(%d);\n"
		"main@global(0) { sc(%s);\n"
		":int3\n" /// XXX USE trap
		"}\n", num, args);
	r_egg_reset (core->egg);
	// TODO: setup arch/bits/os?
	r_egg_load (core->egg, code, 0);

	if (!r_egg_compile (core->egg)) {
		eprintf ("Cannot compile.\n");
	}
	if (!r_egg_assemble (core->egg)) {
		eprintf ("r_egg_assemble: invalid assembly\n");
	}
	if ((b = r_egg_get_bin (core->egg))) {
#if 0
		if (b->length > 0) {
			for (i = 0; i < b->length; i++) {
				r_cons_printf ("%02x", b->buf[i]);
			}
			r_cons_printf ("\n");
		}
#endif
	}
	return b;
}

R_API RCoreAutocomplete *r_core_autocomplete_add(RCoreAutocomplete *parent, const char* cmd, int type, bool lock) {
	if (!parent || !cmd || type < 0 || type >= R_CORE_AUTOCMPLT_END) {
		return NULL;
	}
	RCoreAutocomplete *autocmpl = R_NEW0 (RCoreAutocomplete);
	if (!autocmpl) {
		return NULL;
	}
	RCoreAutocomplete **updated = realloc (parent->subcmds, (parent->n_subcmds + 1) * sizeof (RCoreAutocomplete*));
	if (!updated) {
		free (autocmpl);
		return NULL;
	}
	parent->subcmds = updated;
	parent->subcmds[parent->n_subcmds] = autocmpl;
	parent->n_subcmds++;
	autocmpl->cmd = strdup (cmd);
	autocmpl->locked = lock;
	autocmpl->type = type;
	autocmpl->length = strlen (cmd);
	return autocmpl;
}

R_API void r_core_autocomplete_free(RCoreAutocomplete *obj) {
	if (!obj) {
		return;
	}
	int i;
	for (i = 0; i < obj->n_subcmds; i++) {
		r_core_autocomplete_free (obj->subcmds[i]);
		obj->subcmds[i] = NULL;
	}
	free (obj->subcmds);
	free ((char*) obj->cmd);
	free (obj);
}

R_API RCoreAutocomplete *r_core_autocomplete_find(RCoreAutocomplete *parent, const char* cmd, bool exact) {
	if (!parent || !cmd) {
		return false;
	}
	int len = strlen (cmd);
	int i;
	for (i = 0; i < parent->n_subcmds; i++) {
		if (exact && len == parent->subcmds[i]->length && !strncmp (cmd, parent->subcmds[i]->cmd, len)) {
			return parent->subcmds[i];
		} else if (!exact && !strncmp (cmd, parent->subcmds[i]->cmd, len)) {
			return parent->subcmds[i];
		}
	}
	return NULL;
}

R_API bool r_core_autocomplete_remove(RCoreAutocomplete *parent, const char* cmd) {
	if (!parent || !cmd) {
		return false;
	}
	int i, j;
	for (i = 0; i < parent->n_subcmds; i++) {
		RCoreAutocomplete *ac = parent->subcmds[i];
		if (ac->locked) {
			continue;
		}
		// if (!strncmp (parent->subcmds[i]->cmd, cmd, parent->subcmds[i]->length)) {
		if (r_str_glob (ac->cmd, cmd)) {
			for (j = i + 1; j < parent->n_subcmds; j++) {
				parent->subcmds[j - 1] = parent->subcmds[j];
				parent->subcmds[j] = NULL;
			}
			r_core_autocomplete_free (ac);
			RCoreAutocomplete **updated = realloc (parent->subcmds, (parent->n_subcmds - 1) * sizeof (RCoreAutocomplete*));
			if (!updated && (parent->n_subcmds - 1) > 0) {
				eprintf ("Something really bad has happen.. this should never ever happen..\n");
				return false;
			}
			parent->subcmds = updated;
			parent->n_subcmds--;
			i--;
		}
	}
	return false;
}

R_API RTable *r_core_table(RCore *core) {
	RTable *table = r_table_new ();
	if (table) {
		table->cons = core->cons;
	}
	return table;
}
