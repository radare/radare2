/* radare - LGPL - Copyright 2009-2020 - pancake, nibble, maijin */

#include <r_anal.h>
#include <r_asm.h>
#include <r_arch.h>
#include <r_lib.h>
#include <r_types.h>
#include <r_util.h>
#include <stdio.h>
#include <string.h>
#include <r_main.h>

typedef struct {
	RLib *l;
	RAsm *a;
	RAnal *anal;
	RArch *arch;
	bool oneliner;
	bool coutput;
	bool json;
	bool quiet;
} RAsmState;

static void __load_plugins(RAsmState *as);

static void __as_set_archbits(RAsmState *as) {
	int sysbits = (R_SYS_BITS & R_SYS_BITS_64)? 64: 32;
#if 1
	r_asm_use (as->a, R_SYS_ARCH);
	r_anal_use (as->anal, R_SYS_ARCH);
	r_asm_set_bits (as->a, sysbits);
	r_anal_set_bits (as->anal, sysbits);
#else
	r_arch_use (as->arch, R_SYS_ARCH);
	r_arch_set_bits (as->arch, sys_bits);
#endif
}

static RAsmState *__as_new() {
	RAsmState *as = R_NEW0 (RAsmState);
	if (as) {
		as->l = r_lib_new (NULL, NULL);
		as->a = r_asm_new ();
		if (as->a) {
			as->a->num = r_num_new (NULL, NULL, NULL);
		}
		as->anal = r_anal_new ();
		as->arch = r_arch_new ();
	//	as->a->arch = as->arch;
	//	as->anal->arch = as->arch;
		__load_plugins (as);
		__as_set_archbits (as);
	}
	return as;
}

static void __as_free(RAsmState *as) {
	if (as->a) {
		r_num_free (as->a->num);
	}
	r_asm_free (as->a);
	r_anal_free (as->anal);
	r_arch_free (as->arch);
	r_lib_free (as->l);
    	free (as);
}

static char *stackop2str(int type) {
	switch (type) {
	case R_ANAL_STACK_NULL: return strdup ("null");
	case R_ANAL_STACK_NOP: return strdup ("nop");
	//case R_ANAL_STACK_INCSTACK: return strdup ("incstack");
	case R_ANAL_STACK_GET: return strdup ("get");
	case R_ANAL_STACK_SET: return strdup ("set");
	}
	return strdup ("unknown");
}

static int showanal(RAsmState *as, RAnalOp *op, ut64 offset, ut8 *buf, int len, PJ *pj) {
	int ret = r_anal_op (as->anal, op, offset, buf, len, R_ANAL_OP_MASK_ESIL);
	if (ret < 1) {
		return ret;
	}
	char *stackop = stackop2str (op->stackop);
	const char *optype = r_anal_optype_to_string (op->type);
	char *bytes = r_hex_bin2strdup (buf, ret);
	if (as->json) {
		pj_o (pj);
		pj_kn (pj, "opcode", offset);
		pj_ks (pj, "bytes", bytes);
		pj_ks (pj, "type", optype);
		if (op->jump != UT64_MAX) {
			pj_kn (pj, "jump", op->jump);
		}
		if (op->fail != UT64_MAX) {
			pj_kn (pj, "fail", op->fail);
		}
		if (op->val != UT64_MAX) {
			pj_kn (pj, "val", op->val);
		}
		if (op->ptr != UT64_MAX) {
			pj_kn (pj, "ptr", op->ptr);
		}
		pj_ks (pj, "stackop", stackop);
		pj_ks (pj, "esil", r_strbuf_get (&op->esil));
		pj_kn (pj, "stackptr", op->stackptr);
		pj_end (pj);
	} else {
		printf ("offset:   0x%08" PFMT64x "\n", offset);
		printf ("bytes:    %s\n", bytes);
		printf ("type:     %s\n", optype);
		if (op->jump != -1LL) {
			printf ("jump:     0x%08" PFMT64x "\n", op->jump);
		}
		if (op->fail != -1LL) {
			printf ("fail:     0x%08" PFMT64x "\n", op->fail);
		}
		//if (op->ref != -1LL)
		//      printf ("ref:      0x%08"PFMT64x"\n", op->ref);
		if (op->val != -1LL) {
			printf ("value:    0x%08" PFMT64x "\n", op->val);
		}
		printf ("stackop:  %s\n", stackop);
		printf ("esil:     %s\n", r_strbuf_get (&op->esil));
		printf ("stackptr: %" PFMT64d "\n", op->stackptr);
		// produces (null) printf ("decode str: %s\n", r_anal_op_to_string (anal, op));
		printf ("\n");
	}
	free (stackop);
	free (bytes);
	return ret;
}

// TODO: add israw/len
static int show_analinfo(RAsmState *as, const char *arg, ut64 offset) {
	ut8 *buf = (ut8 *)strdup ((const char *)arg);
	int ret, len = r_hex_str2bin ((char *)buf, buf);
	PJ *pj = pj_new ();
	if (!pj) {
		free (buf);
		return 0;
	}
	
	RAnalOp aop = { 0 };
	
	if (as->json) {
		pj_a (pj);
	}
	for (ret = 0; ret < len;) {
		aop.size = 0;
		if (r_anal_op (as->anal, &aop, offset, buf + ret, len - ret, R_ANAL_OP_MASK_BASIC) < 1) {
			eprintf ("Error analyzing instruction at 0x%08"PFMT64x"\n", offset);
			break;
		}
		if (aop.size < 1) {
			if (as->json) {
				pj_o (pj);
				pj_ks (pj, "bytes",  r_hex_bin2strdup (buf, ret));
				pj_ks (pj, "type", "Invalid");
				pj_end (pj);
			} else {
				eprintf ("Invalid\n");
			}
			break;
		}
		showanal (as, &aop, offset, buf + ret, len - ret, pj);
		ret += aop.size;
		r_anal_op_fini (&aop);
	}
	if (as->json) {
		pj_end (pj); 
		printf ("%s\n", pj_string (pj));
		pj_free (pj);
	}
	free (buf);
	return ret;
}

static const char *has_esil(RAsmState *as, const char *name) {
	RListIter *iter;
	RAnalPlugin *h;
	r_list_foreach (as->anal->plugins, iter, h) {
		if (h->name && !strcmp (name, h->name)) {
			return h->esil? "Ae": "A_";
		}
	}
	return "__";
}

static void rasm2_list(RAsmState *as, const char *arch) {
	int i;
	char bits[32];
	const char *feat2, *feat;
	RAsmPlugin *h;
	RListIter *iter;
	PJ *pj = pj_new ();
	if (!pj) {
		return;
	}
	if (as->json) {
		pj_o (pj);
	}
	r_list_foreach (as->a->plugins, iter, h) {
		if (arch) {
			if (h->cpus && !strcmp (arch, h->name)) {
				char *c = strdup (h->cpus);
				int n = r_str_split (c, ',');
				for (i = 0; i < n; i++) {
					printf ("%s\n", r_str_word_get0 (c, i));
				}
				free (c);
				break;
			}
		} else {
			bits[0] = 0;
			if (h->bits == 27) {
				strcat (bits, "27");
			} else {
				if (h->bits & 8) {
					strcat (bits, "8 ");
				}
				if (h->bits & 16) {
					strcat (bits, "16 ");
				}
				if (h->bits & 32) {
					strcat (bits, "32 ");
				}
				if (h->bits & 64) {
					strcat (bits, "64 ");
				}
			}
			feat = "__";
			if (h->assemble && h->disassemble) {
				feat = "ad";
			}
			if (h->assemble && !h->disassemble) {
				feat = "a_";
			}
			if (!h->assemble && h->disassemble) {
				feat = "_d";
			}
			feat2 = has_esil (as, h->name);
			if (as->quiet) {
				printf ("%s\n", h->name);
			} else if (as->json) {
				pj_k (pj, h->name);
				pj_o (pj);
				pj_k (pj, "bits");
				pj_a (pj);
				pj_i (pj, 32);
				pj_i (pj, 64);
				pj_end (pj);
				pj_ks (pj, "license", h->license? h->license: "unknown");
				pj_ks (pj, "description", h->desc);
				pj_ks (pj, "features", feat);
				pj_end (pj);
			} else {
				printf ("%s%s  %-9s  %-11s %-7s %s",
					feat, feat2, bits, h->name,
					h->license? h->license: "unknown", h->desc);
				if (h->author) {
					printf (" (by %s)", h->author);
				}
				if (h->version) {
					printf (" v%s", h->version);
				}
				printf ("\n");
			}
		}
	}
	if (as->json) {
		pj_end (pj);
		printf ("%s\n", pj_string (pj));
		pj_free (pj);
	}
}

static int rasm_show_help(int v) {
	if (v < 2) {
		printf ("Usage: rasm2 [-ACdDehLBvw] [-a arch] [-b bits] [-o addr] [-s syntax]\n"
			"             [-f file] [-F fil:ter] [-i skip] [-l len] 'code'|hex|-\n");
	}
	if (v != 1) {
		printf (" -a [arch]    Set architecture to assemble/disassemble (see -L)\n"
			" -A           Show Analysis information from given hexpairs\n"
			" -b [bits]    Set cpu register size (8, 16, 32, 64) (RASM2_BITS)\n"
			" -B           Binary input/output (-l is mandatory for binary input)\n"
			" -c [cpu]     Select specific CPU (depends on arch)\n"
			" -C           Output in C format\n"
			" -d, -D       Disassemble from hexpair bytes (-D show hexpairs)\n"
			" -e           Use big endian instead of little endian\n"
			" -E           Display ESIL expression (same input as in -d)\n"
			" -f [file]    Read data from file\n"
			" -F [in:out]  Specify input and/or output filters (att2intel, x86.pseudo, ...)\n"
			" -h, -hh      Show this help, -hh for long\n"
			" -i [len]     ignore/skip N bytes of the input buffer\n"
			" -j           output in json format\n"
			" -k [kernel]  Select operating system (linux, windows, darwin, ..)\n"
			" -l [len]     Input/Output length\n"
			" -L           List Asm plugins: (a=asm, d=disasm, A=analyze, e=ESIL)\n"
			" -o,-@ [addr] Set start address for code (default 0)\n"
			" -O [file]    Output file name (rasm2 -Bf a.asm -O a)\n"
			" -p           Run SPP over input for assembly\n"
			" -q           quiet mode\n"
			" -r           output in radare commands\n"
			" -s [syntax]  Select syntax (intel, att)\n"
			" -v           Show version information\n"
			" -x           Use hex dwords instead of hex pairs when assembling.\n"
			" -w           What's this instruction for? describe opcode\n"
			" If '-l' value is greater than output length, output is padded with nops\n"
			" If the last argument is '-' reads from stdin\n");
		printf ("Environment:\n"
			" RASM2_NOPLUGINS  do not load shared plugins (speedup loading)\n"
			" RASM2_ARCH       same as rasm2 -a\n"
			" RASM2_BITS       same as rasm2 -b\n"
			" R_DEBUG          if defined, show error messages and crash signal\n"
			"");
	}
	if (v == 2) {
		printf ("Supported Assembler directives:\n");
		r_asm_list_directives ();
	}
	return 0;
}

static int rasm_disasm(RAsmState *as, ut64 addr, const char *buf, int len, int bits, int bin, int hex) {
	RAsmCode *acode;
	ut8 *data = NULL;
	int ret = 0;
	ut64 clen = 0;
	if (bits == 1) {
		len /= 8;
	}
	if (bin) {
		if (len < 0) {
			return false;
		}
		clen = len; // XXX
		data = (ut8 *)buf;
	} else {
		clen = r_hex_str2bin (buf, NULL);
		if ((int)clen < 1 || !(data = malloc (clen))) {
			ret = 0;
			goto beach;
		}
		r_hex_str2bin (buf, data);
		len = clen;
	}

	if (!len || clen <= len) {
		len = clen;
	}

	if (hex == 2) {
		RAnalOp aop = { 0 };
		while (ret < len) {
			aop.size = 0;
			if (r_anal_op (as->anal, &aop, addr, data + ret, len - ret, R_ANAL_OP_MASK_ESIL) > 0) {
				printf ("%s\n", R_STRBUF_SAFEGET (&aop.esil));
			}
			if (aop.size < 1) {
				eprintf ("Invalid\n");
				break;
			}
			ret += aop.size;
			r_anal_op_fini (&aop);
		}
	} else if (hex) {
		RAsmOp op;
		r_asm_set_pc (as->a, addr);
		while ((len - ret) > 0) {
			int dr = r_asm_disassemble (as->a, &op, data + ret, len - ret);
			if (dr == -1 || op.size < 1) {
				op.size = 1;
				r_asm_op_set_asm (&op, "invalid");
			}
			char *op_hex = r_asm_op_get_hex (&op);
			printf ("0x%08" PFMT64x "  %2d %24s  %s\n",
				as->a->pc, op.size, op_hex,
				r_asm_op_get_asm (&op));
			free (op_hex);
			ret += op.size;
			r_asm_set_pc (as->a, addr+ ret);
		}
	} else {
		r_asm_set_pc (as->a, addr);
		if (!(acode = r_asm_mdisassemble (as->a, data, len))) {
			goto beach;
		}
		if (as->oneliner) {
			r_str_replace_char (acode->assembly, '\n', ';');
			printf ("%s\"\n", acode->assembly);
		} else {
			printf ("%s", acode->assembly);
		}
		ret = acode->len;
		r_asm_code_free (acode);
	}
beach:
	if (data && data != (ut8 *)buf) {
		free (data);
	}
	return ret;
}

static void print_buf(RAsmState *as, char *str) {
	int i;
	if (as->coutput) {
		printf ("\"");
		for (i = 1; *str; str += 2, i += 2) {
			if (!(i % 41)) {
				printf ("\" \\\n\"");
				i = 1;
			}
			printf ("\\x%c%c", *str, str[1]);
		}
		printf ("\"\n");
	} else {
		printf ("%s\n", str);
	}
}

static bool print_label(void *user, const void *k, const void *v) {
	printf ("f label.%s = %s\n", (const char *)k, (const char *)v);
	return true;
}

static int rasm_asm(RAsmState *as, const char *buf, ut64 offset, ut64 len, int bits, int bin, bool use_spp, bool hexwords) {
	RAsmCode *acode;
	int i, j, ret = 0;
	r_asm_set_pc (as->a, offset);
	if (!(acode = r_asm_rasm_assemble (as->a, buf, use_spp))) {
		return 0;
	}
	if (acode->len) {
		ret = acode->len;
		if (bin) {
			if ((ret = write (1, acode->bytes, acode->len)) != acode->len) {
				eprintf ("Failed to write buffer\n");
				r_asm_code_free (acode);
				return 0;
			}
		} else {
			int b = acode->len;
			if (bits == 1) {
				int bytes = (b / 8) + 1;
				for (i = 0; i < bytes; i++) {
					for (j = 0; j < 8 && b--; j++) {
						printf ("%c", (acode->bytes[i] & (1 << j))? '1': '0');
					}
				}
				printf ("\n");
			} else {
				if (hexwords) {
					size_t i = 0;
					for (i = 0; i < acode->len; i += sizeof (ut32)) {
						ut32 dword = r_read_ble32 (acode->bytes + i, R_SYS_ENDIAN);
						printf ("0x%08x ", dword);
						if ((i/4) == 7) {
							printf ("\n");
						}
					}
					printf ("\n");
				} else {
					char* str = r_asm_code_get_hex (acode);
					if (str) {
						print_buf (as, str);
						free (str);
					}
				}
			}
		}
	}
	r_asm_code_free (acode);
	return (ret > 0);
}

/* asm callback */
static int __lib_asm_cb(RLibPlugin *pl, void *user, void *data) {
	RAsmPlugin *hand = (RAsmPlugin *)data;
	RAsmState *as = (RAsmState *)user;
	r_asm_add (as->a, hand);
	return true;
}

/* anal callback */
static int __lib_anal_cb(RLibPlugin *pl, void *user, void *data) {
	RAnalPlugin *hand = (RAnalPlugin *)data;
	RAsmState *as = (RAsmState *)user;
	r_anal_add (as->anal, hand);
	return true;
}

/* arch callback */
static int __lib_arch_cb(RLibPlugin *pl, void *user, void *data) {
	RArchPlugin *hand = (RArchPlugin *)data;
	RAsmState *as = (RAsmState *)user;
	r_arch_add (as->arch, hand);
	return true;
}

static int print_assembly_output(RAsmState *as, const char *buf, ut64 offset, ut64 len, int bits,
                                 int bin, bool use_spp, bool rad, bool hexwords, const char *arch) {
	if (rad) {
		printf ("e asm.arch=%s\n", arch? arch: R_SYS_ARCH);
		printf ("e asm.bits=%d\n", bits);
		if (offset) {
			printf ("s 0x%"PFMT64x"\n", offset);
		}
		printf ("wx ");
	}
	int ret = rasm_asm (as, (char *)buf, offset, len, as->a->bits, bin, use_spp, hexwords);
	if (rad) {
		printf ("f entry = $$\n");
		printf ("f label.main = $$ + 1\n");
		ht_pp_foreach (as->a->flags, print_label, NULL);
	}
	return ret;
}

static void __load_plugins(RAsmState *as) {
	char *tmp = r_sys_getenv ("RASM2_NOPLUGINS");
	if (tmp) {
		free (tmp);
		return;
	}
	r_lib_add_handler (as->l, R_LIB_TYPE_ASM, "(dis)assembly plugins", &__lib_asm_cb, NULL, as);
	r_lib_add_handler (as->l, R_LIB_TYPE_ANAL, "analysis/emulation plugins", &__lib_anal_cb, NULL, as);
	r_lib_add_handler (as->l, R_LIB_TYPE_ARCH, "unified architeture plugins", &__lib_arch_cb, NULL, as);

	char *path = r_sys_getenv (R_LIB_ENV);
	if (path && *path) {
		r_lib_opendir (as->l, path);
	}

	// load plugins from the home directory
	char *homeplugindir = r_str_home (R2_HOME_PLUGINS);
	r_lib_opendir (as->l, homeplugindir);
	free (homeplugindir);

	// load plugins from the system directory
	char *plugindir = r_str_r2_prefix (R2_PLUGINS);
	char *extrasdir = r_str_r2_prefix (R2_EXTRAS);
	char *bindingsdir = r_str_r2_prefix (R2_BINDINGS);
	r_lib_opendir (as->l, plugindir);
	r_lib_opendir (as->l, extrasdir);
	r_lib_opendir (as->l, bindingsdir);
	free (plugindir);
	free (extrasdir);
	free (bindingsdir);

	free (tmp);
	free (path);
}

R_API int r_main_rasm2(int argc, const char *argv[]) {
	const char *env_arch = r_sys_getenv ("RASM2_ARCH");
	const char *env_bits = r_sys_getenv ("RASM2_BITS");
	const char *arch = NULL;
	const char *cpu = NULL;
	const char *kernel = NULL;
	const char *filters = NULL;
	const char *file = NULL;
	bool isbig = false;
	bool rad = false;
	bool use_spp = false;
	bool hexwords = false;
	ut64 offset = 0;
	int fd = -1, dis = 0, bin = 0, ret = 0, bits = 32, c, whatsop = 0;
	int help = 0;
	ut64 len = 0, idx = 0, skip = 0;
	bool analinfo = false;

	if (argc < 2) {
		return rasm_show_help (1);
	}

	RAsmState *as = __as_new ();

	// TODO set addrbytes
	char *r2arch = r_sys_getenv ("R2_ARCH");
	if (r2arch) {
		arch = r2arch;
	}

	char *r2bits = r_sys_getenv ("R2_BITS");
	if (r2bits) {
		bits = r_num_math (NULL, r2bits);
		free (r2bits);
	}

	RGetopt opt;
	r_getopt_init (&opt, argc, argv, "a:Ab:Bc:CdDeEf:F:hi:jk:l:L@:o:O:pqrs:vwx");
	while ((c = r_getopt_next (&opt)) != -1) {
		switch (c) {
		case 'a':
			arch = opt.arg;
			break;
		case 'A':
			analinfo = true;
			break;
		case 'b':
			bits = r_num_math (NULL, opt.arg);
			break;
		case 'B':
			bin = 1;
			break;
		case 'c':
			cpu = opt.arg;
			break;
		case 'C':
			as->coutput = true;
			break;
		case 'd':
			dis = 1;
			break;
		case 'D':
			dis = 2;
			break;
		case 'e':
			isbig = true;
			break;
		case 'E':
			dis = 3;
			break;
		case 'f':
			file = opt.arg;
			break;
		case 'F':
			filters = opt.arg;
			break;
		case 'h':
			help++;
		case 'i':
			skip = r_num_math (NULL, opt.arg);
			break;
		case 'j':
			as->json = true;
			break;
		case 'k':
			kernel = opt.arg;
			break;
		case 'l':
			len = r_num_math (NULL, opt.arg);
			break;
		case 'L':
			rasm2_list (as, opt.argv[opt.ind]);
			ret = 1;
			goto beach;
		case '@':
		case 'o':
			offset = r_num_math (NULL, opt.arg);
			break;
		case 'O':
			fd = open (opt.arg, O_TRUNC | O_RDWR | O_CREAT, 0644);
			if (fd != -1) {
				dup2 (fd, 1);
			}
			break;
		case 'p':
			use_spp = true;
			break;
		case 'q':
			as->quiet = true;
			break;
		case 'r':
			rad = true;
			break;
		case 's':
			if (*opt.arg == '?') {
				printf ("att\nintel\nmasm\njz\nregnum\n");
				__as_free (as);
				return 0;
			} else {
				int syntax = r_asm_syntax_from_string (opt.arg);
				if (syntax == -1) {
					__as_free (as);
					return 1;
				}
				r_asm_set_syntax (as->a, syntax);
			}
			break;
		case 'v':
			if (as->quiet) {
				printf ("%s\n", R2_VERSION);
			} else {
				ret = r_main_version_print ("rasm2");
			}
			goto beach;
		case 'w':
			whatsop = true;
			break;
		case 'x':
			hexwords = true;
			break;
		default:
			ret = rasm_show_help (0);
			goto beach;
		}
	}

	if (help > 0) {
		ret = rasm_show_help (help > 1? 2: 0);
		goto beach;
	}

	if (arch) {
		if (!r_asm_use (as->a, arch)) {
			eprintf ("rasm2: Unknown asm plugin '%s'\n", arch);
			ret = 0;
			goto beach;
		}
		r_anal_use (as->anal, arch);
	} else if (env_arch) {
		if (!r_asm_use (as->a, env_arch)) {
			eprintf ("rasm2: Unknown asm plugin '%s'\n", env_arch);
			ret = 0;
			goto beach;
		}
	} else if (!r_asm_use (as->a, "x86")) {
		eprintf ("rasm2: Cannot find asm.x86 plugin\n");
		ret = 0;
		goto beach;
	}
	r_asm_set_cpu (as->a, cpu);
	r_asm_set_bits (as->a, (env_bits && *env_bits)? atoi (env_bits): bits);
	r_anal_set_bits (as->anal, (env_bits && *env_bits)? atoi (env_bits): bits);
	as->a->syscall = r_syscall_new ();
	r_syscall_setup (as->a->syscall, arch, bits, cpu, kernel);
	{
		bool canbebig = r_asm_set_big_endian (as->a, isbig);
		if (isbig && !canbebig) {
			eprintf ("Warning: This architecture can't swap to big endian.\n");
		}
		r_anal_set_big_endian (as->anal, canbebig);
	}
	if (whatsop) {
		const char *s = r_asm_describe (as->a, opt.argv[opt.ind]);
		ret = 1;
		if (s) {
			printf ("%s\n", s);
			ret = 0;
		}
		goto beach;
	}
	if (filters) {
		char *p = strchr (filters, ':');
		if (p) {
			*p = 0;
			if (*filters) {
				r_asm_filter_input (as->a, filters);
			}
			if (p[1]) {
				r_asm_filter_output (as->a, p + 1);
			}
			*p = ':';
		} else {
			if (dis) {
				r_asm_filter_output (as->a, filters);
			} else {
				r_asm_filter_input (as->a, filters);
			}
		}
	}

	if (file) {
		char *content;
		size_t length = 0;
		if (!strcmp (file, "-")) {
			int sz = 0;
			ut8 *buf = (ut8 *)r_stdin_slurp (&sz);
			if (!buf || sz < 1) {
				eprintf ("Nothing to do.\n");
				goto beach;
			}
			len = (ut64)sz;
			if (dis) {
				if (skip && length > skip) {
					if (bin) {
						memmove (buf, buf + skip, length - skip);
						length -= skip;
					}
				}
				ret = rasm_disasm (as, offset, (char *)buf, len, as->a->bits, bin, dis - 1);
			} else if (analinfo) {
				ret = show_analinfo (as, (const char *)buf, offset);
			} else {
				ret = print_assembly_output (as, (char *)buf, offset, len,
					as->a->bits, bin, use_spp, rad, hexwords, arch);
			}
			ret = !ret;
			free (buf);
		} else {
			content = r_file_slurp (file, &length);
			if (content) {
				if (length > ST32_MAX) {
					eprintf ("rasm2: File %s is too big\n", file);
					ret = 1;
				} else {
					if (len && len > 0 && len < length) {
						length = len;
					}
					content[length] = '\0';
					if (skip && length > skip) {
						if (bin) {
							memmove (content, content + skip, length - skip);
							length -= skip;
						}
					}
					if (dis) {
						ret = rasm_disasm (as, offset, content,
								length, as->a->bits, bin, dis - 1);
					} else if (analinfo) {
						ret = show_analinfo (as, (const char *)content, offset);
					} else {
						ret = print_assembly_output (as, content, offset, length,
								as->a->bits, bin, use_spp, rad, hexwords, arch);
					}
					ret = !ret;
				}
				free (content);
			} else {
				eprintf ("rasm2: Cannot open file %s\n", file);
				ret = 1;
			}
		}
	} else if (opt.argv[opt.ind]) {
		if (!strcmp (opt.argv[opt.ind], "-")) {
			int length;
			do {
				char buf[1024]; // TODO: use(implement) r_stdin_line() or so
				length = read (0, buf, sizeof (buf) - 1);
				if (length < 1) {
					break;
				}
				if (len > 0 && len < length) {
					length = len;
				}
				buf[length] = 0;
				if ((!bin || !dis) && feof (stdin)) {
					break;
				}
				if (skip && length > skip) {
					if (bin) {
						memmove (buf, buf + skip, length - skip + 1);
						length -= skip;
					}
				}
				if (!bin || !dis) {
					int buflen = strlen ((const char *)buf);
					if (buf[buflen] == '\n') {
						buf[buflen - 1] = '\0';
					}
				}
				if (dis) {
					ret = rasm_disasm (as, offset, (char *)buf, length, as->a->bits, bin, dis - 1);
				} else if (analinfo) {
					ret = show_analinfo (as, (const char *)buf, offset);
				} else {
					ret = rasm_asm (as, (const char *)buf, offset, length, as->a->bits, bin, use_spp, hexwords);
				}
				idx += ret;
				offset += ret;
				if (!ret) {
					goto beach;
				}
			} while (!len || idx < length);
			ret = idx;
			goto beach;
		}
		if (dis) {
			char *usrstr = strdup (opt.argv[opt.ind]);
			len = strlen (usrstr);
			if (skip && len > skip) {
				skip *= 2;
				//eprintf ("SKIP (%s) (%lld)\n", usrstr, skip);
				memmove (usrstr, usrstr + skip, len - skip);
				len -= skip;
				usrstr[len] = 0;
			}
			// XXX this is a wrong usage of endianness
			if (!strncmp (usrstr, "0x", 2)) {
				memmove (usrstr, usrstr + 2, strlen (usrstr + 2) + 1);
			}
			if (rad) {
				as->oneliner = true;
				printf ("e asm.arch=%s\n", arch? arch: R_SYS_ARCH);
				printf ("e asm.bits=%d\n", bits);
				printf ("\"wa ");
			}
			ret = rasm_disasm (as, offset, (char *)usrstr, len,
					as->a->bits, bin, dis - 1);
			free (usrstr);
		} else if (analinfo) {
			ret = show_analinfo (as, (const char *)opt.argv[opt.ind], offset);
		} else {
			ret = print_assembly_output (as, opt.argv[opt.ind], offset, len, as->a->bits,
							bin, use_spp, rad, hexwords, arch);
		}
		if (!ret) {
			eprintf ("invalid\n");
		}
		ret = !ret;
	}
beach:
	__as_free (as);

	free (r2arch);
	if (fd != -1) {
		close (fd);
	}
	return ret;
}
