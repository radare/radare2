/* radare - LGPL - Copyright 2015-2021 - pancake */

#include <r_core.h>
#define TYPE_NONE 0
#define TYPE_STR 1
#define TYPE_SYM 2
#define IS_ALPHA(x) (IS_UPPER(x) || IS_LOWER(x))
#define IS_STRING(x,y) ((x)+3<end && *(x) == 's' && *((x)+1) == 't' && *((x)+2) == 'r' && *((x)+3) == '.')
#define IS_SYMBOL(x,y) ((x)+3<end && *(x) == 's' && *((x)+1) == 'y' && *((x)+2) == 'm' && *((x)+3) == '.')

typedef struct _find_ctx {
	char *comment;
	char *left;
	char *right;
	char *linebegin;
	int leftlen;
	int rightlen;
	int leftpos;
	int leftcolor;
	int commentcolor;
	int rightcolor;
	int linecount;
	int type;
} RFindCTX;

static void find_and_change(char* in, int len) {
	// just to avoid underflows.. len can't be < then len(padding).
	if (!in || len < 1) {
		return;
	}
	char *end;
	RFindCTX ctx = {0};
	end = in + len;
//	type = TYPE_NONE;
	for (ctx.linebegin = in; in < end; in++) {
		if (*in == '\n' || !*in) {
			if (ctx.type == TYPE_SYM && ctx.linecount < 1) {
				ctx.linecount++;
				ctx.linebegin = in + 1;
				continue;
			}
			if (ctx.type != TYPE_NONE && ctx.right && ctx.left && ctx.rightlen > 0 && ctx.leftlen > 0) {
				char* copy = NULL;
				if (ctx.leftlen > ctx.rightlen) {
					// if new string is o
					copy = (char*) malloc (ctx.leftlen);
					if (copy) {
						memmove (copy, ctx.left, ctx.leftlen);
						memmove (ctx.left, ctx.right, ctx.rightlen);
						memset (ctx.left + ctx.rightlen, ' ', ctx.leftlen - ctx.rightlen);
						memmove (ctx.comment - ctx.leftlen + ctx.rightlen, ctx.comment, ctx.right - ctx.comment);
						memmove (ctx.right - ctx.leftlen + ctx.rightlen, copy, ctx.leftlen);
					}
				} else if (ctx.leftlen < ctx.rightlen) {
					if (ctx.linecount < 1) {
						copy = (char*) malloc (ctx.rightlen);
						if (copy) {
							// ###LEFTLEN### ### RIGHT
							// backup ctx.right+len into copy
							memcpy (copy, ctx.right, ctx.rightlen);
							// move string into
							memcpy (ctx.right + ctx.rightlen - ctx.leftlen, ctx.left, ctx.leftlen);
							memmove (ctx.comment + ctx.rightlen - ctx.leftlen, ctx.comment, ctx.right - ctx.comment);
							memmove (ctx.left + ctx.rightlen - ctx.leftlen, copy, ctx.rightlen);
						}
					} else {
//						copy = (char*) malloc (ctx.linebegin - ctx.left);
//						if (copy) {
//							memcpy (copy, ctx.left, ctx.linebegin - ctx.left);
						memset (ctx.right - ctx.leftpos, ' ', ctx.leftpos);
						*(ctx.right - ctx.leftpos - 1) = '\n';
//							memcpy (ctx.comment + 3, copy, ctx.linebegin - ctx.left);
						memset (ctx.left, ' ', ctx.leftlen);
						memset (ctx.linebegin - ctx.leftlen, ' ', ctx.leftlen);
//						}
					}
				} else if (ctx.leftlen == ctx.rightlen) {
					copy = (char*) malloc (ctx.leftlen);
					if (copy) {
						memcpy (copy, ctx.right, ctx.leftlen);
						memcpy (ctx.right, ctx.left, ctx.leftlen);
						memcpy (ctx.left, copy, ctx.leftlen);
					}
				}
				free (copy);
			}
			memset (&ctx, 0, sizeof (ctx));
			ctx.linebegin = in + 1;
		} else if (!ctx.comment && *in == ';' && in[1] == ' ') {
			ctx.comment = in - 1;
			ctx.comment[1] = '/';
			ctx.comment[2] = '/';
		} else if (!ctx.comment && ctx.type == TYPE_NONE) {
			if (IS_STRING (in, ctx)) {
				ctx.type = TYPE_STR;
				ctx.left = in;
				while (!IS_WHITESPACE (*(ctx.left - ctx.leftcolor))) {
					ctx.leftcolor++;
				}
				ctx.leftcolor--;
				ctx.leftpos = ctx.left - ctx.linebegin;
			} else if (IS_SYMBOL (in, ctx)) {
				ctx.type = TYPE_SYM;
				ctx.left = in;
				while (!IS_WHITESPACE (*(ctx.left - ctx.leftcolor))) {
					ctx.leftcolor++;
				}
				ctx.leftcolor--;
				ctx.leftpos = ctx.left - ctx.linebegin;
			}
		} else if (ctx.type == TYPE_STR) {
			if (!ctx.leftlen && ctx.left && IS_WHITESPACE (*in)) {
				ctx.leftlen = in - ctx.left;
			} else if (ctx.comment && *in == '"' && in[-1] != '\\') {
				if (!ctx.right) {
					ctx.right = in;
					while (!IS_WHITESPACE (*(ctx.right - ctx.rightcolor))) {
						ctx.rightcolor++;
					}
					ctx.rightcolor--;
				} else {
					ctx.rightlen = in - ctx.right + 1;
				}
			}
		} else if (ctx.type == TYPE_SYM) {
			if (!ctx.leftlen && ctx.left && IS_WHITESPACE (*in)) {
				ctx.leftlen = in - ctx.left + 3;
			} else if (ctx.comment && *in == '(' && IS_ALPHA (in[-1]) && !ctx.right) {
				// ok so i've found a function written in this way:
				// type = [const|void|int|float|double|short|long]
				// type fcn_name (type arg1, type arg2, ...)
				// right now 'in' points at '(', but the function name is before, so i'll go back
				// till a space is found
				// 'int print(const char*, ...)'
				//           ^
				ctx.right = in - 1;
				while (IS_ALPHA (*ctx.right) || *ctx.right == '_' || *ctx.right == '*') {
					ctx.right--;
				}
				// 'int print(const char*, ...)'
				//     ^
				// right now 'in' points at ' ' before 'p' , but there can be a return value
				// like 'int' in 'int print(const char*, ...)'.
				// so to find for example 'int' we have to go back till a space is found.
				// if a non alpha is found, then we can cut from the function name
				if (*ctx.right == ' ') {
					ctx.right--;
					while (IS_ALPHA (*ctx.right) || *ctx.right == '_' || *ctx.right == '*') {
						ctx.right--;
					}
					// moving forward since it points now to non alpha.
					ctx.right++;
				}
				while (!IS_WHITESPACE (*(ctx.right - ctx.rightcolor))) {
					ctx.rightcolor++;
				}
				ctx.rightcolor--;
			} else if (ctx.comment && *in == ')' && in[1] != '\'') {
				ctx.rightlen = in - ctx.right + 1;
			}
		}
	}
}

static const char *help_msg_pdc[] = {
	"Usage: pdc[oj]", "", "experimental, unreliable and hacky pseudo-decompiler",
	"pdc", "", "pseudeo decompile function in current offset",
	"pdco", "", "show associated offset next to pseudecompiled output",
	"pdcj", "", "in json format for codemeta annotations (used by frontends like iaito)",
	NULL
};

#define I_TAB 2
#define K_MARK(x) sdb_fmt("mark.%"PFMT64x,x)
#define K_ELSE(x) sdb_fmt("else.%"PFMT64x,x)
#define K_INDENT(x) sdb_fmt("loc.%"PFMT64x,x)
#define SET_INDENT(x) { (x) = (x)>0?(x):0; memset (indentstr, ' ', sizeof(indentstr)); indentstr [((x) * I_TAB)] = 0; }
R_API int r_core_pseudo_code(RCore *core, const char *input) {
	if (*input == '?') {
		r_core_cmd_help (core, help_msg_pdc);
		return false;
	}
#define PRINTF(a, ...) {\
	if (pj) {\
		r_strbuf_appendf (codestr, a, ##__VA_ARGS__);\
	} else {\
		r_cons_printf (a, ##__VA_ARGS__);\
	}}
#define NEWLINE(a,i) {\
	size_t eos = R_MIN ((i) * 2, sizeof (indentstr) - 2);\
	if (eos < 1) eos = 0;\
	memset (indentstr, ' ', sizeof (indentstr)); indentstr [(eos * 2)] = 0;\
	if (pj) {\
		if (show_addr) r_strbuf_appendf (codestr, "\n0x%08"PFMT64x" | %s", a, indentstr);\
		else r_strbuf_appendf (codestr, "\n%s", indentstr);\
	} else {\
		r_cons_newline();\
		if (show_addr) r_cons_printf (" 0x%08"PFMT64x" | %s", a, indentstr);\
		else r_cons_printf ("%s", indentstr); }\
	}
	const char *cmdPdc = r_config_get (core->config, "cmd.pdc");
	if (cmdPdc && *cmdPdc && !strstr (cmdPdc, "pdc")) {
		if (strstr (cmdPdc, "!*") || strstr (cmdPdc, "#!")) {
			if (!strcmp (input, "*")) {
				input = " -r2";
			} else if (!strcmp (input, "=")) {
				input = " -a";
			} else if (!strcmp (input, "?")) {
				input = " -h";
			}
		}
		return r_core_cmdf (core, "%s%s", cmdPdc, input);
	}
	const bool show_json = (*input == 'j');
	const bool show_addr = (*input == 'o');

	Sdb *db;
	ut64 queuegoto = 0LL;
	const char *blocktype = "else";
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
	RConfigHold *hc = r_config_hold_new (core->config);
	if (!hc) {
		return false;
	}
	r_config_hold (hc, "asm.pseudo", "asm.decode", "asm.lines", "asm.bytes", "asm.stackptr", NULL);
	r_config_hold (hc, "asm.offset", "asm.flags", "asm.lines.fcn", "asm.comments", NULL);
	r_config_hold (hc, "asm.functions", "asm.section", "asm.cmt.col", "asm.sub.names", NULL);
	r_config_hold (hc, "scr.color", "emu.str", "asm.emu", "emu.write", NULL);
	r_config_hold (hc, "io.cache", NULL);
	if (!fcn) {
		eprintf ("Cannot find function in 0x%08"PFMT64x"\n", core->offset);
		r_config_hold_free (hc);
		return false;
	}
	r_config_set_i (core->config, "scr.color", 0);
	r_config_set_b (core->config, "asm.stackptr", false);
	r_config_set_b (core->config, "asm.pseudo", true);
	r_config_set_b (core->config, "asm.decode", false);
	r_config_set_b (core->config, "asm.sub.names", true);
	r_config_set_b (core->config, "asm.lines", false);
	r_config_set_b (core->config, "asm.bytes", false);
	r_config_set_b (core->config, "asm.offset", true);
	r_config_set_b (core->config, "asm.flags", false);
	r_config_set_b (core->config, "asm.emu", true);
	r_config_set_b (core->config, "emu.str", true);
	r_config_set_b (core->config, "emu.write", true);
	r_config_set_b (core->config, "asm.lines.fcn", false);
	r_config_set_b (core->config, "asm.comments", true);
	r_config_set_b (core->config, "asm.functions", false);
	r_config_set_i (core->config, "asm.tabs", 0);
	r_config_set_b (core->config, "asm.section", false);
	r_config_set_i (core->config, "asm.cmt.col", 30);
	r_config_set_b (core->config, "io.cache", true);
	r_core_cmd0 (core, "aeim");
	PJ *pj = NULL;
	if (show_json) {
		pj = r_core_pj_new (core);
	}

	RStrBuf *codestr = r_strbuf_new ("");
	db = sdb_new0 ();
	// walk all basic blocks
	// define depth level for each block
	// use it for indentation
	// asm.pseudo=true
	// asm.decode=true
	RAnalBlock *bb = r_list_first (fcn->bbs);
	char indentstr[1024] = {0};
	int indent = 0;
	int nindent = 1;
	int n_bb = r_list_length (fcn->bbs);
	if (show_json) {
		pj = r_core_pj_new (core);
		pj_o (pj);
		pj_ka (pj, "annotations");
	}
	NEWLINE (fcn->addr, indent);
	PRINTF ("// global registers\n");
	// only print the used registers
	PRINTF ("int stack[1024];\n");
	PRINTF ("unsigned long long *qword = &stack;\n");
	PRINTF ("unsigned int *dword = &stack;\n");
	PRINTF ("unsigned short *word = &stack;\n");
	PRINTF ("unsigned char *byte = &stack;\n");
	PRINTF ("int eax, ebx, ecx, edx;\n");
	PRINTF ("// This function contains %d basic blocks and its %d long.",
		n_bb, (int)r_anal_function_realsize (fcn));
	NEWLINE (fcn->addr, indent);
	const char *S0 = "esp";
	PRINTF ("static inline void push (int reg) {%s-=%d;stack[%s]=reg;}\n", S0, (int)sizeof (int), S0);
	PRINTF ("static inline int pop() {int r = stack[%s]; %s+=%d; return r;}\n", S0, S0, (int)sizeof (int));
	PRINTF ("int %s (int esi, int edx) {", fcn->name);
	indent++;
	RList *visited = r_list_newf (NULL);
	ut64 addr = fcn->addr;
	do {
		if (!bb) {
			break;
		}
		r_list_append (visited, bb);
		r_cons_push ();
		bool html = r_config_get_b (core->config, "scr.html");
		r_config_set_b (core->config, "scr.html", false);
		char *code = r_core_cmd_str (core, sdb_fmt ("pD %"PFMT64d" @ 0x%08"PFMT64x"\n", bb->size, bb->addr));
		r_cons_pop ();
		r_config_set_b (core->config, "scr.html", html);
		if (indent * I_TAB + 2 >= sizeof (indentstr)) {
			indent = (sizeof (indentstr) / I_TAB) - 2;
		}
		indent = 2;
		SET_INDENT (indent);
		if (!code) {
			eprintf ("No code here\n");
			break;
		}
		code = r_str_replace (code, ";", "//", true);
		const char *R0 = "eax";
		size_t len = strlen (code);
		code[len - 1] = 0; // chop last newline
		find_and_change (code, len);
		if (!sdb_const_get (db, K_MARK (bb->addr), 0)) {
			bool mustprint = !queuegoto || queuegoto != bb->addr;
			if (mustprint) {
				if (queuegoto) {
					NEWLINE (bb->addr, indent);
					PRINTF ("goto loc_0x%"PFMT64x, queuegoto);
					queuegoto = 0LL;
				}
				NEWLINE (bb->addr, indent - 1);
				PRINTF ("loc_0x%"PFMT64x":", bb->addr);
				// foreach lines
				RList *lines = r_str_split_list (code, "\n", 0);
				RListIter *iter;
				const char *line;
				addr = bb->addr;
				r_list_foreach (lines, iter, line) {
					if (*line == '0') {
						ut64 at = r_num_get (NULL, line);
						if (at && at != UT64_MAX) {
							addr = at;
						}
						char *s = strchr (line, ' ');
						if (s) {
							line = r_str_trim_head_ro (s + 1);
						}
					}
					if (pj) {
						pj_o (pj);
						pj_kn (pj, "start", r_strbuf_length (codestr));
						pj_kn (pj, "end", r_strbuf_length (codestr));
						pj_kn (pj, "offset", addr);
						pj_ks (pj, "type", "offset");
						pj_end (pj);
					}
					NEWLINE (addr, indent);
					PRINTF ("%s", line);
				}
				r_list_free (lines);
				free (code);
				sdb_num_set (db, K_MARK (bb->addr), 1, 0);
			}
		}
		if (sdb_const_get (db, K_INDENT (bb->addr), 0)) {
			// already analyzed, go pop and continue
			// XXX check if can't pop
			//eprintf ("%s// 0x%08llx already analyzed\n", indentstr, bb->addr);
			ut64 addr = sdb_array_pop_num (db, "indent", NULL);
			if (addr == UT64_MAX) {
				int i;
				nindent = 1;
				for (i = indent; i != nindent && i > 0; i--) {
					NEWLINE (bb->addr, i);
					PRINTF ("}");
				}
				NEWLINE (bb->addr, indent);
				PRINTF ("return %s;", R0);
				RAnalBlock *nbb = r_anal_bb_from_offset (core->anal, bb->fail);
				if (r_list_contains (visited, nbb)) {
					nbb = r_anal_bb_from_offset (core->anal, bb->jump);
					if (r_list_contains (visited, nbb)) {
						nbb = NULL;
					}
				}
				if (!nbb) {
					break;
				}
				bb = nbb;
				indent--;
				continue;
			}
			if (sdb_num_get (db, K_ELSE (bb->addr), 0)) {
				NEWLINE (addr, indent);
				if (!strcmp (blocktype, "else")) {
					PRINTF (" // } %s {", blocktype);
				} else {
					PRINTF (" // } %s (?);", blocktype);
				}
			} else {
				NEWLINE (addr, indent);
				PRINTF (" // }");
			}
			if (addr != bb->addr) {
				queuegoto = addr;
				// r_cons_printf ("\n%s  goto loc_0x%llx", indentstr, addr);
			}
			bb = r_anal_bb_from_offset (core->anal, addr);
			if (!bb) {
				eprintf ("failed block\n");
				break;
			}
			nindent = sdb_num_get (db, K_INDENT (addr), NULL);
			if (indent > nindent && !strcmp (blocktype, "else")) {
				int i;
				for (i = indent; i != nindent; i--) {
					NEWLINE (addr, i);
					PRINTF ("}");
				}
			}
			indent = nindent - 1;
		} else {
			sdb_set (db, K_INDENT (bb->addr), "passed", 0);
			if (bb->jump != UT64_MAX) {
				int swap = 1;
				// TODO: determine which branch take first
				ut64 jump = swap ? bb->jump : bb->fail;
				ut64 fail = swap ? bb->fail : bb->jump;
				// if its from another function chop it!
				RAnalFunction *curfcn = r_anal_get_fcn_in (core->anal, jump, R_ANAL_FCN_TYPE_NULL);
				if (curfcn != fcn) {
					// chop that branch
					NEWLINE (jump, indent);
					PRINTF ("// chop");
					// break;
				}
				if (sdb_get (db, K_INDENT (jump), 0)) {
					// already tracekd
					if (!sdb_get (db, K_INDENT (fail), 0)) {
						bb = r_anal_bb_from_offset (core->anal, fail);
					} else {
						eprintf (" // FAIL%c", 10);
					}
				} else {
					bb = r_anal_bb_from_offset (core->anal, jump);
					if (!bb) {
						eprintf ("failed to retrieve block at 0x%"PFMT64x"\n", jump);
						break;
					}
					if (fail != UT64_MAX) {
						// do not push if already pushed
						indent++;
						if (sdb_get (db, K_INDENT (bb->fail), 0)) {
							/* do nothing here */
							eprintf ("BlockAlready 0x%"PFMT64x"\n", bb->addr);
						} else {
							// r_cons_printf (" { RADICAL %llx\n", bb->addr);
							sdb_array_push_num (db, "indent", fail, 0);
							sdb_num_set (db, K_INDENT (fail), indent, 0);
							sdb_num_set (db, K_ELSE (fail), 1, 0);
							NEWLINE (bb->addr, indent);
						}
					} else {
						sdb_array_push_num (db, "indent", jump, 0);
						sdb_num_set (db, K_INDENT (jump), indent, 0);
						sdb_num_set (db, K_ELSE (jump), 1, 0);
						if (jump <= bb->addr) {
							blocktype = "while";
						} else {
							blocktype = "else";
						}
						NEWLINE (bb->addr, indent);
						PRINTF (" // do {");
						indent++;
					}
				}
			} else {
				ut64 addr = sdb_array_pop_num (db, "indent", NULL);
				if (addr == UT64_MAX) {
					NEWLINE (bb->addr, indent);
					PRINTF (" // (break)");
					break;
				}
				bb = r_anal_bb_from_offset (core->anal, addr);
				nindent = sdb_num_get (db, K_INDENT (addr), NULL);
				if (indent > nindent) {
					int i;
					for (i = indent; i != nindent; i--) {
						NEWLINE (bb->addr, i);
						PRINTF ("}");
					}
				}
				if (nindent != indent) {
					NEWLINE (bb->addr, indent);
					PRINTF (" // } else {");
				}
				indent = nindent;
			}
		}
		//n_bb --;
	} while (n_bb > 0);
	RListIter *iter;
	size_t orphan = 0;
	r_list_foreach (fcn->bbs, iter, bb) {
		if (!r_list_contains (visited, bb)) {
			orphan ++;
			char *s = r_core_cmd_strf (core, "pdb@0x%08"PFMT64x"@e:asm.offset=0", bb->addr);
			s = r_str_replace (s, ";", "//", true);
			char *os = r_str_prefix_all (s, indentstr);
			free (s);
			s = os;
			if (pj) {
				pj_o (pj);
				pj_kn (pj, "start", r_strbuf_length (codestr));
				r_strbuf_append (codestr, s);
				pj_kn (pj, "end", r_strbuf_length (codestr));
				pj_kn (pj, "offset", addr);
				pj_ks (pj, "type", "offset");
				pj_end (pj);
			}
			NEWLINE (bb->addr, 1);
			PRINTF ("loc_0x%08"PFMT64x": // orphan\n%s", bb->addr, s);
			free (s);
		}
	}
	r_list_free (visited);
	indent = 0;
	NEWLINE (addr, indent);
	PRINTF ("}\n");
	if (pj) {
		pj_end (pj);
		char *kode = r_strbuf_drain (codestr);
		pj_ks (pj, "code", kode);
		pj_end (pj);
		char *j = pj_drain (pj);
		r_cons_printf ("%s\n", j);
		free (kode);
		free (j);
	}
	r_config_hold_restore (hc);
	r_config_hold_free (hc);
	sdb_free (db);
	return true;
}
