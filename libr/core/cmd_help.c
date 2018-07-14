/* radare - LGPL - Copyright 2009-2018 - pancake */

#include <stddef.h>
#include "r_cons.h"
#include "r_core.h"
#include "r_util.h"

static ut32 vernum(const char *s) {
	// XXX this is known to be buggy, only works for strings like "x.x.x"
	// XXX anything like "x.xx.x" will break the parsing
	// XXX -git is ignored, maybe we should shift for it
	char *a = strdup (s);
	a = r_str_replace (a, ".", "0", 1);
	char *dash = strchr (a, '-');
	if (dash) {
		*dash = 0;
	}
	ut32 res = atoi (a);
	free (a);
	return res;
}

static const char *help_msg_root[] = {
	"%var", "=value", "alias for 'env' command",
	"*", "[?] off[=[0x]value]", "pointer read/write data/values (see ?v, wx, wv)",
	"(macro arg0 arg1)",  "", "manage scripting macros",
	".", "[?] [-|(m)|f|!sh|cmd]", "Define macro or load r2, cparse or rlang file",
	"=","[?] [cmd]", "send/listen for remote commands (rap://, http://, <fd>)",
	"<","[...]", "push escaped string into the RCons.readChar buffer",
	"/","[?]", "search for bytes, regexps, patterns, ..",
	"!","[?] [cmd]", "run given command as in system(3)",
	"#","[?] !lang [..]", "Hashbang to run an rlang script",
	"a","[?]", "analysis commands",
	"b","[?]", "display or change the block size",
	"c","[?] [arg]", "compare block with given data",
	"C","[?]", "code metadata (comments, format, hints, ..)",
	"d","[?]", "debugger commands",
	"e","[?] [a[=b]]", "list/get/set config evaluable vars",
	"f","[?] [name][sz][at]", "add flag at current address",
	"g","[?] [arg]", "generate shellcodes with r_egg",
	"i","[?] [file]", "get info about opened file from r_bin",
	"k","[?] [sdb-query]", "run sdb-query. see k? for help, 'k *', 'k **' ...",
	"L","[?] [-] [plugin]", "list, unload load r2 plugins",
	"m","[?]", "mountpoints commands",
	"o","[?] [file] ([offset])", "open file at optional address",
	"p","[?] [len]", "print current block with format and length",
	"P","[?]", "project management utilities",
	"q","[?] [ret]", "quit program with a return value",
	"r","[?] [len]", "resize file",
	"s","[?] [addr]", "seek to address (also for '0x', '0x1' == 's 0x1')",
	"S","[?]", "io section manipulation information",
	"t","[?]", "types, noreturn, signatures, C parser and more",
	"T","[?] [-] [num|msg]", "Text log utility",
	"u","[?]", "uname/undo seek/write",
	"V","", "visual mode (V! = panels, VV = fcngraph, VVV = callgraph)",
	"w","[?] [str]", "multiple write operations",
	"x","[?] [len]", "alias for 'px' (print hexadecimal)",
	"y","[?] [len] [[[@]addr", "Yank/paste bytes from/to memory",
	"z", "[?]", "zignatures management",
	"?[??]","[expr]", "Help or evaluate math expression",
	"?$?", "", "show available '$' variables and aliases",
	"?@?", "", "misc help for '@' (seek), '~' (grep) (see ~?""?)",
	"?>?", "", "output redirection",
	NULL
};

static const char *help_msg_question[] = {
	"Usage: ?[?[?]] expression", "", "",
	"?", " eip-0x804800", "show hex and dec result for this math expr",
	"?:", "", "list core cmd plugins",
	"[cmd]?*", "", "recursive help for the given cmd",
	"?!", " [cmd]", "run cmd if $? == 0",
	"?$", "", "show value all the variables ($)",
	"?+", " [cmd]", "run cmd if $? > 0",
	"?-", " [cmd]", "run cmd if $? < 0",
	"?=", " eip-0x804800", "hex and dec result for this math expr",
	"??", " [cmd]", "run cmd if $? != 0",
	"??", "", "show value of operation",
	"?_", " hudfile", "load hud menu with given file",
	"?a", "", "show ascii table",
	"?b", " [num]", "show binary value of number",
	"?b64[-]", " [str]", "encode/decode in base64",
	"?btw", " num|expr num|expr num|expr", "returns boolean value of a <= b <= c",
	"?B", " [elem]", "show range boundaries like 'e?search.in",
	"?e[nbgc]", " string", "echo string (nonl, gotoxy, column, bars)",
	"?f", " [num] [str]", "map each bit of the number as flag string index",
	"?F", "", "flush cons output",
	"?h", " [str]", "calculate hash for given string",
	"?i", "[ynmkp] arg", "prompt for number or Yes,No,Msg,Key,Path and store in $$?",
	"?ik", "", "press any key input dialog",
	"?im", " message", "show message centered in screen",
	"?in", " prompt", "noyes input prompt",
	"?iy", " prompt", "yesno input prompt",
	"?l", "[q] str", "returns the length of string ('q' for quiet, just set $?)",
	"?o", " num", "get octal value",
	"?O", " [id]", "List mnemonics for current asm.arch / asm.bits",
	"?p", " vaddr", "get physical address for given virtual address",
	"?P", " paddr", "get virtual address for given physical one",
	"?q", " eip-0x804800", "compute expression like ? or ?v but in quiet mode",
	"?r", " [from] [to]", "generate random number between from-to",
	"?s", " from to step", "sequence of numbers from to by steps",
	"?S", " addr", "return section name of given address",
	"?t", " cmd", "returns the time to run a command",
	"?T", "", "show loading times",
	"?u", " num", "get value in human units (KB, MB, GB, TB)",
	"?v", " eip-0x804800", "show hex value of math expr",
	"?vi", " rsp-rbp", "show decimal value of math expr",
	"?V", "", "show library version of r_core",
	"?w", " addr", "show what's in this address (like pxr/pxq does)",
	"?x", " str", "returns the hexpair of number or string",
	"?x", "+num", "like ?v, but in hexpairs honoring cfg.bigendian",
	"?x", "-hexst", "convert hexpair into raw string with newline",
	"?X", " num|expr", "returns the hexadecimal value numeric expr",
	"?y", " [str]", "show contents of yank buffer, or set with string",
	NULL
};

static const char *help_msg_question_v[] = {
	"Usage: ?v [$.]","","",
	"$$", "", "here (current virtual seek)",
	"$$$", "", "current non-temporary virtual seek",
	"$?", "", "last comparison value",
	"$alias", "=value", "alias commands (simple macros)",
	"$b", "", "block size",
	"$B", "", "base address (aligned lowest map address)",
	"$f", "", "jump fail address (e.g. jz 0x10 => next instruction)",
	"$fl", "", "flag length (size) at current address (fla; pD $l @ entry0)",
	"$F", "", "current function size",
	"$FB", "", "begin of function",
	"$Fb", "", "address of the current basic block",
	"$Fs", "", "size of the current basic block",
	"$FE", "", "end of function",
	"$FS", "", "function size",
	"$Fj", "", "function jump destination",
	"$Ff", "", "function false destination",
	"$FI", "", "function instructions",
	"$c,$r", "", "get width and height of terminal",
	"$Cn", "", "get nth call of function",
	"$Dn", "", "get nth data reference in function",
	"$D", "", "current debug map base address ?v $D @ rsp",
	"$DD", "", "current debug map size",
	"$e", "", "1 if end of block, else 0",
	"$j", "", "jump address (e.g. jmp 0x10, jz 0x10 => 0x10)",
	"$Ja", "", "get nth jump of function",
	"$Xn", "", "get nth xref of function",
	"$l", "", "opcode length",
	"$m", "", "opcode memory reference (e.g. mov eax,[0x10] => 0x10)",
	"$M", "", "map address (lowest map address)",
	"$o", "", "here (current disk io offset)",
	"$p", "", "getpid()",
	"$P", "", "pid of children (only in debug)",
	"$s", "", "file size",
	"$S", "", "section offset",
	"$SS", "", "section size",
	"$v", "", "opcode immediate value (e.g. lui a0,0x8010 => 0x8010)",
	"$w", "", "get word size, 4 if asm.bits=32, 8 if 64, ...",
	"${ev}", "", "get value of eval config variable",
	"$r{reg}", "", "get value of named register",
	"$k{kv}", "", "get value of an sdb query value",
	"$s{flag}", "", "get size of flag",
	"RNum", "", "$variables usable in math expressions",
	NULL
};

static const char *help_msg_question_V[] = {
	"Usage: ?V[jq]","","",
	"?V", "", "show version information",
	"?Vc", "", "show numeric version",
	"?Vj", "", "same as above but in JSON",
	"?Vq", "", "quiet mode, just show the version number",
	NULL
};

static const char *help_msg_greater_sign[] = {
	"Usage:", "[cmd]>[file]", "redirects console from 'cmd' output to 'file'",
	"[cmd] > [file]", "", "redirect STDOUT of 'cmd' to 'file'",
	"[cmd] H> [file]", "", "redirect html output of 'cmd' to 'file'",
	"[cmd] 2> [file]", "", "redirect STDERR of 'cmd' to 'file'",
	"[cmd] 2> /dev/null", "", "omit the STDERR output of 'cmd'",
	NULL
};

static void cmd_help_init(RCore *core) {
	DEFINE_CMD_DESCRIPTOR_SPECIAL (core, ?, question);
	DEFINE_CMD_DESCRIPTOR_SPECIAL (core, ?v, question_v);
	DEFINE_CMD_DESCRIPTOR_SPECIAL (core, ?V, question_V);
}

static const char* findBreakChar(const char *s) {
	while (*s) {
		if (!r_name_validate_char (*s)) {
			break;
		}
		s++;
	}
	return s;
}

static char *filterFlags(RCore *core, const char *msg) {
	const char *dollar, *end;
	char *word, *buf = NULL;
	for (;;) {
		dollar = strchr (msg, '$');
		if (!dollar) {
			break;
		}
		buf = r_str_appendlen (buf, msg, dollar-msg);
		if (dollar[1]=='{') {
			// find }
			end = strchr (dollar+2, '}');
			if (end) {
				word = r_str_newlen (dollar+2, end-dollar-2);
				end++;
			} else {
				msg = dollar+1;
				buf = r_str_append (buf, "$");
				continue;
			}
		} else {
			end = findBreakChar (dollar+1);
			if (!end) {
				end = dollar + strlen (dollar);
			}
			word = r_str_newlen (dollar+1, end-dollar-1);
		}
		if (end && word) {
			ut64 val = r_num_math (core->num, word);
			char num[32];
			snprintf (num, sizeof (num), "0x%"PFMT64x, val);
			buf = r_str_append (buf, num);
			msg = end;
		} else {
			break;
		}
		free (word);
	}
	buf = r_str_append (buf, msg);
	return buf;
}

static const char *getClippy() {
	const int choose = r_num_rand (3);
	switch (choose) {
	case 0: return
" .--.     .-%s-.\n"
" | _|     | %s |\n"
" | O O   <  %s |\n"
" |  |  |  | %s |\n"
" || | /   `-%s-'\n"
" |`-'|\n"
" `---'\n";
	case 1: return
" .--.     .-%s-.\n"
" | __\\    | %s |\n"
" | > <   <  %s |\n"
" |  \\|    | %s |\n"
" |/_//    `-%s-'\n"
" |  / \n"
" `-'\n";
	case 2: return
" .--.     .-%s-.\n"
" | _|_    | %s |\n"
" | O O   <  %s |\n"
" |  ||    | %s |\n"
" | _:|    `-%s-'\n"
" |   |\n"
" `---'\n";
	}
	return "";
}

R_API void r_core_clippy(const char *msg) {
	int msglen = strlen (msg);
	char *l = strdup (r_str_pad ('-', msglen));
	char *s = strdup (r_str_pad (' ', msglen));
	r_cons_printf (getClippy(), l, s, msg, s, l);
	free (l);
	free (s);
}

static int cmd_help(void *data, const char *input) {
	RCore *core = (RCore *)data;
	RIOMap *map;
	const char *k;
	RListIter *iter;
	char *p, out[128] = R_EMPTY;
	ut64 n;
	int i;
	RList *tmp;

	switch (input[0]) {
	case '0': // "?0"
		core->curtab = 0;
		break;
	case '1': // "?1"
		if (core->curtab < 0) {
			core->curtab = 0;
		}
		core->curtab ++;
		break;
	case 'r': // "?r"
		{ // TODO : Add support for 64bit random numbers
		ut64 b = 0;
		ut32 r = UT32_MAX;
		if (input[1]) {
			strncpy (out, input+(input[1]==' '? 2: 1), sizeof (out)-1);
			p = strchr (out+1, ' ');
			if (p) {
				*p = 0;
				b = (ut32)r_num_math (core->num, out);
				r = (ut32)r_num_math (core->num, p+1)-b;
			} else {
				r = (ut32)r_num_math (core->num, out);
			}
		} else {
			r = 0LL;
		}
		if (!r) {
			r = UT32_MAX >> 1;
		}
		core->num->value = (ut64) (b + r_num_rand (r));
		r_cons_printf ("0x%"PFMT64x"\n", core->num->value);
		}
		break;
	case 'a': // "?a"
		r_cons_printf ("%s", ret_ascii_table());
		break;
	case 'b': // "?b"
		if (input[1] == '6' && input[2] == '4') {
			//b64 decoding takes at most strlen(str) * 4
			const int buflen = (strlen (input+3) * 4) + 1;
			char* buf = calloc (buflen, sizeof(char));
			if (!buf) {
				return false;
			}
			if (input[3] == '-') {
				r_base64_decode ((ut8*)buf, input + 5, strlen (input + 5));
			} else {
				r_base64_encode (buf, (const ut8*)input + 4, strlen (input + 4));
			}
			r_cons_println (buf);
			free (buf);
		} else if (input[1] == 't' && input[2] == 'w') { // "?btw"
			if (r_num_between (core->num, input + 3) == -1) {
				eprintf ("Usage: ?btw num|(expr) num|(expr) num|(expr)\n");
			}
		} else {
			n = r_num_get (core->num, input+1);
			r_num_to_bits (out, n);
			r_cons_printf ("%sb\n", out);
		}
		break;
	case 'B': // "?B"
		k = r_str_trim_ro (input + 1);
		tmp = r_core_get_boundaries_prot (core, -1, k, "search");
		r_list_foreach (tmp, iter, map) {
			r_cons_printf ("0x%"PFMT64x" 0x%"PFMT64x"\n", map->itv.addr, r_itv_end (map->itv));
		}
		r_list_free (tmp);
		break;
	case 'h': // "?h"
		if (input[1] == ' ') {
			r_cons_printf ("0x%08x\n", (ut32)r_str_hash (input + 2));
		} else {
			eprintf ("Usage: ?h [string-to-hash]\n");
		}
		break;
	case 'y': // "?y"
		for (input++; input[0]==' '; input++);
		if (*input) {
			r_core_yank_set_str (core, R_CORE_FOREIGN_ADDR, input, strlen (input)+1);
		} else {
			r_core_yank_cat (core, 0);
		}
		break;
	case 'F': // "?F"
		r_cons_flush ();
		break;
	case 'f': // "?f"
		if (input[1] == ' ') {
			char *q, *p = strdup (input + 2);
			if (!p) {
				eprintf ("Cannot strdup\n");
				return 0;
			}
			q = strchr (p, ' ');
			if (q) {
				*q = 0;
				n = r_num_get (core->num, p);
				r_str_bits (out, (const ut8*)&n, sizeof (n) * 8, q + 1);
				r_cons_println (out);
			} else {
				eprintf ("Usage: \"?b value bitstring\"\n");
			}
			free (p);
		} else {
			eprintf ("Whitespace expected after '?f'\n");
		}
		break;
	case 'o': // "?o"
		n = r_num_math (core->num, input+1);
		r_cons_printf ("0%"PFMT64o"\n", n);
		break;
	case 'O': // "?O"
		if (input[1] == '?') {
			r_cons_printf ("Usage: ?O[jd] [arg] .. list all mnemonics for asm.arch (d = describe, j=json)\n");
		} else if (input[1] == 'd') {
			const int id = (input[2]==' ')
				?(int)r_num_math (core->num, input + 2): -1;
			char *ops = r_asm_mnemonics (core->assembler, id, false);
			if (ops) {
				char *ptr = ops;
				char *nl = strchr (ptr, '\n');
				while (nl) {
					*nl = 0;
					char *desc = r_asm_describe (core->assembler, ptr);
					if (desc) {
						const char *pad = r_str_pad (' ', 16 - strlen (ptr));
						r_cons_printf ("%s%s%s\n", ptr, pad, desc);
						free (desc);
					} else {
						r_cons_printf ("%s\n", ptr);
					}
					ptr = nl + 1;
					nl = strchr (ptr, '\n');
				}
				free (ops);
			}
		} else if (input[1] && !IS_DIGIT (input[2])) {
			r_cons_printf ("%d\n", r_asm_mnemonics_byname (core->assembler, input + 2));
		} else {
			bool json = false;
			if (input[1] == 'j') {
				json = true;
			}
			const int id = (input[1] != '\0' && input[2] == ' ')
				?(int)r_num_math (core->num, input + 2): -1;
			char *ops = r_asm_mnemonics (core->assembler, id, json);
			if (ops) {
				r_cons_print (ops);
				free (ops);
			}
		}
		break;
	case 'T': // "?T"
		r_cons_printf("plug.init = %"PFMT64d"\n"
			"plug.load = %"PFMT64d"\n"
			"file.load = %"PFMT64d"\n",
			core->times->loadlibs_init_time,
			core->times->loadlibs_time,
			core->times->file_open_time);
		break;
	case 'u': // "?u"
		{
			char unit[32];
			n = r_num_math (core->num, input+1);
			r_num_units (unit, n);
			r_cons_println (unit);
		}
		break;
	case ' ': // "? "
		{
			char *asnum, unit[32];
			ut32 s, a;
			double d;
			float f;
			char * const inputs = strdup (input + 1);
			RList *list = r_num_str_split_list (inputs);
			const int list_len = r_list_length (list);
			for (i = 0; i < list_len; i++) {
				const char *str = r_list_pop_head (list);
				if (!*str) {
					continue;
				}
				n = r_num_math (core->num, str);
				if (core->num->dbz) {
					eprintf ("RNum ERROR: Division by Zero\n");
				}
				asnum  = r_num_as_string (NULL, n, false);
				/* decimal, hexa, octal */
				s = n >> 16 << 12;
				a = n & 0x0fff;
				r_num_units (unit, n);
				r_cons_printf ("hex     0x%"PFMT64x"\n", n);
				r_cons_printf ("octal   0%"PFMT64o"\n", n);
				r_cons_printf ("unit    %s\n", unit);
				r_cons_printf ("segment %04x:%04x\n", s, a);
				if (n >> 32) {
					r_cons_printf ("int64   %"PFMT64d"\n", (st64)n);
				} else {
					r_cons_printf ("int32   %d\n", (st32)n);
				}
				if (asnum) {
					r_cons_printf ("string  \"%s\"\n", asnum);
					free (asnum);
				}
				/* binary and floating point */
				r_str_bits64 (out, n);
				f = d = core->num->fvalue;
				memcpy (&f, &n, sizeof (f));
				memcpy (&d, &n, sizeof (d));
				/* adjust sign for nan floats, different libcs are confused */
				if (isnan (f) && signbit (f)) {
					f = -f;
				}
				if (isnan (d) && signbit (d)) {
					d = -d;
				}
				r_cons_printf ("binary  0b%s\n", out);
				r_cons_printf ("fvalue: %.1lf\n", core->num->fvalue);
				r_cons_printf ("float:  %ff\n", f);
				r_cons_printf ("double: %lf\n", d);

				/* ternary */
				r_num_to_trits (out, n);
				r_cons_printf ("trits   0t%s\n", out);
			}
			free (inputs);
			r_list_free (list);
		}
		break;
	case 'q': // "?q"
		if (core->num->dbz) {
			eprintf ("RNum ERROR: Division by Zero\n");
		}
		if (input[1] == '?') {
			r_cons_printf ("|Usage: ?q [num]  # Update $? without printing anything\n"
				"|?q 123; ?? x    # hexdump if 123 != 0");
		} else {
			const char *space = strchr (input, ' ');
			if (space) {
				n = r_num_math (core->num, space + 1);
			} else {
				n = r_num_math (core->num, "$?");
			}
			core->num->value = n; // redundant
		}
		break;
	case 'v': // "?v"
		{
			const char *space = strchr (input, ' ');
			if (space) {
				n = r_num_math (core->num, space + 1);
			} else {
				n = r_num_math (core->num, "$?");
			}
		}
		if (core->num->dbz) {
			eprintf ("RNum ERROR: Division by Zero\n");
		}
		switch (input[1]) {
		case '?':
			r_cons_printf ("|Usage: ?v[id][ num]  # Show value\n"
				"|?vi1 200    -> 1 byte size value (char)\n"
				"|?vi2 0xffff -> 2 byte size value (short)\n"
				"|?vi4 0xffff -> 4 byte size value (int)\n"
				"|?vi8 0xffff -> 8 byte size value (st64)\n"
				"| No argument shows $? value\n"
				"|?vi will show in decimal instead of hex\n");
			break;
		case '\0':
			r_cons_printf ("%d\n", (st32)n);
			break;
		case 'i': // "?vi"
			switch (input[2]) {
			case '1': // byte
				r_cons_printf ("%d\n", (st8)(n & UT8_MAX));
				break;
			case '2': // word
				r_cons_printf ("%d\n", (st16)(n & UT16_MAX));
				break;
			case '4': // dword
				r_cons_printf ("%d\n", (st32)(n & UT32_MAX));
				break;
			case '8': // qword
				r_cons_printf ("%"PFMT64d"\n", (st64)(n & UT64_MAX));
				break;
			default:
				r_cons_printf ("%"PFMT64d"\n", n);
				break;
			}
			break;
		case 'd':
			r_cons_printf ("%"PFMT64d"\n", n);
			break;
		default:
			r_cons_printf ("0x%"PFMT64x"\n", n);
		}
		core->num->value = n; // redundant
		break;
	case '=': // "?=" set num->value
		if (input[1]) {
			r_num_math (core->num, input+1);
		} else {
			r_cons_printf ("0x%"PFMT64x"\n", core->num->value);
		}
		break;
	case '+': // "?+"
		if (input[1]) {
			st64 n = (st64)core->num->value;
			if (n > 0) {
				r_core_cmd (core, input + 1, 0);
			}
		} else {
			r_cons_printf ("0x%"PFMT64x"\n", core->num->value);
		}
		break;
	case '-': // "?-"
		if (input[1]) {
			st64 n = (st64)core->num->value;
			if (n < 0) {
				r_core_cmd (core, input + 1, 0);
			}
		} else {
			r_cons_printf ("0x%"PFMT64x"\n", core->num->value);
		}
		break;
	case '!': // "?!"
		if (input[1]) {
			if (!core->num->value) {
				if (input[1] == '?') {
					r_core_sysenv_help (core);
					return 0;
				} else {
					return core->num->value = r_core_cmd (core, input+1, 0);
				}
			}
		} else {
			r_cons_printf ("0x%"PFMT64x"\n", core->num->value);
		}
		break;
	case '@': // "?@"
		if (input[1] == '@') {
			if (input[2] == '@') {
				r_core_cmd_help (core, help_msg_at_at_at);
			} else {
				r_core_cmd_help (core, help_msg_at_at);
			}
		} else {
			r_core_cmd_help (core, help_msg_at);
		}
		break;
	case '&': // "?&"
		helpCmdTasks (core);
		break;
	case '$': // "?$"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_question_v);
		} else {
			int i = 0;
			const char *vars[] = {
				"$$", "$$$", "$?", "$b", "$B", "$F", "$Fj", "$Ff", "$FB", "$Fb", "$Fs", "$FE", "$FS",
				"$FI", "$c", "$r", "$D", "$DD", "$e", "$f", "$j", "$Ja", "$l", "$m", "$M", "$o",
				"$p", "$P", "$s", "$S", "$SS", "$v", "$w", NULL
			};
			while (vars[i]) {
				const char *pad = r_str_pad (' ', 6 - strlen (vars[i]));
				eprintf ("%s %s 0x%08"PFMT64x"\n", vars[i], pad, r_num_math (core->num, vars[i]));
				i++;
			}
		}
		return true;
	case 'V': // "?V"
		switch (input[1]) {
		case '?': // "?V?"
			r_core_cmd_help (core, help_msg_question_V);
			break;
		case 0: // "?V"
#if R2_VERSION_COMMIT == 0
			r_cons_printf ("%s release\n", R2_VERSION);
#else
			if (!strcmp (R2_VERSION, R2_GITTAP)) {
				r_cons_printf ("%s %d\n", R2_VERSION, R2_VERSION_COMMIT);
			} else {
				r_cons_printf ("%s aka %s commit %d\n", R2_VERSION, R2_GITTAP, R2_VERSION_COMMIT);
			}
#endif
			break;
		case 'c': // "?Vc"
			r_cons_printf ("%d\n", vernum (R2_VERSION));
			break;
		case 'j': // "?Vj"
			r_cons_printf ("{\"archos\":\"%s-%s\"", R_SYS_OS, R_SYS_ARCH);
			r_cons_printf (",\"arch\":\"%s\"", R_SYS_ARCH);
			r_cons_printf (",\"os\":\"%s\"", R_SYS_OS);
			r_cons_printf (",\"commit\":%d", R2_VERSION_COMMIT);
			r_cons_printf (",\"tap\":\"%s\"", R2_GITTAP);
			r_cons_printf (",\"nversion\":%d", vernum (R2_VERSION));
			r_cons_printf (",\"version\":\"%s\"}\n", R2_VERSION);
			break;
		case 'q': // "?Vq"
			r_cons_println (R2_VERSION);
			break;
		}
		break;
	case 'l': // "?l"
		if (input[1] == 'q') {
			for (input+=2; input[0] == ' '; input++);
			core->num->value = strlen (input);
		} else {
			for (input++; input[0] == ' '; input++);
			core->num->value = strlen (input);
			r_cons_printf ("%d\n", core->num->value);
		}
		break;
	case 'X': // "?X"
		for (input++; input[0] == ' '; input++);
		n = r_num_math (core->num, input);
		r_cons_printf ("%"PFMT64x"\n", n);
		break;
	case 'x': // "?x"
		for (input++; input[0] == ' '; input++);
		if (*input == '-') {
			ut8 *out = malloc (strlen (input)+1);
			int len = r_hex_str2bin (input+1, out);
			out[len] = 0;
			r_cons_println ((const char*)out);
			free (out);
		} else if (*input == '+') {
			ut64 n = r_num_math (core->num, input);
			int bits = r_num_to_bits (NULL, n) / 8;
			for (i = 0; i < bits; i++) {
				r_cons_printf ("%02x", (ut8)((n >> (i * 8)) &0xff));
			}
			r_cons_newline ();
		} else {
			if (*input == ' ') {
				input++;
			}
			for (i = 0; input[i]; i++) {
				r_cons_printf ("%02x", input[i]);
			}
			r_cons_newline ();
		}
		break;
	case 'E': // "?E" clippy echo
		r_core_clippy (r_str_trim_ro (input + 1));
		break;
	case 'e': // "?e" echo
		switch (input[1]) {
		case 'b': { // "?eb"
			char *arg = strdup (r_str_trim_ro (input + 2));
			int n = r_str_split (arg, ' ');
			ut64 *portions = calloc (n, sizeof (ut64));
			for (i = 0; i < n; i++) {
				portions[i] = r_num_math (core->num, r_str_word_get0 (arg, i));
			}
			r_print_portionbar (core->print, portions, n);
			free (arg);
			break;
		}
		case 's': { // "?es"
			char *msg = strdup (input + 2);
			msg = r_str_trim (msg);
			char *p = strchr (msg, '&');
			if (p) *p = 0;
			r_sys_tts (msg, p != NULL);
			free (msg);
			break;
		}
		case 'c': // "?ec" column
			r_cons_column (r_num_math (core->num, input + 2));
			break;
		case 'g': { // "?eg" gotoxy
			int x = atoi (input + 2);
			char *arg = strchr (input + 2, ' ');
			int y = arg? atoi (arg + 1): 0;
			r_cons_gotoxy (x, y);
			}
			break;
		case 'n': { // "?en" echo -n
			const char *msg = r_str_trim_ro (input + 2);
			// TODO: replace all ${flagname} by its value in hexa
			char *newmsg = filterFlags (core, msg);
			r_str_unescape (newmsg);
			r_cons_print (newmsg);
			free (newmsg);
			break;
		}
		case 'p':
			  {
			char *word, *str = strdup (input + 2);
				  RList *list = r_str_split_list (str, " ");
				  ut64 *nums = calloc (sizeof (ut64), r_list_length (list));
				  int i = 0;
				  r_list_foreach (list, iter, word) {
					nums[i] = r_num_math (core->num, word);;
					i++;
				  }
				  int size = r_config_get_i (core->config, "hex.cols");
				  r_print_pie (core->print, nums, r_list_length (list), size);
				  r_list_free (list);
			  }
			break;
		case ' ': {
			const char *msg = r_str_trim_ro (input+1);
			// TODO: replace all ${flagname} by its value in hexa
			char *newmsg = filterFlags (core, msg);
			r_str_unescape (newmsg);
			r_cons_println (newmsg);
			free (newmsg);
			}
			break;
		case 0:
			r_cons_newline ();
			break;
		default:
			eprintf ("Usage: ?e[...]\n");
			eprintf (" e msg       echo message\n");
			eprintf (" ep N...     echo pie chart\n");
			eprintf (" eb N...     echo portions bar\n");
			eprintf (" en msg      echo without newline\n");
			eprintf (" eg x y      gotoxy\n");
			eprintf (" es msg      use text-to-speech technology\n");
			break;
		}
		break;
	case 's': { // "?s" sequence from to step
		ut64 from, to, step;
		char *p, *p2;
		for (input++; *input==' '; input++);
		p = strchr (input, ' ');
		if (p) {
			*p = '\0';
			from = r_num_math (core->num, input);
			p2 = strchr (p+1, ' ');
			if (p2) {
				*p2 = '\0';
				step = r_num_math (core->num, p2 + 1);
			} else {
				step = 1;
			}
			to = r_num_math (core->num, p + 1);
			for (;from <= to; from += step)
				r_cons_printf ("%"PFMT64d" ", from);
			r_cons_newline ();
		}
		break;
	}
	case 'P': // "?P"
		if (core->io->va) {
			ut64 o, n = (input[0] && input[1])?
				r_num_math (core->num, input+2): core->offset;
			RIOMap *map = r_io_map_get_paddr (core->io, n);
			if (map) {
				o = n + map->itv.addr - map->delta;
				r_cons_printf ("0x%08"PFMT64x"\n", o);
			} else {
				r_cons_printf ("no map at 0x%08"PFMT64x"\n", n);
			}
		} else {
			r_cons_printf ("0x%08"PFMT64x"\n", core->offset);
		}
		break;
	case 'p': // "?p"
		if (core->io->va) {
			// physical address
			ut64 o, n = (input[0] && input[1])?
				r_num_math (core->num, input + 2): core->offset;
			RIOMap *map = r_io_map_get (core->io, n);
			if (map) {
				o = n - map->itv.addr + map->delta;
				r_cons_printf ("0x%08"PFMT64x"\n", o);
			} else {
				r_cons_printf ("no map at 0x%08"PFMT64x"\n", n);
			}
		} else {
			r_cons_printf ("0x%08"PFMT64x"\n", core->offset);
		}
		break;
	case 'S': { // "?S" section name
		RIOSection *s;
		ut64 n = input[1] ? r_num_math (core->num, input + 2) : core->offset;
		SdbList *sections = core->io->va ? r_io_sections_vget (core->io, n) : r_io_sections_get (core->io, n);
		SdbListIter *iter;
		if (sections) {
			ls_foreach (sections, iter, s) {
				r_cons_printf ("%s\n", s->name);
			}
			ls_free (sections);
		}
		break;
	}
	case '_': // "?_" hud input
		r_core_yank_hud_file (core, input+1);
		break;
	case 'i': // "?i" input num
		r_cons_set_raw(0);
		if (!r_config_get_i (core->config, "scr.interactive")) {
			eprintf ("Not running in interactive mode\n");
		} else {
			switch (input[1]) {
			case 'f': // "?if"
				core->num->value = !r_num_conditional (core->num, input + 2);
				eprintf ("%s\n", r_str_bool (!core->num->value));
				break;
			case 'm': // "?im"
				r_cons_message (input+2);
				break;
			case 'p': // "?ip"
				core->num->value = r_core_yank_hud_path (core, input + 2, 0) == true;
				break;
			case 'k': // "?ik"
				 r_cons_any_key (NULL);
				 break;
			case 'y': // "?iy"
				 for (input += 2; *input==' '; input++);
				 core->num->value = r_cons_yesno (1, "%s? (Y/n)", input);
				 break;
			case 'n': // "?in"
				 for (input += 2; *input==' '; input++);
				 core->num->value = r_cons_yesno (0, "%s? (y/N)", input);
				 break;
			default: {
				char foo[1024];
				r_cons_flush ();
				for (input++; *input == ' '; input++);
				// TODO: r_cons_input()
				snprintf (foo, sizeof (foo) - 1, "%s: ", input);
				r_line_set_prompt (foo);
				r_cons_fgets (foo, sizeof (foo)-1, 0, NULL);
				foo[sizeof (foo) - 1] = 0;
				r_core_yank_set_str (core, R_CORE_FOREIGN_ADDR, foo, strlen (foo) + 1);
				core->num->value = r_num_math (core->num, foo);
				}
				break;
			}
		}
		r_cons_set_raw (0);
		break;
	case 'w': { // "?w"
		ut64 addr = r_num_math (core->num, input + 1);
		const char *rstr = core->print->hasrefs (core->print->user, addr, true);
		r_cons_println (rstr);
		break;
	}
	case 't': { // "?t"
		struct r_prof_t prof;
		r_prof_start (&prof);
		r_core_cmd (core, input + 1, 0);
		r_prof_end (&prof);
		core->num->value = (ut64)(int)prof.result;
		eprintf ("%lf\n", prof.result);
		break;
	}
	case '?': // "??"
		if (input[1] == '?') {
			if (input[2] == '?') { // "???"
				r_core_clippy ("What are you doing?");
				return 0;
			}
			if (input[2]) {
				if (core->num->value) {
					r_core_cmd (core, input + 1, 0);
				}
				break;
			}
			r_core_cmd_help (core, help_msg_question);
			return 0;
		} else if (input[1]) {
			if (core->num->value) {
				core->num->value = r_core_cmd (core, input+1, 0);
			}
		} else {
			if (core->num->dbz) {
				eprintf ("RNum ERROR: Division by Zero\n");
			}
			r_cons_printf ("%"PFMT64d"\n", core->num->value);
		}
		break;
	case '\0': // "?"
	default:
		// TODO #7967 help refactor
		r_cons_printf ("Usage: [.][times][cmd][~grep][@[@iter]addr!size][|>pipe] ; ...\n"
				"Append '?' to any char command to get detailed help\n"
				"Prefix with number to repeat command N times (f.ex: 3x)\n");
		r_core_cmd_help (core, help_msg_root);
		break;
	}
	return 0;
}
