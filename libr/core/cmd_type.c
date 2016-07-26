/* radare - LGPL - Copyright 2009-2016 - pancake, oddcoder, Anton Kochkov, Jody Frankowski */
#include <string.h>

#include "r_anal.h"
#include "r_cons.h"
#include "r_core.h"
#include "sdb/sdb.h"

static void save_parsed_type(RCore *core, const char *parsed) {
	if (!core || !core->anal || !parsed) {
		return;
	}
	// First, if this exists, let's remove it.
	char *type = strdup (parsed);
	if (type) {
		char *name = strtok (type, "=");
		if (!name || strchr (name, '\n') || strchr (name, ';')) {
			/* do nothing */
		} else {
			r_core_cmdf (core, "\"t- %s\"", name);
			// Now add the type to sdb.
			sdb_query_lines (core->anal->sdb_types, parsed);
		}
		free (type);
	}
}

//TODO
//look at the next couple of functions
//can be optimized into one right ... you see it you do it :P
static int sdbforcb (void *p, const char *k, const char *v) {
	if (!strncmp (v, "type", strlen ("type") + 1))
		r_cons_println (k);
	return 1;
}
static int stdprintifstruct (void *p, const char *k, const char *v) {
	if (!strncmp (v, "struct", strlen ("struct") + 1))
		r_cons_println (k);
	return 1;
}
static int stdprintiffunc (void *p, const char *k, const char *v) {
	if (!strncmp (v, "func", strlen ("func") + 1))
		r_cons_println (k);
	return 1;
}
static int stdprintifunion (void *p, const char *k, const char *v) {
	if (!strncmp (v, "union", strlen ("union") + 1))
		r_cons_println (k);
	return 1;
}
static int sdbdelete (void *p, const char *k, const char *v) {
	RCore *core = (RCore *)p;
	r_anal_type_del (core->anal, k);
	return 1;
}
static int sdbdeletelink (void *p, const char *k, const char *v) {
	RCore *core = (RCore *)p;
	if (!strncmp (k, "link.", strlen ("link.")))
		r_anal_type_del (core->anal, k);
	return 1;
}
static int linklist (void *p, const char *k, const char *v) {
	if (!strncmp (k, "link.", strlen ("link.")))
		r_cons_printf ("tl %s = 0x%s\n", v, k + strlen ("link."));
	return 1;
}
static int linklist_readable (void *p, const char *k, const char *v) {
	RCore *core = (RCore *)p;
	if (!strncmp (k, "link.", strlen ("link."))) {
		char *fmt = r_anal_type_format (core->anal, v);
		if (!fmt) {
			eprintf("Cant fint type %s", v);
			return 1;
		}
		r_cons_printf ("(%s)\n", v);
		r_core_cmdf (core, "pf %s @ 0x%s\n", fmt, k + strlen ("link."));
	}
	return 1;

}
static int typelist (void *p, const char *k, const char *v) {
	r_cons_printf ("tk %s = %s\n", k, v);
#if 0
	if (!strcmp (v, "func")) {
		const char *rv = sdb_const_get (DB,
						sdb_fmt (0, "func.%s.ret", k), 0);
		r_cons_printf ("# %s %s(", rv, k);
		for (i = 0; i < 16; i++) {
			char *av = sdb_get (DB,
					sdb_fmt (0, "func.%s.arg.%d", k, i), 0);
			if (!av) break;
			r_str_replace_char (av, ',', ' ');
			r_cons_printf ("%s%s", i? ", ": "", av);
			free (av);
		}
		r_cons_printf (");\n");
		// signature in pf for asf
		r_cons_printf ("asf %s=", k);
		// formats
		for (i = 0; i < 16; i++) {
			const char *fmt;
			char *comma, *av = sdb_get (DB,
						sdb_fmt (0, "func.%s.arg.%d", k, i), 0);
			if (!av) break;
			comma = strchr (av, ',');
			if (comma) *comma = 0;
			fmt = sdb_const_get (DB, sdb_fmt (0, "type.%s", av), 0);
			r_cons_printf ("%s", fmt);
			if (comma) *comma = ',';
			free (av);
		}
		// names
		for (i = 0; i < 16; i++) {
			char *comma, *av = sdb_get (DB,
						sdb_fmt (0, "func.%s.arg.%d", k, i), 0);
			if (!av) break;
			comma = strchr (av, ',');
			if (comma) *comma++ = 0;
			r_cons_printf (" %s", comma);
			free (av);
		}
		r_cons_newline ();
	}
#endif
	return 1;
}

static int cmd_type(void *data, const char *input) {
	RCore *core = (RCore *)data;

	switch (input[0]) {
	// t [typename] - show given type in C syntax
	case 'u': // "tu"
		switch (input[1]) {
		case '?': {
			r_core_cmd_help (core, help_msg_tu);
		} break;
		case 0:
			sdb_foreach (core->anal->sdb_types, stdprintifunion, core);
			break;
		}
		break;
	case 'k': // "tk"
		if (input[1] == ' ') {
			sdb_query (core->anal->sdb_types, input + 2);
		} else sdb_query (core->anal->sdb_types, "*");
		fflush (stdout);
		break;
	case 's': // "ts"
		switch (input[1]) {
		case '?': {
			r_core_cmd_help (core, help_msg_ts);
		} break;
		case 0:
			sdb_foreach (core->anal->sdb_types, stdprintifstruct, core);
			break;
		}
		break;
	case 'b': {
		char *p, *s = (strlen (input) > 1)? strdup (input + 2): NULL;
		const char *isenum;
		p = s? strchr (s, ' '): NULL;
		if (p) {
			*p++ = 0;
			// dupp in core.c (see getbitfield())
			isenum = sdb_const_get (core->anal->sdb_types, s, 0);
			if (isenum && !strcmp (isenum, "enum")) {
				*--p = '.';
				const char *res = sdb_const_get (core->anal->sdb_types, s, 0);
				if (res)
					r_cons_println (res);
				else eprintf ("Invalid enum member\n");
			} else {
				eprintf ("This is not an enum\n");
			}
		} else {
			eprintf ("Missing value\n");
		}
		free (s);
	} break;
	case 'e': {
		if (!input[1]) {
			char *name = NULL;
			SdbKv *kv;
			SdbListIter *iter;
			SdbList *l = sdb_foreach_list (core->anal->sdb_types);
			ls_foreach (l, iter, kv) {
				if (!strcmp (kv->value, "enum")) {
					if (!name || strcmp (kv->value, name)) {
						free (name);
						name = strdup (kv->key);
						r_cons_println (name);
					}
				}
			}
			free (name);
			ls_free (l);
			break;
		}
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_te);
			break;
		}
		char *p, *s = strdup (input + 2);
		const char *isenum;
		p = strchr (s, ' ');
		if (p) {
			*p++ = 0;
			isenum = sdb_const_get (core->anal->sdb_types, s, 0);
			if (isenum && !strcmp (isenum, "enum")) {
				const char *q = sdb_fmt (0, "%s.0x%x", s, (ut32)r_num_math (core->num, p));
				const char *res = sdb_const_get (core->anal->sdb_types, q, 0);
				if (res)
					r_cons_println (res);
			} else {
				eprintf ("This is not an enum\n");
			}
		} else {
			//eprintf ("Missing value\n");
			r_core_cmdf (core, "t~&%s,=0x", s);
		}
		free (s);
	} break;
	case ' ': {
		const char *isenum = sdb_const_get (core->anal->sdb_types, input + 1, 0);
		if (isenum && !strcmp (isenum, "enum")) {
			eprintf ("IS ENUM! \n");
		} else {
			char *fmt = r_anal_type_format (core->anal, input + 1);
			if (fmt) {
				r_str_chop (fmt);
				r_cons_printf ("pf %s\n", fmt);
				free (fmt);
			} else eprintf ("Cannot find '%s' type\n", input + 1);
		}
	} break;
	// t* - list all types in 'pf' syntax
	case '*':
		sdb_foreach (core->anal->sdb_types, typelist, core);
		break;
	case 0:
		sdb_foreach (core->anal->sdb_types, sdbforcb, core);
		break;
	case 'o':
		if (!r_sandbox_enable (0)) {
			if (input[1] == ' ') {
				const char *filename = input + 2;
				char *homefile = NULL;
				if (*filename == '~') {
					if (filename[1] && filename[2]) {
						homefile = r_str_home (filename + 2);
						filename = homefile;
					}
				}
				if (!strcmp (filename, "-")) {
					char *out, *tmp;
					tmp = r_core_editor (core, NULL, "");
					if (tmp) {
						out = r_parse_c_string (tmp);
						if (out) {
							//		r_cons_strcat (out);
							save_parsed_type (core, out);
							free (out);
						}
						free (tmp);
					}
				} else {
					char *out = r_parse_c_file (filename);
					if (out) {
						//r_cons_strcat (out);
						save_parsed_type (core, out);
						free (out);
					}
					//r_anal_type_loadfile (core->anal, filename);
				}
				free (homefile);
			}
		} else {
			eprintf ("Sandbox: system call disabled\n");
		}
		break;
	// td - parse string with cparse engine and load types from it
	case 'd':
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_td);

		} else if (input[1] == ' ') {
			char tmp[8192];
			snprintf (tmp, sizeof (tmp) - 1, "%s;", input + 2);
			//const char *string = input + 2;
			//r_anal_str_to_type (core->anal, string);
			char *out = r_parse_c_string (tmp);
			if (out) {
				//r_cons_strcat (out);
				save_parsed_type (core, out);
				free (out);
			}
		} else {
			eprintf ("Invalid use of td. See td? for help\n");
		}
		break;
	// tl - link a type to an address
	case 'l':
		switch (input[1]) {
		case '?': {
			r_core_cmd_help (core, help_msg_tl);
			} break;
		case ' ': {
			char *type = strdup (input + 2);
			char *ptr = strchr (type, '=');
			ut64 addr;

			if (ptr) {
				*ptr++ = 0;
				r_str_chop (ptr);
				if (ptr && *ptr) {
					addr = r_num_math (core->num, ptr);
				} else {
					eprintf ("address is unvalid\n");
					free (type);
					break;
				}
			} else {
				addr = core->offset;
			}
			r_str_chop (type);
			char *tmp = sdb_get (core->anal->sdb_types, type, 0);
			if (tmp && *tmp) {
				r_anal_type_link (core->anal, type, addr);
				free (tmp);
			} else {
				eprintf ("unknown type %s\n", type);
			}
			free (type);
			}
			break;
		case 's': {
			int ptr;
			char *addr = strdup (input + 2);
			SdbKv *kv;
			SdbListIter *sdb_iter;
			SdbList *sdb_list = sdb_foreach_list (core->anal->sdb_types);
			r_str_chop (addr);
			ptr = r_num_math (NULL, addr);
			//r_core_cmdf (core, "tl~0x%08"PFMT64x" = ", addr);
			ls_foreach (sdb_list, sdb_iter, kv) {
				char *linkptr;
				if (strncmp (kv->key, "link.", strlen ("link."))) {
					continue;
				}
				linkptr = sdb_fmt (-1,"0x%s", kv->key + strlen ("link."));
				if (ptr == r_num_math (NULL, linkptr)) {
					linklist_readable (core, kv->key, kv->value);
				}
			}
			free (addr);
			ls_free (sdb_list);
			}
			break;
		case '-':
			switch (input[2]) {
			case '*':
				sdb_foreach (core->anal->sdb_types, sdbdeletelink, core);
				break;
			case ' ': {
				const char *ptr = input + 3;
				ut64 addr = r_num_math (core->num, ptr);
				r_anal_type_unlink (core->anal, addr);
				}
				break;
			}
			break;
		case '*':
			sdb_foreach (core->anal->sdb_types, linklist, core);
			break;
		case '\0':
			sdb_foreach (core->anal->sdb_types, linklist_readable, core);
			break;
		}
		break;
	case 'p':
		if (input[2]) {
			ut64 addr = core->offset;
			const char *type = input + 2;
			char *ptr = strchr (type, '=');
			if (ptr) {
				char *tmp = ptr-1;
				*ptr++ = 0;
				while(isspace (*ptr)) ptr++;
				while(isspace (*tmp)) *tmp-- = 0;
				addr = r_num_math (core->num, ptr);
			}
			char *fmt = r_anal_type_format (core->anal, type);
			if (fmt) {
				r_core_cmdf (core, "pf %s @ 0x%08" PFMT64x "\n", fmt, addr);
				free (fmt);
			} else eprintf ("Cannot find '%s' type\n", input + 1);
		} else {
			eprintf ("see t?\n");
			break;
		}
		break;
	case '-':
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_tminus);
		} else if (input[1] == '*') {
			sdb_foreach (core->anal->sdb_types, sdbdelete, core);
		} else {
			const char *name = input + 1;
			while (IS_WHITESPACE (*name)) name++;
			if (*name) {
				SdbKv *kv;
				SdbListIter *iter;
				const char *type = sdb_const_get (core->anal->sdb_types, name, 0);
				if (!type)
					break;
				int tmp_len = strlen (name) + strlen (type);
				char *tmp = malloc (tmp_len + 1);
				r_anal_type_del (core->anal, name);
				if (tmp) {
					snprintf (tmp, tmp_len + 1, "%s.%s.", type, name);
					SdbList *l = sdb_foreach_list (core->anal->sdb_types);
					ls_foreach (l, iter, kv) {
						if (!strncmp (kv->key, tmp, tmp_len))
							r_anal_type_del (core->anal, kv->key);
					}
					free (tmp);
				}
			} else eprintf ("Invalid use of t- . See t-? for help.\n");
		}
		break;
	// tv - get/set type value linked to a given address
	case 'f':
		sdb_foreach (core->anal->sdb_types, stdprintiffunc, core);
		break;

	case '?':
		r_core_cmd_help (core, help_msg_t);
		break;
	}
	return true;
}
