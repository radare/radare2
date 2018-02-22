/* radare - LGPL - Copyright 2013-2017 - pancake, sghctoma */

#include <r_cons.h>

#define RCOLOR_AT(i) (RColor *) (((ut8 *) &(r_cons_singleton ()->cpal)) + keys[i].coff)
#define COLOR_AT(i) (char **) (((ut8 *) &(r_cons_singleton ()->pal)) + keys[i].off)

static struct {
	const char *name;
	int off;  // RConsPrintablePalette offset
	int coff; // RConsPalette offset
} keys[] = {
	{ "comment", r_offsetof (RConsPrintablePalette, comment), r_offsetof (RConsPalette, comment) },
	{ "usrcmt", r_offsetof (RConsPrintablePalette, usercomment), r_offsetof (RConsPalette, usercomment) },
	{ "args", r_offsetof (RConsPrintablePalette, args), r_offsetof (RConsPalette, args) },
	{ "fname", r_offsetof (RConsPrintablePalette, fname), r_offsetof (RConsPalette, fname) },
	{ "floc", r_offsetof (RConsPrintablePalette, floc), r_offsetof (RConsPalette, floc) },
	{ "fline", r_offsetof (RConsPrintablePalette, fline), r_offsetof (RConsPalette, fline) },
	{ "flag", r_offsetof (RConsPrintablePalette, flag), r_offsetof (RConsPalette, flag) },
	{ "label", r_offsetof (RConsPrintablePalette, label), r_offsetof (RConsPalette, label) },
	{ "help", r_offsetof (RConsPrintablePalette, help), r_offsetof (RConsPalette, help) },
	{ "flow", r_offsetof (RConsPrintablePalette, flow), r_offsetof (RConsPalette, flow) },
	{ "flow2", r_offsetof (RConsPrintablePalette, flow2), r_offsetof (RConsPalette, flow2) },
	{ "prompt", r_offsetof (RConsPrintablePalette, prompt), r_offsetof (RConsPalette, prompt) },
	{ "offset", r_offsetof (RConsPrintablePalette, offset), r_offsetof (RConsPalette, offset) },
	{ "input", r_offsetof (RConsPrintablePalette, input), r_offsetof (RConsPalette, input) },
	{ "invalid", r_offsetof (RConsPrintablePalette, invalid), r_offsetof (RConsPalette, invalid) },
	{ "other", r_offsetof (RConsPrintablePalette, other), r_offsetof (RConsPalette, other) },
	{ "b0x00", r_offsetof (RConsPrintablePalette, b0x00), r_offsetof (RConsPalette, b0x00) },
	{ "b0x7f", r_offsetof (RConsPrintablePalette, b0x7f), r_offsetof (RConsPalette, b0x7f) },
	{ "b0xff", r_offsetof (RConsPrintablePalette, b0xff), r_offsetof (RConsPalette, b0xff) },
	{ "math", r_offsetof (RConsPrintablePalette, math), r_offsetof (RConsPalette, math) },
	{ "bin", r_offsetof (RConsPrintablePalette, bin), r_offsetof (RConsPalette, bin) },
	{ "btext", r_offsetof (RConsPrintablePalette, btext), r_offsetof (RConsPalette, btext) },
	{ "push",  r_offsetof (RConsPrintablePalette, push), r_offsetof (RConsPalette, push) },
	{ "pop", r_offsetof (RConsPrintablePalette, pop), r_offsetof (RConsPalette, pop) },
	{ "crypto", r_offsetof (RConsPrintablePalette, crypto), r_offsetof (RConsPalette, crypto) },
	{ "jmp", r_offsetof (RConsPrintablePalette, jmp), r_offsetof (RConsPalette, jmp) },
	{ "cjmp", r_offsetof (RConsPrintablePalette, cjmp), r_offsetof (RConsPalette, cjmp) },
	{ "call", r_offsetof (RConsPrintablePalette, call), r_offsetof (RConsPalette, call) },
	{ "nop", r_offsetof (RConsPrintablePalette, nop), r_offsetof (RConsPalette, nop) },
	{ "ret", r_offsetof (RConsPrintablePalette, ret), r_offsetof (RConsPalette, ret) },
	{ "trap", r_offsetof (RConsPrintablePalette, trap), r_offsetof (RConsPalette, trap) },
	{ "swi", r_offsetof (RConsPrintablePalette, swi), r_offsetof (RConsPalette, swi) },
	{ "cmp", r_offsetof (RConsPrintablePalette, cmp), r_offsetof (RConsPalette, cmp) },
	{ "reg", r_offsetof (RConsPrintablePalette, reg), r_offsetof (RConsPalette, reg) },
	{ "creg", r_offsetof (RConsPrintablePalette, creg), r_offsetof (RConsPalette, creg) },
	{ "num", r_offsetof (RConsPrintablePalette, num), r_offsetof (RConsPalette, num) },
	{ "mov", r_offsetof (RConsPrintablePalette, mov), r_offsetof (RConsPalette, mov) },

	{ "ai.read", r_offsetof (RConsPrintablePalette, ai_read), r_offsetof (RConsPalette, ai_read) },
	{ "ai.write", r_offsetof (RConsPrintablePalette, ai_write), r_offsetof (RConsPalette, ai_write) },
	{ "ai.exec", r_offsetof (RConsPrintablePalette, ai_exec), r_offsetof (RConsPalette, ai_exec) },
	{ "ai.seq", r_offsetof (RConsPrintablePalette, ai_seq), r_offsetof (RConsPalette, ai_seq) },
	{ "ai.ascii", r_offsetof (RConsPrintablePalette, ai_ascii), r_offsetof (RConsPalette, ai_ascii) },

	{ "graph.box", r_offsetof (RConsPrintablePalette, graph_box), r_offsetof (RConsPalette, graph_box) },
	{ "graph.box2", r_offsetof (RConsPrintablePalette, graph_box2), r_offsetof (RConsPalette, graph_box2) },
	{ "graph.box3", r_offsetof (RConsPrintablePalette, graph_box3), r_offsetof (RConsPalette, graph_box3) },
	{ "graph.box4", r_offsetof (RConsPrintablePalette, graph_box4), r_offsetof (RConsPalette, graph_box4) },
	{ "graph.true", r_offsetof (RConsPrintablePalette, graph_true), r_offsetof (RConsPalette, graph_true) },
	{ "graph.false", r_offsetof (RConsPrintablePalette, graph_false), r_offsetof (RConsPalette, graph_false) },
	{ "graph.trufae", r_offsetof (RConsPrintablePalette, graph_trufae), r_offsetof (RConsPalette, graph_trufae) },
	{ "graph.current", r_offsetof (RConsPrintablePalette, graph_current), r_offsetof (RConsPalette, graph_current) },
	{ "graph.traced", r_offsetof (RConsPrintablePalette, graph_traced), r_offsetof (RConsPalette, graph_traced) },

	{ "gui.cflow", r_offsetof (RConsPrintablePalette, gui_cflow), r_offsetof (RConsPalette, gui_cflow) },
	{ "gui.dataoffset", r_offsetof (RConsPrintablePalette, gui_dataoffset), r_offsetof (RConsPalette, gui_dataoffset) },
	{ "gui.background", r_offsetof (RConsPrintablePalette, gui_background), r_offsetof (RConsPalette, gui_background) },
	{ "gui.alt_background", r_offsetof (RConsPrintablePalette, gui_alt_background), r_offsetof (RConsPalette, gui_alt_background) },
	{ "gui.border", r_offsetof (RConsPrintablePalette, gui_border), r_offsetof (RConsPalette, gui_border) },
	{ "highlight", r_offsetof (RConsPrintablePalette, highlight), r_offsetof (RConsPalette, highlight) },
	{ NULL, 0, 0 }
};

struct {
	const char *name;
	RColor rcolor;
	const char *code;
	const char *bgcode;
} colors[] = {
	{ "black",    RColor_BLACK,    Color_BLACK,    Color_BGBLACK },
	{ "red",      RColor_RED,      Color_RED,      Color_BGRED },
	{ "bred",     RColor_BRED,     Color_BRED,     Color_BGRED },
	{ "white",    RColor_WHITE,    Color_WHITE,    Color_BGWHITE },
	{ "green",    RColor_GREEN,    Color_GREEN,    Color_BGGREEN },
	{ "bgreen",   RColor_BGREEN,   Color_BGREEN,   Color_BGGREEN },
	{ "magenta",  RColor_MAGENTA,  Color_MAGENTA,  Color_BGMAGENTA },
	{ "bmagenta", RColor_BMAGENTA, Color_BMAGENTA, Color_BGMAGENTA },
	{ "yellow",   RColor_YELLOW,   Color_YELLOW,   Color_BGYELLOW },
	{ "byellow",  RColor_BYELLOW,  Color_BYELLOW,  Color_BGBYELLOW },
	{ "cyan",     RColor_CYAN,     Color_CYAN,     Color_BGCYAN },
	{ "bcyan",    RColor_BCYAN,    Color_BCYAN,    Color_BGCYAN },
	{ "blue",     RColor_BLUE,     Color_BLUE,     Color_BGBLUE },
	{ "bblue",    RColor_BBLUE,    Color_BBLUE,    Color_BGBLUE },
	{ "gray",     RColor_GRAY,     Color_GRAY,     Color_BGGRAY },
	{ "bgray",    RColor_BGRAY,    Color_BGRAY,    Color_BGGRAY },
	{ "none",     RColor_WHITE,    Color_RESET,    Color_RESET }, // TODO xarkes
	{ NULL, RColor_NULL, NULL, NULL }
};

static inline ut8 rgbnum (const char ch1, const char ch2) {
	ut8 r = 0, r2 = 0;
	r_hex_to_byte (&r, ch1);
	r_hex_to_byte (&r2, ch2);
	return r << 4 | r2;
}

R_API void r_cons_pal_init () {
	RCons *cons = r_cons_singleton ();

	memset (&cons->cpal, 0, sizeof (cons->cpal));
	memset (&cons->pal, 0, sizeof (cons->pal));

	cons->cpal.b0x00 = RColor_GREEN;
	cons->cpal.b0x7f = RColor_CYAN;
	cons->cpal.b0xff = RColor_RED;
	cons->cpal.args = RColor_YELLOW;
	cons->cpal.bin = RColor_CYAN;
	cons->cpal.btext = RColor_YELLOW;
	cons->cpal.call = RColor_BGREEN;
	cons->cpal.cjmp = RColor_GREEN;
	cons->cpal.cmp = RColor_CYAN;
	cons->cpal.comment = RColor_RED;
	cons->cpal.usercomment = RColor_WHITE;
	cons->cpal.creg = RColor_CYAN;
	cons->cpal.flag = RColor_CYAN;
	cons->cpal.fline = RColor_CYAN;
	cons->cpal.floc = RColor_CYAN;
	cons->cpal.flow = RColor_CYAN;
	cons->cpal.flow2 = RColor_BLUE;
	cons->cpal.fname = RColor_RED;
	cons->cpal.help = RColor_GREEN;
	cons->cpal.input = RColor_WHITE;
	cons->cpal.invalid = RColor_BRED;
	cons->cpal.jmp = RColor_GREEN;
	cons->cpal.label = RColor_CYAN;
	cons->cpal.math = RColor_YELLOW;
	cons->cpal.mov = RColor_WHITE;
	cons->cpal.nop = RColor_BLUE;
	cons->cpal.num = RColor_YELLOW;
	cons->cpal.offset = RColor_GREEN;
	cons->cpal.other = RColor_WHITE;
	cons->cpal.pop = RColor_BMAGENTA;
	cons->cpal.prompt = RColor_YELLOW;
	cons->cpal.push = RColor_MAGENTA;
	cons->cpal.crypto = RColor_BGBLUE;
	cons->cpal.reg = RColor_CYAN;
	cons->cpal.ret = RColor_RED;
	cons->cpal.swi = RColor_MAGENTA;
	cons->cpal.trap = RColor_BRED;

	cons->cpal.ai_read = RColor_GREEN;
	cons->cpal.ai_write = RColor_BLUE;
	cons->cpal.ai_exec = RColor_RED;
	cons->cpal.ai_seq = RColor_MAGENTA;
	cons->cpal.ai_ascii = RColor_YELLOW;

	cons->cpal.gui_cflow = RColor_YELLOW;
	cons->cpal.gui_dataoffset = RColor_YELLOW;
	cons->cpal.gui_background = RColor_BLACK;
	cons->cpal.gui_alt_background = RColor_WHITE;
	cons->cpal.gui_border = RColor_BLACK;
	cons->cpal.highlight = RColor_BGRED;

	cons->cpal.graph_box2 = RColor_BLUE;
	cons->cpal.graph_box3 = RColor_MAGENTA;
	cons->cpal.graph_box4 = RColor_GRAY;
	cons->cpal.graph_true = RColor_GREEN;
	cons->cpal.graph_false = RColor_RED;
	cons->cpal.graph_trufae = RColor_BLUE; // single jump
	cons->cpal.graph_traced = RColor_YELLOW;
	cons->cpal.graph_current = RColor_BLUE;

	cons->pal.rainbow = NULL;
	cons->pal.rainbow_sz = 0;
	r_cons_pal_free ();
	cons->pal.reset = Color_RESET; // Reset is not user accessible, so we can use a const char*
	cons->pal.graph_box = strdup (Color_RESET); // Accessible by user, strdup needed

	r_cons_pal_update_event ();
}

R_API void r_cons_pal_free () {
	int i;
	for (i = 0; keys[i].name; i++) {
		char **color = COLOR_AT(i);
		if (color && *color) R_FREE (*color);
	}
}

R_API void r_cons_pal_random () {
	int i;
	RColor *rcolor;
	for (i = 0; keys[i].name; i++) {
		rcolor = RCOLOR_AT(i);
		*rcolor = r_cons_color_random (ALPHA_NORMAL);
	}
	r_cons_pal_update_event ();
}

/* Return NULL if outcol is given */
R_API char *r_cons_pal_parse (const char *str, RColor *outcol) {
	int i;
	RColor rcolor = { ALPHA_NORMAL, 0, 0, 0 };
	char out[128];
	char *s = strdup (str);
	if (!s) {
		return NULL;
	}
	char *p = strchr (s + 1, ' ');
	out[0] = 0;
	if (p) *p++ = 0;
	if (!strcmp (str, "random")) {
		rcolor = r_cons_color_random (ALPHA_NORMAL);
		if (!outcol) {
			r_cons_rgb_str (out, rcolor.r, rcolor.g, rcolor.b, ALPHA_NORMAL);
		}
	} else if (!strncmp (s, "#", 1)) { // "#00ff00" HTML format
		if (strlen (s) == 7) {
			sscanf (s, "%02hhx%02hhx%02hhx", &rcolor.r, &rcolor.g, &rcolor.b);
			if (!outcol) {
				r_cons_rgb_str (out, rcolor.r, rcolor.g, rcolor.b, ALPHA_NORMAL);
			}
		} else {
			eprintf ("Invalid html color code\n");
		}
	} else if (!strncmp (s, "rgb:", 4)) { // "rgb:123" rgb format
		if (strlen (s) == 7) {
			rcolor.r = rgbnum (s[4], '0');
			rcolor.g = rgbnum (s[5], '0');
			rcolor.b = rgbnum (s[6], '0');
			if (!outcol) {
				r_cons_rgb_str (out, rcolor.r, rcolor.g, rcolor.b, ALPHA_NORMAL);
			}
		} else if (strlen (s) == 10) {
			rcolor.r = rgbnum (s[4], s[5]);
			rcolor.g = rgbnum (s[6], s[7]);
			rcolor.b = rgbnum (s[8], s[9]);
			if (!outcol) {
				r_cons_rgb_str (out, rcolor.r, rcolor.g, rcolor.b, ALPHA_NORMAL);
			}
		}
	} else if (p && !strncmp (p, "rgb:", 4)) { // "rgb:123" rgb format
		if (strlen (p) == 7) {
			rcolor.r = rgbnum (p[4], '0');
			rcolor.g = rgbnum (p[5], '0');
			rcolor.b = rgbnum (p[6], '0');
			if (!outcol) {
				r_cons_rgb_str (out + strlen (out), rcolor.r, rcolor.g, rcolor.b, ALPHA_BG);
			}
		} else if (strlen (p) == 10) {
			rcolor.r = rgbnum (p[4], p[5]);
			rcolor.g = rgbnum (p[6], p[7]);
			rcolor.b = rgbnum (p[8], p[9]);
			if (!outcol) {
				r_cons_rgb_str (out + strlen (out), rcolor.r, rcolor.g, rcolor.b, ALPHA_BG);
			}
		}
	}
	for (i = 0; colors[i].name; i++) {
		if (!strcmp (s, colors[i].name)) {
			rcolor = colors[i].rcolor;
			if (!outcol) {
				strncat (out, colors[i].code,
					sizeof (out) - strlen (out) - 1);
			}
		}
		if (p && !strcmp (p, colors[i].name)) {
			rcolor = colors[i].rcolor;
			if (!outcol) {
				strncat (out, colors[i].bgcode,
					sizeof (out) - strlen (out) - 1);
			}
		}
	}
	if (outcol) {
		*outcol = rcolor;
	}
	free (s);
	return (*out && !outcol) ? strdup (out) : NULL;
}

static void r_cons_pal_show_gs () {
	int i, n;
	r_cons_print ("\nGreyscale:\n");
	for (i = 0x08, n = 0;  i <= 0xee; i += 0xa) {
		char fg[32], bg[32];

		if (i < 0x76) strcpy (fg, Color_WHITE);
		else strcpy (fg, Color_BLACK);
		r_cons_rgb_str (bg, i, i, i, 1);
		r_cons_printf ("%s%s rgb:%02x%02x%02x "Color_RESET,
			fg, bg, i, i, i);
		if (n++ == 5) {
			n = 0;
			r_cons_newline ();
		}
	}
}

static void r_cons_pal_show_256 () {
	int r, g, b;
	r_cons_print ("\n\nXTerm colors:\n");
	for (r = 0x00; r <= 0xff; r += 0x28) {
		if (r == 0x28) {
			r = 0x5f;
		}
		for (b = 0x00; b <= 0xff; b += 0x28) {
			if (b == 0x28) {
				b = 0x5f;
			}
			for (g = 0x00; g <= 0xff; g += 0x28) {
				char fg[32], bg[32];
				if (g == 0x28) {
					g = 0x5f;
				}
				if ((r <= 0x5f) && (g <= 0x5f)) {
					strcpy (fg, Color_WHITE);
				} else {
					strcpy (fg, Color_BLACK);
				}
				r_cons_rgb_str (bg, r, g, b, 1);
				r_cons_printf ("%s%s rgb:%02x%02x%02x "
					Color_RESET, fg, bg, r, g, b);
				if (g == 0xff) {
					r_cons_newline ();
				}
			}
		}
	}
}

static void r_cons_pal_show_rgb () {
	const int inc = 3;
	int i, j, k, n = 0;
	r_cons_print ("\n\nRGB:\n");
	for (i = n = 0; i <= 0xf; i += inc) {
		for (k = 0; k <= 0xf; k += inc) {
			for (j = 0; j <= 0xf; j += inc) {
				char fg[32], bg[32];
				int r = i * 16;
				int g = j * 16;
				int b = k * 16;
				strcpy (fg, ((i < 6) && (j < 5))
					? Color_WHITE: Color_BLACK);
				r_cons_rgb_str (bg, r, g, b, 1);
				r_cons_printf ("%s%s rgb:%02x%02x%02x "
					Color_RESET, fg, bg, r, g, b);
				//if (n++==7) {
				if (n ++== 5) {
					n = 0;
					r_cons_newline ();
				}
			}
		}
	}
}

R_API void r_cons_pal_show () {
	int i;
	for (i = 0; colors[i].name; i++) {
		r_cons_printf ("%s%s__"Color_RESET" %s\n",
			colors[i].code,
			colors[i].bgcode,
			colors[i].name);
	}
	switch (r_cons_singleton ()->truecolor) {
	case 1: // 256 color palette
		r_cons_pal_show_gs ();
		r_cons_pal_show_256 ();
		break;
	case 2: // 16M
		r_cons_pal_show_gs ();
		r_cons_pal_show_rgb ();
		break;
	}
}

R_API void r_cons_pal_list (int rad, const char *arg) {
	RColor *rcolor = NULL; 
	char *name, **color;
	const char *hasnext;
	int i;
	if (rad == 'j') {
		r_cons_print ("{");
	}
	for (i = 0; keys[i].name; i++) {
		rcolor = RCOLOR_AT(i);
		color = COLOR_AT(i);
		switch (rad) {
		case 'j':
			hasnext = (keys[i + 1].name) ? "," : "";
			r_cons_printf ("\"%s\":[%d,%d,%d]%s",
				keys[i].name, rcolor->r, rcolor->g, rcolor->b, hasnext);
			break;
		case 'c': {
			const char *prefix = r_str_trim_ro (arg);
			if (!prefix) {
				prefix = "";
			}
			hasnext = (keys[i + 1].name) ? "\n" : "";
			//Need to replace the '.' char because this is not
			//valid CSS
			char *name = strdup (keys[i].name);
			int j, len = strlen (name);
			for (j = 0; j < len; j++) {
				if (name[j] == '.') {
					name[j] = '_';
				}
			}
			r_cons_printf (".%s%s { color: rgb(%d, %d, %d); }%s",
				prefix, name, rcolor->r, rcolor->g, rcolor->b, hasnext);
			free (name);
			}
			break;
		case 'h':
			name = strdup (keys[i].name);
			r_str_replace_char (name, '.', '_');
			r_cons_printf (".%s { color:#%02x%02x%02x }\n",
				name, rcolor->r, rcolor->g, rcolor->b);
			free (name);
			break;
		case '*':
		case 'r':
		case 1:
			r_cons_printf ("ec %s rgb:%02x%02x%02x\n",
				keys[i].name, rcolor->r, rcolor->g, rcolor->b);
			break;
		default:
			r_cons_printf (" %s##"Color_RESET"  %s\n", *color,
				keys[i].name);
		}
	}
	if (rad == 'j') {
		r_cons_print ("}\n");
	}
}

/* Modify the palette to set a color value.
 * r_cons_pal_update_event () must be called after this function
 * so the changes take effect. */
R_API int r_cons_pal_set(const char *key, const char *val) {
	int i;
	RColor *rcolor;
	for (i = 0; keys[i].name; i++) {
		if (!strcmp (key, keys[i].name)) {
			rcolor = RCOLOR_AT(i);
			r_cons_pal_parse (val, rcolor);
			return true;
		}
	}
	return false;
}

/* Get the named RColor */
R_API RColor r_cons_pal_get (const char *key) {
	int i;
	RColor *rcolor;
	for (i = 0; keys[i].name; i++) {
		if (!strcmp (key, keys[i].name)) {
			rcolor = RCOLOR_AT(i);
			return rcolor? *rcolor: RColor_NULL;
		}
	}
	return RColor_NULL;
}

/* Get the RColor at specified index */
R_API RColor r_cons_pal_get_i (int index) {
	RColor *rcolor;
	rcolor = RCOLOR_AT(index);
	return *rcolor;
}

/* Get color name at index */
R_API const char *r_cons_pal_get_name (int index) {
	int i;
	for (i = 0; i < index && keys[i].name; i++) {}
	return (i == index) ? keys[index].name : NULL;
}

R_API void r_cons_pal_update_event() {
	Sdb *db = sdb_new0 ();
	int i, n = 0;
	char **color;
	RColor *rcolor;
	/* Compute cons->pal values */
	for (i = 0; keys[i].name; i++) {
		rcolor = RCOLOR_AT(i);
		color = COLOR_AT(i);
		if (*color) {
			R_FREE (*color);
		}
		// Color is dynamically allocated, needs to be freed
		*color = r_cons_rgb_str (NULL, rcolor->r, rcolor->g, rcolor->b, rcolor->a);
		const char *rgb = sdb_fmt (0, "rgb:%02x%02x%02x", rcolor->r, rcolor->g, rcolor->b);
		sdb_set (db, rgb, "1", 0);
	}
	SdbList *list = sdb_foreach_list (db, true);
	SdbListIter *iter;
	SdbKv *kv;
	r_cons_rainbow_free ();
	r_cons_rainbow_new (list->length);
	ls_foreach (list, iter, kv) {
		r_cons_singleton ()->pal.rainbow[n++] = strdup (kv->key);
	}
	r_cons_singleton ()->pal.rainbow_sz = n;
	ls_free (list);
	sdb_free (db);
}

R_API void r_cons_rainbow_new(int sz) {
	RCons *cons = r_cons_singleton ();
	cons->pal.rainbow_sz = sz;
	free (cons->pal.rainbow);
	cons->pal.rainbow = calloc (sizeof (char *), sz);
}

R_API void r_cons_rainbow_free() {
	RCons *cons = r_cons_singleton ();
	int i, sz = cons->pal.rainbow_sz;
	if (cons->pal.rainbow) {
		for (i = 0; i < sz ; i++) {
			free (cons->pal.rainbow[i]);
		}
	}
	cons->pal.rainbow_sz = 0;
	R_FREE (cons->pal.rainbow);
}

R_API char *r_cons_rainbow_get(int idx, int last, bool bg) {
	RCons *cons = r_cons_singleton ();
	if (last < 0) {
		last = cons->pal.rainbow_sz;
	}
	if (idx < 0 || idx >= last || !cons->pal.rainbow) {
		return NULL;
	}
	int x = (last == cons->pal.rainbow_sz)
		? idx : (cons->pal.rainbow_sz * idx) / (last + 1);
	const char *a = cons->pal.rainbow[x];
	if (bg) {
		char *dup = r_str_newf ("%s %s", a, a);
		char *res = r_cons_pal_parse (dup, NULL);
		free (dup);
		return res;
	}
	return r_cons_pal_parse (a, NULL);
}

