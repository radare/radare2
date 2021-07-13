/* radare - LGPL - Copyright 2009-2021 - nibble, pancake, dso */

#include "r_core.h"

#define HASRETRY 1
#define HAVE_LOCALS 1
#define DEFAULT_NARGS 4
#define FLAG_PREFIX ";-- "

#define COLOR(ds, field) ((ds)->show_color ? (ds)->field : "")
#define COLOR_ARG(ds, field) ((ds)->show_color && (ds)->show_color_args ? (ds)->field : "")
#define COLOR_CONST(ds, color) ((ds)->show_color ? Color_ ## color : "")
#define COLOR_RESET(ds) COLOR_CONST(ds, RESET)

// ugly globals but meh
static ut64 emustack_min = 0LL;
static ut64 emustack_max = 0LL;

static const char* r_vline_a[] = {
	"|",  // LINE_VERT
	"|-", // LINE_CROSS
	"-",  // LINE_HORIZ
	":",  // LINE_UP
	",",  // LUP_CORNER
	"\\", // RDWN_CORNER
	"/",  // RUP_CORNER
	"`",  // LDWN_CORNER
	"->", // ARROW_RIGHT
	"=<", // ARROW_LEFT
};

static const char* r_vline_u[] = {
	"│", // LINE_VERT
	"├", // LINE_CROSS
	"─", // LINE_HORIZ
	"╎", // LINE_UP
	// "↑", // LINE_UP
	//"┌", // LUP_CORNER
	"┘", // LUP_CORNER
	"└", // RDWN_CORNER
	"┌", // RUP_CORNER
	"┐", // LDWN_CORNER
	">", // ARROW_RIGHT
	"<", // ARROW_LEFT
};

static const char* r_vline_uc[] = {
	"│", // LINE_VERT
	"├", // LINE_CROSS
	"─", // LINE_HORIZ
	// "↑", // LINE_UP
	"╎", // LINE_UP
	// "≀", // LINE_UP
	//"┌", // LUP_CORNER
	"╯", // LUP_CORNER
	"╰", // RDWN_CORNER
	"╭", // RUP_CORNER
	"╮", // LDWN_CORNER
	">", // ARROW_RIGHT
	"<", // ARROW_LEFT
};

#define DS_PRE_NONE         0
#define DS_PRE_EMPTY        1
#define DS_PRE_FCN_HEAD     2
#define DS_PRE_FCN_MIDDLE   3
#define DS_PRE_FCN_TAIL     4

// TODO: what about using bit shifting and enum for keys? see libr/util/bitmap.c
// the problem of this is that the fields will be more opaque to bindings, but we will earn some bits
typedef struct {
	RCore *core;
	char str[1024], strsub[1024];
	bool immtrim;
	bool immstr;
	bool use_esil;
	bool show_color;
	bool show_color_bytes;
	bool show_color_args;
	int colorop;
	int acase;
	bool capitalize;
	bool show_flgoff;
	bool hasMidflag;
	bool hasMidbb;
	int atabs;
	int atabsonce;
	int atabsoff;
	int decode;
	bool pseudo;
	int subnames;
	int interactive;
	bool subjmp;
	bool subvar;
	bool show_lines;
	bool show_lines_bb;
	bool show_lines_ret;
	bool show_lines_call;
	bool show_lines_fcn;
	bool linesright;
	int tracespace;
	int cyclespace;
	int cmtfold;
	int show_indent;
	bool show_dwarf;
	bool show_size;
	bool show_trace;
	bool show_family;
	bool asm_describe;
	int linesout;
	int adistrick;
	bool asm_meta;
	bool asm_xrefs_code;
	int asm_demangle;
	bool asm_instr;
	bool show_offset;
	bool show_offdec; // dupe for r_print->flags
	bool show_bbline;
	bool show_emu;
	bool pre_emu;
	bool show_emu_str;
	bool show_emu_stroff;
	bool show_emu_strinv;
	bool show_emu_strflag;
	bool show_emu_stack;
	bool show_emu_write;
	bool show_optype;
	bool show_emu_strlea;
	bool show_emu_ssa;
	bool show_section;
	int show_section_col;
	bool flags_inline;
	bool show_section_perm;
	bool show_section_name;
	bool show_symbols;
	int show_symbols_col;
	bool show_offseg;
	bool show_flags;
	bool bblined;
	bool show_bytes;
	bool show_bytes_right;
	bool show_reloff;
	bool show_reloff_flags;
	bool show_comments;
	bool show_usercomments;
	bool asm_hints;
	bool asm_hint_jmp;
	bool asm_hint_cdiv;
	bool asm_hint_call;
	bool asm_hint_call_indirect;
	bool asm_hint_lea;
	bool asm_hint_imm;
	bool asm_hint_emu;
	int  asm_hint_pos;
	ut64 emuptr;
	bool show_slow;
	Sdb *ssa;
	int cmtcol;
	bool show_calls;
	bool show_cmtflgrefs;
	bool show_cmtesil;
	bool show_cycles;
	bool show_refptr;
	bool show_stackptr;
	int stackFd;
	bool show_xrefs;
	bool show_cmtrefs;
	const char *show_cmtoff;
	bool show_functions;
	bool show_marks;
	bool show_asciidot;
	RStrEnc strenc;
	int cursor;
	int show_comment_right_default;
	RSpace *flagspace_ports;
	bool show_flag_in_bytes;
	int lbytes;
	int show_comment_right;
	int pre;
	char *ocomment;
	int linesopts;
	int lastfail;
	int ocols;
	int lcols;
	int nb, nbytes;
	int show_utf8;
	int lines;
	int oplen;
	bool show_varaccess;
	bool show_vars;
	bool show_fcnsig;
	bool hinted_line;
	int show_varsum;
	int midflags;
	bool midbb;
	bool midcursor;
	bool show_noisy_comments;
	ut64 asm_highlight;
	const char *pal_comment;
	const char *color_comment;
	const char *color_usrcmt;
	const char *color_fname;
	const char *color_floc;
	const char *color_fline;
	const char *color_flow;
	const char *color_flow2;
	const char *color_flag;
	const char *color_label;
	const char *color_offset;
	const char *color_other;
	const char *color_nop;
	const char *color_bin;
	const char *color_math;
	const char *color_btext;
	const char *color_jmp;
	const char *color_cjmp;
	const char *color_call;
	const char *color_cmp;
	const char *color_swi;
	const char *color_trap;
	const char *color_ret;
	const char *color_push;
	const char *color_pop;
	const char *color_reg;
	const char *color_num;
	const char *color_mov;
	const char *color_invalid;
	const char *color_gui_cflow;
	const char *color_gui_dataoffset;
	const char *color_gui_background;
	const char *color_gui_alt_background;
	const char *color_gui_border;
	const char *color_linehl;
	const char *color_func_var;
	const char *color_func_var_type;
	const char *color_func_var_addr;

	RFlagItem *lastflag;
	RAnalHint *hint;
	RPrint *print;

	ut64 esil_old_pc;
	ut8* esil_regstate;
	int esil_regstate_size;
	bool esil_likely;

	int l;
	int middle;
	int indent_level;
	int indent_space;
	char *line;
	char *line_col, *prev_line_col;
	char *refline, *refline2;
	char *comment;
	char *opstr;
	char *osl, *sl;
	int stackptr, ostackptr;
	int index;
	ut64 at, vat, addr, dest;
	int tries, cbytes, idx;
	char chref;
	bool retry;
	RAsmOp asmop;
	RAnalOp analop;
	RAnalFunction *fcn;
	RAnalFunction *pdf;
	const ut8 *buf;
	int len;
	int maxrefs;
	int foldxrefs;
	char *prev_ins;
	bool prev_ins_eq;
	int prev_ins_count;
	bool show_nodup;
	bool has_description;
	// caches
	char *_tabsbuf;
	int _tabsoff;
	bool dwarfFile;
	bool dwarfAbspath;
	bool showpayloads;
	bool showrelocs;
	int cmtcount;
	bool asm_anal;
	ut64 printed_str_addr;
	ut64 printed_flag_addr;
	ut64 min_ref_addr;

	PJ *pj; // not null if printing json
	int buf_line_begin;
	const char *strip;
	int maxflags;
	int asm_types;
} RDisasmState;

static void ds_setup_print_pre(RDisasmState *ds, bool tail, bool middle);
static void ds_setup_pre(RDisasmState *ds, bool tail, bool middle);
static void ds_print_pre(RDisasmState *ds, bool fcnline);
static void ds_pre_line(RDisasmState *ds);
static void ds_begin_line(RDisasmState *ds);
static void ds_newline(RDisasmState *ds);
static void ds_begin_cont(RDisasmState *ds);
static void ds_print_esil_anal(RDisasmState *ds);
static void ds_reflines_init(RDisasmState *ds);
static void ds_align_comment(RDisasmState *ds);
static RDisasmState * ds_init(RCore * core);
static void ds_build_op_str(RDisasmState *ds, bool print_color);
static void ds_print_show_bytes(RDisasmState *ds);
static void ds_pre_xrefs(RDisasmState *ds, bool no_fcnlines);
static void ds_show_xrefs(RDisasmState *ds);
static void ds_atabs_option(RDisasmState *ds);
static void ds_show_functions(RDisasmState *ds);
static void ds_control_flow_comments(RDisasmState *ds);
static void ds_adistrick_comments(RDisasmState *ds);
static void ds_print_comments_right(RDisasmState *ds);
static void ds_show_comments_right(RDisasmState *ds);
static void ds_show_flags(RDisasmState *ds, bool overlapped);
static void ds_update_ref_lines(RDisasmState *ds);
static int ds_disassemble(RDisasmState *ds, ut8 *buf, int len);
static void ds_print_lines_right(RDisasmState *ds);
static void ds_print_lines_left(RDisasmState *ds);
static void ds_print_cycles(RDisasmState *ds);
static void ds_print_family(RDisasmState *ds);
static void ds_print_stackptr(RDisasmState *ds);
static void ds_print_offset(RDisasmState *ds);
static void ds_print_op_size(RDisasmState *ds);
static void ds_print_trace(RDisasmState *ds);
static void ds_print_opstr(RDisasmState *ds);
static void ds_print_color_reset(RDisasmState *ds);
static int ds_print_middle(RDisasmState *ds, int ret);
static bool ds_print_labels(RDisasmState *ds, RAnalFunction *f);
static void ds_print_sysregs(RDisasmState *ds);
static void ds_print_fcn_name(RDisasmState *ds);
static void ds_print_as_string(RDisasmState *ds);
static bool ds_print_core_vmode(RDisasmState *ds, int pos);
static void ds_print_dwarf(RDisasmState *ds);
static void ds_print_asmop_payload(RDisasmState *ds, const ut8 *buf);
static char *ds_esc_str(RDisasmState *ds, const char *str, int len, const char **prefix_out, bool is_comment);
static void ds_print_ptr(RDisasmState *ds, int len, int idx);
static void ds_print_demangled(RDisasmState *ds);
static void ds_print_str(RDisasmState *ds, const char *str, int len, ut64 refaddr);
static char *ds_sub_jumps(RDisasmState *ds, char *str);
static void ds_start_line_highlight(RDisasmState *ds);
static void ds_end_line_highlight(RDisasmState *ds);
static bool line_highlighted(RDisasmState *ds);
static int ds_print_shortcut(RDisasmState *ds, ut64 addr, int pos);

R_API ut64 r_core_pava (RCore *core, ut64 addr) {
	if (core->print->pava) {
		RIOMap *map = r_io_map_get_paddr (core->io, addr);
		if (map) {
			return addr - map->delta + r_io_map_begin (map);
		}
	}
	return addr;
}

static RAnalFunction *fcnIn(RDisasmState *ds, ut64 at, int type) {
	if (ds->fcn && r_anal_function_contains (ds->fcn, at)) {
		return ds->fcn;
	}
	return r_anal_get_fcn_in (ds->core->anal, at, type);
}

static const char *get_utf8_char(const char line, RDisasmState *ds) {
	switch (line) {
	case '<': return ds->core->cons->vline[ARROW_LEFT];
	case '>': return ds->core->cons->vline[ARROW_RIGHT];
	case ':': return ds->core->cons->vline[LINE_UP];
	case '|': return ds->core->cons->vline[LINE_VERT];
	case '=':
	case '-': return ds->core->cons->vline[LINE_HORIZ];
	case ',': return ds->core->cons->vline[CORNER_TL];
	case '.': return ds->core->cons->vline[CORNER_TR];
	case '`': return ds->core->cons->vline[CORNER_BL];
	default: return " ";
	}
}

static void ds_print_ref_lines(char *line, char *line_col, RDisasmState *ds) {
	int i;
	int len = strlen (line);
	if (ds->core->cons->use_utf8 || ds->linesopts & R_ANAL_REFLINE_TYPE_UTF8) {
		if (ds->show_color) {
			for (i = 0; i < len; i++) {
				if (line[i] == ' ') {
					r_cons_printf (" ");
					continue;
				}
				const char *flow_tint = (line_col[i] == 'd')? COLOR (ds, color_flow): COLOR (ds, color_flow2);
				r_cons_printf ("%s%s%s", flow_tint, get_utf8_char (line[i], ds), COLOR_RESET (ds));
			}
		} else {
			len = strlen (line);
			for (i = 0; i < len; i++) {
				r_cons_printf ("%s", get_utf8_char (line[i], ds));
			}
		}
	} else {
		if (ds->show_color) {
			for (i = 0; i < len; i++) {
				if (line[i] == ' ') {
					r_cons_printf (" ");
					continue;
				}
				const char *flow_tint = (line_col[i] == 'd')? COLOR (ds, color_flow): COLOR (ds, color_flow2);
				r_cons_printf ("%s%c%s", flow_tint, line[i], COLOR_RESET (ds));
			}
		} else {
			r_cons_printf ("%s", line);
		}
	}
}

static void get_bits_comment(RCore *core, RAnalFunction *f, char *cmt, int cmt_size) {
	if (core && f && cmt && cmt_size > 0 && f->bits && f->bits != core->rasm->bits) {
		const char *asm_arch = r_config_get (core->config, "asm.arch");
		if (asm_arch && *asm_arch && strstr (asm_arch, "arm")) {
			switch (f->bits) {
			case 16: strcpy (cmt, " (thumb)"); break;
			case 32: strcpy (cmt, " (arm)"); break;
			case 64: strcpy (cmt, " (aarch64)"); break;
			}
		} else {
			snprintf (cmt, cmt_size, " (%d bits)", f->bits);
		}
	} else {
		if (cmt) {
			cmt[0] = 0;
		}
	}
}

R_API const char *r_core_get_section_name(RCore *core, ut64 addr) {
	static char section[128] = "";
	static ut64 oaddr = UT64_MAX;
	if (oaddr == addr) {
		return section;
	}
	if (r_config_get_b (core->config, "cfg.debug")) {
		char *rv = r_core_cmd_strf (core, "dmi.@0x%08"PFMT64x, addr);
		if (rv) {
			r_str_replace_char (rv, '\n', ' ');
			r_str_ncpy (section, rv, sizeof (section) - 1);
			return section;
		}
		return NULL;
	}
	RBinObject *bo = r_bin_cur_object (core->bin);
	RBinSection *s = bo? r_bin_get_section_at (bo, addr, core->io->va): NULL;
	if (s && s->name && *s->name) {
		snprintf (section, sizeof (section) - 1, "%10s ", s->name);
	} else {
		RListIter *iter;
		RDebugMap *map;
		*section = 0;
		r_list_foreach (core->dbg->maps, iter, map) {
			if (addr >= map->addr && addr < map->addr_end) {
				const char *mn = r_str_lchr (map->name, '/');
				r_str_ncpy (section, mn? mn + 1: map->name, sizeof (section));
				break;
			}
		}
	}
	oaddr = addr;
	return section;
}

// up means if this lines go up, it controls whether to insert `_
// nl if we have to insert new line, it controls whether to insert \n
static void _ds_comment_align_(RDisasmState *ds, bool up, bool nl) {
	if (ds->show_comment_right) {
		if (ds->show_color) {
			r_cons_print (ds->pal_comment);
		}
		return;
	}
	const char *sn = ds->show_section ? r_core_get_section_name (ds->core, ds->at) : "";
	ds_align_comment (ds);
	// ds_align_comment (ds);
	r_cons_print (COLOR_RESET (ds));
	ds_print_pre (ds, true);
	r_cons_printf ("%s%s", nl? "\n": "", sn);
	ds_print_ref_lines (ds->refline, ds->line_col, ds);
	r_cons_printf ("  %s %s",up? "": ".-", COLOR (ds, color_comment));
}
#define CMT_ALIGN _ds_comment_align_ (ds, true, false)

static void ds_comment_lineup(RDisasmState *ds) {
	CMT_ALIGN;
}

static void ds_comment_(RDisasmState *ds, bool align, bool nl, const char *format, va_list ap) {
	char *s = r_str_newvf (format, ap);
	char *p = s;
	bool multiline = strchr (p, '\n');
	bool first = true;
	while (true) {
		char *nl = strchr (p, '\n');
		if (nl) {
			*nl = 0;
		}
		if (ds->show_comments) {
			if (ds->show_comment_right && align) {
				ds_align_comment (ds);
			}
		}
		r_cons_printf ("%s", COLOR (ds, color_comment));
		if (multiline) {
			if (!first) {
				ds_begin_line (ds);
				//ds_print_labels (ds, f);
				ds_setup_print_pre (ds, false, false);
				ds_print_lines_left (ds);
				//core->print->resetbg = (ds->asm_highlight == UT64_MAX);
				r_cons_print ("; ");
			}
		}
		r_cons_print (p);
		if (!nl) {
			break;
		}
		if (!ds->show_comment_right && nl) {
			r_cons_newline ();
		}
		first = false;
		p = nl + 1;
	}
	free (s);
	if (!ds->show_comment_right && nl) {
		ds_newline (ds);
	}
}

static void ds_comment(RDisasmState *ds, bool align, const char *format, ...) {
	va_list ap;
	va_start (ap, format);
	ds->cmtcount++;
	ds_comment_ (ds, align, align, format, ap);
	va_end (ap);
}

#define DS_COMMENT_FUNC(name, align, nl) \
	static void ds_comment_##name(RDisasmState *ds, const char *format, ...) { \
		va_list ap; \
		va_start (ap, format); \
		ds_comment_ (ds, align, nl, format, ap); \
		va_end (ap); \
	}

DS_COMMENT_FUNC (start, true, false)
DS_COMMENT_FUNC (middle, false, false)
DS_COMMENT_FUNC (end, false, true)

static void ds_comment_esil(RDisasmState *ds, bool up, bool end, const char *format, ...) {
	va_list ap;
	va_start (ap, format);

	if (ds->show_comments && up) {
		ds->show_comment_right ? ds_align_comment (ds) : ds_comment_lineup (ds);
	}
	r_cons_printf_list (format, ap);
	va_end (ap);

	if (ds->show_comments && !ds->show_comment_right) {
		if (end) {
			ds_newline (ds);
		}
	}
}

static void ds_print_esil_anal_fini(RDisasmState *ds) {
	RCore *core = ds->core;
	if (ds->show_emu && ds->esil_regstate) {
		RCore* core = ds->core;
		core->anal->last_disasm_reg = r_reg_arena_peek (core->anal->reg);
		const char *pc = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
		RRegSet *regset = r_reg_regset_get (ds->core->anal->reg, R_REG_TYPE_GPR);
		if (ds->esil_regstate_size  == regset->arena->size) {
			r_reg_arena_poke (core->anal->reg, ds->esil_regstate);
		}
		r_reg_setv (core->anal->reg, pc, ds->esil_old_pc);
		R_FREE (ds->esil_regstate);
	}
	if (core && core->anal && core->anal->esil) {
		// make sure to remove reference to ds to avoid UAF
		core->anal->esil->user = NULL;
	}
}

static RDisasmState * ds_init(RCore *core) {
	RDisasmState *ds = R_NEW0 (RDisasmState);
	if (!ds) {
		return NULL;
	}
	ds->core = core;
	ds->strip = r_config_get (core->config, "asm.strip");
	ds->pal_comment = core->cons->context->pal.comment;
	#define P(x) (core->cons && core->cons->context->pal.x)? core->cons->context->pal.x
	ds->color_comment = P(comment): Color_CYAN;
	ds->color_usrcmt = P(usercomment): Color_CYAN;
	ds->color_fname = P(fname): Color_RED;
	ds->color_floc = P(floc): Color_MAGENTA;
	ds->color_fline = P(fline): Color_CYAN;
	ds->color_flow = P(flow): Color_CYAN;
	ds->color_flow2 = P(flow2): Color_BLUE;
	ds->color_flag = P(flag): Color_CYAN;
	ds->color_label = P(label): Color_CYAN;
	ds->color_offset = P(offset): Color_GREEN;
	ds->color_other = P(other): Color_WHITE;
	ds->color_nop = P(nop): Color_BLUE;
	ds->color_bin = P(bin): Color_YELLOW;
	ds->color_math = P(math): Color_YELLOW;
	ds->color_btext = P(btext): Color_YELLOW;
	ds->color_jmp = P(jmp): Color_GREEN;
	ds->color_cjmp = P(cjmp): Color_GREEN;
	ds->color_call = P(call): Color_BGREEN;
	ds->color_cmp = P(cmp): Color_MAGENTA;
	ds->color_swi = P(swi): Color_MAGENTA;
	ds->color_trap = P(trap): Color_BRED;
	ds->color_ret = P(ret): Color_RED;
	ds->color_push = P(push): Color_YELLOW;
	ds->color_pop = P(pop): Color_BYELLOW;
	ds->color_reg = P(reg): Color_YELLOW;
	ds->color_num = P(num): Color_CYAN;
	ds->color_mov = P(mov): Color_WHITE;
	ds->color_invalid = P(invalid): Color_BRED;
	ds->color_gui_cflow = P(gui_cflow): Color_YELLOW;
	ds->color_gui_dataoffset = P(gui_dataoffset): Color_YELLOW;
	ds->color_gui_background = P(gui_background): Color_BLACK;
	ds->color_gui_alt_background = P(gui_alt_background): Color_GRAY;
	ds->color_gui_border = P(gui_border): Color_BGGRAY;
	ds->color_linehl = P(linehl): Color_BGBLUE;
	ds->color_func_var = P(func_var): Color_WHITE;
	ds->color_func_var_type = P(func_var_type): Color_BLUE;
	ds->color_func_var_addr = P(func_var_addr): Color_CYAN;

	ds->immstr = r_config_get_i (core->config, "asm.imm.str");
	ds->immtrim = r_config_get_i (core->config, "asm.imm.trim");
	ds->use_esil = r_config_get_i (core->config, "asm.esil");
	ds->pre_emu = r_config_get_i (core->config, "emu.pre");
	ds->show_flgoff = r_config_get_i (core->config, "asm.flags.offset");
	ds->show_nodup = r_config_get_i (core->config, "asm.nodup");
	{
		const char *ah = r_config_get (core->config, "asm.highlight");
		ds->asm_highlight = (ah && *ah)? r_num_math (core->num, ah): UT64_MAX;
	}
	ds->asm_anal = r_config_get_i (core->config, "asm.anal");
	ds->show_color = r_config_get_i (core->config, "scr.color");
	ds->show_color_bytes = r_config_get_i (core->config, "scr.color.bytes"); // maybe rename to asm.color.bytes
	ds->show_color_args = r_config_get_i (core->config, "scr.color.args");
	ds->colorop = r_config_get_i (core->config, "scr.color.ops"); // XXX confusing name // asm.color.inst (mnemonic + operands) ?
	ds->show_utf8 = r_config_get_i (core->config, "scr.utf8");
	ds->acase = r_config_get_i (core->config, "asm.ucase");
	ds->capitalize = r_config_get_i (core->config, "asm.capitalize");
	ds->atabs = r_config_get_i (core->config, "asm.tabs");
	ds->atabsonce = r_config_get_i (core->config, "asm.tabs.once");
	ds->atabsoff = r_config_get_i (core->config, "asm.tabs.off");
	ds->midflags = r_config_get_i (core->config, "asm.flags.middle");
	ds->midbb = r_config_get_i (core->config, "asm.bbmiddle");
	ds->midcursor = r_config_get_i (core->config, "asm.midcursor");
	ds->decode = r_config_get_i (core->config, "asm.decode");
	core->parser->pseudo = ds->pseudo = r_config_get_i (core->config, "asm.pseudo");
	if (ds->pseudo) {
		ds->atabs = 0;
	}
	ds->subnames = r_config_get_i (core->config, "asm.sub.names");
	ds->interactive = r_cons_is_interactive ();
	ds->subjmp = r_config_get_i (core->config, "asm.sub.jmp");
	ds->subvar = r_config_get_i (core->config, "asm.sub.var");
	core->parser->subrel = r_config_get_i (core->config, "asm.sub.rel");
	core->parser->subreg = r_config_get_i (core->config, "asm.sub.reg");
	core->parser->localvar_only = r_config_get_i (core->config, "asm.sub.varonly");
	core->parser->retleave_asm = NULL;
	ds->show_fcnsig = r_config_get_i (core->config, "asm.fcnsig");
	ds->show_vars = r_config_get_i (core->config, "asm.var");
	ds->show_varsum = r_config_get_i (core->config, "asm.var.summary");
	ds->show_varaccess = r_config_get_i (core->config, "asm.var.access");
	ds->maxrefs = r_config_get_i (core->config, "asm.xrefs.max");
	ds->maxflags = r_config_get_i (core->config, "asm.flags.limit");
	ds->flags_inline = r_config_get_i (core->config, "asm.flags.inline");
	ds->asm_types = r_config_get_i (core->config, "asm.types");
	ds->foldxrefs = r_config_get_i (core->config, "asm.xrefs.fold");
	ds->show_lines = r_config_get_i (core->config, "asm.lines");
	ds->show_lines_bb = ds->show_lines ? r_config_get_i (core->config, "asm.lines.jmp") : false;
	ds->linesright = r_config_get_i (core->config, "asm.lines.right");
	ds->show_indent = r_config_get_i (core->config, "asm.indent");
	ds->indent_space = r_config_get_i (core->config, "asm.indentspace");
	ds->tracespace = r_config_get_i (core->config, "asm.tracespace");
	ds->cyclespace = r_config_get_i (core->config, "asm.cyclespace");
	ds->show_dwarf = r_config_get_i (core->config, "asm.dwarf");
	ds->dwarfFile = r_config_get_i (ds->core->config, "asm.dwarf.file");
	ds->dwarfAbspath = r_config_get_i (ds->core->config, "asm.dwarf.abspath");
	ds->show_lines_call = ds->show_lines ? r_config_get_i (core->config, "asm.lines.call") : false;
	ds->show_lines_ret = ds->show_lines ? r_config_get_i (core->config, "asm.lines.ret") : false;
	ds->show_size = r_config_get_i (core->config, "asm.size");
	ds->show_trace = r_config_get_i (core->config, "asm.trace");
	ds->linesout = r_config_get_i (core->config, "asm.lines.out");
	ds->adistrick = r_config_get_i (core->config, "asm.middle"); // TODO: find better name
	ds->asm_demangle = r_config_get_i (core->config, "asm.demangle");
	ds->asm_describe = r_config_get_i (core->config, "asm.describe");
	ds->show_offset = r_config_get_i (core->config, "asm.offset");
	ds->show_offdec = r_config_get_i (core->config, "asm.decoff");
	ds->show_bbline = r_config_get_i (core->config, "asm.lines.bb");
	ds->show_section = r_config_get_i (core->config, "asm.section");
	ds->show_section_col = r_config_get_i (core->config, "asm.section.col");
	ds->show_section_perm = r_config_get_i (core->config, "asm.section.perm");
	ds->show_section_name = r_config_get_i (core->config, "asm.section.name");
	ds->show_symbols = r_config_get_i (core->config, "asm.symbol");
	ds->show_symbols_col = r_config_get_i (core->config, "asm.symbol.col");
	ds->asm_instr = r_config_get_i (core->config, "asm.instr");
	ds->show_emu = r_config_get_i (core->config, "asm.emu");
	ds->show_emu_str = r_config_get_i (core->config, "emu.str");
	ds->show_emu_stroff = r_config_get_i (core->config, "emu.str.off");
	ds->show_emu_strinv = r_config_get_i (core->config, "emu.str.inv");
	ds->show_emu_strflag = r_config_get_i (core->config, "emu.str.flag");
	ds->show_emu_strlea = r_config_get_i (core->config, "emu.str.lea");
	ds->show_emu_write = r_config_get_i (core->config, "emu.write");
	ds->show_emu_ssa = r_config_get_i (core->config, "emu.ssa");
	ds->show_emu_stack = r_config_get_i (core->config, "emu.stack");
	ds->stackFd = -1;
	if (ds->show_emu_stack) {
		// TODO: initialize fake stack in here
		const char *uri = "malloc://32K";
		ut64 size = r_num_get (core->num, "32K");
		ut64 addr = r_reg_getv (core->anal->reg, "SP") - (size / 2);
		emustack_min = addr;
		emustack_max = addr + size;
		ds->stackFd = r_io_fd_open (core->io, uri, R_PERM_RW, 0);
		RIOMap *map = r_io_map_add (core->io, ds->stackFd, R_PERM_RW, 0LL, addr, size);
		if (!map) {
			r_io_fd_close (core->io, ds->stackFd);
			eprintf ("Cannot create map for tha stack, fd %d got closed again\n", ds->stackFd);
			ds->stackFd = -1;
		} else {
			r_io_map_set_name (map, "fake.stack");
		}
	}
	ds->stackptr = core->anal->stackptr;
	ds->show_offseg = r_config_get_i (core->config, "asm.segoff");
	ds->show_flags = r_config_get_i (core->config, "asm.flags");
	ds->show_bytes = r_config_get_i (core->config, "asm.bytes");
	ds->show_bytes_right = r_config_get_i (core->config, "asm.bytes.right");
	ds->show_optype = r_config_get_i (core->config, "asm.optype");
	ds->asm_meta = r_config_get_i (core->config, "asm.meta");
	ds->asm_xrefs_code = r_config_get_i (core->config, "asm.xrefs.code");
	ds->show_reloff = r_config_get_i (core->config, "asm.reloff");
	ds->show_reloff_flags = r_config_get_i (core->config, "asm.reloff.flags");
	ds->show_lines_fcn = ds->show_lines ? r_config_get_i (core->config, "asm.lines.fcn") : false;
	ds->show_comments = r_config_get_i (core->config, "asm.comments");
	ds->show_usercomments = r_config_get_i (core->config, "asm.usercomments");
	ds->asm_hint_jmp = r_config_get_i (core->config, "asm.hint.jmp");
	ds->asm_hint_call = r_config_get_i (core->config, "asm.hint.call");
	ds->asm_hint_call_indirect = r_config_get_i (core->config, "asm.hint.call.indirect");
	ds->asm_hint_lea = r_config_get_i (core->config, "asm.hint.lea");
	ds->asm_hint_imm = r_config_get_i (core->config, "asm.hint.imm");
	ds->asm_hint_emu = r_config_get_i (core->config, "asm.hint.emu");
	ds->asm_hint_cdiv = r_config_get_i (core->config, "asm.hint.cdiv");
	ds->asm_hint_pos = r_config_get_i (core->config, "asm.hint.pos");
	ds->asm_hints = r_config_get_i (core->config, "asm.hints"); // only for cdiv wtf
	ds->show_slow = r_config_get_i (core->config, "asm.slow");
	ds->show_refptr = r_config_get_i (core->config, "asm.refptr");
	ds->show_calls = r_config_get_i (core->config, "asm.calls");
	ds->show_family = r_config_get_i (core->config, "asm.family");
	ds->cmtcol = r_config_get_i (core->config, "asm.cmt.col");
	ds->show_cmtesil = r_config_get_i (core->config, "asm.cmt.esil");
	ds->show_cmtflgrefs = r_config_get_i (core->config, "asm.cmt.flgrefs");
	ds->show_cycles = r_config_get_i (core->config, "asm.cycles");
	ds->show_stackptr = r_config_get_i (core->config, "asm.stackptr");
	ds->show_xrefs = r_config_get_i (core->config, "asm.xrefs");
	ds->show_cmtrefs = r_config_get_i (core->config, "asm.cmt.refs");
	ds->cmtfold = r_config_get_i (core->config, "asm.cmt.fold");
	ds->show_cmtoff = r_config_get (core->config, "asm.cmt.off");
	if (!ds->show_cmtoff) {
		ds->show_cmtoff = "nodup";
	}
	ds->show_functions = r_config_get_i (core->config, "asm.functions");
	ds->nbytes = r_config_get_i (core->config, "asm.nbytes");
	ds->show_asciidot = !strcmp (core->print->strconv_mode, "asciidot");
	const char *strenc_str = r_config_get (core->config, "bin.str.enc");
	if (!strenc_str) {
		ds->strenc = R_STRING_ENC_GUESS;
	} else if (!strcmp (strenc_str, "latin1")) {
		ds->strenc = R_STRING_ENC_LATIN1;
	} else if (!strcmp (strenc_str, "utf8")) {
		ds->strenc = R_STRING_ENC_UTF8;
	} else if (!strcmp (strenc_str, "utf16le")) {
		ds->strenc = R_STRING_ENC_UTF16LE;
	} else if (!strcmp (strenc_str, "utf32le")) {
		ds->strenc = R_STRING_ENC_UTF32LE;
	} else if (!strcmp (strenc_str, "utf16be")) {
		ds->strenc = R_STRING_ENC_UTF16BE;
	} else if (!strcmp (strenc_str, "utf32be")) {
		ds->strenc = R_STRING_ENC_UTF32BE;
	} else {
		ds->strenc = R_STRING_ENC_GUESS;
	}
	core->print->bytespace = r_config_get_i (core->config, "asm.bytes.space");
	ds->cursor = 0;
	ds->nb = 0;
	ds->flagspace_ports = r_flag_space_get (core->flags, "ports");
	ds->lbytes = r_config_get_i (core->config, "asm.lbytes");
	ds->show_comment_right_default = r_config_get_b (core->config, "asm.cmt.right");
	ds->show_comment_right = ds->show_comment_right_default;
	ds->show_flag_in_bytes = r_config_get_i (core->config, "asm.flags.inbytes");
	ds->show_marks = r_config_get_i (core->config, "asm.marks");
	ds->show_noisy_comments = r_config_get_i (core->config, "asm.noisy");
	ds->pre = DS_PRE_NONE;
	ds->ocomment = NULL;
	ds->linesopts = 0;
	ds->lastfail = 0;
	ds->ocols = 0;
	ds->lcols = 0;
	ds->printed_str_addr = UT64_MAX;
	ds->printed_flag_addr = UT64_MAX;

	ds->esil_old_pc = UT64_MAX;
	ds->esil_regstate = NULL;
	ds->esil_likely = false;

	ds->showpayloads = r_config_get_i (ds->core->config, "asm.payloads");
	ds->showrelocs = r_config_get_i (core->config, "bin.relocs");
	ds->min_ref_addr = r_config_get_i (core->config, "asm.sub.varmin");

	if (ds->show_flag_in_bytes) {
		ds->show_flags = false;
	}
	if (r_config_get_i (core->config, "asm.lines.wide")) {
		ds->linesopts |= R_ANAL_REFLINE_TYPE_WIDE;
	}
	if (core->cons->vline) {
		if (ds->show_utf8) {
			ds->linesopts |= R_ANAL_REFLINE_TYPE_UTF8;
		}
	}
	if (ds->show_lines_bb) {
		ds->ocols += 10; // XXX
	}
	if (ds->show_offset) {
		ds->ocols += 14;
	}
	ds->lcols = ds->ocols + 2;
	if (ds->show_bytes) {
		ds->ocols += 20;
	}
	if (ds->show_trace) {
		ds->ocols += 8;
	}
	if (ds->show_stackptr) {
		ds->ocols += 4;
	}
	/* disasm */ ds->ocols += 20;
	ds->nb = ds->nbytes? (1 + ds->nbytes * 2): 0;
	ds->tries = 3;
	if (core->print->cur_enabled) {
		if (core->print->cur < 0) {
			core->print->cur = 0;
		}
		ds->cursor = core->print->cur;
	} else {
		ds->cursor = -1;
	}
	if (r_config_get_i (core->config, "asm.lines.wide")) {
		ds->linesopts |= R_ANAL_REFLINE_TYPE_WIDE;
	}
	if (core->cons->vline) {
		if (ds->show_utf8) {
			ds->linesopts |= R_ANAL_REFLINE_TYPE_UTF8;
		}
	}
	return ds;
}

static ut64 lastaddr = UT64_MAX;

static void ds_reflines_fini(RDisasmState *ds) {
	RAnal *anal = ds->core->anal;
	r_list_free (anal->reflines);
	anal->reflines = NULL;
	R_FREE (ds->refline);
	R_FREE (ds->refline2);
	R_FREE (ds->prev_line_col);
}

static void ds_reflines_init(RDisasmState *ds) {
	RAnal *anal = ds->core->anal;

	lastaddr = UT64_MAX;

	if (ds->show_lines_bb || ds->pj) {
		ds_reflines_fini (ds);
		anal->reflines = r_anal_reflines_get (anal,
			ds->addr, ds->buf, ds->len, ds->l,
			ds->linesout, ds->show_lines_call);
	} else {
		r_list_free (anal->reflines);
		anal->reflines = NULL;
	}
}

static void ds_free(RDisasmState *ds) {
	if (!ds) {
		return;
	}
	if (ds->show_emu_stack) {
		// TODO: destroy fake stack in here
		eprintf ("Free fake stack\n");
		if (ds->stackFd != -1) {
			r_io_fd_close (ds->core->io, ds->stackFd);
		}
	}
	r_asm_op_fini (&ds->asmop);
	r_anal_op_fini (&ds->analop);
	r_anal_hint_free (ds->hint);
	ds_print_esil_anal_fini (ds);
	ds_reflines_fini (ds);
	ds_print_esil_anal_fini (ds);
	sdb_free (ds->ssa);
	free (ds->comment);
	free (ds->line);
	free (ds->line_col);
	free (ds->refline);
	free (ds->refline2);
	free (ds->prev_line_col);
	free (ds->opstr);
	free (ds->osl);
	free (ds->sl);
	free (ds->_tabsbuf);
	R_FREE (ds);
}

/* XXX move to r_print */
static char *colorize_asm_string(RCore *core, RDisasmState *ds, bool print_color) {
	char *source = ds->opstr? ds->opstr: r_asm_op_get_asm (&ds->asmop);
	const char *hlstr = r_meta_get_string (ds->core->anal, R_META_TYPE_HIGHLIGHT, ds->at);
	bool partial_reset = line_highlighted (ds) ? true : ((hlstr && *hlstr) ? true : false);
	RAnalFunction *f = ds->show_color_args ? fcnIn (ds, ds->vat, R_ANAL_FCN_TYPE_NULL) : NULL;
	if (!ds->asm_meta && *source == '.') {
		return strdup (source);
	}
	if (!ds->show_color || !ds->colorop) {
		return strdup (source);
	}

	if (print_color) {
		r_cons_strcat (r_print_color_op_type (core->print, ds->analop.type));
	}
	// workaround dummy colorizer in case of paired commands (tms320 & friends)
	char *spacer = strstr (source, "||");
	if (spacer) {
		char *scol1, *s1 = r_str_ndup (source, spacer - source);
		char *scol2, *s2 = strdup (spacer + 2);

		scol1 = r_print_colorize_opcode (ds->core->print, s1, ds->color_reg, ds->color_num, partial_reset, f ? f->addr : 0);
		free (s1);
		scol2 = r_print_colorize_opcode (ds->core->print, s2, ds->color_reg, ds->color_num, partial_reset, f ? f->addr : 0);
		free (s2);
		if (!scol1) {
			scol1 = strdup ("");
		}
		if (!scol2) {
			scol2 = strdup ("");
		}
		source = r_str_newf ("%s||%s", scol1, scol2);
		free (scol1);
		free (scol2);
		return source;
	}
	return r_print_colorize_opcode (ds->core->print, source, ds->color_reg, ds->color_num, partial_reset, f ? f->addr : 0);
}

static bool ds_must_strip(RDisasmState *ds) {
	if (ds && ds->strip && *ds->strip) {
		const char * optype = r_anal_optype_to_string (ds->analop.type);
		if (optype && *optype) {
			return strstr (ds->strip, optype);
		}
	}
	return false;
}

static void ds_highlight_word(RDisasmState * ds, char *word, char *color) {
	char *source = ds->opstr? ds->opstr: r_asm_op_get_asm (&ds->asmop);
	const char *color_reset = line_highlighted (ds) ? ds->color_linehl : Color_RESET_BG;
	char *asm_str = r_str_highlight (source, word, color, color_reset);
	ds->opstr = asm_str? asm_str: source;
}

static void __replaceImports(RDisasmState *ds) {
	if (ds->core->anal->imports) {
		char *imp;
		RListIter *iter;
		r_list_foreach (ds->core->anal->imports, iter, imp) {
			ds->opstr = r_str_replace (ds->opstr, imp,  ".", 1);
		}
	}
	if (ds->fcn && ds->fcn->imports) {
		char *imp;
		RListIter *iter;
		r_list_foreach (ds->fcn->imports, iter, imp) {
			ds->opstr = r_str_replace (ds->opstr, imp,  ".", 1);
		}
	}
}

static char *get_op_ireg (void *user, ut64 addr) {
	RCore *core = (RCore *)user;
	char *res = NULL;
	RAnalOp *op = r_core_anal_op (core, addr, 0);
	if (op && op->ireg) {
		res = strdup (op->ireg);
	}
	r_anal_op_free (op);
	return res;
}

static st64 get_ptr_at(RAnalFunction *fcn, st64 delta, ut64 addr) {
	return r_anal_function_get_var_stackptr_at (fcn, delta, addr);
}

static const char *get_reg_at(RAnalFunction *fcn, st64 delta, ut64 addr) {
	return r_anal_function_get_var_reg_at (fcn, delta, addr);
}

static void ds_build_op_str(RDisasmState *ds, bool print_color) {
	RCore *core = ds->core;
	if (ds->use_esil) {
		free (ds->opstr);
		if (*R_STRBUF_SAFEGET (&ds->analop.esil)) {
			ds->opstr = strdup (R_STRBUF_SAFEGET (&ds->analop.esil));
		} else {
			ds->opstr = strdup (",");
		}
		return;
	}
	if (ds->decode) {
		free (ds->opstr);
		ds->opstr = r_anal_op_to_string (core->anal, &ds->analop);
		return;
	}
	if (!ds->opstr) {
		ds->opstr = strdup (r_asm_op_get_asm (&ds->asmop));
	}
	/* initialize */
	core->parser->subrel = r_config_get_i (core->config, "asm.sub.rel");
	core->parser->subreg = r_config_get_i (core->config, "asm.sub.reg");
	core->parser->subrel_addr = 0;
	if (core->parser->subrel
	    && (ds->analop.type == R_ANAL_OP_TYPE_LEA || ds->analop.type == R_ANAL_OP_TYPE_MOV
	        || ds->analop.type == R_ANAL_OP_TYPE_CMP)
	    && ds->analop.ptr != UT64_MAX) {
		core->parser->subrel_addr = ds->analop.ptr;
	}
	if (ds->subvar && ds->opstr) {
		ut64 at = ds->vat;
		RAnalFunction *f = fcnIn (ds, at, R_ANAL_FCN_TYPE_NULL);
		core->parser->get_op_ireg = get_op_ireg;
		core->parser->get_ptr_at = get_ptr_at;
		core->parser->get_reg_at = get_reg_at;
		r_parse_subvar (core->parser, f, at, ds->analop.size,
			ds->opstr, ds->strsub, sizeof (ds->strsub));
		if (*ds->strsub) {
			free (ds->opstr);
			ds->opstr = strdup (ds->strsub);
		}
		if (core->parser->subrel) {
			RList *list = r_anal_refs_get (core->anal, at);
			RListIter *iter;
			RAnalRef *ref;
			r_list_foreach (list, iter, ref) {
				if ((ref->type == R_ANAL_REF_TYPE_DATA
					|| ref->type == R_ANAL_REF_TYPE_STRING)
					&& ds->analop.type == R_ANAL_OP_TYPE_LEA) {
					core->parser->subrel_addr = ref->addr;
					break;
				}
			}
			r_list_free (list);
		}
	}

	if (ds->pseudo) {
		const char *opstr = ds->opstr ? ds->opstr : r_asm_op_get_asm (&ds->asmop);
		r_parse_parse (core->parser, opstr, ds->str);
		free (ds->opstr);
		ds->opstr = strdup (ds->str);
	}
	ds->opstr = ds_sub_jumps (ds, ds->opstr);
	if (ds->immtrim) {
		char *res = r_parse_immtrim (ds->opstr);
		if (res) {
			ds->opstr = res;
		}
		return;
	}
	if (ds->hint && ds->hint->opcode) {
		free (ds->opstr);
		ds->opstr = strdup (ds->hint->opcode);
	}
	if (ds->subnames) {
		RSpace *ofs = core->parser->flagspace;
		RSpace *fs = ds->flagspace_ports;
		if (ds->analop.type == R_ANAL_OP_TYPE_IO) {
			core->parser->notin_flagspace = NULL;
			core->parser->flagspace = fs;
		} else {
			if (fs) {
				core->parser->notin_flagspace = fs;
				core->parser->flagspace = fs;
			} else {
				core->parser->notin_flagspace = NULL;
				core->parser->flagspace = NULL;
			}
		}
		if (core->parser->subrel && ds->analop.refptr) {
			if (core->parser->subrel_addr == 0) {
				ut64 killme = UT64_MAX;
				const int be = core->rasm->big_endian;
				r_io_read_i (core->io, ds->analop.ptr, &killme, ds->analop.refptr, be);
				core->parser->subrel_addr = killme;
			}
		}
		char *asm_str = colorize_asm_string (core, ds, print_color);
		if (ds->subjmp) {
			r_parse_filter (core->parser, ds->vat, core->flags, ds->hint, asm_str,
					ds->str, sizeof (ds->str), core->print->big_endian);
		} else {
			if (ds->opstr) {
				r_str_ncpy (ds->str, ds->opstr, sizeof (ds->str));
			}
		}
		free (asm_str);
		// subvar depends on filter
		if (ds->subvar) {
			// HACK to do subvar outside rparse becacuse the whole rparse api must be rewritten
			char *ox = strstr (ds->str, "0x");
			if (ox) {
				char *e = strchr (ox, ']');
				if (e) {
					e = strdup (e);
					ut64 addr = r_num_get (NULL, ox);
					if (addr > ds->min_ref_addr) {
						RFlagItem *fi = r_flag_get_i (ds->core->flags, addr);
						if (fi) {
							r_str_cpy (ox, fi->name);
							r_str_cat (ox, e);
						}
					}
					free (e);
				}
			}
		}
		core->parser->flagspace = ofs;
		free (ds->opstr);
		ds->opstr = strdup (ds->str);
	} else {
		r_str_trim (ds->opstr); // trim before coloring git
		char *asm_str = colorize_asm_string (core, ds, print_color);
		free (ds->opstr);
		ds->opstr = asm_str;
	}
	r_str_trim (ds->opstr);
	// updates ds->opstr
	__replaceImports (ds);
	if (ds->show_color) {
		int i = 0;
		char *word = NULL;
		char *bgcolor = NULL;
		const char *wcdata = r_meta_get_string (ds->core->anal, R_META_TYPE_HIGHLIGHT, ds->at);
		int argc = 0;
		char **wc_array = r_str_argv (wcdata, &argc);
		for (i = 0; i < argc; i++) {
			bgcolor = strchr (wc_array[i], '\x1b');
			word = r_str_newlen (wc_array[i], bgcolor - wc_array[i]);
			ds_highlight_word (ds, word, bgcolor);
		}
	}
}

R_API RAnalHint *r_core_hint_begin(RCore *core, RAnalHint* hint, ut64 at) {
	static char *hint_syntax = NULL;
	r_anal_hint_free (hint);
	hint = r_anal_hint_get (core->anal, at);
	if (hint_syntax) {
		r_config_set (core->config, "asm.syntax", hint_syntax);
		hint_syntax = NULL;
	}
	if (hint) {
		/* syntax */
		if (hint->syntax) {
			if (!hint_syntax) {
				hint_syntax = strdup (r_config_get (core->config, "asm.syntax"));
			}
			r_config_set (core->config, "asm.syntax", hint->syntax);
		}
		if (hint->high) {
			/* TODO: do something here */
		}
	}
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, at, 0);
	if (fcn) {
		if (fcn->bits == 16 || fcn->bits == 32) {
			if (!hint) {
				hint = R_NEW0 (RAnalHint);
			}
			hint->bits = fcn->bits;
			hint->new_bits = fcn->bits;
		}
	}
	return hint;
}

static void ds_pre_line(RDisasmState *ds) {
	ds_setup_pre (ds, false, false);
	ds_print_pre (ds, true);
	char *tmp = ds->line;
	char *tmp_col = ds->line_col;
	ds->line = ds->refline2;
	ds->line_col = ds->prev_line_col;
	ds_print_lines_left (ds);
	ds->line = tmp;
	ds->line_col = tmp_col;
}

static void ds_begin_line(RDisasmState *ds) {
	if (ds->pj) {
		pj_o (ds->pj);
		pj_kn (ds->pj, "offset", ds->vat);
		if (ds->core->anal->reflines) {
			RAnalRefline *ref;
			RListIter *iter;
			// XXX Probably expensive
			r_list_foreach (ds->core->anal->reflines, iter, ref) {
				if (ref->from == ds->vat) {
					pj_kn (ds->pj, "arrow", ref->to);
					break;
				}
			}
		}
		pj_k (ds->pj, "text");
	}
	ds->buf_line_begin = r_cons_get_buffer_len ();
	if (!ds->pj && ds->asm_hint_pos == -1) {
		if (!ds_print_core_vmode (ds, ds->asm_hint_pos)) {
			r_cons_printf ("    ");
		}
	}
}

static void ds_newline(RDisasmState *ds) {
	if (ds->pj) {
		const bool is_html = r_config_get_i (ds->core->config, "scr.html");
		if (is_html) {
			char *s = r_cons_html_filter (r_cons_get_buffer (), NULL);
			pj_s (ds->pj, s);
			free (s);
		} else {
			pj_s (ds->pj, r_cons_get_buffer ());
		}
		r_cons_reset ();
		pj_end (ds->pj);
	} else {
		r_cons_newline ();
	}
}

static void ds_begin_cont(RDisasmState *ds) {
	ds_begin_line (ds);
	ds_setup_print_pre (ds, false, false);
	if (!ds->linesright && ds->show_lines_bb && ds->line) {
		RAnalRefStr *refstr = r_anal_reflines_str (ds->core, ds->at,
		                    ds->linesopts | R_ANAL_REFLINE_TYPE_MIDDLE_AFTER);
		ds_print_ref_lines (refstr->str, refstr->cols, ds);
		r_anal_reflines_str_free (refstr);
	}
}

static void ds_begin_comment(RDisasmState *ds) {
	if (ds->show_comment_right) {
		CMT_ALIGN;
	} else {
		ds_begin_line (ds);
		ds_pre_xrefs (ds, false);
	}
}

static void ds_show_refs(RDisasmState *ds) {
	RAnalRef *ref;
	RListIter *iter;

	if (!ds->show_cmtrefs) {
		return;
	}
	RList *list = r_anal_xrefs_get_from (ds->core->anal, ds->at);

	r_list_foreach (list, iter, ref) {
		const char *cmt = r_meta_get_string (ds->core->anal, R_META_TYPE_COMMENT, ref->addr);
		const RList *fls = r_flag_get_list (ds->core->flags, ref->addr);
		RListIter *iter2;
		RFlagItem *fis;
		r_list_foreach (fls, iter2, fis) {
			ds_begin_comment (ds);
			ds_comment (ds, true, "; (%s)", fis->name);
		}

		// ds_align_comment (ds);
		if (ds->show_color) {
			r_cons_strcat (ds->color_comment);
		}
		if (cmt) {
			ds_begin_comment (ds);
			ds_comment (ds, true, "; (%s)", cmt);
		}
		if (ref->type & R_ANAL_REF_TYPE_CALL) {
			RAnalOp aop;
			ut8 buf[12];
			r_io_read_at (ds->core->io, ref->at, buf, sizeof (buf));
			r_anal_op (ds->core->anal, &aop, ref->at, buf, sizeof (buf), R_ANAL_OP_MASK_ALL);
			if ((aop.type & R_ANAL_OP_TYPE_MASK) == R_ANAL_OP_TYPE_UCALL) {
				RAnalFunction * fcn = r_anal_get_function_at (ds->core->anal, ref->addr);
				ds_begin_comment (ds);
				if (fcn) {
					ds_comment (ds, true, "; %s", fcn->name);
				} else {
					ds_comment (ds, true, "; 0x%" PFMT64x"", ref->addr);
				}
			}
		}
		ds_print_color_reset (ds);
	}
	r_list_free (list);
}

static void ds_show_xrefs(RDisasmState *ds) {
	RAnalRef *refi;
	RListIter *iter, *it;
	RCore *core = ds->core;
	char *name, *realname;
	int count = 0;
	if (!ds->show_xrefs || !ds->show_comments) {
		return;
	}
	/* show xrefs */
	RList *xrefs = r_anal_xrefs_get (core->anal, ds->at);
	if (!xrefs) {
		return;
	}
	// only show fcnline in xrefs when addr is not the beginning of a function
	bool fcnlines = (ds->fcn && ds->fcn->addr == ds->at);
	if (r_list_length (xrefs) > ds->maxrefs) {
		ds_begin_line (ds);
		ds_pre_xrefs (ds, fcnlines);
		ds_comment (ds, false, "%s; XREFS(%d)",
			ds->show_color? ds->pal_comment: "",
			r_list_length (xrefs));
		if (ds->show_color) {
			ds_print_color_reset (ds);
		}
		ds_newline (ds);
		r_list_free (xrefs);
		return;
	}
	if (r_list_length (xrefs) > ds->foldxrefs) {
		int cols = r_cons_get_size (NULL);
		cols -= 15;
		cols /= 23;
		cols = cols > 5 ? 5 : cols;
		ds_begin_line (ds);
		ds_pre_xrefs (ds, fcnlines);
		ds_comment (ds, false, "%s; XREFS: ", ds->show_color? ds->pal_comment: "");
		r_list_foreach (xrefs, iter, refi) {
			ds_comment (ds, false, "%s 0x%08"PFMT64x"  ",
				r_anal_xrefs_type_tostring (refi->type), refi->addr);
			if (count == cols) {
				if (iter->n) {
					ds_print_color_reset (ds);
					ds_newline (ds);
					ds_begin_line (ds);
					ds_pre_xrefs (ds, fcnlines);
					ds_comment (ds, false, "%s; XREFS: ", ds->show_color? ds->pal_comment: "");
				}
				count = 0;
			} else {
				count++;
			}
		}
		ds_print_color_reset (ds);
		ds_newline (ds);
		r_list_free (xrefs);
		return;
	}

	RList *addrs = r_list_newf (free);
	RAnalFunction *fun, *next_fun;
	RFlagItem *f, *next_f;
	r_list_foreach (xrefs, iter, refi) {
		if (!ds->asm_xrefs_code && refi->type == R_ANAL_REF_TYPE_CODE) {
			continue;
		}
		if (refi->at == ds->at) {
			realname = NULL;
			fun = fcnIn (ds, refi->addr, -1);
			if (fun) {
				if (iter != xrefs->tail) {
					ut64 next_addr = ((RAnalRef *)(iter->n->data))->addr;
					next_fun = r_anal_get_fcn_in (core->anal, next_addr, -1);
					if (next_fun && next_fun->addr == fun->addr) {
						r_list_append (addrs, r_num_dup (refi->addr));
						continue;
					}
				}
				if (ds->asm_demangle) {
					f = r_flag_get_by_spaces (core->flags, fun->addr, R_FLAGS_FS_SYMBOLS, NULL);
					if (f && f->demangled && f->realname) {
						realname = strdup (f->realname);
					}
				}
				name = strdup (fun->name);
				r_list_append (addrs, r_num_dup (refi->addr));
			} else {
				f = r_flag_get_at (core->flags, refi->addr, true);
				if (f) {
					if (iter != xrefs->tail) {
						ut64 next_addr = ((RAnalRef *)(iter->n->data))->addr;
						next_f = r_flag_get_at (core->flags, next_addr, true);
						if (next_f && f->offset == next_f->offset) {
							r_list_append (addrs, r_num_dup (refi->addr - f->offset));
							continue;
						}
					}
					if (ds->asm_demangle) {
						RFlagItem *f_sym = f;
						if (!r_str_startswith (f_sym->name, "sym.")) {
							f_sym = r_flag_get_by_spaces (core->flags, f->offset,
							                              R_FLAGS_FS_SYMBOLS, NULL);
						}
						if (f_sym && f_sym->demangled && f_sym->realname) {
							f = f_sym;
							realname = strdup (f->realname);
						}
					}
					name = strdup (f->name);
					r_list_append (addrs, r_num_dup (refi->addr - f->offset));
				} else {
					name = strdup ("unk");
				}
			}
			ds_begin_line (ds);
			ds_pre_xrefs (ds, fcnlines);
			const char* plural = r_list_length (addrs) > 1 ? "S" : "";
			const char* plus = fun ? "" : "+";
			ds_comment (ds, false, "%s; %s XREF%s from %s @ ",
				COLOR (ds, pal_comment), r_anal_xrefs_type_tostring (refi->type), plural,
				realname ? realname : name);
			ut64 *addrptr;
			r_list_foreach (addrs, it, addrptr) {
				if (addrptr && *addrptr) {
					ds_comment (ds, false, "%s%s0x%"PFMT64x, it == addrs->head ? "" : ", ", plus, *addrptr);
				}
			}
			if (realname && (!fun || r_anal_get_function_at (core->anal, ds->at))) {
				const char *pad = ds->show_comment_right ? "" : " ";
				if (!ds->show_comment_right) {
					ds_newline (ds);
					ds_begin_line (ds);
					ds_pre_xrefs (ds, fcnlines);
				}
				ds_comment (ds, false, " %s; %s", pad, name);
			}
			ds_comment (ds, false, "%s", COLOR_RESET (ds));
			ds_newline (ds);
			r_list_purge (addrs);
			R_FREE (name);
			free (realname);
		} else {
			eprintf ("Corrupted database?\n");
		}
	}
	r_list_free (addrs);
	r_list_free (xrefs);
}

static void ds_atabs_option(RDisasmState *ds) {
	int n, i = 0, comma = 0, word = 0;
	int brackets = 0;
	char *t, *b;
	if (!ds || !ds->atabs) {
		return;
	}
	size_t bufasm_len = r_strbuf_length (&ds->asmop.buf_asm);
	size_t size = (bufasm_len * (ds->atabs + 1)) + 8;
	if (size < 1 || size < bufasm_len) {
		return;
	}
	b = malloc (size + 1);
	if (!b) {
		return;
	}
	if (ds->opstr) {
		strcpy (b, ds->opstr);
	} else {
		strcpy (b, r_asm_op_get_asm (&ds->asmop));
	}
	free (ds->opstr);
	ds->opstr = b;
	for (; *b; b++, i++) {
		if (*b == '(' || *b == '[') {
			brackets++;
		}
		if (*b == ')' || *b == ']') {
			brackets--;
		}
		if (*b == ',') {
			comma = 1;
		}
		if (*b != ' ') {
			continue;
		}
		if (word > 0 && !comma) {
			continue; //&& b[1]=='[') continue;
		}
		if (brackets > 0) {
			continue;
		}
		comma = 0;
		brackets = 0;
		n = (ds->atabs - i);
		t = strdup (b + 1); //XXX slow!
		if (n < 1) {
			n = 1;
		}
		memset (b, ' ', n);
		b += n;
		strcpy (b, t);
		free (t);
		i = 0;
		word++;
		if (ds->atabsonce) {
			break;
		}
	}
}

static int handleMidFlags(RCore *core, RDisasmState *ds, bool print) {
	int i;

	ds->midflags = r_config_get_i (core->config, "asm.flags.middle");
	ds->hasMidflag = false;
	if (ds->midcursor && core->print->cur != -1) {
		ut64 cur = core->offset + core->print->cur;
		ut64 from = ds->at;
		ut64 to = ds->at + ds->oplen;
		if (cur > from && cur < to) {
			return cur - from;
		}
	}
	if (ds->midflags == R_MIDFLAGS_HIDE) {
		return 0;
	}

	for (i = 1; i < ds->oplen; i++) {
		RFlagItem *fi = r_flag_get_i (core->flags, ds->at + i);
		if (fi && fi->name) {
			if (r_anal_get_block_at (core->anal, ds->at)) {
				ds->midflags = ds->midflags? R_MIDFLAGS_SHOW: R_MIDFLAGS_HIDE;
			}
			if (ds->midflags == R_MIDFLAGS_REALIGN && ((fi->name[0] == '$') || (fi->realname && fi->realname[0] == '$'))) {
				i = 0;
			} else if (!strncmp (fi->name, "hit.", 4)) { // use search.prefix ?
				i = 0;
			} else if (!strncmp (fi->name, "str.", 4)) {
				ds->midflags = R_MIDFLAGS_REALIGN;
			} else if (!strncmp (fi->name, "reloc.", 6)) {
				continue;
			} else if (ds->midflags == R_MIDFLAGS_SYMALIGN) {
				if (strncmp (fi->name, "sym.", 4)) {
					continue;
				}
			}
			ds->hasMidflag = true;
			return i;
		}
	}
	return 0;
}

static int handleMidBB(RCore *core, RDisasmState *ds) {
	int i;
	ds->hasMidbb = false;
	r_return_val_if_fail (core->anal, 0);
	// Unfortunately, can't just check the addr of the last insn byte since
	// a bb (and fcn) can be as small as 1 byte, and advancing i based on
	// bb->size is unsound if basic blocks can nest or overlap
	for (i = 1; i < ds->oplen; i++) {
		RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, ds->at + i, 0);
		if (fcn) {
			RAnalBlock *bb = r_anal_fcn_bbget_in (core->anal, fcn, ds->at + i);
			if (bb && bb->addr > ds->at) {
				ds->hasMidbb = true;
				return bb->addr - ds->at;
			}
		}
	}
	return 0;
}

R_API int r_core_flag_in_middle(RCore *core, ut64 at, int oplen, int *midflags) {
	r_return_val_if_fail (midflags, 0);
	RDisasmState ds = {
		.at = at,
		.oplen = oplen,
		.midflags = *midflags
	};
	int ret = handleMidFlags (core, &ds, true);
	*midflags = ds.midflags;
	return ret;
}

R_API int r_core_bb_starts_in_middle(RCore *core, ut64 at, int oplen) {
	RDisasmState ds = {
		.at = at,
		.oplen = oplen
	};
	return handleMidBB (core, &ds);
}

static void ds_print_show_cursor(RDisasmState *ds) {
	RCore *core = ds->core;
	char res[] = "     ";
	if (!ds->show_marks) {
		return;
	}
	int q = core->print->cur_enabled &&
		ds->cursor >= ds->index &&
		ds->cursor < (ds->index + ds->asmop.size);
	RBreakpointItem *p = r_bp_get_at (core->dbg->bp, ds->at);
	(void)handleMidFlags (core, ds, false);
	if (ds->midbb) {
		(void)handleMidBB (core, ds);
	}
	if (p) {
		res[0] = 'b';
	}
	if (ds->hasMidflag || ds->hasMidbb) {
		res[1] = '~';
	}
	if (q) {
		if (ds->cursor == ds->index) {
			res[2] = '*';
		} else {
			int i = 2, diff = ds->cursor - ds->index;
			if (diff > 9) {
				res[i++] = '0' + (diff / 10);
			}
			res[i] = '0' + (diff % 10);
		}
	}
	r_cons_strcat (res);
}

static void ds_pre_xrefs(RDisasmState *ds, bool no_fcnlines) {
	ds_setup_pre (ds, false, false);
	if (ds->pre != DS_PRE_NONE && ds->pre != DS_PRE_EMPTY) {
		ds->pre = no_fcnlines ? DS_PRE_EMPTY : DS_PRE_FCN_MIDDLE;
	}
	ds_print_pre (ds, !no_fcnlines);
	char *tmp = ds->line;
	char *tmp_col = ds->line_col;
	ds->line = ds->refline2;
	ds->line_col = ds->prev_line_col;
	ds_print_lines_left (ds);
	if (!ds->show_offset && ds->show_marks) {
		ds_print_show_cursor (ds);
	}
	ds->line = tmp;
	ds->line_col = tmp_col;
}

//TODO: this function is a temporary fix. All analysis should be based on realsize. However, now for same architectures realisze is not used
static ut32 tmp_get_realsize (RAnalFunction *f) {
	ut32 size = r_anal_function_realsize (f);
	return (size > 0) ? size : r_anal_function_linear_size (f);
}

static void ds_show_functions_argvar(RDisasmState *ds, RAnalFunction *fcn, RAnalVar *var, const char *base, bool is_var, char sign) {
	int delta = var->kind == 'b' ? R_ABS (var->delta + fcn->bp_off) : R_ABS (var->delta - ((var->kind=='s')?8:0));
	const char *pfx = is_var ? "var" : "arg";
	char *constr = r_anal_var_get_constraints_readable (var);
	r_cons_printf ("%s%s %s%s%s%s %s%s%s%s@ %s%c0x%x", COLOR_ARG (ds, color_func_var), pfx,
			COLOR_ARG (ds, color_func_var_type), var->type,
			r_str_endswith (var->type, "*") ? "" : " ",
			var->name, COLOR_ARG (ds, color_func_var_addr),
			constr? " { ":"",
			r_str_get (constr),
			constr? "} ":"",
			base, sign, delta);
	if (ds->show_varsum == -1) {
		char *val = r_core_cmd_strf (ds->core, ".afvd %s", var->name);
		if (val) {
			r_str_replace_char (val, '\n', '\0');
			r_cons_printf (" = %s", val);
			free (val);
		}
	}
	free (constr);
}

static void printVarSummary(RDisasmState *ds, RList *list) {
	const char *numColor = ds->core->cons->context->pal.num;
	RAnalVar *var;
	RListIter *iter;
	int bp_vars = 0;
	int sp_vars = 0;
	int rg_vars = 0;
	int bp_args = 0;
	int sp_args = 0;
	int rg_args = 0;
	const char *bp_vars_color = COLOR_RESET (ds);
	const char *sp_vars_color = COLOR_RESET (ds);
	const char *rg_vars_color = COLOR_RESET (ds);
	const char *bp_args_color = COLOR_RESET (ds);
	const char *sp_args_color = COLOR_RESET (ds);
	const char *rg_args_color = COLOR_RESET (ds);
	r_list_foreach (list, iter, var) {
		if (var->isarg) {
			switch (var->kind) {
			case 'b':
				bp_args++;
				break;
			case 's':
				sp_args++;
				break;
			case 'r':
				rg_args++;
				break;
			}
		} else {
			switch (var->kind) {
			case 'b':
				bp_vars++;
				break;
			case 's':
				sp_vars++;
				break;
			case 'r':
				rg_vars++;
				break;
			}
		}
	}
	if (bp_vars) { bp_vars_color = numColor; }
	if (sp_vars) { sp_vars_color = numColor; }
	if (rg_vars) { rg_vars_color = numColor; }
	if (bp_args) { bp_args_color = numColor; }
	if (sp_args) { sp_args_color = numColor; }
	if (rg_args) { rg_args_color = numColor; }
	if (ds->show_varsum == 2) {
		ds_begin_line (ds);
		ds_print_pre (ds, true);
		r_cons_printf ("vars: %s%d%s %s%d%s %s%d%s",
				bp_vars_color, bp_vars, COLOR_RESET (ds),
				sp_vars_color, sp_vars, COLOR_RESET (ds),
				rg_vars_color, rg_vars, COLOR_RESET (ds));
		ds_newline (ds);
		ds_begin_line (ds);
		ds_print_pre (ds, true);
		r_cons_printf ("args: %s%d%s %s%d%s %s%d%s",
				bp_args_color, bp_args, COLOR_RESET (ds),
				sp_args_color, sp_args, COLOR_RESET (ds),
				rg_args_color, rg_args, COLOR_RESET (ds));
		ds_newline (ds);
		return;
	}
	ds_begin_line (ds);
	ds_print_pre (ds, true);
	r_cons_printf ("bp: %s%d%s (vars %s%d%s, args %s%d%s)",
			bp_args || bp_vars ? numColor : COLOR_RESET (ds), bp_args + bp_vars, COLOR_RESET (ds),
			bp_vars_color, bp_vars, COLOR_RESET (ds),
			bp_args_color, bp_args, COLOR_RESET (ds));
	ds_newline (ds);
	ds_begin_line (ds);
	ds_print_pre (ds, true);
	r_cons_printf ("sp: %s%d%s (vars %s%d%s, args %s%d%s)",
			sp_args || sp_vars ? numColor : COLOR_RESET (ds), sp_args+sp_vars, COLOR_RESET (ds),
			sp_vars_color, sp_vars, COLOR_RESET (ds),
			sp_args_color, sp_args, COLOR_RESET (ds));
	ds_newline (ds);
	ds_begin_line (ds);
	ds_print_pre (ds, true);
	r_cons_printf ("rg: %s%d%s (vars %s%d%s, args %s%d%s)",
			rg_args || rg_vars ? numColor : COLOR_RESET (ds), rg_args+rg_vars, COLOR_RESET (ds),
			rg_vars_color, rg_vars, COLOR_RESET (ds),
			rg_args_color, rg_args, COLOR_RESET (ds));
	ds_newline (ds);
}

static bool empty_signature(const char *s) {
	return (s && !strncmp (s, "void ", 5) && strstr (s, "()"));
}

static void ds_show_functions(RDisasmState *ds) {
	RAnalFunction *f;
	RCore *core = ds->core;
	char *fcn_name;
	bool fcn_name_alloc = false; // whether fcn_name needs to be freed by this function

	if (!ds->show_functions) {
		return;
	}
	bool demangle = r_config_get_i (core->config, "bin.demangle");
	bool keep_lib = r_config_get_i (core->config, "bin.demangle.libs");
	bool showSig = ds->show_fcnsig && ds->show_calls;
	bool call = r_config_get_i (core->config, "asm.calls");
	const char *lang = demangle ? r_config_get (core->config, "bin.lang") : NULL;
	f = r_anal_get_function_at (core->anal, ds->at);
	if (!f) {
		return;
	}
	if (demangle) {
		fcn_name = r_bin_demangle (core->bin->cur, lang, f->name, f->addr, keep_lib);
		if (fcn_name) {
			fcn_name_alloc = true;
		} else {
			fcn_name = f->name;
		}
	} else {
		fcn_name = f->name;
	}

	ds_begin_line (ds);
	char *sign = r_anal_function_get_signature (f);
	if (empty_signature (sign)) {
		R_FREE (sign);
	}
	if (f->type == R_ANAL_FCN_TYPE_LOC) {
		r_cons_printf ("%s%s ", COLOR (ds, color_fline),
			core->cons->vline[LINE_CROSS]); // |-
		if (!showSig) {
			r_cons_printf ("%s%s%s %"PFMT64u, COLOR (ds, color_floc),
					fcn_name, COLOR_RESET (ds), r_anal_function_linear_size (f));
			ds_newline (ds);
		}
	} else {
		const char *fcntype;
		char cmt[32];
		get_bits_comment (core, f, cmt, sizeof (cmt));

		switch (f->type) {
		case R_ANAL_FCN_TYPE_FCN:
		case R_ANAL_FCN_TYPE_SYM:
			fcntype = "fcn";
			break;
		case R_ANAL_FCN_TYPE_IMP:
			fcntype = "imp";
			break;
		default:
			fcntype = "loc";
			break;
		}
		//ds_set_pre (ds, core->cons->vline[CORNER_TL]);
		if (ds->show_lines_fcn) {
			ds->pre = DS_PRE_FCN_HEAD;
		}
		ds_print_pre (ds, true);
		if (ds->show_flgoff) {
			ds_print_lines_left (ds);
			ds_print_offset (ds);
		}
		if (!showSig) {
			r_cons_printf ("%s(%s) %s%s%s %d", COLOR (ds, color_fname),
					fcntype, fcn_name, cmt, COLOR_RESET (ds), tmp_get_realsize (f));
			ds_newline (ds);
		}
	}
	if (!showSig) {
		if (sign) {
			ds_begin_line (ds);
			r_cons_printf ("// %s", sign);
			ds_newline (ds);
		}
	}
	R_FREE (sign);
	if (ds->show_lines_fcn) {
		ds->pre = DS_PRE_FCN_MIDDLE;
	}
	ds->stackptr = core->anal->stackptr;
	RAnalFcnVarsCache vars_cache;
	r_anal_fcn_vars_cache_init (core->anal, &vars_cache, f);

	int o_varsum = ds->show_varsum;
	if (ds->interactive && !o_varsum) {
		int padding = 10;
		int numvars = vars_cache.bvars->length + vars_cache.rvars->length + vars_cache.svars->length + padding;
		if (numvars > ds->l) {
			ds->show_varsum = 1;
		} else {
			ds->show_varsum = 0;
		}
	}

	if (call) {
		if (!showSig) {
			ds_begin_line (ds);
			r_cons_print (COLOR (ds, color_fline));
			ds_print_pre (ds, true);
			r_cons_printf ("%s  ", COLOR_RESET (ds));
		}
		r_cons_printf ("%" PFMT64d ": ", r_anal_function_realsize (f));

		// show function's realname in the signature if realnames are enabled
		if (core->flags->realnames) {
			RFlagItem *flag = r_flag_get (core->flags, fcn_name);
			if (flag && flag->realname) {
				fcn_name = flag->realname;
			}
		}

		char *sig = r_anal_fcn_format_sig (core->anal, f, fcn_name, &vars_cache, COLOR (ds, color_fname), COLOR_RESET (ds));
		if (sig) {
			r_cons_print (sig);
			free (sig);
		}
		ds_newline (ds);
	}

	if (ds->show_vars) {
		if (ds->show_varsum && ds->show_varsum != -1) {
			RList *all_vars = vars_cache.bvars;
			r_list_join (all_vars, vars_cache.svars);
			r_list_join (all_vars, vars_cache.rvars);
			printVarSummary (ds, all_vars);
		} else {
			char spaces[32];
			RAnalVar *var;
			RListIter *iter;
			RList *all_vars = vars_cache.bvars;
			r_list_join (all_vars, vars_cache.svars);
			r_list_join (all_vars, vars_cache.rvars);
			r_list_foreach (all_vars, iter, var) {
				ds_begin_line (ds);
				int idx;
				RAnal *anal = ds->core->anal;
				memset (spaces, ' ', sizeof(spaces));
				idx = 12 - strlen (var->name);
				if (idx < 0) {
					idx = 0;
				}
				spaces[idx] = 0;
				ds_pre_xrefs (ds, false);

				if (ds->show_flgoff) {
					ds_print_offset (ds);
				}
				r_cons_printf ("%s; ", COLOR_ARG (ds, color_func_var));
				switch (var->kind) {
				case R_ANAL_VAR_KIND_BPV: {
					char sign = var->isarg || (-var->delta <= f->bp_off) ? '+' : '-';
					bool is_var = !var->isarg;
					ds_show_functions_argvar (ds, f, var,
						anal->reg->name[R_REG_NAME_BP], is_var, sign);
					}
					break;
				case R_ANAL_VAR_KIND_REG: {
					RRegItem *i = r_reg_index_get (anal->reg, var->delta);
					if (!i) {
						eprintf ("Register not found");
						break;
					}
					r_cons_printf ("%sarg %s%s%s%s %s@ %s", COLOR_ARG (ds, color_func_var),
						COLOR_ARG (ds, color_func_var_type),
						var->type, r_str_endswith (var->type, "*") ? "" : " ",
						var->name, COLOR_ARG (ds, color_func_var_addr), i->name);
					if (ds->show_varsum == -1) {
						char *val = r_core_cmd_strf (ds->core, ".afvd %s", var->name);
						if (val) {
							r_str_replace_char (val, '\n', '\0');
							r_cons_printf ("%s", val);
							free (val);
						}
					}
					}
					break;
				case R_ANAL_VAR_KIND_SPV: {
					bool is_var = !var->isarg;
					int saved_delta = var->delta;
					var->delta = f->maxstack + var->delta;
					char sign = var->isarg || (-var->delta <= f->maxstack) ? '+' : '-';
					ds_show_functions_argvar (ds, f, var,
						anal->reg->name[R_REG_NAME_SP],
						is_var, sign);
					var->delta = saved_delta;
					}
					break;
				}
				if (var->comment) {
					r_cons_printf ("    %s; %s", COLOR (ds, color_comment), var->comment);
				}
				r_cons_print (COLOR_RESET (ds));
				ds_newline (ds);
			}
		}
	}
	ds->show_varsum = o_varsum;
	r_anal_fcn_vars_cache_fini (&vars_cache);
	if (fcn_name_alloc) {
		free (fcn_name);
	}
	{
		RListIter *iter;
		char *imp;
		if (ds->fcn && ds->fcn->imports) {
			r_list_foreach (ds->fcn->imports, iter, imp) {
				ds_print_pre (ds, true);
				ds_print_lines_left(ds);
				r_cons_printf (".import %s", imp);
				ds_newline (ds);
			}
		}
		r_list_foreach (ds->core->anal->imports, iter, imp) {
			ds_print_pre (ds, true);
			ds_print_lines_left(ds);
			r_cons_printf (".globalimport %s", imp);
			ds_newline (ds);
		}
	}
}

static void ds_setup_print_pre(RDisasmState *ds, bool tail, bool middle) {
	ds_setup_pre (ds, tail, middle);
	ds_print_pre (ds, true);
}

static void ds_setup_pre(RDisasmState *ds, bool tail, bool middle) {
	ds->cmtcount = 0;
	if (!ds->show_functions || !ds->show_lines_fcn) {
		ds->pre = DS_PRE_NONE;
		return;
	}
	ds->pre = DS_PRE_EMPTY;
	RAnalFunction *f = fcnIn (ds, ds->at, R_ANAL_FCN_TYPE_NULL);
	if (f) {
		if (f->addr == ds->at) {
			if (ds->analop.size == r_anal_function_linear_size (f) && !middle) {
				ds->pre = DS_PRE_FCN_TAIL;
			} else {
				ds->pre = DS_PRE_FCN_MIDDLE;
			}
		} else if (r_anal_function_max_addr (f) - ds->analop.size == ds->at && f->addr == r_anal_function_min_addr (f)) {
			ds->pre = DS_PRE_FCN_TAIL;
		} else if (r_anal_function_contains (f, ds->at)) {
			ds->pre = DS_PRE_FCN_MIDDLE;
		}
		if (tail) {
			if (ds->pre == DS_PRE_FCN_TAIL) {
				ds->pre = DS_PRE_EMPTY;
			}
			if (ds->pre == DS_PRE_FCN_MIDDLE) {
				ds->pre = DS_PRE_FCN_TAIL;
			}
		}
	}
}

static void ds_print_pre(RDisasmState *ds, bool fcnline) {
	RCore *core = ds->core;
	int pre = ds->pre;
	const char *c = NULL;
	if (!fcnline) {
		pre = DS_PRE_EMPTY;
	}
	switch (pre) {
	case DS_PRE_FCN_HEAD:
		c = core->cons->vline[CORNER_TL];
		break;
	case DS_PRE_FCN_MIDDLE:
		c = core->cons->vline[LINE_VERT];
		break;
	case DS_PRE_FCN_TAIL:
		c = core->cons->vline[CORNER_BL];
		break;
	case DS_PRE_EMPTY:
		r_cons_print ("  ");
		return;
	case DS_PRE_NONE:
	default:
		return;
	}
	char *kolor = strdup (ds->color_fline);
	RAnalBlock *bb;
	RList *list = r_anal_get_blocks_in (core->anal, ds->at);
	RListIter *iter;
	r_list_foreach (list, iter, bb) {
		if (bb->color.r || bb->color.g || bb->color.b) {
			free (kolor);
			kolor = r_cons_rgb_str (NULL, -1, &bb->color);
			break;
		}
	}
	r_cons_printf ("%s%s%s ", kolor, c, COLOR_RESET (ds));
	r_list_free (list);
	free (kolor);
}

static void ds_show_comments_describe(RDisasmState *ds) {
	/* respect asm.describe */
	char *desc = NULL;
	if (ds->asm_describe && !ds->has_description) {
		char *op, *locase = strdup (r_asm_op_get_asm (&ds->asmop));
		if (!locase) {
			return;
		}
		op = strchr (locase, ' ');
		if (op) {
			*op = 0;
		}
		r_str_case (locase, 0);
		desc = r_asm_describe (ds->core->rasm, locase);
		free (locase);
	}
	if (desc && *desc) {
		ds_begin_comment (ds);
		ds_align_comment (ds);
		if (ds->show_color) {
			r_cons_strcat (ds->color_comment);
		}
		r_cons_strcat ("; ");
		r_cons_strcat (desc);
		ds_print_color_reset (ds);
		ds_newline (ds);
		free (desc);
	}
}

//XXX review this with asm.cmt.right
static void ds_show_comments_right(RDisasmState *ds) {
	int linelen;
	RCore *core = ds->core;
	/* show comment at right? */
	int scr = ds->show_comment_right;
	if (!ds->show_comments && !ds->show_usercomments) {
		return;
	}
	RFlagItem *item = r_flag_get_i (core->flags, ds->at);
	const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, ds->at);
	const char *vartype = r_meta_get_string (core->anal, R_META_TYPE_VARTYPE, ds->at);
	if (!comment) {
		if (vartype) {
			ds->comment = r_str_newf ("%s; %s", COLOR_ARG (ds, color_func_var_type), vartype);
		} else if (item && item->comment && *item->comment) {
			ds->ocomment = item->comment;
			ds->comment = strdup (item->comment);
		}
	} else if (vartype) {
		ds->comment = r_str_newf ("%s; %s %s%s; %s", COLOR_ARG (ds, color_func_var_type), vartype, Color_RESET, COLOR (ds, color_usrcmt), comment);
	} else {
		ds->comment = r_str_newf ("%s; %s", COLOR_ARG (ds, color_usrcmt), comment);
	}
	if (!ds->comment || !*ds->comment) {
		return;
	}
	linelen = strlen (ds->comment) + 5;
	if (ds->show_comment_right_default) {
		if (ds->ocols + linelen < core->cons->columns) {
			if (!strchr (ds->comment, '\n')) { // more than one line?
				ds->show_comment_right = true;
			}
		}
	}
	if (!ds->show_comment_right) {
		ds_begin_line (ds);
		int mycols = ds->lcols;
		if ((mycols + linelen + 10) > core->cons->columns) {
			mycols = 0;
		}
		mycols /= 2;
		if (ds->show_color) {
			r_cons_strcat (ds->pal_comment);
		}
		/* print multiline comment */
		if (ds->cmtfold) {
			char *p = strdup (ds->comment);
			char *q = strchr (p, '\n');
			if (q) {
				*q = 0;
				r_cons_strcat (p);
				r_cons_strcat (" ; [z] unfold");
			}
			free (p);
		} else {
			ds_pre_xrefs (ds, false);
			if (ds->show_color) {
				r_cons_strcat (ds->color_usrcmt);
			}
			ds_comment (ds, false, "%s", ds->comment);
		}
		if (ds->show_color) {
			ds_print_color_reset (ds);
		}
		R_FREE (ds->comment);
		ds_newline (ds);
		/* flag one */
		if (item && item->comment && ds->ocomment != item->comment) {
			ds_begin_line (ds);
			ds_newline (ds);
			ds_begin_line (ds);
			if (ds->show_color) {
				r_cons_strcat (ds->pal_comment);
			}
			r_cons_strcat ("  ;  ");
			r_cons_strcat_justify (item->comment, mycols, ';');
			ds_newline (ds);
			if (ds->show_color) {
				ds_print_color_reset (ds);
			}
		}
	}
	ds->show_comment_right = scr;
}

static int flagCmp(const void *a, const void *b) {
	const RFlagItem *fa = a;
	const RFlagItem *fb = b;
	if (fa->realname && fb->realname) {
		return strcmp (fa->realname, fb->realname);
	}
	return strcmp (fa->name, fb->name);
}

static void __preline_flag(RDisasmState *ds, RFlagItem *flag) {
	ds_newline (ds);
	ds_begin_line (ds);
	ds_pre_line (ds);
	if (ds->show_color) {
		bool hasColor = false;
		if (flag->color) {
			char *color = r_cons_pal_parse (flag->color, NULL);
			if (color) {
				r_cons_strcat (color);
				free (color);
				ds->lastflag = flag;
				hasColor = true;
			}
		}
		if (!hasColor) {
			r_cons_strcat (ds->color_flag);
		}
	}
	if (!ds->show_offset) {
		r_cons_printf ("     ");
	}
}

static bool is_first (const char *fs) {
	if (fs) {
		if (strstr (fs, "segment")) {
			return true;
		}
		if (strstr (fs, "section")) {
			return true;
		}
		if (strstr (fs, "format")) {
			return true;
		}
		if (strstr (fs, "class")) {
			return true;
		}
	}
	return false;
}
static RList *custom_sorted_flags(const RList *flaglist) {
	RListIter *iter;
	RFlagItem *flag;
	if (!flaglist) {
		return NULL;
	}
	RList *list = r_list_uniq (flaglist, flagCmp);
	RList *res = r_list_newf (NULL);
	RList *rest = r_list_newf (NULL);
	RList *tail = r_list_newf (NULL);
	r_list_foreach (list, iter, flag) {
		const char *fs = flag->space? flag->space->name: NULL;
		if (is_first (fs)) {
			r_list_append (res, flag);
		} else {
			r_list_append (rest, flag);
		}
	}
	r_list_foreach (rest, iter, flag) {
		const char *fs = flag->space? flag->space->name: NULL;
		if (fs && !strcmp (fs, "registers")) {
			r_list_append (tail, flag);
		} else {
			r_list_append (res, flag);
		}
	}
	r_list_foreach (tail, iter, flag) {
		r_list_append (res, flag);
	}
	r_list_free (tail);
	r_list_free (rest);
	list->free = NULL;
	r_list_free (list);
	return res;
}

#define printPre (outline || !*comma)
static void ds_show_flags(RDisasmState *ds, bool overlapped) {
	//const char *beginch;
	RFlagItem *flag;
	RListIter *iter;
	RAnalFunction *f = NULL;
	if (!ds->show_flags) {
		return;
	}
	RCore *core = ds->core;
	char addr[64] = {0};
	ut64 switch_addr = UT64_MAX;
	int case_start = -1, case_prev = 0, case_current = 0;
	f = r_anal_get_function_at (ds->core->anal, ds->at);
	const RList *flaglist = r_flag_get_list (core->flags, ds->at);
	RList *uniqlist = custom_sorted_flags (flaglist);
	int count = 0;
	bool outline = !ds->flags_inline;
	const char *comma = "";
	bool keep_lib = r_config_get_i (core->config, "bin.demangle.libs");
	bool docolon = true;
	int nth = 0;
#if 0
	r_list_foreach (uniqlist, iter, flag) {
		r_cons_printf ("(%s)(at:%s),", flag->name, flag->space->name);
	}
#endif
	r_list_foreach (uniqlist, iter, flag) {
		if (!overlapped && f && f->addr == flag->offset && !strcmp (flag->name, f->name)) {
			// do not show non-overlapped flags that have the same name as the function
			// do not show flags that have the same name as the function
			continue;
		}
		bool no_fcn_lines = (!overlapped && f && f->addr == flag->offset);
		if (ds->maxflags && count >= ds->maxflags) {
			if (printPre) {
				ds_pre_xrefs (ds, no_fcn_lines);
			}
			r_cons_printf ("...");
			break;
		}
		count++;
		if (!strncmp (flag->name, "case.", 5)) {
			char *chop = strdup (flag->name + 5);
			char *dot = strchr (chop, '.');
			if (dot) {
				int mul = 1;
				*dot++ = 0;
				if (*dot == '_') {
					mul = -1;
					dot++;
				}
				ut64 saddr = r_num_get (core->num, chop);
				case_current = mul * atoi (dot);
				snprintf (addr, sizeof (addr), "0x%08"PFMT64x, saddr);
				R_FREE (chop);
				if (case_start == -1) {
					switch_addr = saddr;
					case_prev = case_current;
					case_start = case_current;
					if (iter != uniqlist->tail) {
						continue;
					}
				}
				if (case_current == case_prev + 1 && switch_addr == saddr) {
					case_prev = case_current;
					if (iter != uniqlist->tail) {
						continue;
					}
				}
			}
			R_FREE (chop);
		}
		if (printPre) {
			ds_begin_line (ds);
		}

		bool fake_flag_marks = (!ds->show_offset && ds->show_marks);
		if (printPre) {
			if (ds->show_flgoff) {
				ds_pre_line (ds);
				ds_print_offset (ds);
				if (!fake_flag_marks) {
					r_cons_printf (" ");
				}
			} else {
				ds_pre_xrefs (ds, no_fcn_lines);
			}
		}

		bool hasColor = false;
		char *color = NULL;
		if (ds->show_color) {
			if (flag->color) {
				color = r_cons_pal_parse (flag->color, NULL);
				if (color) {
					r_cons_strcat (color);
					ds->lastflag = flag;
					hasColor = true;
				}
			}
			if (!hasColor) {
				r_cons_strcat (ds->color_flag);
			}
		}

		if (ds->asm_demangle && flag->realname) {
			if (!strncmp (flag->name, "switch.", 7)) {
				r_cons_printf (FLAG_PREFIX"switch");
			} else if (!strncmp (flag->name, "case.", 5)) {
				if (nth > 0) {
					__preline_flag (ds, flag);
				}
				if (!strncmp (flag->name + 5, "default", 7)) {
					r_cons_printf (FLAG_PREFIX "default:"); // %s:", flag->name);
					r_str_ncpy (addr, flag->name + 5 + strlen ("default."), sizeof (addr));
					nth = 0;
				} else if (case_prev != case_start) {
					r_cons_printf (FLAG_PREFIX "case %d...%d:", case_start, case_prev);
					if (iter != uniqlist->head && iter != uniqlist->tail) {
						iter = iter->p;
					}
					case_start = case_current;
				} else {
					r_cons_printf (FLAG_PREFIX "case %d:", case_prev);
					case_start = -1;
				}
				case_prev = case_current;
				ds_align_comment (ds);
				r_cons_printf ("%s; from %s", ds->show_color ? ds->pal_comment : "", addr);
				outline = false;
				docolon = false;
			} else {
				const char *lang = r_config_get (core->config, "bin.lang");
				char *name = r_bin_demangle (core->bin->cur, lang, flag->realname, flag->offset, keep_lib);
				if (!name) {
					const char *n = flag->realname? flag->realname: flag->name;
					if (n) {
						name = strdup (n);
					}
				}
				if (name) {
					r_str_ansi_filter (name, NULL, NULL, -1);
					if (!ds->flags_inline || nth == 0) {
						r_cons_printf (FLAG_PREFIX);
						if (overlapped) {
							r_cons_printf ("%s(0x%08"PFMT64x")%s ",
									ds->show_color ? ds->color_offset : "", ds->at,
									ds->show_color ? (hasColor ? color : ds->color_flag): "");
						}
					}
					if (outline) {
						r_cons_printf ("%s:", name);
					} else {
						r_cons_printf ("%s%s", comma, flag->name);
					}
					R_FREE (name);
				}
			}
		} else {
			if (outline) {
				r_cons_printf ("%s", flag->name);
			} else {
				r_cons_printf ("%s%s", comma, flag->name);
			}
		}
		if (ds->show_color) {
			r_cons_strcat (Color_RESET);
		}
		if (outline) {
			ds_newline (ds);
		} else {
			comma = ", ";
		}
		nth++;
		free (color);
	}
	if (!outline && *comma) {
		if (nth > 0 && docolon) {
			r_cons_printf (":");
		}
		ds_newline (ds);
	}
	r_list_free (uniqlist);
}

static void ds_update_ref_lines(RDisasmState *ds) {
	if (ds->show_lines_bb) {
		free (ds->line);
		free (ds->line_col);
		RAnalRefStr *line = r_anal_reflines_str (ds->core, ds->at, ds->linesopts);
		ds->line = line->str;
		ds->line_col = line->cols;
		free (ds->refline);
		ds->refline = ds->line? strdup (ds->line): NULL;
		free (ds->refline2);
		free (ds->prev_line_col);
		free (line);
		line = r_anal_reflines_str (ds->core, ds->at,
			ds->linesopts | R_ANAL_REFLINE_TYPE_MIDDLE_BEFORE);
		ds->refline2 = line->str;
		ds->prev_line_col = line->cols;
		if (ds->line) {
			if (strchr (ds->line, '<')) {
				ds->indent_level++;
			}
			if (strchr (ds->line, '>')) {
				ds->indent_level--;
			}
		} else {
			ds->indent_level = 0;
		}
		free (line);
	} else {
		R_FREE (ds->line);
		R_FREE (ds->line_col);
		R_FREE (ds->prev_line_col);
		free (ds->refline);
		free (ds->refline2);
		free (ds->prev_line_col);
		ds->refline = strdup ("");
		ds->refline2 = strdup ("");
		ds->line = NULL;
		ds->line_col = NULL;
		ds->prev_line_col = NULL;
	}
}

static int ds_disassemble(RDisasmState *ds, ut8 *buf, int len) {
	RCore *core = ds->core;
	int ret;

	// find the meta item at this offset if any
	RPVector *metas = r_meta_get_all_at (ds->core->anal, ds->at); // TODO: do in range
	RAnalMetaItem *meta = NULL;
	ut64 meta_size = UT64_MAX;
	if (metas) {
		void **it;
		r_pvector_foreach (metas, it) {
			RIntervalNode *node = *it;
			RAnalMetaItem *mi = node->data;
			switch (mi->type) {
			case R_META_TYPE_DATA:
			case R_META_TYPE_STRING:
			case R_META_TYPE_FORMAT:
			case R_META_TYPE_MAGIC:
			case R_META_TYPE_HIDE:
			case R_META_TYPE_RUN:
				meta = mi;
				meta_size = r_meta_item_size (node->start, node->end);
				break;
			default:
				break;
			}
		}
		r_pvector_free (metas);
	}
	if (ds->hint && ds->hint->bits) {
		if (!ds->core->anal->opt.ignbithints) {
			r_config_set_i (core->config, "asm.bits", ds->hint->bits);
		}
	}
	if (ds->hint && ds->hint->size) {
		ds->oplen = ds->hint->size;
	}
	if (ds->hint && ds->hint->opcode) {
		free (ds->opstr);
		ds->opstr = strdup (ds->hint->opcode);
	}
	r_asm_op_fini (&ds->asmop);
	ret = r_asm_disassemble (core->rasm, &ds->asmop, buf, len);
	if (ds->asmop.size < 1) {
		ds->asmop.size = 1;
	}
	// handle meta here //
	if (!ds->asm_meta) {
		size_t i = 0;
		if (meta && meta_size > 0 && meta->type != R_META_TYPE_HIDE) {
			// XXX this is just noise. should be rewritten
			switch (meta->type) {
			case R_META_TYPE_DATA:
#if 0
				if (!R_STR_ISEMPTY (meta->str)) {
					r_cons_printf (".data: %s\n", meta->str);
				}
#endif
				i += meta_size;
				break;
			case R_META_TYPE_STRING:
				i += meta_size;
				break;
			case R_META_TYPE_FORMAT:
				r_cons_printf (".format : %s\n", meta->str);
				i += meta_size;
				break;
			case R_META_TYPE_MAGIC:
				r_cons_printf (".magic : %s\n", meta->str);
				i += meta_size;
				break;
			case R_META_TYPE_RUN:
				r_core_cmd0 (core, meta->str);
				break;
			default:
				break;
			}
			int sz = R_MIN (16, meta_size);
			ds->asmop.size = sz;
			r_asm_op_set_hexbuf (&ds->asmop, buf, sz);
			const char *tail = (meta_size > 16)? "...": "";
			switch (meta->type) {
			case R_META_TYPE_STRING:
				r_asm_op_set_asm (&ds->asmop, sdb_fmt (".string \"%s%s\"", meta->str, tail));
				break;
			default: {
				char *op_hex = r_asm_op_get_hex (&ds->asmop);
				r_asm_op_set_asm (&ds->asmop, sdb_fmt (".hex %s%s", op_hex, tail));
				bool be = ds->core->print->big_endian;
				int immbase = (ds->hint && ds->hint->immbase)? ds->hint->immbase: 0;
				switch (meta_size) {
				case 2:
					ds->analop.val = r_read_ble16 (buf, be);
					r_asm_op_set_asm (&ds->asmop, sdb_fmt (".word 0x%04hx%s", (ut16)ds->analop.val, tail));
					break;
				case 4:
					ds->analop.val = r_read_ble32 (buf, be);
					switch (immbase) {
					case 10:
						r_asm_op_set_asm (&ds->asmop, sdb_fmt (".int32 %d%s", (st32)ds->analop.val, tail));
						break;
					case 32:
						r_asm_op_set_asm (&ds->asmop, sdb_fmt (".ipaddr 0x%08x%s", (ut32)ds->analop.val, tail));
						break;
					default:
						r_asm_op_set_asm (&ds->asmop, sdb_fmt (".dword 0x%08x%s", (ut32)ds->analop.val, tail));
						break;
					}
					break;
				case 8:
					ds->analop.val = r_read_ble64 (buf, be);
					r_asm_op_set_asm (&ds->asmop, sdb_fmt (".qword 0x%016"PFMT64x"%s", ds->analop.val, tail));
					break;
				}
				free (op_hex);
				break;
			}
			}
			ds->oplen = meta_size;
			return i;
		}
	}

	if (ds->show_nodup) {
		const char *opname = (ret < 1)? "invalid": r_asm_op_get_asm (&ds->asmop);
		if (ds->prev_ins && !strcmp (ds->prev_ins, opname)) {
			if (!ds->prev_ins_eq) {
				ds->prev_ins_eq = true;
				r_cons_printf ("...");
			}
			ds->prev_ins_count++;
			return -31337;
		}
		if (ds->prev_ins_eq) {
			r_cons_printf ("dup (%d)\n", ds->prev_ins_count);
		}
		ds->prev_ins_count = 0;
		ds->prev_ins_eq = false;
		if (ds->prev_ins) {
			R_FREE (ds->prev_ins);
		}
		ds->prev_ins = strdup (r_asm_op_get_asm (&ds->asmop));
	}
	ds->oplen = ds->asmop.size;

	if (ret < 1) {
		ret = -1;
#if HASRETRY
		if (!ds->cbytes && ds->tries > 0) {
			ds->addr = core->rasm->pc;
			ds->tries--;
			ds->idx = 0;
			ds->retry = true;
			return ret;
		}
#endif
		ds->lastfail = 1;
		ds->asmop.size = (ds->hint && ds->hint->size) ? ds->hint->size : 1;
		ds->oplen = ds->asmop.size;
	} else {
		ds->lastfail = 0;
		ds->asmop.size = (ds->hint && ds->hint->size)
				? ds->hint->size
				: r_asm_op_get_size (&ds->asmop);
		ds->oplen = ds->asmop.size;
	}
	if (ds->pseudo) {
		r_parse_parse (core->parser, ds->opstr
				? ds->opstr
				: r_asm_op_get_asm (&ds->asmop),
				ds->str);
		free (ds->opstr);
		ds->opstr = strdup (ds->str);
	}
	if (ds->acase) {
		r_str_case (r_asm_op_get_asm (&ds->asmop), 1);
	} else if (ds->capitalize) {
		char *ba = r_asm_op_get_asm (&ds->asmop);
		*ba = toupper ((ut8)*ba);
	}
	if (meta && meta_size != UT64_MAX) {
		ds->oplen = meta_size;
	}
	return ret;
}

static void ds_control_flow_comments(RDisasmState *ds) {
	if (ds->show_comments && ds->show_cmtflgrefs) {
		RFlagItem *item;
		if (ds->asm_anal) {
			switch (ds->analop.type) {
			case R_ANAL_OP_TYPE_CALL:
				r_core_cmdf (ds->core, "af @ 0x%"PFMT64x, ds->analop.jump);
				break;
			}
		}
		switch (ds->analop.type) {
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_CALL:
			item = r_flag_get_i (ds->core->flags, ds->analop.jump);
			if (item && item->comment) {
				if (ds->show_color) {
					r_cons_strcat (ds->pal_comment);
				}
				ds_align_comment (ds);
				r_cons_printf ("  ; ref to %s: %s\n", item->name, item->comment);
				ds_print_color_reset (ds);
			}
			break;
		}
	}
}

static void ds_print_lines_right(RDisasmState *ds){
	if (ds->linesright && ds->show_lines_bb && ds->line) {
		ds_print_ref_lines (ds->line, ds->line_col, ds);
	}
}

static void printCol(RDisasmState *ds, char *sect, int cols, const char *color) {
	int pre;
	if (cols < 8) {
		cols = 8;
	}
	int outsz = cols + 32;
	char *out = malloc (outsz);
	if (!out) {
		return;
	}
	memset (out, ' ', outsz);
	out[outsz - 1] = 0;
	int sect_len = strlen (sect);

	if (sect_len > cols) {
		sect[cols - 2] = '.';
		sect[cols - 1] = '.';
		sect[cols] = 0;
	}
	if (ds->show_color) {
		pre = strlen (color) + 1;
		snprintf (out, outsz-pre, "%s %s", color, sect);
		strcat (out, Color_RESET);
		out[outsz - 1] = 0;
	} else {
		r_str_ncpy (out + 1, sect, outsz - 2);
	}
	strcat (out, " ");
	r_cons_strcat (out);
	free (out);
}

static void ds_print_lines_left(RDisasmState *ds) {
	if (ds->linesright) {
		return;
	}
	RCore *core = ds->core;
	if (ds->show_section) {
		char *str = NULL;
		if (ds->show_section_perm) {
			// iosections must die, this should be rbin_section_get
			RIOMap *map = r_io_map_get_at (core->io, ds->at);
			str = strdup (map? r_str_rwx_i (map->perm): "---");
		}
		if (ds->show_section_name) {
			str = r_str_appendf (str, " %s", r_core_get_section_name (core, ds->at));
		}
		char *sect = str? str: strdup ("");
		printCol (ds, sect, ds->show_section_col, ds->color_reg);
		free (sect);
	}
	if (ds->show_symbols) {
		static RFlagItem sfi = R_EMPTY;
		const char *name = "";
		int delta = 0;
		if (ds->fcn) {
			sfi.offset = ds->fcn->addr;
			sfi.name = ds->fcn->name;
			ds->lastflag = &sfi;
		} else {
			RFlagItem *fi = r_flag_get_at (core->flags, ds->at, !ds->lastflag);
			if (fi) { // && (!ds->lastflag || fi->offset != ds->at))
				sfi.offset = fi->offset;
				sfi.name = fi->name;
				ds->lastflag = &sfi;
			}
		}
		if (ds->lastflag && ds->lastflag->name) {
			name = ds->lastflag->name;
			delta = ds->at - ds->lastflag->offset;
		}
		{
			char *str = r_str_newf ("%s + %-4d", name, delta);
			printCol (ds, str, ds->show_symbols_col, ds->color_num);
			free (str);
		}
	}
	if (ds->line) {
		ds_print_ref_lines (ds->line, ds->line_col, ds);
	}
}

static void ds_print_family(RDisasmState *ds) {
	if (ds->show_family) {
		const char *familystr = r_anal_op_family_to_string (ds->analop.family);
		r_cons_printf ("%5s ", r_str_get (familystr));
	}
}

static void ds_print_cycles(RDisasmState *ds) {
	if (ds->show_cycles) {
		if (!ds->analop.failcycles) {
			r_cons_printf ("%3d     ", ds->analop.cycles);
		} else {
			r_cons_printf ("%3d %3d ", ds->analop.cycles, ds->analop.failcycles);
		}
	}
	if (ds->cyclespace) {
		char spaces [32];
		int times = R_MIN (ds->analop.cycles/4, 30); // limit to 30
		memset (spaces, ' ', sizeof (spaces));
		spaces[times] = 0;
		r_cons_strcat (spaces);
	}
}

#include "disasm_stackptr.inc"

static void ds_print_offset(RDisasmState *ds) {
	RCore *core = ds->core;
	ut64 at = ds->vat;

	bool hasCustomColor = false;
	// probably tooslow
	RFlagItem *f = r_flag_get_at (core->flags, at, 1);
	if (ds->show_color && f) { // ds->lastflag) {
		const char *color = f->color;
		if (ds->at >= f->offset && ds->at < f->offset + f->size) {
		//	if (r_itv_inrange (f->itv, ds->at))
			if (color && *color) {
				char *k = r_cons_pal_parse (f->color, NULL);
				if (k) {
					r_cons_printf ("%s", k);
					hasCustomColor = true;
					free (k);
				}
			}
		}
	}
	r_print_set_screenbounds (core->print, at);
	if (ds->show_offset) {
		static RFlagItem sfi = R_EMPTY;
		const char *label = NULL;
		RFlagItem *fi;
		int delta = -1;
		bool show_trace = false;
		unsigned int seggrn = r_config_get_i (core->config, "asm.seggrn");

		if (ds->show_reloff) {
			RAnalFunction *f = r_anal_get_function_at (core->anal, at);
			if (!f) {
				f = fcnIn (ds, at, R_ANAL_FCN_TYPE_NULL); // r_anal_get_fcn_in (core->anal, at, R_ANAL_FCN_TYPE_NULL);
			}
			if (f) {
				delta = at - f->addr;
				sfi.name = f->name;
				sfi.offset = f->addr;
				ds->lastflag = &sfi;
				label = f->name;
			} else {
				if (ds->show_reloff_flags) {
					/* XXX: this is wrong if starting to disasm after a flag */
					fi = r_flag_get_i (core->flags, at);
					if (fi) {
						ds->lastflag = fi;
					}
					if (ds->lastflag) {
						if (ds->lastflag->offset == at) {
							delta = 0;
						} else {
							delta = at - ds->lastflag->offset;
						}
					} else {
						delta = at - core->offset;
					}
					if (ds->lastflag) {
						label = ds->lastflag->name;
					}
				}
			}
			if (!ds->lastflag) {
				delta = 0;
			}
		}
		if (ds->show_trace) {
			RDebugTracepoint *tp = r_debug_trace_get (ds->core->dbg, ds->at);
			show_trace = (tp? !!tp->count: false);
		}
		if (ds->hint && ds->hint->high) {
			show_trace = true;
		}
		if (hasCustomColor) {
			int of = core->print->flags;
			core->print->flags = 0;
			r_print_offset_sg (core->print, at, (at == ds->dest) || show_trace,
					ds->show_offseg, seggrn, ds->show_offdec, delta, label);
			core->print->flags = of;
			r_cons_strcat (Color_RESET);
		} else {
			r_print_offset_sg (core->print, at, (at == ds->dest) || show_trace,
					ds->show_offseg, seggrn, ds->show_offdec, delta, label);
		}
	}
	if (ds->atabsoff > 0 && ds->show_offset) {
		if (ds->_tabsoff != ds->atabsoff) {
			// TODO optimize to avoid down resizing
			char *b = malloc (ds->atabsoff + 1);
			if (b) {
				memset (b, ' ', ds->atabsoff);
				b[ds->atabsoff] = 0;
				free (ds->_tabsbuf);
				ds->_tabsbuf = b;
				ds->_tabsoff = ds->atabsoff;
			}
		}
		r_cons_strcat (ds->_tabsbuf);
	}
}

static void ds_print_op_size(RDisasmState *ds) {
	if (ds->show_size) {
		int size = ds->oplen;
		r_cons_printf ("%d ", size); //ds->analop.size);
	}
}

static void ds_print_trace(RDisasmState *ds) {
	RDebugTracepoint *tp = NULL;
	if (ds->show_trace) {
		tp = r_debug_trace_get (ds->core->dbg, ds->at);
		r_cons_printf ("%02x:%04x ", tp?tp->times:0, tp?tp->count:0);
	}
	if (ds->tracespace) {
		char spaces [32];
		int times;
		if (!tp) {
			tp = r_debug_trace_get (ds->core->dbg, ds->at);
		}
		if (tp) {
			times = R_MIN (tp->times, 30); // limit to 30
			memset (spaces, ' ', sizeof (spaces));
			spaces[times] = 0;
			r_cons_strcat (spaces);
		}
	}
}

static void ds_adistrick_comments(RDisasmState *ds) {
	if (ds->adistrick) {
		ds->middle = r_anal_reflines_middle (ds->core->anal,
			ds->core->anal->reflines, ds->at, ds->analop.size);
	}
}

// TODO move into RAnal.meta
static bool ds_print_data_type(RDisasmState *ds, const ut8 *obuf, int ib, int size) {
	RCore *core = ds->core;
	const char *type = NULL;
	char msg[64];
	const int isSigned = (ib == 1 || ib == 8 || ib == 10)? 1: 0;
	switch (size) {
	case 1: type = isSigned? ".char": ".byte"; break;
	case 2: type = isSigned? ".int16": ".word"; break;
	case 3: type = "htons"; break;
	case 4: type = isSigned? ".int32": ".dword"; break;
	case 8: type = isSigned? ".int64": ".qword"; break;
	default: return false;
	}
	ut8 buf[sizeof(ut64)] = {0};
	memcpy (buf, obuf, R_MIN (sizeof (ut64), size));
	// adjust alignment
	ut64 n = r_read_ble (buf, core->print->big_endian, size * 8);
	if (r_config_get_i (core->config, "asm.marks")) {
		r_cons_printf ("  ");
		int q = core->print->cur_enabled &&
			ds->cursor >= ds->index &&
			ds->cursor < (ds->index + size);
		if (q) {
			if (ds->cursor > ds->index) {
				int diff = ds->cursor - ds->index;
				r_cons_printf ("%d  ", diff);
			} else if (ds->cursor == ds->index) {
				r_cons_printf ("*  ");
			} else {
				r_cons_printf ("   ");
			}
		} else {
			r_cons_printf ("   ");
		}
	}

	r_cons_strcat (ds->color_mov);
	switch (ib) {
	case 1:
		r_str_bits (msg, buf, size * 8, NULL);
		r_cons_printf ("%s %sb", type, msg);
		break;
	case 3:
		r_cons_printf ("%s %d", type, ntohs (n & 0xFFFF));
		break;
	case 8:
		r_cons_printf ("%s %" PFMT64o "o", type, n);
		break;
	case 10:
		r_cons_printf ("%s %" PFMT64d, type, n);
		break;
	default:
		switch (size) {
		case 1:
			r_cons_printf ("%s 0x%02" PFMT64x, type, n);
			break;
		case 2:
			r_cons_printf ("%s 0x%04" PFMT64x, type, n);
			break;
		case 4:
			r_cons_printf ("%s 0x%08" PFMT64x, type, n);
			break;
		case 8:
			r_cons_printf ("%s 0x%016" PFMT64x, type, n);
			break;
		default:
			return false;
		}
	}

	if (size == 4 || size == 8) {
		if (r_str_startswith (r_config_get (core->config, "asm.arch"), "arm")) {
			ut64 bits = r_config_get_i (core->config, "asm.bits");
			//adjust address for arm/thumb address
			if (bits < 64) {
				if (n & 1) {
					n--;
				}
			}
		}
		if (n >= ds->min_ref_addr) {
			const RList *flags = r_flag_get_list (core->flags, n);
			RListIter *iter;
			RFlagItem *fi;
			r_list_foreach (flags, iter, fi) {
				r_cons_printf (" ; %s", fi->name);
			}
		}
	}
	return true;
}

static bool ds_print_meta_infos(RDisasmState *ds, ut8* buf, int len, int idx, int *mi_type) {
	bool ret = false;
	RAnalMetaItem *fmi;
	RCore *core = ds->core;
	if (!ds->asm_meta) {
		return false;
	}
	RPVector *metas = r_meta_get_all_in (core->anal, ds->at, R_META_TYPE_ANY);
	if (!metas) {
		return false;
	}
	bool once = true;
	fmi = NULL;
	void **it;
	r_pvector_foreach (metas, it) {
		RIntervalNode *node = *it;
		RAnalMetaItem *mi = node->data;
		switch (mi->type) {
		case R_META_TYPE_DATA:
			if (once) {
				if (ds->asm_hint_pos == 0) {
					if (ds->asm_hint_lea) {
						ds_print_shortcut (ds, node->start, 0);
					} else {
						r_cons_strcat ("   ");
					}
				}
				once = false;
			}
			break;
		case R_META_TYPE_STRING:
			fmi = mi;
			break;
		default:
			break;
		}
	}
	r_pvector_foreach (metas, it) {
		RIntervalNode *node = *it;
		RAnalMetaItem *mi = node->data;
		ut64 mi_size = r_meta_node_size (node);
		char *out = NULL;
		int hexlen;
		int delta;
		if (fmi && mi != fmi) {
			continue;
		}
		if (mi_type) {
			*mi_type = mi->type;
		}
		switch (mi->type) {
		case R_META_TYPE_STRING:
		if (mi->str) {
			bool esc_bslash = core->print->esc_bslash;

			switch (mi->subtype) {
			case R_STRING_ENC_UTF8:
				out = r_str_escape_utf8 (mi->str, false, esc_bslash);
				break;
			case 0:  /* temporary legacy workaround */
				esc_bslash = false;
				/* fallthrough */
			default:
				out = r_str_escape_latin1 (mi->str, false, esc_bslash, false);
			}
			if (!out) {
				break;
			}
			r_cons_printf ("    .string %s\"%s\"%s ; len=%"PFMT64d,
					COLOR (ds, color_btext), out, COLOR_RESET (ds),
					mi_size);
			free (out);
			delta = ds->at - node->start;
			ds->oplen = mi_size - delta;
			ds->asmop.size = (int)mi_size;
			//i += mi->size-1; // wtf?
			R_FREE (ds->line);
			R_FREE (ds->line_col);
			R_FREE (ds->refline);
			R_FREE (ds->refline2);
			R_FREE (ds->prev_line_col);
			ret = true;
			break;
		}
		case R_META_TYPE_HIDE:
			r_cons_printf ("(%"PFMT64d" bytes hidden)", mi_size);
			ds->asmop.size = mi_size;
			ds->oplen = mi_size;
			ret = true;
			break;
		case R_META_TYPE_RUN:
			r_core_cmdf (core, "%s @ 0x%"PFMT64x, mi->str, ds->at);
			ds->asmop.size = mi_size;
			ds->oplen = mi_size;
			ret = true;
			break;
		case R_META_TYPE_DATA:
			hexlen = len - idx;
			delta = ds->at - node->start;
			if (mi_size < hexlen) {
				hexlen = mi_size;
			}
			ds->oplen = mi_size - delta;
			core->print->flags &= ~R_PRINT_FLAGS_HEADER;
			int size = mi_size;
			ut8 *b = malloc (mi_size);
			if (b) {
				r_io_read_at (core->io, ds->at, b, mi_size);
				if (size > 0 && !ds_print_data_type (ds, b, ds->hint? ds->hint->immbase: 0, mi_size)) {
					if (size > delta) {
						r_cons_printf ("hex size=%d delta=%d\n", size , delta);
						int remaining = size - delta;
						remaining = R_MAX (remaining, 0);
						if (remaining > (len - delta)) {
							ut8 *b = calloc (1, size - delta);
							memcpy (b, buf, len);
							r_print_hexdump (core->print, ds->at,
									b + idx, remaining, 16, 1, 1);
							free (b);
						} else {
							r_print_hexdump (core->print, ds->at,
									buf + idx, remaining, 16, 1, 1);
						}
					} else {
						r_cons_printf ("hex size=%d hexlen=%d delta=%d",
								size, hexlen, delta);
					}
				}
				free (b);
			}
			core->print->flags |= R_PRINT_FLAGS_HEADER;
			ds->asmop.size = (int)size - (node->start - ds->at);
			R_FREE (ds->line);
			R_FREE (ds->line_col);
			R_FREE (ds->refline);
			R_FREE (ds->refline2);
			R_FREE (ds->prev_line_col);
			ret = true;
			break;
		case R_META_TYPE_FORMAT:
			{
				r_cons_printf ("pf %s # size=%" PFMT64d "\n", mi->str, mi_size);
				int len_before = r_cons_get_buffer_len ();
				r_print_format (core->print, ds->at, buf + idx,
						len - idx, mi->str, R_PRINT_MUSTSEE, NULL, NULL);
				int len_after = r_cons_get_buffer_len ();
				const char *cons_buf = r_cons_get_buffer ();
				if (len_after > len_before && buf && cons_buf[len_after - 1] == '\n') {
					r_cons_drop (1);
				}
				ds->oplen = ds->asmop.size = (int)mi_size;
				R_FREE (ds->line);
				R_FREE (ds->refline);
				R_FREE (ds->refline2);
				R_FREE (ds->prev_line_col);
				ret = true;
			}
			break;
		default:
			break;
		}
	}
	r_pvector_free (metas);
	return ret;
}

static st64 revert_cdiv_magic(st64 magic) {
	ut64 amagic = llabs (magic);
	const st64 N = ST64_MAX;
	st64 E, candidate;
	short s;

	if (amagic < 0xFFFFFF || amagic > UT32_MAX) {
		return 0;
	}
	if (magic < 0) {
		magic += 1LL << 32;
	}
	for (s = 0; s < 16; s++) {
		E = 1LL << (32 + s);
		candidate = (E + magic - 1) / magic;
		if (candidate > 0) {
			if ( ((N * magic) >> (32 + s)) == (N / candidate) ) {
				return candidate;
			}
		}
	}
	return 0;
}

static void ds_cdiv_optimization(RDisasmState *ds) {
	char *esil;
	char *end, *comma;
	st64 imm;
	st64 divisor;
	if (!ds->asm_hints || !ds->asm_hint_cdiv) {
		return;
	}
	switch (ds->analop.type) {
	case R_ANAL_OP_TYPE_MOV:
	case R_ANAL_OP_TYPE_MUL:
		esil = R_STRBUF_SAFEGET (&ds->analop.esil);
		while (esil) {
			comma = strchr (esil, ',');
			if (!comma) {
				break;
			}
			imm = strtol (esil, &end, 10);
			if (comma && comma == end) {
				divisor = revert_cdiv_magic (imm);
				if (divisor) {
					r_cons_printf (" ; CDIV: %lld * 2^n", divisor);
					break;
				}
			}
			esil = comma + 1;
		}
	}
	// /TODO: check following SHR instructions
}

static void ds_print_show_bytes(RDisasmState *ds) {
	RCore* core = ds->core;
	char *nstr, *str = NULL, pad[64];
	char *flagstr = NULL;
	int oldFlags = core->print->flags;
	char extra[128];
	int j, k;

	if (!ds->show_bytes || ds->nb < 1) {
		return;
	}
	if (!ds->show_color_bytes) {
		core->print->flags &= ~R_PRINT_FLAGS_COLOR;
	}
	strcpy (extra, " ");
	if (ds->show_flag_in_bytes) {
		flagstr = r_flag_get_liststr (core->flags, ds->at);
	}
	if (flagstr) {
		str = r_str_newf ("%s:", flagstr);
		if (ds->nb > 0) {
			k = ds->nb - strlen (str) - 1;
			if (k < 0) {
				str[ds->nb - 1] = '\0';
			}
			if (k > sizeof (pad)) {
				k = 0;
			}
			for (j = 0; j < k; j++) {
				pad[j] = ' ';
			}
			pad[j] = '\0';
		} else {
			pad[0] = 0;
		}
		R_FREE (flagstr);
	} else {
		if (ds->show_flag_in_bytes) {
			k = ds->nb - 1;
			if (k < 0 || k > sizeof (pad)) {
				k = 0;
			}
			for (j = 0; j < k; j++) {
				pad[j] = ' ';
			}
			pad[j] = '\0';
			str = strdup ("");
		} else {
			str = r_asm_op_get_hex (&ds->asmop);
			if (r_str_ansi_len (str) > ds->nb) {
				char *p = (char *)r_str_ansi_chrn (str, ds->nb);
				if (p)  {
					p[0] = '.';
					p[1] = '\0';
				}
			}
			ds->print->cur_enabled = (ds->cursor != -1);
			nstr = r_print_hexpair (ds->print, str, ds->index);
			if (ds->print->bytespace) {
				k = (ds->nb + (ds->nb / 2)) - r_str_ansi_len (nstr) + 2;
			} else {
				k = ds->nb - r_str_ansi_len (nstr) + 1;
			}
  			if (k > 0) {
				// setting to sizeof screw up the disasm
				if (k > sizeof (pad)) {
					k = 18;
				}
				for (j = 0; j < k; j++) {
					pad[j] = ' ';
				}
				pad[j] = 0;
				if (ds->lbytes) {
					// hack to align bytes left
					strcpy (extra, pad);
					*pad = 0;
				}
			} else {
				pad[0] = 0;
			}
			free (str);
			str = nstr;
		}
	}
	r_cons_printf ("%s%s %s", pad, str, extra);
	free (str);
	core->print->flags = oldFlags;
}

static void ds_print_indent(RDisasmState *ds) {
	if (ds->show_indent) {
		char indent[128];
		int num = ds->indent_level * ds->indent_space;
		if (num < 0) {
			num = 0;
		}
		if (num >= sizeof (indent)) {
			num = sizeof (indent) - 1;
		}
		memset (indent, ' ', num);
		indent[num] = 0;
		r_cons_strcat (indent);
	}
}

static void ds_print_optype(RDisasmState *ds) {
	if (ds->show_optype) {
		const char *optype = r_anal_optype_to_string (ds->analop.type);
		ds_print_color_reset (ds);
		const char *pad = r_str_pad (' ', 8 - strlen (optype));
		r_cons_printf ("[%s]%s", optype, pad);
	}
}

static void ds_print_opstr(RDisasmState *ds) {
	ds_print_indent (ds);
	if (ds->asm_instr) {
		r_cons_strcat (ds->opstr);
		ds_print_color_reset (ds);
	}
}

static void ds_print_color_reset(RDisasmState *ds) {
	if (ds->show_color) {
		r_cons_strcat (Color_RESET);
	}
}

static int ds_print_middle(RDisasmState *ds, int ret) {
	if (ds->middle != 0) {
		ret -= ds->middle;
		ds_align_comment (ds);
		if (ds->show_color) {
			r_cons_strcat (ds->pal_comment);
		}
		r_cons_printf (" ; *middle* %d", ret);
		if (ds->show_color) {
			r_cons_strcat (Color_RESET);
		}
	}
	return ret;
}

static bool ds_print_labels(RDisasmState *ds, RAnalFunction *f) {
	const char *label;
	if (!f) {
		// f = r_anal_get_fcn_in (core->anal, ds->at, 0);
		f = fcnIn (ds, ds->at, 0);
	}
	if (!f) {
		return false;
	}
	label = r_anal_function_get_label_at (f, ds->at);
	if (!label) {
		return false;
	}
	ds_pre_line (ds);
	if (ds->show_color) {
		r_cons_strcat (ds->color_label);
		r_cons_printf (" .%s:\n", label);
		ds_print_color_reset (ds);
	} else {
		r_cons_printf (" .%s:\n", label);
	}
	return true;
}

static void ds_print_sysregs(RDisasmState *ds) {
	RCore *core = ds->core;
	if (!ds->show_comments) {
		return;
	}
	switch (ds->analop.type) {
	// Syscalls first
	case R_ANAL_OP_TYPE_IO:
		{
			const int imm = (int)ds->analop.val;
			RSyscall *sc = core->anal->syscall;
			const char *ioname = r_syscall_get_io (sc, imm);
			if (ioname && *ioname) {
				CMT_ALIGN;
				ds_comment (ds, true, "; IO %s", ioname);
				ds->has_description = true;
			}
		}
		break;
	// Then sysregs
	case R_ANAL_OP_TYPE_MOV:
	case R_ANAL_OP_TYPE_LEA:
	case R_ANAL_OP_TYPE_LOAD:
	case R_ANAL_OP_TYPE_STORE:
		{
			const int imm = (int)ds->analop.ptr;
			const char *sr = r_syscall_sysreg (core->anal->syscall, "reg", imm);
			if (sr) {
				CMT_ALIGN;
				ds_comment (ds, true, "; REG %s - %s", sr, "");
				// TODO: add register description description
				ds->has_description = true;
			}
		}
		break;
	}
}

static void ds_print_fcn_name(RDisasmState *ds) {
	if (!ds->show_comments) {
		return;
	}
	if (ds->analop.type != R_ANAL_OP_TYPE_JMP
		&& ds->analop.type != R_ANAL_OP_TYPE_CJMP
		&& ds->analop.type != R_ANAL_OP_TYPE_CALL) {
		return;
	}
	RAnalFunction *f = fcnIn (ds, ds->analop.jump, R_ANAL_FCN_TYPE_NULL);
	if (!f && ds->core->flags && (!ds->core->vmode || (!ds->subjmp && !ds->subnames))) {
		const char *arch;
		RFlagItem *flag = r_flag_get_by_spaces (ds->core->flags, ds->analop.jump,
		                                        R_FLAGS_FS_CLASSES, R_FLAGS_FS_SYMBOLS, NULL);
		if (flag && flag->name && ds->opstr && !strstr (ds->opstr, flag->name)
		    && (r_str_startswith (flag->name, "sym.") || r_str_startswith (flag->name, "method."))
		    && (arch = r_config_get (ds->core->config, "asm.arch")) && strcmp (arch, "dalvik")) {
			RFlagItem *flag_sym = flag;
			if (ds->core->vmode && ds->asm_demangle
			    && (r_str_startswith (flag->name, "sym.")
			        || (flag_sym = r_flag_get_by_spaces (ds->core->flags, ds->analop.jump,
			                                             R_FLAGS_FS_SYMBOLS, NULL)))
			    && flag_sym->demangled) {
				return;
			}
			ds_begin_comment (ds);
			ds_comment (ds, true, "; %s", flag->name);
			return;
		}
	}
	if (!f || !f->name) {
		return;
	}
	st64 delta = ds->analop.jump - f->addr;
	const char *label = r_anal_function_get_label_at (f, ds->analop.jump);
	if (label) {
		ds_begin_comment (ds);
		ds_comment (ds, true, "; %s.%s", f->name, label);
	} else {
		RAnalFunction *f2 = fcnIn (ds, ds->at, 0);
		if (f == f2) {
			return;
		}
		if (delta > 0) {
			ds_begin_comment (ds);
			ds_comment (ds, true, "; %s+0x%x", f->name, delta);
		} else if (delta < 0) {
			ds_begin_comment (ds);
			ds_comment (ds, true, "; %s-0x%x", f->name, -delta);
		} else if ((!ds->core->vmode || (!ds->subjmp && !ds->subnames))
			   && (!ds->opstr || !strstr (ds->opstr, f->name))) {
			RFlagItem *flag_sym;
			if (ds->core->vmode && ds->asm_demangle
			    && (flag_sym = r_flag_get_by_spaces (ds->core->flags, ds->analop.jump,
			                                         R_FLAGS_FS_SYMBOLS, NULL))
			    && flag_sym->demangled) {
				return;
			}
			ds_begin_comment (ds);
			ds_comment (ds, true, "; %s", f->name);
		}
	}
}

static int ds_print_shortcut(RDisasmState *ds, ut64 addr, int pos) {
	char *shortcut = r_core_add_asmqjmp (ds->core, addr);
	int slen = shortcut? strlen (shortcut): 0;
	if (ds->asm_hint_pos > 0) {
		if (pos) {
			ds_align_comment (ds);
		}
	}
	const char *ch = (pos)? ";": "";
	if (ds->asm_hint_pos == -1) {
		ch = " ";
	}
	if (ds->show_color) {
		r_cons_strcat (ds->pal_comment);
	}
	if (*ch) {
		slen++;
	}
	if (shortcut) {
		if (ds->core->is_asmqjmps_letter) {
			r_cons_printf ("%s[o%s]", ch, shortcut);
			slen++;
		} else {
			r_cons_printf ("%s[%s]", ch, shortcut);
		}
		free (shortcut);
	} else {
		r_cons_printf ("%s[?]", ch);
	}
	if (ds->show_color) {
		if (ds->core->print->resetbg) {
			r_cons_strcat (Color_RESET);
		} else {
			r_cons_strcat (Color_RESET_NOBG);
		}
	}
	slen++;
	return slen;
}

static bool ds_print_core_vmode_jump_hit(RDisasmState *ds, int pos) {
	RCore *core = ds->core;
	RAnal *a = core->anal;
	RAnalHint *hint = r_anal_hint_get (a, ds->at);
	bool res = false;
	if (hint) {
		if (hint->jump != UT64_MAX) {
			ds_print_shortcut (ds, hint->jump, pos);
			res = true;
		}
		r_anal_hint_free (hint);
	}
	return res;
}

static ut64 get_ptr(RDisasmState *ds, ut64 addr) {
	ut8 buf[sizeof (ut64)] = {0};
	r_io_read_at (ds->core->io, addr, buf, sizeof (buf));
	ut64 n64_32;
	if (ds->core->rasm->bits == 64) {
		n64_32 = r_read_ble64 (buf, 0);
	} else {
		n64_32 = r_read_ble32 (buf, 0);
	}
	return n64_32;
}

static ut64 get_ptr_ble(RDisasmState *ds, ut64 addr) {
	ut8 buf[sizeof (ut64)] = {0};
	int endian = ds->core->rasm->big_endian;
	ut64 n64_32;
	r_io_read_at (ds->core->io, addr, buf, sizeof (buf));
	if (ds->core->rasm->bits == 64) {
		n64_32 = r_read_ble64 (buf, endian);
	} else {
		n64_32 = r_read_ble32 (buf, endian);
	}
	return n64_32;
}

static bool ds_print_core_vmode(RDisasmState *ds, int pos) {
	RCore *core = ds->core;
	bool gotShortcut = false;
	int i, slen = 0;

	if (!core->vmode) {
		return false;
	}
	if (!ds->asm_hints) {
		return false;
	}
	if (ds->asm_hint_emu) {
		if (ds->emuptr) {
			if (r_io_is_valid_offset (core->io, ds->emuptr, 0)) {
				ds_print_shortcut (ds, ds->emuptr, pos);
				//getPtr (ds, ds->emuptr, pos);
				ds->emuptr = 0;
				ds->hinted_line = true;
				gotShortcut = true;
				goto beach;
			}
		}
	}
	if (ds->asm_hint_lea) {
		ut64 size;
		RAnalMetaItem *mi = r_meta_get_at (ds->core->anal, ds->at, R_META_TYPE_ANY, &size);
		if (mi) {
			int obits = ds->core->rasm->bits;
			ds->core->rasm->bits = size * 8;
			slen = ds_print_shortcut(ds, get_ptr (ds, ds->at), pos);
			ds->core->rasm->bits = obits;
			gotShortcut = true;
		}
	}
	switch (ds->analop.type) {
	case R_ANAL_OP_TYPE_UJMP:
	case R_ANAL_OP_TYPE_UJMP | R_ANAL_OP_TYPE_IND:
	case R_ANAL_OP_TYPE_UJMP | R_ANAL_OP_TYPE_IND | R_ANAL_OP_TYPE_COND:
	case R_ANAL_OP_TYPE_UJMP | R_ANAL_OP_TYPE_IND | R_ANAL_OP_TYPE_REG:
		if (ds->asm_hint_lea) {
			if (ds->analop.ptr != UT64_MAX && ds->analop.ptr != UT32_MAX) {
				slen = ds_print_shortcut (ds, get_ptr (ds, ds->analop.ptr), pos);
				gotShortcut = true;
			}
		}
		break;
	case R_ANAL_OP_TYPE_MOV:
	case R_ANAL_OP_TYPE_LEA:
	case R_ANAL_OP_TYPE_LOAD:
		if (ds->asm_hint_imm) {
			if (ds->analop.val != UT64_MAX && ds->analop.val != UT32_MAX && ds->analop.val > 256) {
				slen = ds_print_shortcut (ds, ds->analop.val, pos);
				gotShortcut = true;
			}
		} else
		if (ds->asm_hint_lea) {
			if (ds->analop.ptr != UT64_MAX && ds->analop.ptr != UT32_MAX && ds->analop.ptr > 256) {
				slen = ds_print_shortcut (ds, ds->analop.ptr, pos);
				gotShortcut = true;
			}
		}
		break;
	case R_ANAL_OP_TYPE_UCALL:
	case R_ANAL_OP_TYPE_UCALL | R_ANAL_OP_TYPE_REG | R_ANAL_OP_TYPE_IND:
	case R_ANAL_OP_TYPE_UCALL | R_ANAL_OP_TYPE_IND:
		if (ds->asm_hint_call) {
			if (ds->analop.jump != UT64_MAX) {
				slen = ds_print_shortcut (ds, ds->analop.jump, pos);
			} else {
				ut64 addr;
				if (ds->asm_hint_call_indirect) {
					addr = get_ptr_ble (ds, ds->analop.ptr);
				} else {
					addr = ds->analop.ptr;
				}
				slen = ds_print_shortcut (ds, addr, pos);
			}
			gotShortcut = true;
		}
		break;
	case R_ANAL_OP_TYPE_RJMP:
	case R_ANAL_OP_TYPE_RCALL:
		if (ds->analop.jump != UT64_MAX && ds->analop.jump != UT32_MAX) {
			ds->analop.jump = get_ptr_ble (ds, ds->analop.jump);
			slen = ds_print_shortcut (ds, ds->analop.jump, pos);
			gotShortcut = true;
		}
		break;
	case R_ANAL_OP_TYPE_JMP:
	case R_ANAL_OP_TYPE_CJMP:
		if (ds->asm_hint_jmp) {
			slen = ds_print_shortcut (ds, ds->analop.jump, pos);
			gotShortcut = true;
		}
		break;
	case R_ANAL_OP_TYPE_CALL:
	case R_ANAL_OP_TYPE_COND | R_ANAL_OP_TYPE_CALL:
		if (ds->asm_hint_call) {
			slen = ds_print_shortcut (ds, ds->analop.jump, pos);
			gotShortcut = true;
		}
		break;
	default:
		if (ds_print_core_vmode_jump_hit (ds, pos)) {
			gotShortcut = true;
		}
		break;
	}
beach:
	if (ds->asm_hint_pos > 0) {
		const int begin = gotShortcut ? 2: 3;
		for (i = begin - slen; i > 0; i--) {
			r_cons_strcat (" ");
		}
	} else if (ds->asm_hint_pos == 0 && !gotShortcut) {
		r_cons_strcat ("   ");
	}
	ds->hinted_line = gotShortcut;
	return gotShortcut;
}

static void ds_begin_nl_comment(RDisasmState *ds) {
	if (ds->cmtcount > 0 && ds->show_comment_right) {
		ds_newline (ds);
		ds_begin_cont (ds);
	} else if (ds->cmtcount > 0 || !ds->show_comment_right) {
		ds_begin_line (ds);
		ds_pre_xrefs (ds, false);
	}
	if (ds->show_color && (ds->cmtcount > 0 || ds->show_comment_right)) {
		r_cons_print (ds->pal_comment);
	}
}

// align for comment
static void ds_align_comment(RDisasmState *ds) {
	if (!ds->show_comment_right_default) {
		return;
	}
	const int cmtcol = ds->cmtcol - 1;
	const char *ll = r_cons_get_buffer ();
	if (!ll) {
		return;
	}
	ll += ds->buf_line_begin;
	int cells = r_str_len_utf8_ansi (ll);
	int cols = ds->interactive ? ds->core->cons->columns : 1024;
	if (cells < cmtcol) {
		int len = cmtcol - cells;
		if (len < cols && len > 0) {
			r_cons_memset (' ', len);
		}
	}
	r_cons_print (" ");
}

static void ds_print_dwarf(RDisasmState *ds) {
	if (ds->show_dwarf) {
		// TODO: cache value in ds
		int dwarfFile = (int)ds->dwarfFile + (int)ds->dwarfAbspath;
		free (ds->sl);
		ds->sl = r_bin_addr2text (ds->core->bin, ds->at, dwarfFile);
		if (ds->sl) {
			if ((!ds->osl || (ds->osl && strcmp (ds->sl, ds->osl)))) {
				char *line = strdup (ds->sl);
				if (!line) {
					return;
				}
				r_str_replace_char (line, '\t', ' ');
				r_str_replace_char (line, '\x1b', ' ');
				r_str_replace_char (line, '\r', ' ');
				r_str_replace_char (line, '\n', '\x00');
				r_str_trim (line);
				if (!*line) {
					free (line);
					return;
				}
				// handle_set_pre (ds, "  ");
				ds_align_comment (ds);
				if (ds->show_color) {
					r_cons_printf ("%s; %s"Color_RESET, ds->pal_comment, line);
				} else {
					r_cons_printf ("; %s", line);
				}
				free (ds->osl);
				ds->osl = ds->sl;
				ds->sl = NULL;
				free (line);
			}
		}
	}
}

static void ds_print_asmop_payload(RDisasmState *ds, const ut8 *buf) {
	if (ds->show_varaccess) {
		// XXX assume analop is filled
		//r_anal_op (core->anal, &ds->analop, ds->at, core->block+i, core->blocksize-i);
		int v = ds->analop.ptr;
		switch (ds->analop.stackop) {
		case R_ANAL_STACK_GET:
			if (v < 0) {
				r_cons_printf (" ; local.get %d", -v);
			} else {
				r_cons_printf (" ; arg.get %d", v);
			}
			break;
		case R_ANAL_STACK_SET:
			if (v < 0) {
				r_cons_printf (" ; local.set %d", -v);
			} else {
				r_cons_printf (" ; arg.set %d", v);
			}
			break;
		default:
			break;
		}
	}
	if (ds->asmop.payload != 0) {
		r_cons_printf ("\n; .. payload of %d byte(s)", ds->asmop.payload);
		if (ds->showpayloads) {
			int mod = ds->asmop.payload % ds->core->rasm->dataalign;
			int x;
			for (x = 0; x < ds->asmop.payload; x++) {
				r_cons_printf ("\n        0x%02x", buf[ds->oplen + x]);
			}
			for (x = 0; x < mod; x++) {
				r_cons_printf ("\n        0x%02x ; alignment", buf[ds->oplen + ds->asmop.payload + x]);
			}
		}
	}
}

/* Do not use this function for escaping JSON! */
static char *ds_esc_str(RDisasmState *ds, const char *str, int len, const char **prefix_out, bool is_comment) {
	int str_len;
	char *escstr = NULL;
	const char *prefix = "";
	bool esc_bslash = ds->core->print->esc_bslash;
	RStrEnc strenc = ds->strenc;
	if (strenc == R_STRING_ENC_GUESS) {
		strenc = r_utf_bom_encoding ((ut8 *)str, len);
	}
	switch (strenc) {
	case R_STRING_ENC_LATIN1:
		escstr = r_str_escape_latin1 (str, ds->show_asciidot, esc_bslash, is_comment);
		break;
	case R_STRING_ENC_UTF8:
		escstr = r_str_escape_utf8 (str, ds->show_asciidot, esc_bslash);
		break;
	case R_STRING_ENC_UTF16LE:
		escstr = r_str_escape_utf16le (str, len, ds->show_asciidot, esc_bslash);
		prefix = "u";
		break;
	case R_STRING_ENC_UTF32LE:
		escstr = r_str_escape_utf32le (str, len, ds->show_asciidot, esc_bslash);
		prefix = "U";
		break;
	case R_STRING_ENC_UTF16BE:
		escstr = r_str_escape_utf16be (str, len, ds->show_asciidot, esc_bslash);
		prefix = "ub";
		break;
	case R_STRING_ENC_UTF32BE:
		escstr = r_str_escape_utf32be (str, len, ds->show_asciidot, esc_bslash);
		prefix = "Ub";
		break;
	default:
		str_len = strlen (str);
		if ((str_len == 1 && len > 3 && str[2] && !str[3])
		    || (str_len == 3 && len > 5 && !memcmp (str, "\xff\xfe", 2) && str[4] && !str[5])) {
			escstr = r_str_escape_utf16le (str, len, ds->show_asciidot, esc_bslash);
			prefix = "u";
		} else if (str_len == 1 && len > 7 && !str[2] && !str[3] && str[4] && !str[5]) {
			RStrEnc enc = R_STRING_ENC_UTF32LE;
			RRune ch;
			const char *ptr, *end;
			end = (const char *)r_mem_mem_aligned ((ut8 *)str, len, (ut8 *)"\0\0\0\0", 4, 4);
			if (!end) {
				end = str + len - 1;
			}
			for (ptr = str; ptr < end; ptr += 4) {
				if (r_utf32le_decode ((ut8 *)ptr, end - ptr, &ch) > 0 && ch > 0x10ffff) {
					enc = R_STRING_ENC_LATIN1;
					break;
				}
			}
			if (enc == R_STRING_ENC_UTF32LE) {
				escstr = r_str_escape_utf32le (str, len, ds->show_asciidot, esc_bslash);
				prefix = "U";
			} else {
				escstr = r_str_escape_latin1 (str, ds->show_asciidot, esc_bslash, is_comment);
			}
		} else {
			RStrEnc enc = R_STRING_ENC_LATIN1;
			const char *ptr = str, *end = str + str_len;
			for (; ptr < end; ptr++) {
				if (r_utf8_decode ((ut8 *)ptr, end - ptr, NULL) > 1) {
					enc = R_STRING_ENC_UTF8;
					break;
				}
			}
			escstr = (enc == R_STRING_ENC_UTF8 ?
				r_str_escape_utf8 (str, ds->show_asciidot, esc_bslash) :
				r_str_escape_latin1 (str, ds->show_asciidot, esc_bslash, is_comment));
		}
	}
	if (prefix_out) {
		*prefix_out = prefix;
	}
	return escstr;
}

static void ds_print_str(RDisasmState *ds, const char *str, int len, ut64 refaddr) {
	if (ds->core->flags->realnames || !r_bin_string_filter (ds->core->bin, str, refaddr)) {
		return;
	}
	// do not resolve strings on arm64 pointed with ADRP
	if (ds->analop.type == R_ANAL_OP_TYPE_LEA) {
		if (ds->core->rasm->bits == 64 && r_str_startswith (r_config_get (ds->core->config, "asm.arch"), "arm")) {
			return;
		}
	}
	const char *prefix;
	char *escstr = ds_esc_str (ds, str, len, &prefix, false);
	if (escstr) {
		bool inv = ds->show_color && !ds->show_emu_strinv;
		ds_begin_comment (ds);
		ds_comment (ds, true, "; %s%s\"%s\"%s", inv ? Color_INVERT : "", prefix, escstr,
		            inv ? Color_INVERT_RESET : "");
		ds->printed_str_addr = refaddr;
		free (escstr);
	}
}

static inline bool is_filtered_flag(RDisasmState *ds, const char *name) {
	if (ds->show_noisy_comments || strncmp (name, "str.", 4)) {
		return false;
	}
	ut64 refaddr = ds->analop.ptr;
	const char *anal_flag = r_meta_get_string (ds->core->anal, R_META_TYPE_STRING, refaddr);
	if (anal_flag) {
		char *dupped = strdup (anal_flag);
		if (dupped) {
			r_name_filter (dupped, -1);
			if (!strcmp (&name[4], dupped)) {
				return true;
			}
		}
	}
	return false;
}

/* convert numeric value in opcode to ascii char or number */
static void ds_print_ptr(RDisasmState *ds, int len, int idx) {
	RCore *core = ds->core;
	ut64 p = ds->analop.ptr;
	ut64 v = ds->analop.val;
	ut64 refaddr = p;
	bool aligned = false;
	int refptr = ds->analop.refptr;
	RFlagItem *f = NULL, *f2 = NULL;
	bool f2_in_opstr = false;  /* Also if true, f exists */
	if (!ds->show_comments || !ds->show_slow) {
		return;
	}
	const int opType = ds->analop.type & R_ANAL_OP_TYPE_MASK;
	bool canHaveChar = opType == R_ANAL_OP_TYPE_MOV;
	if (!canHaveChar) {
		canHaveChar = opType == R_ANAL_OP_TYPE_PUSH;
	}

	ds->chref = 0;
	if ((char)v > 0 && v >= '!') {
		ds->chref = (char)v;
		if (ds->immstr) {
			char *str = r_str_from_ut64 (r_read_ble64 (&v, core->print->big_endian));
			if (str && *str) {
				const char *ptr = str;
				bool printable = true;
				for (; *ptr; ptr++) {
					if (!IS_PRINTABLE (*ptr)) {
						printable = false;
						break;
					}
				}
				if (r_flag_get_i (core->flags, v)) {
					printable = false;
				}
				if (canHaveChar && printable) {
					ds_begin_comment (ds);
					ds_comment (ds, true, "; '%s'", str);
				}
			}
			free (str);
		} else {
			if (canHaveChar && (char)v > 0 && v >= '!' && v <= '~') {
				ds_begin_comment (ds);
				aligned = true;
				ds_comment (ds, true, "; '%c'", (char)v);
			}
		}
	}
	RList *list = NULL;
	RListIter *iter;
	RAnalRef *ref;
	list = r_anal_refs_get (core->anal, ds->at);
	r_list_foreach (list, iter, ref) {
		if (ref->type == R_ANAL_REF_TYPE_STRING || ref->type == R_ANAL_REF_TYPE_DATA) {
			if ((f = r_flag_get_i (core->flags, ref->addr))) {
				refaddr = ref->addr;
				break;
			}
		}
	}
	r_list_free (list);
	if (ds->analop.type == (R_ANAL_OP_TYPE_MOV | R_ANAL_OP_TYPE_REG)
	    && ds->analop.stackop == R_ANAL_STACK_SET
	    && ds->analop.val != UT64_MAX && ds->analop.val > 10) {
		const char *arch = r_config_get (core->config, "asm.arch");
		if (arch && !strcmp (arch, "x86")) {
			p = refaddr = ds->analop.val;
			refptr = 0;
		}
	}
	bool flag_printed = false;
	bool refaddr_printed = false;
	bool string_printed = false;
	if (refaddr == UT64_MAX) {
		/* do nothing */
	} else if (((st64)p) > 0 || ((st64)refaddr) > 0) {
		const char *kind;
		char *msg = calloc (sizeof (char), len);
		if (((st64)p) > 0) {
			f = r_flag_get_i (core->flags, p);
			if (f) {
				ut64 subrel_addr = core->parser->subrel_addr;
				if (subrel_addr && subrel_addr != p) {
					f2 = r_core_flag_get_by_spaces (core->flags, subrel_addr);
					f2_in_opstr = f2 && ds->opstr && (strstr (ds->opstr, f2->name) || strstr (ds->opstr, f2->realname)) ;
				}
				refaddr = p;
				if (!flag_printed && !is_filtered_flag (ds, f->name)
				    && (!ds->opstr || (!strstr (ds->opstr, f->name) && !strstr (ds->opstr, f->realname)))
				    && !f2_in_opstr) {
					ds_begin_comment (ds);
					ds_comment (ds, true, "; %s", f->name);
					ds->printed_flag_addr = p;
					flag_printed = true;
				}
			}
		}
		r_io_read_at (core->io, refaddr, (ut8*)msg, len - 1);
		if (refptr && ds->show_refptr) {
			ut64 num = r_read_ble (msg, core->print->big_endian, refptr * 8);
			st64 n = (st64)num;
			st32 n32 = (st32)(n & UT32_MAX);
			if (ds->analop.type == R_ANAL_OP_TYPE_LEA) {
				char str[128] = {0};
				f = r_flag_get_i (core->flags, refaddr);
				if (!f && ds->show_slow) {
					r_io_read_at (ds->core->io, ds->analop.ptr,
						      (ut8 *)str, sizeof (str) - 1);
					str[sizeof (str) - 1] = 0;
					if (!string_printed && str[0] && r_str_is_printable_incl_newlines (str)) {
						ds_print_str (ds, str, sizeof (str), ds->analop.ptr);
						string_printed = true;
					}
				}
			} else {
				if (n == UT32_MAX || n == UT64_MAX) {
					ds_begin_nl_comment (ds);
					ds_comment (ds, true, "; [0x%" PFMT64x":%d]=-1",
							refaddr, refptr);
				} else if (n == n32 && (n32 > -512 && n32 < 512)) {
					ds_begin_nl_comment (ds);
					ds_comment (ds, true, "; [0x%" PFMT64x
							  ":%d]=%"PFMT64d, refaddr, refptr, n);
				} else {
					const char *kind, *flag = "";
					char *msg2 = NULL;
					RFlagItem *f2_ = r_flag_get_i (core->flags, n);
					if (f2_) {
						flag = f2_->name;
					} else {
						msg2 = calloc (sizeof (char), len);
						r_io_read_at (core->io, n, (ut8*)msg2, len - 1);
						msg2[len - 1] = 0;
						kind = r_anal_data_kind (core->anal, refaddr, (const ut8*)msg2, len - 1);
						if (kind && !strcmp (kind, "text")) {
							r_str_filter (msg2, 0);
							if (*msg2) {
								char *lala = r_str_newf ("\"%s\"", msg2);
								free (msg2);
								flag = msg2 = lala;
							}
						}
					}
					//ds_align_comment (ds);
					{
						const char *refptrstr = "";
						if (core->print->flags & R_PRINT_FLAGS_SECSUB) {
							RBinObject *bo = r_bin_cur_object (core->bin);
							RBinSection *s = bo? r_bin_get_section_at (bo, n, core->io->va): NULL;
							if (s) {
								refptrstr = s->name;
							}
						}
						ds_begin_nl_comment (ds);
						ds_comment_start (ds, "; [");
						if (f && f2_in_opstr) {
							ds_comment_middle (ds, "%s", f->name);
							flag_printed = true;
						} else {
							ds_comment_middle (ds, "0x%" PFMT64x, refaddr);
						}
						ds_comment_end (ds, ":%d]=%s%s0x%" PFMT64x "%s%s",
								refptr, refptrstr, *refptrstr ? "." : "",
								n, (flag && *flag) ? " " : "", flag);
					}
					free (msg2);
				}
				refaddr_printed = true;
			}
		}
		if (!strcmp (ds->show_cmtoff, "true")) {
			ds_begin_comment (ds);
			ds_comment (ds, true, "; 0x%" PFMT64x, refaddr);
			refaddr_printed = true;
		} else if (!refaddr_printed && strcmp (ds->show_cmtoff, "false")) {
			char addrstr[32] = {0};
			snprintf (addrstr, sizeof (addrstr), "0x%" PFMT64x, refaddr);
			if (!ds->opstr || !strstr (ds->opstr, addrstr)) {
				snprintf (addrstr, sizeof (addrstr), "0x%08" PFMT64x, refaddr);
				if (!ds->opstr || !strstr (ds->opstr, addrstr)) {
					bool print_refaddr = true;
					if (refaddr < 10) {
						snprintf (addrstr, sizeof (addrstr), "%" PFMT64u, refaddr);
						if (ds->opstr && strstr (ds->opstr, addrstr)) {
							print_refaddr = false;
						}
					}
					if (print_refaddr) {
						if (!aligned) {
							ds_begin_nl_comment (ds);
						}
						ds_comment (ds, true, "; 0x%" PFMT64x, refaddr);
						refaddr_printed = true;
					}
				}
			}
		}
		bool print_msg = true;
#if 1
		if (ds->strenc == R_STRING_ENC_GUESS
		    && r_utf_bom_encoding ((ut8 *)msg, len) == R_STRING_ENC_GUESS
		    && !(IS_PRINTABLE (*msg) || IS_WHITECHAR (*msg))) {
			print_msg = false;
		} else {
			msg[len - 1] = 0;
		}
#endif
		f = r_flag_get_i (core->flags, refaddr);
		if (f) {
			if (strlen (msg) != 1) {
				char *msg2 = r_str_new (msg);
				if (msg2) {
					r_str_filter (msg2, 0);
					if (!strncmp (msg2, "UH..", 4)) {
						print_msg = false;
					}
					free (msg2);
				}
			}
			if (print_msg) {
				if (!string_printed) {
					ds_print_str (ds, msg, len, refaddr);
					string_printed = true;
				}
			} else if (!flag_printed && (!ds->opstr ||
						(!strstr (ds->opstr, f->name) && !strstr (ds->opstr, f->realname)))) {
				ds_begin_nl_comment (ds);
				ds_comment (ds, true, "; %s", f->name);
				ds->printed_flag_addr = refaddr;
				flag_printed = true;
			}
		} else {
			if (refaddr == UT64_MAX || refaddr == UT32_MAX) {
				ds_begin_comment (ds);
				ds_comment (ds, true, "; -1");
			} else if (((char)refaddr > 0) && refaddr >= '!' && refaddr <= '~') {
				char ch = refaddr;
				if (canHaveChar && ch != ds->chref) {
					ds_begin_comment (ds);
					ds_comment (ds, true, "; '%c'", ch);
				}
			} else if (refaddr > 10) {
				if ((st64)refaddr < 0) {
					// resolve local var if possible
					RAnalFunction *fcn = r_anal_get_function_at (core->anal, ds->at);
					RAnalVar *v = fcn ? r_anal_function_get_var (fcn, 'v', (int)refaddr) : NULL;
					ds_begin_comment (ds);
					if (v) {
						ds_comment (ds, true, "; var %s", v->name);
					} else {
						ds_comment (ds, true, "; var %d", -(int)refaddr);
					}
				} else {
					if (r_core_anal_address (core, refaddr) & R_ANAL_ADDR_TYPE_ASCII) {
						if (!string_printed && print_msg) {
							ds_print_str (ds, msg, len, refaddr);
							string_printed = true;
						}
					}
				}
			}
			//XXX this should be refactored with along the above
			kind = r_anal_data_kind (core->anal, refaddr, (const ut8*)msg, len - 1);
			if (kind) {
				if (!strcmp (kind, "text")) {
					if (!string_printed && print_msg) {
						ds_print_str (ds, msg, len, refaddr);
						string_printed = true;
					}
				} else if (!strcmp (kind, "invalid")) {
					int *n = (int*)&refaddr;
					ut64 p = ds->analop.val;
					if (p == UT64_MAX || p == UT32_MAX) {
						p = ds->analop.ptr;
					}
					/* avoid double ; -1 */
					if (p != UT64_MAX && p != UT32_MAX) {
						if (*n > -0xfff && *n < 0xfff) {
							if (!aligned) {
								ds_begin_comment (ds);
							}
							ds_comment (ds, true, "; %"PFMT64d, p);
						}
					}
				} else {
					// r_cons_printf (" ; %s", kind);
				}
				// TODO: check for more data kinds
			}
		}
		free (msg);
	} else {
		ds_print_as_string (ds);
	}
	if (!ds->show_comment_right && ds->cmtcount > 0) {
		const char *p = r_cons_get_buffer ();
		if (p) {
			int l = strlen (p);
			if (p[l - 1] != '\n') {
				ds_newline (ds);
			}
		}
	}
#if DEADCODE
	if (aligned && ds->show_color) {
		r_cons_strcat (Color_RESET);
	}
#endif
}

static void ds_print_demangled(RDisasmState *ds) {
	if (!ds->show_comments || !ds->asm_demangle) {
		return;
	}
	RCore *core = ds->core;
	RFlagItem *f;
	int optype = ds->analop.type & 0xFFFF;
	switch (optype) {
	case R_ANAL_OP_TYPE_JMP:
	case R_ANAL_OP_TYPE_UJMP:
	case R_ANAL_OP_TYPE_CALL:
		f = r_flag_get_by_spaces (core->flags, ds->analop.jump, R_FLAGS_FS_SYMBOLS, NULL);
		if (f && f->demangled && f->realname && ds->opstr && !strstr (ds->opstr, f->realname)) {
			ds_begin_nl_comment (ds);
			ds_comment (ds, true, "; %s", f->realname);
		}
	}
}

static void ds_print_relocs(RDisasmState *ds) {
	char *demname = NULL;
	if (!ds->showrelocs || !ds->show_slow) {
		return;
	}
	RCore *core = ds->core;
	const char *lang = r_config_get (core->config, "bin.lang");
	bool demangle = r_config_get_i (core->config, "asm.demangle");
	bool keep_lib = r_config_get_i (core->config, "bin.demangle.libs");
	RBinReloc *rel = r_core_getreloc (core, ds->at, ds->analop.size);
	if (rel) {
		int cstrlen = 0;
		char *ll = r_cons_lastline (&cstrlen);
		if (!ll) {
			return;
		}
		int ansilen = r_str_ansi_len (ll);
		int utf8len = r_utf8_strlen ((const ut8*)ll);
		int cells = utf8len - (cstrlen - ansilen);
		int len = ds->cmtcol - cells;
		r_cons_memset (' ', len);
		if (rel->import) {
			if (demangle) {
				demname = r_bin_demangle (core->bin->cur, lang, rel->import->name, rel->vaddr, keep_lib);
			}
			r_cons_printf ("; RELOC %d %s", rel->type, demname ? demname : rel->import->name);
		} else if (rel->symbol) {
			if (demangle) {
				demname = r_bin_demangle (core->bin->cur, lang, rel->symbol->name, rel->symbol->vaddr, keep_lib);
			}
			r_cons_printf ("; RELOC %d %s @ 0x%08" PFMT64x,
					rel->type, demname ? demname : rel->symbol->name,
					rel->symbol->vaddr);
			if (rel->addend) {
				if (rel->addend > 0) {
					r_cons_printf (" + 0x%" PFMT64x, rel->addend);
				} else {
					r_cons_printf (" - 0x%" PFMT64x, -rel->addend);
				}
			}
		} else {
			r_cons_printf ("; RELOC %d ", rel->type);
		}
		free (demname);
	}
}

static bool mymemwrite0(RAnalEsil *esil, ut64 addr, const ut8 *buf, int len) {
	return false;
}

static bool mymemwrite1(RAnalEsil *esil, ut64 addr, const ut8 *buf, int len) {
	return true;
}

static bool mymemwrite2(RAnalEsil *esil, ut64 addr, const ut8 *buf, int len) {
	return (addr >= emustack_min && addr < emustack_max);
}

static char *ssa_get(RAnalEsil *esil, const char *reg) {
	RDisasmState *ds = esil->user;
	if (isdigit ((unsigned char)*reg)) {
		return strdup (reg);
	}
	if (!ds->ssa) {
		ds->ssa = sdb_new0 ();
	}
	int n = sdb_num_get (ds->ssa, reg, NULL);
	return r_str_newf ("%s_%d", reg, n);
}

static void ssa_set(RAnalEsil *esil, const char *reg) {
	RDisasmState *ds = esil->user;
	(void)sdb_num_inc (ds->ssa, reg, 1, 0);
}

#define R_DISASM_MAX_STR 512
static bool myregread(RAnalEsil *esil, const char *name, ut64 *res, int *size) {
	RDisasmState *ds = esil->user;
	if (ds && ds->show_emu_ssa) {
		if (!isdigit ((unsigned char)*name)) {
			char *r = ssa_get (esil, name);
			ds_comment_esil (ds, true, false, "<%s", r);
			free (r);
		}
	}
	return false;
}

static bool myregwrite(RAnalEsil *esil, const char *name, ut64 *val) {
	char str[64], *msg = NULL;
	ut32 *n32 = (ut32*)str;
	RDisasmState *ds = esil->user;
	if (!ds) {
		return false;
	}
	if (!ds->show_emu_strlea && ds->analop.type == R_ANAL_OP_TYPE_LEA) {
		// useful for ARM64
		// reduce false positives in emu.str=true when loading strings via adrp+add
		return false;
	}
	ds->esil_likely = true;
	if (ds->show_emu_ssa) {
		ssa_set (esil, name);
		char *r = ssa_get (esil, name);
		ds_comment_esil (ds, true, false, ">%s", r);
		free (r);
		return false;
	}
	if (!ds->show_slow) {
		return false;
	}
	memset (str, 0, sizeof (str));
	if (*val) {
		bool emu_str_printed = false;
		char *type = NULL;
		(void)r_io_read_at (esil->anal->iob.io, *val, (ut8*)str, sizeof (str)-1);
		str[sizeof (str) - 1] = 0;
		ds->emuptr = *val;
		// support cstring here
		{
			ut64 *cstr = (ut64*) str;
			ut64 addr = cstr[0];
			if (!(*val >> 32)) {
				addr = addr & UT32_MAX;
			}
			if (cstr[0] == 0 && cstr[1] < 0x1000) {
				ut64 addr = cstr[2];
				if (!(*val >> 32)) {
					addr = addr & UT32_MAX;
				}
				(void)r_io_read_at (esil->anal->iob.io, addr,
					(ut8*)str, sizeof (str)-1);
			//	eprintf ("IS CSTRING 0x%llx %s\n", addr, str);
				type = r_str_newf ("(cstr 0x%08"PFMT64x") ", addr);
				ds->printed_str_addr = cstr[2];
			} else if (r_io_is_valid_offset (esil->anal->iob.io, addr, 0)) {
				ds->printed_str_addr = cstr[0];
				type = r_str_newf ("(pstr 0x%08"PFMT64x") ", addr);
				(void)r_io_read_at (esil->anal->iob.io, addr,
					(ut8*)str, sizeof (str) - 1);
			//	eprintf ("IS PSTRING 0x%llx %s\n", addr, str);
			}
		}

		if (*str && !r_bin_strpurge (ds->core->bin, str, *val) && r_str_is_printable_incl_newlines (str)
		    && (ds->printed_str_addr == UT64_MAX || *val != ds->printed_str_addr)) {
			bool jump_op = false;
			bool ignored = false;
			switch (ds->analop.type) {
			case R_ANAL_OP_TYPE_JMP:
			case R_ANAL_OP_TYPE_UJMP:
			case R_ANAL_OP_TYPE_RJMP:
			case R_ANAL_OP_TYPE_IJMP:
			case R_ANAL_OP_TYPE_IRJMP:
			case R_ANAL_OP_TYPE_CJMP:
			case R_ANAL_OP_TYPE_MJMP:
			case R_ANAL_OP_TYPE_UCJMP:
				jump_op = true;
				break;
			case R_ANAL_OP_TYPE_TRAP:
			case R_ANAL_OP_TYPE_RET:
				ignored = true;
				break;
			case R_ANAL_OP_TYPE_LEA:
				if (ds->core->rasm->bits == 64 && r_str_startswith (r_config_get (ds->core->config, "asm.arch"), "arm")) {
					ignored = true;
				}
				break;
			}
			if (!jump_op && !ignored) {
				const char *prefix;
				ut32 len = sizeof (str) -1;
#if 0
				RCore *core = ds->core;
				ut32 len = core->blocksize + 256;
				if (len < core->blocksize || len > R_DISASM_MAX_STR) {
					len = R_DISASM_MAX_STR;
				}
#endif
				ds->emuptr = *val;
				char *escstr = ds_esc_str (ds, str, (int)len, &prefix, false);
				if (escstr) {
					char *m;
					if (ds->show_color) {
						bool inv = ds->show_emu_strinv;
						m = r_str_newf ("%s%s%s\"%s\"%s",
						                  prefix, r_str_get (type), inv ? Color_INVERT : "",
						                  escstr, inv ? Color_INVERT_RESET : "");
					} else {
						m = r_str_newf ("%s%s\"%s\"", prefix, r_str_get (type), escstr);
					}
					msg = r_str_append_owned (msg, m);
					emu_str_printed = true;
					free (escstr);
				}
			}
		} else {
			if (!*n32) {
				// msg = strdup ("NULL");
			} else if (*n32 == UT32_MAX) {
				/* nothing */
			} else {
				if (!ds->show_emu_str) {
					msg = r_str_appendf (msg, "-> 0x%x", *n32);
				}
			}
		}
		R_FREE (type);
		if ((ds->printed_flag_addr == UT64_MAX || *val != ds->printed_flag_addr)
		    && (ds->show_emu_strflag || !emu_str_printed)) {
			RFlagItem *fi = r_flag_get_i (esil->anal->flb.f, *val);
			if (fi && (!ds->opstr || !strstr (ds->opstr, fi->name))) {
				msg = r_str_appendf (msg, "%s%s", msg && *msg ? " " : "", fi->name);
			}
		}
	}
	if (ds->show_emu_str) {
		if (msg && *msg) {
			ds->emuptr = *val;
			if (ds->show_emu_stroff && *msg == '"') {
				ds_comment_esil (ds, true, false, "; 0x%"PFMT64x" %s", *val, msg);
			} else {
				ds_comment_esil (ds, true, false, "; %s", msg);
			}
			if (ds->show_comments && !ds->show_comment_right) {
				ds_newline (ds);
			}
		}
	} else {
		if (msg && *msg) {
			ds_comment_esil (ds, true, false, "; %s=0x%"PFMT64x" %s", name, *val, msg);
		} else {
			ds_comment_esil (ds, true, false, "; %s=0x%"PFMT64x, name, *val);
		}
		if (ds->show_comments && !ds->show_comment_right) {
			ds_newline (ds);
		}
	}
	free (msg);
	return false;
}

static void ds_pre_emulation(RDisasmState *ds) {
	bool do_esil = ds->show_emu;
	if (!ds->pre_emu) {
		return;
	}
	RFlagItem *f = r_flag_get_at (ds->core->flags, ds->core->offset, true);
	if (!f) {
		return;
	}
	ut64 base = f->offset;
	RAnalEsil *esil = ds->core->anal->esil;
	int i, end = ds->core->offset - base;
	int maxemu = 1024 * 1024;
	RAnalEsilHookRegWriteCB orig_cb = esil->cb.hook_reg_write;
	if (end < 0 || end > maxemu) {
		return;
	}
	ds->stackptr = ds->core->anal->stackptr;
	esil->cb.hook_reg_write = NULL;
	for (i = 0; i < end; i++) {
		ut64 addr = base + i;
		RAnalOp* op = r_core_anal_op (ds->core, addr, R_ANAL_OP_MASK_ESIL | R_ANAL_OP_MASK_HINT);
		if (op) {
			if (do_esil) {
				r_anal_esil_set_pc (esil, addr);
				r_anal_esil_parse (esil, R_STRBUF_SAFEGET (&op->esil));
				if (op->size > 0) {
					i += op->size - 1;
				}
			}
			ds_update_stackptr (ds, op);
			r_anal_op_free (op);
		}
	}
	esil->cb.hook_reg_write = orig_cb;
}

static void ds_print_esil_anal_init(RDisasmState *ds) {
	RCore *core = ds->core;
	const char *pc = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
	if (!pc) {
		return;
	}
	ds->esil_old_pc = r_reg_getv (core->anal->reg, pc);
	if (!ds->esil_old_pc || ds->esil_old_pc == UT64_MAX) {
		ds->esil_old_pc = core->offset;
	}
	if (!ds->show_emu) {
		// XXX. stackptr not computed without asm.emu, when its not required
		return;
	}
	if (!core->anal->esil) {
		int iotrap = r_config_get_i (core->config, "esil.iotrap");
		int esd = r_config_get_i (core->config, "esil.stack.depth");
		unsigned int addrsize = r_config_get_i (core->config, "esil.addr.size");

		if (!(core->anal->esil = r_anal_esil_new (esd, iotrap, addrsize))) {
			R_FREE (ds->esil_regstate);
			return;
		}
		r_anal_esil_setup (core->anal->esil, core->anal, 0, 0, 1);
	}
	core->anal->esil->user = ds;
	free (ds->esil_regstate);
	R_FREE (core->anal->last_disasm_reg);
	if (core->anal->gp) {
		r_reg_setv (core->anal->reg, "gp", core->anal->gp);
	}
	ds->esil_regstate = r_reg_arena_peek (core->anal->reg);
	RRegSet *regset = r_reg_regset_get (core->anal->reg, R_REG_TYPE_GPR);
	if (ds->esil_regstate && regset) {
		ds->esil_regstate_size = regset->arena->size;
	}

	// TODO: emulate N instructions BEFORE the current offset to get proper full function emulation
	ds_pre_emulation (ds);
}

static void ds_print_bbline(RDisasmState *ds) {
	if (!ds->show_bbline || !ds->at) {
		return;
	}
	RAnalBlock *bb = NULL;
	RAnalFunction *f_before = NULL;
	if (ds->fcn) {
		bb = r_anal_fcn_bbget_at (ds->core->anal, ds->fcn, ds->at);
	} else {
		f_before = fcnIn (ds, ds->at - 1, R_ANAL_FCN_TYPE_NULL);
	}
	if ((ds->fcn && bb && ds->fcn->addr != ds->at) || (!ds->fcn && f_before)) {
		ds_begin_line (ds);
		// adapted from ds_setup_pre ()
		ds->cmtcount = 0;
		if (!ds->show_functions || !ds->show_lines_fcn) {
			ds->pre = DS_PRE_NONE;
		} else {
			ds->pre = DS_PRE_EMPTY;
			if (!f_before) {
				f_before = fcnIn (ds, ds->at - 1, R_ANAL_FCN_TYPE_NULL);
			}
			if (f_before == ds->fcn) {
				ds->pre = DS_PRE_FCN_MIDDLE;
			}
		}
		ds_print_pre (ds, true);
		if (ds->show_section && ds->line_col) {
			const char *sn = r_core_get_section_name (ds->core, ds->at);
			size_t snl = strlen (sn) + 4;
			r_cons_printf ("%s", r_str_pad (' ', R_MAX (10, snl - 1)));
		}
		if (!ds->linesright && ds->show_lines_bb && ds->line) {
			char *refline, *reflinecol = NULL;
			ds_update_ref_lines (ds);
			refline = ds->refline2;
			reflinecol = ds->prev_line_col;
			ds_print_ref_lines (refline, reflinecol, ds);
		}
		r_cons_printf ("|");
		ds_newline (ds);
	}
}

static void print_fcn_arg(RCore *core, const char *type, const char *name,
			   const char *fmt, const ut64 addr,
			   const int on_stack, int asm_types) {
	if (on_stack == 1 && asm_types > 1) {
		r_cons_printf ("%s", type);
	}
	if (addr != UT32_MAX && addr != UT64_MAX  && addr != 0) {
		char *res = r_core_cmd_strf (core, "pf%s %s%s %s @ 0x%08" PFMT64x,
				(asm_types==2)? "": "q", (on_stack == 1) ? "*" : "", fmt, name, addr);
		r_str_trim (res);
		if (r_str_startswith (res, "\"\\xff\\xff")) {
			// r_cons_printf ("0x%08"PFMT64x, addr);
			r_cons_printf ("\"\"");
		} else {
			r_cons_printf ("%s", res);
		}
		free (res);
	} else {
		r_cons_printf ("-1");
	}
	r_cons_chop ();
}

static void delete_last_comment(RDisasmState *ds) {
	if (!ds->show_comment_right_default) {
		return;
	}
	const char *ll = r_cons_get_buffer ();
	if (!ll) {
		return;
	}
	ll += ds->buf_line_begin;
	const char *begin = ll;
	if (begin) {
		ds_newline (ds);
		ds_begin_cont (ds);
	}
}

static bool can_emulate_metadata(RCore *core, ut64 at) {
	// check if there is a meta at the addr that is unemulateable
	const char *emuskipmeta = r_config_get (core->config, "emu.skip");
	bool ret = true;
	RPVector *metas = r_meta_get_all_at (core->anal, at);
	void **it;
	r_pvector_foreach (metas, it) {
		RAnalMetaItem *item = ((RIntervalNode *)*it)->data;
		if (strchr (emuskipmeta, (char)item->type)) {
			ret = false;
			break;
		}
	}
	r_pvector_free (metas);
	return ret;
}

static void mipsTweak(RDisasmState *ds) {
	RCore *core = ds->core;
	const char *asm_arch = r_config_get (core->config, "asm.arch");
	if (asm_arch && *asm_arch && strstr (asm_arch, "mips")) {
		if (r_config_get_i (core->config, "anal.gpfixed")) {
			ut64 gp = r_config_get_i (core->config, "anal.gp");
			r_reg_setv (core->anal->reg, "gp", gp);
		}
	}
}

// modifies anal register state
static void ds_print_esil_anal(RDisasmState *ds) {
	RCore *core = ds->core;
	RAnalEsil *esil = core->anal->esil;
	const char *pc;
	bool (*hook_mem_write)(RAnalEsil *esil, ut64 addr, const ut8 *buf, int len) = NULL;
	int i, nargs;
	ut64 at = r_core_pava (core, ds->at);
	RConfigHold *hc = r_config_hold_new (core->config);
	if (!hc) {
		return;
	}
	if (!esil) {
		ds_print_esil_anal_init (ds);
		esil = core->anal->esil;
	}
	if (!ds->show_emu) {
		goto beach;
	}
	if (!can_emulate_metadata (core, at)) {
		goto beach;
	}
	if (ds->show_color) {
		r_cons_strcat (ds->pal_comment);
	}
	esil = core->anal->esil;
	pc = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
	if (pc) {
		r_reg_setv (core->anal->reg, pc, at + ds->analop.size);
		esil->cb.user = ds;
		esil->cb.hook_reg_write = myregwrite;
		esil->cb.hook_reg_read = myregread;
		hook_mem_write = esil->cb.hook_mem_write;
	}
	if (ds->show_emu_stack) {
		esil->cb.hook_mem_write = mymemwrite2;
	} else {
		if (ds->show_emu_write) {
			esil->cb.hook_mem_write = mymemwrite0;
		} else {
			esil->cb.hook_mem_write = mymemwrite1;
		}
	}
	ds->esil_likely = 0;
	const char *esilstr = R_STRBUF_SAFEGET (&ds->analop.esil);
	if (R_STR_ISNOTEMPTY (esilstr)) {
		mipsTweak (ds);
		r_anal_esil_set_pc (esil, at);
		r_anal_esil_parse (esil, esilstr);
	}
	r_anal_esil_stack_free (esil);
	r_config_hold (hc, "io.cache", NULL);
	r_config_set (core->config, "io.cache", "true");
	if (!ds->show_comments) {
		goto beach;
	}
	switch (ds->analop.type) {
	case R_ANAL_OP_TYPE_SWI: {
		char *s = cmd_syscall_dostr (core, ds->analop.val, at);
		if (s) {
			ds_comment_esil (ds, true, true, "; %s", s);
			free (s);
		}
		} break;
	case R_ANAL_OP_TYPE_CJMP:
		ds_comment_esil (ds, true, true, ds->esil_likely? "; likely" : "; unlikely");
		break;
	case R_ANAL_OP_TYPE_JMP:
		{
			ut64 addr = ds->analop.jump;
			if (!r_anal_get_function_at (ds->core->anal, addr)
					&& !r_flag_get_at (core->flags, addr, false)) {
				break;
			}
		}
	case R_ANAL_OP_TYPE_UCALL:
	case R_ANAL_OP_TYPE_ICALL:
	case R_ANAL_OP_TYPE_RCALL:
	case R_ANAL_OP_TYPE_IRCALL:
	case R_ANAL_OP_TYPE_CALL:
		{
			RAnalFunction *fcn;
			RAnalFuncArg *arg;
			RListIter *iter;
			RListIter *nextele;
			const char *fcn_name = NULL;
			char *key = NULL;
			ut64 pcv = ds->analop.jump;
			if (ds->analop.type == R_ANAL_OP_TYPE_RCALL) {
				pcv = UT64_MAX;
			}
			if (pcv == UT64_MAX) {
				pcv = ds->analop.ptr; // call [reloc-addr] // windows style
				if (pcv == UT64_MAX || !pcv) {
					r_anal_esil_reg_read (esil, "$jt", &pcv, NULL);
					if (pcv == UT64_MAX || !pcv) {
						pcv = r_reg_getv (core->anal->reg, pc);
					}
				}
			}
			fcn = r_anal_get_function_at (core->anal, pcv);
			if (fcn) {
				fcn_name = fcn->name;
			} else {
				RFlagItem *item = r_flag_get_i (core->flags, pcv);
				if (item) {
					fcn_name = item->name;
				}
			}
			if (fcn_name) {
				key = resolve_fcn_name (core->anal, fcn_name);
			}
			if (key) {
				if (ds->asm_types < 1) {
					free (key);
					break;
				}
				const char *fcn_type = r_type_func_ret (core->anal->sdb_types, key);
				int nargs = r_type_func_args_count (core->anal->sdb_types, key);
				// remove other comments
				delete_last_comment (ds);
				// ds_comment_start (ds, "");
				ds_comment_esil (ds, true, false, "%s", ds->show_color ? ds->pal_comment : "");
				if (fcn_type) {
					ds_comment_middle (ds, "; %s%s%s(", r_str_getf (fcn_type),
							(*fcn_type && fcn_type[strlen (fcn_type) - 1] == '*') ? "" : " ",
							r_str_getf (key));
					if (!nargs) {
						ds_comment_end (ds, "void)");
						free (key);
						break;
					}
				}
			}
			ut64 s_width = (core->anal->bits == 64)? 8: 4;
			const char *sp = r_reg_get_name (core->anal->reg, R_REG_NAME_SP);
			ut64 spv = r_reg_getv (core->anal->reg, sp);
			r_reg_setv (core->anal->reg, sp, spv + s_width); // temporarily set stack ptr to sync with carg.c
			RList *list = r_core_get_func_args (core, fcn_name);
			if (!r_list_empty (list)) {
				bool warning = false;
				bool on_stack = false;
				r_list_foreach (list, iter, arg) {
					if (arg->cc_source && r_str_startswith (arg->cc_source, "stack")) {
						on_stack = true;
					}
					if (!arg->size) {
						if (ds->asm_types == 2) {
							ds_comment_middle (ds, "%s: unk_size", arg->c_type);
						}
						warning = true;
					}
					nextele = r_list_iter_get_next (iter);
					if (!arg->fmt) {
						if (ds->asm_types > 1) {
							if (warning) {
								ds_comment_middle (ds, "_format");
							} else {
								ds_comment_middle (ds, "%s : unk_format", arg->c_type);
							}
						} else {
							ds_comment_middle (ds, "?");
						}
						ds_comment_middle (ds, nextele?", ":")");
					} else {
						// TODO: may need ds_comment_esil
						print_fcn_arg (core, arg->orig_c_type, arg->name, arg->fmt, arg->src, on_stack, ds->asm_types);
						ds_comment_middle (ds, nextele?", ":")");
					}
				}
				ds_comment_end (ds, "");
				r_list_free (list);
				free (key);
				break;
			} else {
				r_list_free (list);
				// function name not resolved
				r_warn_if_fail (!key);
				free (key);
				nargs = DEFAULT_NARGS;
				if (fcn) {
					// @TODO: fcn->nargs should be updated somewhere and used here instead
					nargs = r_anal_var_count (core->anal, fcn, 's', 1) +
							r_anal_var_count (core->anal, fcn, 'b', 1) +
							r_anal_var_count (core->anal, fcn, 'r', 1);
				}
				if (nargs > 0) {
					ds_comment_esil (ds, true, false, "%s", ds->show_color? ds->pal_comment : "");
					if (fcn_name) {
						ds_comment_middle (ds, "; %s(", fcn_name);
					} else {
						ds_comment_middle (ds, "; 0x%"PFMT64x"(", pcv);
					}
					const char *cc = r_anal_syscc_default (core->anal);
					for (i = 0; i < nargs; i++) {
						ut64 v = r_debug_arg_get (core->dbg, cc, i);
						if (v == UT64_MAX || v == UT32_MAX) {
							ds_comment_middle (ds, "%s-1", i?", ":"");
						} else {
							ds_comment_middle (ds, "%s0x%"PFMT64x, i?", ":"", v);
						}
					}
					ds_comment_end (ds, ")");
				}
			}
			r_reg_setv (core->anal->reg, sp, spv); // reset stack ptr
		}
		break;
	}
	ds_print_color_reset (ds);
beach:
	if (esil) {
		esil->cb.hook_mem_write = hook_mem_write;
	}
	r_config_hold_restore (hc);
	r_config_hold_free (hc);
}

static void ds_print_calls_hints(RDisasmState *ds) {
	int emu = r_config_get_i (ds->core->config, "asm.emu");
	int emuwrite = r_config_get_i (ds->core->config, "emu.write");
	if (emu && emuwrite) {
		// this is done by ESIL
		return;
	}
	RAnal *anal = ds->core->anal;
	Sdb *TDB = anal->sdb_types;
	char *name;
	char *full_name = NULL;
	if (ds->analop.type == R_ANAL_OP_TYPE_CALL) {
		// RAnalFunction *fcn = r_anal_get_fcn_in (anal, ds->analop.jump, -1);
		RAnalFunction *fcn = fcnIn (ds, ds->analop.jump, -1);
		if (fcn) {
			full_name = fcn->name;
		}
	} else if (ds->analop.ptr != UT64_MAX) {
		RFlagItem *flag = r_flag_get_i (ds->core->flags, ds->analop.ptr);
		if (flag && flag->space && !strcmp (flag->space->name, R_FLAGS_FS_IMPORTS)) {
			full_name = flag->realname;
		}
	}
	if (!full_name) {
		return;
	}
	if (r_type_func_exist (TDB, full_name)) {
		name = strdup (full_name);
	} else if (!(name = r_type_func_guess (TDB, full_name))) {
		return;
	}
	ds_begin_comment (ds);
	const char *fcn_type = r_type_func_ret (TDB, name);
	if (!fcn_type || !*fcn_type) {
		free (name);
		return;
	}
	char *cmt = r_str_newf ("; %s%s%s(", fcn_type,
		fcn_type[strlen (fcn_type) - 1] == '*' ? "" : " ",
		name);
	int i, arg_max = r_type_func_args_count (TDB, name);
	if (!arg_max) {
		cmt = r_str_append (cmt, "void)");
	} else {
		for (i = 0; i < arg_max; i++) {
			char *type = r_type_func_args_type (TDB, name, i);
			const char *tname = r_type_func_args_name (TDB, name, i);
			if (type && *type) {
				cmt = r_str_appendf (cmt, "%s%s%s%s%s", i == 0 ? "": " ", type,
						type[strlen (type) - 1] == '*' ? "": " ",
						tname, i == arg_max - 1 ? ")": ",");
			} else if (tname && !strcmp (tname, "...")) {
				cmt = r_str_appendf (cmt, "%s%s%s", i == 0 ? "": " ",
						tname, i == arg_max - 1 ? ")": ",");
			}
			free (type);
		}
	}
	ds_comment (ds, true, "%s", cmt);
	ds_print_color_reset (ds);
	free (cmt);
	free (name);
}

static void ds_print_comments_right(RDisasmState *ds) {
	char *desc = NULL;
	RCore *core = ds->core;
	ds_print_relocs (ds);
	bool is_code = (!ds->hint) || (ds->hint && ds->hint->type != 'd');
	RAnalMetaItem *mi = r_meta_get_at (ds->core->anal, ds->at, R_META_TYPE_ANY, NULL);
	if (mi) {
		is_code = mi->type != 'd';
		mi = NULL;
	}
	if (is_code && ds->asm_describe && !ds->has_description) {
		char *op, *locase = strdup (r_asm_op_get_asm (&ds->asmop));
		if (!locase) {
			return;
		}
		op = strchr (locase, ' ');
		if (op) {
			*op = 0;
		}
		r_str_case (locase, 0);
		desc = r_asm_describe (core->rasm, locase);
		free (locase);
	}
	if (ds->show_usercomments || ds->show_comments) {
		if (desc && *desc) {
			ds_align_comment (ds);
			if (ds->show_color) {
				r_cons_strcat (ds->color_comment);
			}
			r_cons_strcat ("; ");
			r_cons_strcat (desc);
			ds_print_color_reset (ds);
		}
		if (ds->show_comment_right && ds->comment) {
			char *comment = ds->comment;
			r_str_trim (comment);
			if (*comment) {
				if (!desc) {
					ds_align_comment (ds);
				}
				if (strchr (comment, '\n')) {
					comment = strdup (comment);
					if (comment) {
						ds_newline (ds);
						ds_begin_line (ds);
						size_t lines_count;
						size_t *line_indexes = r_str_split_lines (comment, &lines_count);
						if (line_indexes) {
							int i;
							for (i = 0; i < lines_count; i++) {
								char *c = comment + line_indexes[i];
								ds_print_pre (ds, true);
								ds_align_comment (ds);
								if (ds->show_color) {
									r_cons_strcat (ds->color_usrcmt);
								}
								r_cons_printf (i == 0 ? "%s" : "; %s", c);
								if (i < lines_count - 1) {
									ds_newline (ds);
									ds_begin_line (ds);
								}
							}
						}
						free (line_indexes);
					}
					free (comment);
				} else {
					if (comment) {
						r_cons_strcat (comment);
					}
				}
			}
			//r_cons_strcat_justify (comment, strlen (ds->refline) + 5, ';');
			ds_print_color_reset (ds);
			R_FREE (ds->comment);
		}
	}
	free (desc);
	if ((ds->analop.type == R_ANAL_OP_TYPE_CALL || ds->analop.type & R_ANAL_OP_TYPE_UCALL) && ds->show_calls) {
		ds_print_calls_hints (ds);
	}
}

static void ds_print_as_string(RDisasmState *ds) {
	char *str = r_num_as_string (NULL, ds->analop.ptr, true);
	if (str) {
		ds_comment (ds, false, "%s; \"%s\"%s", COLOR (ds, pal_comment),
			str, COLOR_RESET (ds));
	}
	free (str);
}

static char *_find_next_number(char *op) {
	char *p = op;
	if (p) {
		while (*p) {
			// look for start of next separator or ANSI sequence
			while (*p && !IS_SEPARATOR (*p) && *p != 0x1b) {
				p++;
			}
			if (*p == 0x1b) {
				// skip to end of ANSI sequence (lower or uppercase char)
				while (*p && !(*p >= 'A' && *p <= 'Z') && !(*p >= 'a' && *p <= 'z')) {
					p++;
				}
				if (*p) {
					p++;
				}
			}
			if (IS_SEPARATOR (*p)) {
				// skip to end of separator
				while (*p && IS_SEPARATOR (*p)) {
					p++;
				}
			}
			if (IS_DIGIT (*p)) {
				// we found the start of the next number
				return p;
			}
		}
	}
	return NULL;
}

static bool set_jump_realname(RDisasmState *ds, ut64 addr, const char **kw, const char **name) {
	RFlag *f = ds->core->flags;
	if (!f) {
		return false;
	}
	if (!ds->asm_demangle && !f->realnames) {
		// nothing to do, neither demangled nor regular realnames should be shown
		return false;
	}
	RFlagItem *flag_sym = r_flag_get_by_spaces (f, addr, R_FLAGS_FS_SYMBOLS, NULL);
	if (!flag_sym || !flag_sym->realname) {
		// nothing to replace
		return false;
	}
	if (!flag_sym->demangled && !f->realnames) {
		// realname is not demangled and we don't want to show non-demangled realnames
		return false;
	}
	*name = flag_sym->realname;
	RFlagItem *flag_mthd = r_flag_get_by_spaces (f, addr, R_FLAGS_FS_CLASSES, NULL);
	if (!f->realnames) {
		// for asm.flags.real, we don't want these prefixes
		if (flag_mthd && flag_mthd->name && r_str_startswith (flag_mthd->name, "method.")) {
			*kw = "method ";
		} else {
			*kw = "sym ";
		}
	}
	return true;
}

// TODO: this should be moved into r_parse
static char *ds_sub_jumps(RDisasmState *ds, char *str) {
	RAnal *anal = ds->core->anal;
	RFlag *f = ds->core->flags;
	const char *name = NULL;
	const char *kw = "";
	if (!ds->subjmp || !anal) {
		return str;
	}
	int optype = ds->analop.type & 0xFFFF;
	switch (optype) {
	case R_ANAL_OP_TYPE_JMP:
	case R_ANAL_OP_TYPE_UJMP:
	case R_ANAL_OP_TYPE_CALL:
		break;
	default:
		return str;
	}
	ut64 addr = ds->analop.jump;

	RAnalFunction *fcn = r_anal_get_function_at (anal, addr);
	if (fcn) {
		if (!set_jump_realname (ds, addr, &kw, &name)) {
			name = fcn->name;
		}
	} else if (f) {
		RBinReloc *rel = NULL;
		if (!ds->core->bin->is_reloc_patched) {
			rel = r_core_getreloc (ds->core, ds->analop.addr, ds->analop.size);
		}
		if (!rel) {
			rel = r_core_getreloc (ds->core, addr, ds->analop.size);
		}
		if (rel) {
			if (rel && rel->import && rel->import->name) {
				name = rel->import->name;
			} else if (rel && rel->symbol && rel->symbol->name) {
				name = rel->symbol->name;
			}
		} else {
			if (!set_jump_realname (ds, addr, &kw, &name)) {
				RFlagItem *flag = r_core_flag_get_by_spaces (f, addr);
				if (flag) {
					if (strchr (flag->name, '.')) {
						name = flag->name;
						if (f->realnames && flag->realname) {
							name = flag->realname;
						}
					}
				}
			}
		}
	}
	if (name) {
		char *nptr, *ptr;
		ut64 numval;
		ptr = str;
		while ((nptr = _find_next_number (ptr))) {
			ptr = nptr;
			numval = r_num_get (NULL, ptr);
			if (numval == addr) {
				while (*nptr && !IS_SEPARATOR (*nptr) && *nptr != 0x1b) {
					nptr++;
				}
				char *kwname = r_str_newf ("%s%s", kw, name);
				if (kwname) {
					char* numstr = r_str_ndup (ptr, nptr-ptr);
					if (numstr) {
						str = r_str_replace (str, numstr, kwname, 0);
						free (numstr);
					}
					free (kwname);
				}
				break;
			}
		}
	}
	return str;
}

static bool line_highlighted(RDisasmState *ds) {
	return ds->asm_highlight != UT64_MAX && ds->vat == ds->asm_highlight;
}

static void ds_start_line_highlight(RDisasmState *ds) {
	if (ds->show_color && line_highlighted (ds)) {
		r_cons_strcat (ds->color_linehl);
	}
}

static void ds_end_line_highlight(RDisasmState *ds) {
	if (ds->show_color && line_highlighted (ds)) {
		r_cons_strcat (Color_RESET);
	}
}

// int l is for lines
R_API int r_core_print_disasm(RPrint *p, RCore *core, ut64 addr, ut8 *buf, int len, int l, int invbreak, int cbytes, bool json, PJ *pj, RAnalFunction *pdf) {
	int continueoninvbreak = (len == l) && invbreak;
	RAnalFunction *of = NULL;
	RAnalFunction *f = NULL;
	bool calc_row_offsets = p->calc_row_offsets;
	int ret, i, inc = 0, skip_bytes_flag = 0, skip_bytes_bb = 0, idx = 0;
	ut8 *nbuf = NULL;
	const int addrbytes = core->io->addrbytes;

	// TODO: All those ds must be print flags
	RDisasmState *ds = ds_init (core);
	ds->cbytes = cbytes;
	ds->print = p;
	ds->l = l;
	ds->buf = buf;
	ds->len = len;
	ds->addr = addr;
	ds->hint = NULL;
	ds->buf_line_begin = 0;
	ds->pdf = pdf;

	if (json) {
		ds->pj = pj ? pj : r_core_pj_new (core);
		if (!ds->pj) {
			ds_free (ds);
			return 0;
		}
		r_cons_push ();
	} else {
		ds->pj = NULL;
	}

	// disable row_offsets to prevent other commands to overwrite computed info
	p->calc_row_offsets = false;

	//r_cons_printf ("len =%d l=%d ib=%d limit=%d\n", len, l, invbreak, p->limit);
	// TODO: import values from debugger is possible
	// TODO: allow to get those register snapshots from traces
	// TODO: per-function register state trace
	// XXX - is there a better way to reset a the analysis counter so that
	// when code is disassembled, it can actually find the correct offsets
	{ /* used by asm.emu */
		r_reg_arena_push (core->anal->reg);
	}

	ds_reflines_init (ds);
	/* reset jmp table if not asked to keep it */
	if (!core->keep_asmqjmps) { // hack
		core->asmqjmps_count = 0;
		ut64 *p = realloc (core->asmqjmps, R_CORE_ASMQJMPS_NUM * sizeof (ut64));
		if (p) {
			core->asmqjmps_size = R_CORE_ASMQJMPS_NUM;
			core->asmqjmps = p;
			for (i = 0; i < R_CORE_ASMQJMPS_NUM; i++) {
				core->asmqjmps[i] = UT64_MAX;
			}
		}
	}
	if (ds->pj && !pj) {
		pj_a (ds->pj);
	}
toro:
	// uhm... is this necessary? imho can be removed
	r_asm_set_pc (core->rasm, r_core_pava (core, ds->addr + idx));
	core->cons->vline = r_config_get_i (core->config, "scr.utf8") ? (r_config_get_i (core->config, "scr.utf8.curvy") ? r_vline_uc : r_vline_u) : r_vline_a;

	if (core->print->cur_enabled) {
		// TODO: support in-the-middle-of-instruction too
		r_anal_op_fini (&ds->analop);
		if (r_anal_op (core->anal, &ds->analop, core->offset + core->print->cur,
			buf + core->print->cur, (int)(len - core->print->cur), R_ANAL_OP_MASK_ALL)) {
			// TODO: check for ds->analop.type and ret
			ds->dest = ds->analop.jump;
		}
	} else {
		/* highlight eip */
		const char *pc = core->anal->reg->name[R_REG_NAME_PC];
		if (pc) {
			RFlagItem *item = r_flag_get (core->flags, pc);
			if (item) {
				ds->dest = item->offset;
			}
		}
	}

	ds_print_esil_anal_init (ds);
	inc = 0;
	if (!ds->l) {
		ds->l = core->blocksize;
	}
	r_cons_break_push (NULL, NULL);
	for (i = idx = ret = 0; addrbytes * idx < len && ds->lines < ds->l; idx += inc, i++, ds->index += inc, ds->lines++) {
		ds->at = ds->addr + idx;
		ds->vat = r_core_pava (core, ds->at);
		if (r_cons_is_breaked ()) {
			R_FREE (nbuf);
			if (ds->pj) {
				r_cons_pop ();
			}
			r_cons_break_pop ();
			ds_free (ds);
			return 0; //break;
		}
		if (core->print->flags & R_PRINT_FLAGS_UNALLOC) {
			if (!core->anal->iob.is_valid_offset (core->anal->iob.io, ds->at, 0)) {
				ds_begin_line (ds);
				ds_print_labels (ds, f);
				ds_setup_print_pre (ds, false, false);
				ds_print_lines_left (ds);
				core->print->resetbg = (ds->asm_highlight == UT64_MAX);
				ds_start_line_highlight (ds);
				ds_print_offset (ds);
				r_cons_printf ("  unmapped\n");
				inc = 1;
				continue;
			}
		}
		if (!ds->show_comment_right) {
			if (ds->show_cmtesil) {
				const char *esil = R_STRBUF_SAFEGET (&ds->analop.esil);
				// ds_begin_line (ds);
				ds_pre_line (ds);
				ds_setup_print_pre (ds, false, false);
				r_cons_strcat ("      ");
                                ds_print_lines_left (ds);
				ds_begin_comment (ds);
				if (ds->show_color) {
					ds_comment (ds, true, "; %s%s%s",
						ds->pal_comment, esil, Color_RESET);
				} else {
					ds_comment (ds, true, "; %s", esil);
				}
			}
		}
		r_core_seek_arch_bits (core, ds->at); // slow but safe
		ds->has_description = false;
		ds->hint = r_core_hint_begin (core, ds->hint, ds->at);
		ds->printed_str_addr = UT64_MAX;
		ds->printed_flag_addr = UT64_MAX;
		// XXX. this must be done in ds_update_pc()
		// ds_update_pc (ds, ds->at);
		r_asm_set_pc (core->rasm, ds->at);
		ds_update_ref_lines (ds);
		r_anal_op_fini (&ds->analop);
		r_anal_op (core->anal, &ds->analop, ds->at, buf + addrbytes * idx, (int)(len - addrbytes * idx), R_ANAL_OP_MASK_ALL);
		if (ds_must_strip (ds)) {
			inc = ds->analop.size;
			// inc = ds->asmop.payload + (ds->asmop.payload % ds->core->rasm->dataalign);
			r_anal_op_fini (&ds->analop);
			continue;
		}
		// f = r_anal_get_fcn_in (core->anal, ds->at, R_ANAL_FCN_TYPE_NULL);
		f = ds->fcn = fcnIn (ds, ds->at, R_ANAL_FCN_TYPE_NULL);
		if (f && f->folded && r_anal_function_contains (f, ds->at)) {
			int delta = (ds->at <= f->addr) ? (ds->at - r_anal_function_max_addr (f)) : 0;
			if (of != f) {
				char cmt[32];
				get_bits_comment (core, f, cmt, sizeof (cmt));
				const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, ds->at);
				if (comment) {
					ds_pre_xrefs (ds, true);
					r_cons_printf ("; %s\n", comment);
				}
				r_cons_printf ("%s%s%s (fcn) %s%s%s\n",
					COLOR (ds, color_fline), core->cons->vline[CORNER_TL],
					COLOR (ds, color_fname), f->name, cmt, COLOR_RESET (ds));
				ds_setup_print_pre (ds, true, false);
				ds_print_lines_left (ds);
				ds_print_offset (ds);
				r_cons_printf ("(%" PFMT64d " byte folded function)\n", r_anal_function_linear_size (f));
				//r_cons_printf ("%s%s%s\n", COLOR (ds, color_fline), core->cons->vline[RDWN_CORNER], COLOR_RESET (ds));
				if (delta < 0) {
					delta = -delta;
				}
				ds->addr += delta + idx;
				r_io_read_at (core->io, ds->addr, buf, len);
				inc = 0; //delta;
				idx = 0;
				of = f;
				r_anal_op_fini (&ds->analop);
				if (len == l) {
					break;
				}
			} else {
				ds->lines--;
				ds->addr += 1;
				r_io_read_at (core->io, ds->addr, buf, len);
				inc = 0; //delta;
				idx = 0;
				r_anal_op_fini (&ds->analop);
			}
			continue;
		}
		ds_show_comments_right (ds);
		// TRY adding here
		char *link_key = sdb_fmt ("link.%08"PFMT64x, ds->addr + idx);
		const char *link_type = sdb_const_get (core->anal->sdb_types, link_key, 0);
		if (link_type) {
			char *fmt = r_type_format (core->anal->sdb_types, link_type);
			if (fmt) {
				r_cons_printf ("(%s)\n", link_type);
				r_core_cmdf (core, "pf %s @ 0x%08"PFMT64x"\n", fmt, ds->addr + idx);
				const ut32 type_bitsize = r_type_get_bitsize (core->anal->sdb_types, link_type);
				// always round up when calculating byte_size from bit_size of types
				// could be struct with a bitfield entry
				inc = (type_bitsize >> 3) + (!!(type_bitsize & 0x7));
				free (fmt);
				r_anal_op_fini (&ds->analop);
				continue;
			}
		} else {
			if (idx >= 0) {
				ret = ds_disassemble (ds, buf + addrbytes * idx, len - addrbytes * idx);
				if (ret == -31337) {
					inc = ds->oplen;
					r_anal_op_fini (&ds->analop);
					continue;
				}
			}
		}
		if (ds->retry) {
			ds->retry = false;
			r_cons_break_pop ();
			r_anal_op_fini (&ds->analop);
			goto retry;
		}
		ds_atabs_option (ds);
		if (ds->analop.addr != ds->at) {
			r_anal_op_fini (&ds->analop);
			r_anal_op (core->anal, &ds->analop, ds->at, buf + addrbytes * idx, (int)(len - addrbytes * idx), R_ANAL_OP_MASK_ALL);
		}
		if (ret < 1) {
			r_strbuf_fini (&ds->analop.esil);
			r_strbuf_init (&ds->analop.esil);
			ds->analop.type = R_ANAL_OP_TYPE_ILL;
		}
		if (ds->hint) {
			if (ds->hint->size) {
				ds->analop.size = ds->hint->size;
			}
			if (ds->hint->ptr) {
				ds->analop.ptr = ds->hint->ptr;
			}
		}
		ds_print_bbline (ds);
		if (ds->at >= addr) {
			r_print_set_rowoff (core->print, ds->lines, ds->at - addr, calc_row_offsets);
		}
		skip_bytes_flag = handleMidFlags (core, ds, true);
		if (ds->midbb) {
			skip_bytes_bb = handleMidBB(core, ds);
		}
		ds_show_flags (ds, false);
		ds_show_xrefs (ds);
		if (skip_bytes_flag && ds->midflags == R_MIDFLAGS_SHOW &&
				(!ds->midbb || !skip_bytes_bb || skip_bytes_bb > skip_bytes_flag)) {
			ds->at += skip_bytes_flag;
			ds_show_flags(ds, true);
			ds_show_xrefs(ds);
			ds->at -= skip_bytes_flag;
		}
		if (ds->pdf) {
			static bool sparse = false;
			RAnalBlock *bb = r_anal_fcn_bbget_in (core->anal, ds->pdf, ds->at);
			if (!bb) {
				for (inc = 1; inc < ds->oplen; inc++) {
					RAnalBlock *bb = r_anal_fcn_bbget_in (core->anal, ds->pdf, ds->at + inc);
					if (bb) {
						break;
					}
				}
				r_anal_op_fini (&ds->analop);
				if (!sparse) {
					r_cons_printf ("..\n");
					sparse = true;
				}
				continue;
			}
			sparse = false;
		}
		ds_control_flow_comments (ds);
		ds_adistrick_comments (ds);
		/* XXX: This is really cpu consuming.. need to be fixed */
		ds_show_functions (ds);

		if (ds->show_comments && !ds->show_comment_right) {
			ds_show_refs (ds);
			ds_build_op_str (ds, false);
			ds_print_ptr (ds, len + 256, idx);
			ds_print_sysregs (ds);
			ds_print_fcn_name (ds);
			ds_print_demangled (ds);
			ds_print_color_reset (ds);
			if (!ds->pseudo) {
				R_FREE (ds->opstr);
			}
			if (ds->show_emu) {
				ds_print_esil_anal (ds);
			}
			if ((ds->analop.type == R_ANAL_OP_TYPE_CALL || ds->analop.type & R_ANAL_OP_TYPE_UCALL) && ds->show_calls) {
				ds_print_calls_hints (ds);
			}
			ds_show_comments_describe (ds);
		}

		f = fcnIn (ds, ds->addr, 0);
		ds_begin_line (ds);
		ds_print_labels (ds, f);
		ds_setup_print_pre (ds, false, false);
		ds_print_lines_left (ds);
		core->print->resetbg = (ds->asm_highlight == UT64_MAX);
		ds_start_line_highlight (ds);
		ds_print_offset (ds);
		////
		RAnalFunction *fcn = f;
		if (fcn) {
			RAnalBlock *bb = r_anal_fcn_bbget_in (core->anal, fcn, ds->at);
			if (!bb) {
				fcn = r_anal_get_function_at (core->anal, ds->at);
				if (fcn) {
					bb = r_anal_fcn_bbget_in (core->anal, fcn, ds->at);
				}
			}
			if (bb) {
				if (bb->folded) {
					r_cons_printf ("[+] Folded BB [..0x%08"PFMT64x"]\n", ds->at + bb->size);
					inc = bb->size;
					continue;
				}
			}
		}
		////
		int mi_type;
		bool mi_found = ds_print_meta_infos (ds, buf, len, idx, &mi_type);
		if (ds->asm_hint_pos == 0) {
			if (mi_found) {
				r_cons_printf ("      ");
			} else {
				ds_print_core_vmode (ds, ds->asm_hint_pos);
			}
		}
		ds_print_op_size (ds);
		ds_print_trace (ds);
		ds_print_cycles (ds);
		ds_print_family (ds);
		ds_print_stackptr (ds);
		if (mi_found) {
			ds_print_dwarf (ds);
			ret = ds_print_middle (ds, ret);

			ds_print_asmop_payload (ds, buf + addrbytes * idx);
			if (core->rasm->syntax != R_ASM_SYNTAX_INTEL) {
				RAsmOp ao; /* disassemble for the vm .. */
				int os = core->rasm->syntax;
				r_asm_set_syntax (core->rasm, R_ASM_SYNTAX_INTEL);
				r_asm_disassemble (core->rasm, &ao, buf + addrbytes * idx,
					len - addrbytes * idx + 5);
				r_asm_set_syntax (core->rasm, os);
			}
			if (mi_type == R_META_TYPE_FORMAT) {
				if ((ds->show_comments || ds->show_usercomments) && ds->show_comment_right) {
			//		haveMeta = false;
				}
			}
			if (mi_type != R_META_TYPE_FORMAT) {
				if (ds->asm_hint_pos > 0) {
					ds_print_core_vmode (ds, ds->asm_hint_pos);
				}
			}
			{
				ds_end_line_highlight (ds);
				if ((ds->show_comments || ds->show_usercomments) && ds->show_comment_right) {
					ds_print_color_reset (ds);
					ds_print_comments_right (ds);
				}
			}
		} else {
			/* show cursor */
			ds_print_show_cursor (ds);
			if (!ds->show_bytes_right) {
				ds_print_show_bytes (ds);
			}
			ds_print_lines_right (ds);
			ds_print_optype (ds);
			ds_build_op_str (ds, true);
			ds_print_opstr (ds);
			ds_end_line_highlight (ds);
			ds_print_dwarf (ds);
			ret = ds_print_middle (ds, ret);

			ds_print_asmop_payload (ds, buf + addrbytes * idx);
			if (core->rasm->syntax != R_ASM_SYNTAX_INTEL) {
				RAsmOp ao; /* disassemble for the vm .. */
				int os = core->rasm->syntax;
				r_asm_set_syntax (core->rasm, R_ASM_SYNTAX_INTEL);
				r_asm_disassemble (core->rasm, &ao, buf + addrbytes * idx,
					len - addrbytes * idx + 5);
				r_asm_set_syntax (core->rasm, os);
			}
			if (ds->show_bytes_right && ds->show_bytes) {
				ds_comment (ds, true, "");
				ds_print_show_bytes (ds);
			}
			if (ds->asm_hint_pos > 0) {
				ds_print_core_vmode (ds, ds->asm_hint_pos);
			}
			// ds_print_cc_update (ds);

			ds_cdiv_optimization (ds);
			if ((ds->show_comments || ds->show_usercomments) && ds->show_comment_right) {
				if (ds->show_cmtesil) {
					const char *esil = R_STRBUF_SAFEGET (&ds->analop.esil);
					if (ds->show_color) {
						ds_comment (ds, true, "; %s%s%s",
							ds->pal_comment, esil, Color_RESET);
					} else {
						ds_comment (ds, true, "; %s", esil);
					}
				}
				ds_print_ptr (ds, len + 256, idx);
				ds_print_sysregs (ds);
				ds_print_fcn_name (ds);
				ds_print_demangled (ds);
				ds_print_color_reset (ds);
				ds_print_comments_right (ds);
				ds_print_esil_anal (ds);
				ds_show_refs (ds);
			}
		}
		core->print->resetbg = true;
		ds_newline (ds);
		if (ds->line) {
			if (ds->show_lines_ret && ds->analop.type == R_ANAL_OP_TYPE_RET) {
				if (strchr (ds->line, '>')) {
					memset (ds->line, ' ', r_str_len_utf8 (ds->line));
				}
				ds_begin_line (ds);
				ds_print_pre (ds, true);
				ds_print_ref_lines (ds->line, ds->line_col, ds);
				r_cons_printf ("; --------------------------------------");
				ds_newline (ds);
			}
			R_FREE (ds->line);
			R_FREE (ds->line_col);
			R_FREE (ds->refline);
			R_FREE (ds->refline2);
			R_FREE (ds->prev_line_col);
		}
		R_FREE (ds->opstr);
		inc = ds->oplen;

		if (ds->midflags == R_MIDFLAGS_REALIGN && skip_bytes_flag) {
			inc = skip_bytes_flag;
		}
		if (skip_bytes_bb && skip_bytes_bb < inc) {
			inc = skip_bytes_bb;
		}
		if (inc < 1) {
			inc = 1;
		}
		inc += ds->asmop.payload + (ds->asmop.payload % ds->core->rasm->dataalign);
	}
	r_anal_op_fini (&ds->analop);

	R_FREE (nbuf);
	r_cons_break_pop ();

#if HASRETRY
	if (!ds->cbytes && ds->lines < ds->l) {
		ds->addr = ds->at + inc;
	retry:
		if (len < 4) {
			len = 4;
		}
		free (nbuf);
		buf = nbuf = malloc (len);
		if (ds->tries > 0) {
			if (r_io_read_at (core->io, ds->addr, buf, len)) {
				goto toro;
			}
		}
		if (ds->lines < ds->l) {
			//ds->addr += idx;
			if (!r_io_read_at (core->io, ds->addr, buf, len)) {
				//ds->tries = -1;
			}
			goto toro;
		}
		if (continueoninvbreak) {
			goto toro;
		}
		R_FREE (nbuf);
	}
#endif
	if (ds->pj) {
		r_cons_pop ();
		if (!pj) {
			pj_end (ds->pj);
			r_cons_printf ("%s", pj_string (ds->pj));
			pj_free (ds->pj);
		}
	}
	r_print_set_rowoff (core->print, ds->lines, ds->at - addr, calc_row_offsets);
	r_print_set_rowoff (core->print, ds->lines + 1, UT32_MAX, calc_row_offsets);
	// TODO: this too (must review)
	ds_print_esil_anal_fini (ds);
	ds_reflines_fini (ds);
	ds_free (ds);
	R_FREE (nbuf);
	p->calc_row_offsets = calc_row_offsets;
	/* used by asm.emu */
	r_reg_arena_pop (core->anal->reg);
	return addrbytes * idx; //-ds->lastfail;
}

static inline bool check_end(int nb_opcodes, int nb_bytes, int i, int j) {
	if (nb_opcodes > 0) {
		if (nb_bytes > 0) {
			return j < nb_opcodes && i < nb_bytes;
		}
		return j < nb_opcodes;
	}
	return i < nb_bytes;
}

R_API int r_core_print_disasm_instructions_with_buf(RCore *core, ut64 address, ut8 *buf, int nb_bytes, int nb_opcodes) {
	RDisasmState *ds = NULL;
	int i, j, ret, len = 0;
	char *tmpopstr;
	const ut64 old_offset = core->offset;
	bool hasanal = false;
	const size_t addrbytes = buf ? 1 : core->io->addrbytes;
	int skip_bytes_flag = 0, skip_bytes_bb = 0;

	if (nb_bytes < 1 && nb_opcodes < 1) {
		return 0;
	}

	r_reg_arena_push (core->anal->reg);

	ds = ds_init (core);
	ds->l = nb_opcodes;
	ds->len = nb_opcodes * 8;

	if (!buf) {
		r_core_seek (core, address, true);
		buf = core->block;
	}

	core->offset = address;

	r_cons_break_push (NULL, NULL);
	//build ranges to map addr with bits
	j = 0;
toro:
	for (i = 0; check_end (nb_opcodes, nb_bytes, addrbytes * i, j); i += ret, j++) {
		ds->at = address + i;
		ds->vat = r_core_pava (core, ds->at);
		hasanal = false;
		r_core_seek_arch_bits (core, ds->at);
		if (r_cons_is_breaked ()) {
			break;
		}
		ds->hint = r_core_hint_begin (core, ds->hint, ds->at);
		ds->has_description = false;
		r_asm_set_pc (core->rasm, ds->at);
		// XXX copypasta from main disassembler function
		// r_anal_get_fcn_in (core->anal, ds->at, R_ANAL_FCN_TYPE_NULL);
		ret = r_asm_disassemble (core->rasm, &ds->asmop,
			buf + addrbytes * i, nb_bytes - addrbytes * i);
		ds->oplen = ret;
		skip_bytes_flag = handleMidFlags (core, ds, true);
		if (ds->midbb) {
			skip_bytes_bb = handleMidBB (core, ds);
		}
		if (skip_bytes_flag && ds->midflags > R_MIDFLAGS_SHOW) {
			ret = skip_bytes_flag;
		}
		if (skip_bytes_bb && skip_bytes_bb < ret) {
			ret = skip_bytes_bb;
		}
		r_anal_op_fini (&ds->analop);
		if (!hasanal) {
			// XXX we probably don't need MASK_ALL
			r_anal_op (core->anal, &ds->analop, ds->at, buf + addrbytes * i, nb_bytes - addrbytes * i, R_ANAL_OP_MASK_ALL);
			hasanal = true;
		}
		if (ds_must_strip (ds)) {
			continue;
		}

		if (ds->hint && ds->hint->size > 0) {
			ret = ds->hint->size;
			ds->oplen = ret;
			ds->analop.size = ret;
			ds->asmop.size = ret;
		}
		/* fix infinite loop */
		if (ret < 1) {
			ret = 1;
		}
		len += R_MAX (0, ret);
		if (ds->hint && ds->hint->opcode) {
			free (ds->opstr);
			ds->opstr = strdup (ds->hint->opcode);
		} else {
			if (ds->decode && !ds->immtrim) {
				R_FREE (ds->opstr);
				if (!hasanal) {
					r_anal_op (core->anal, &ds->analop, ds->at, buf + i, nb_bytes - i, R_ANAL_OP_MASK_ALL);
					hasanal = true;
				}
				tmpopstr = r_anal_op_to_string (core->anal, &ds->analop);
				ds->opstr = (tmpopstr)? tmpopstr: strdup (r_asm_op_get_asm (&ds->asmop));
			} else if (ds->immtrim) {
				free (ds->opstr);
				ds->opstr = strdup (r_asm_op_get_asm (&ds->asmop));
				char *res = r_parse_immtrim (strdup (ds->opstr));
				if (res) {
					free (ds->opstr);
					ds->opstr = res;
				}
			} else if (ds->use_esil) {
				if (!hasanal) {
					r_anal_op (core->anal, &ds->analop,
						ds->at, buf + i,
						nb_bytes - i, R_ANAL_OP_MASK_ESIL | R_ANAL_OP_MASK_HINT);
					hasanal = true;
				}
				if (*R_STRBUF_SAFEGET (&ds->analop.esil)) {
					free (ds->opstr);
					ds->opstr = strdup (R_STRBUF_SAFEGET (&ds->analop.esil));
				}
			} else if (ds->subnames) {
				char *asm_str;
				RSpace *ofs = core->parser->flagspace;
				RSpace *fs = ds->flagspace_ports;
				if (ds->analop.type == R_ANAL_OP_TYPE_IO) {
					core->parser->notin_flagspace = NULL;
					core->parser->flagspace = fs;
				} else {
					if (fs) {
						core->parser->notin_flagspace = fs;
						core->parser->flagspace = fs;
					} else {
						core->parser->notin_flagspace = NULL;
						core->parser->flagspace = NULL;
					}
				}
				ds_build_op_str (ds, true);
				free (ds->opstr);
				ds->opstr = strdup (ds->str);
				asm_str = colorize_asm_string (core, ds, true);
				core->parser->flagspace = ofs;
				free (ds->opstr);
				ds->opstr = asm_str;
			} else {
				ds->opstr = strdup (r_asm_op_get_asm (&ds->asmop));
			}
			if (ds->immtrim) {
				free (ds->opstr);
				ds->opstr = strdup (r_asm_op_get_asm (&ds->asmop));
				ds->opstr = r_parse_immtrim (ds->opstr);
			}
		}
		if (ds->asm_instr) {
			const char *opcolor = NULL;
			if (ds->show_color) {
				opcolor = r_print_color_op_type (core->print, ds->analop.type);
				r_cons_printf ("%s%s" Color_RESET "\n", opcolor, ds->opstr);
			} else {
				r_cons_println (ds->opstr);
			}
			R_FREE (ds->opstr);
		}
		if (ds->hint) {
			r_anal_hint_free (ds->hint);
			ds->hint = NULL;
		}
	}
	if (buf == core->block && nb_opcodes > 0 && j < nb_opcodes) {
		r_core_seek (core, core->offset + i, true);
		i = 0;
		goto toro;
	}
	r_cons_break_pop ();
	ds_free (ds);
	core->offset = old_offset;
	r_reg_arena_pop (core->anal->reg);

	return len;
}

static bool handle_backwards_disasm(RCore *core, int *nb_opcodes, int *nb_bytes) {
	if (!*nb_opcodes && !*nb_bytes) {
		return false;
	}
	if (!*nb_bytes) {
		*nb_bytes = core->blocksize;
		if (*nb_opcodes < 0) {
			/* Backward disassembly of nb_opcodes opcodes
			 * - We compute the new starting offset
			 * - Read at the new offset */
			*nb_opcodes = -*nb_opcodes;

			const ut64 old_offset = core->offset;
			int nbytes = 0;

			// We have some anal_info.
			if (r_core_prevop_addr (core, core->offset, *nb_opcodes, &core->offset)) {
				nbytes = old_offset - core->offset;
			} else {
				// core->offset is modified by r_core_prevop_addr
				core->offset = old_offset;
				r_core_asm_bwdis_len (core, &nbytes, &core->offset, *nb_opcodes);
			}
			if (nbytes > core->blocksize) {
				r_core_block_size (core, nbytes);
			}
			r_io_read_at (core->io, core->offset, core->block, nbytes);
		}
	} else {
		if (*nb_bytes < 0) { // Disassemble backward `nb_bytes` bytes
			*nb_bytes = -*nb_bytes;
			core->offset -= *nb_bytes;
			if (*nb_bytes > core->blocksize) {
				ut64 obsz = core->blocksize;
				r_core_block_size (core, *nb_bytes);
				if (core->blocksize == *nb_bytes) {
					r_io_read_at (core->io, core->offset, core->block, *nb_bytes);
				} else {
					eprintf ("Cannot read that much!\n");
					r_core_block_size (core, obsz);
					return false;
				}
				r_core_block_size (core, obsz);
			} else {
				r_io_read_at (core->io, core->offset, core->block, *nb_bytes);
			}
		} else {
			if (*nb_bytes > core->blocksize) {
				r_core_block_size (core, *nb_bytes);
				r_io_read_at (core->io, core->offset, core->block, *nb_bytes);
			}
		}
	}
	return true;
}

/* Disassemble either `nb_opcodes` instructions, or
 * `nb_bytes` bytes; both can be negative.
 * Set to 0 the parameter you don't use */
R_API int r_core_print_disasm_instructions(RCore *core, int nb_bytes, int nb_opcodes) {
	const ut64 ocore_offset = core->offset;
	int ret = -1;
	if (handle_backwards_disasm (core, &nb_opcodes, &nb_bytes)) {
		ret = r_core_print_disasm_instructions_with_buf (core, core->offset, NULL, nb_bytes, nb_opcodes);
	}
	r_core_seek (core, ocore_offset, true);
	return ret;
}

R_API int r_core_print_disasm_json(RCore *core, ut64 addr, ut8 *buf, int nb_bytes, int nb_opcodes, PJ *pj) {
	RAsmOp asmop;
	RDisasmState *ds;
	RAnalFunction *f;
	int i, j, k, ret, line;
	ut64 old_offset = core->offset;
	ut64 at;
	int dis_opcodes = 0;
	int limit_by = 'b';
	char str[512];

	if (nb_opcodes != 0) {
		limit_by = 'o';
	}
	if (nb_opcodes) { // Disassemble `nb_opcodes` opcodes.
		if (nb_opcodes < 0) {
			int count, nbytes = 0;

			/* Backward disassembly of `nb_opcodes` opcodes:
			 * - We compute the new starting offset
			 * - Read at the new offset */
			nb_opcodes = -nb_opcodes;

			if (nb_opcodes > 0xffff) {
				eprintf ("Too many backward instructions\n");
				return false;
			}

			if (r_core_prevop_addr (core, core->offset, nb_opcodes, &addr)) {
				nbytes = old_offset - addr;
			} else if (!r_core_asm_bwdis_len (core, &nbytes, &addr, nb_opcodes)) {
				/* workaround to avoid empty arrays */
#define BWRETRY 0
#if BWRETRY
				nb_opcodes ++;
				if (!r_core_asm_bwdis_len (core, &nbytes, &addr, nb_opcodes)) {
#endif
					pj_end (pj);
					return false;
#if BWRETRY
				}
#endif
				nb_opcodes --;
			}
			count = R_MIN (nb_bytes, nbytes);
			if (count > 0) {
				r_io_read_at (core->io, addr, buf, count);
				r_io_read_at (core->io, addr+count, buf+count, nb_bytes-count);
			} else {
				if (nb_bytes > 0) {
					memset (buf, 0xff, nb_bytes);
				}
			}
		} else {
			// If we are disassembling a positive number of lines, enable dis_opcodes
			// to be used to finish the loop
			// If we are disasembling a negative number of lines, we just calculate
			// the equivalent addr and nb_size and scan a positive number of BYTES
			// so keep dis_opcodes = 0;
			dis_opcodes = 1;
			r_io_read_at (core->io, addr, buf, nb_bytes);
		}
	} else { // Disassemble `nb_bytes` bytes
		if (nb_bytes < 0) {
			//Backward disassembly of `nb_bytes` bytes
			nb_bytes = -nb_bytes;
			addr -= nb_bytes;
			r_io_read_at (core->io, addr, buf, nb_bytes);
		}
	}
	core->offset = addr;

	// TODO: add support for anal hints
	// If using #bytes i = j
	// If using #opcodes, j is the offset from start address. i is the
	// offset in current disassembly buffer (256 by default)
	i = k = j = line = 0;
	// i = number of bytes
	// j = number of instructions
	// k = delta from addr
	ds = ds_init (core);
	bool result = false;

	for (;;) {
		bool end_nbopcodes, end_nbbytes;
		int skip_bytes_flag = 0, skip_bytes_bb = 0;

		at = addr + k;
		ds->hint = r_core_hint_begin (core, ds->hint, ds->at);
		r_asm_set_pc (core->rasm, at);
		// 32 is the biggest opcode length in intel
		// Make sure we have room for it
		if (dis_opcodes == 1 && i >= nb_bytes - 32) {
			// Read another nb_bytes bytes into buf from current offset
			r_io_read_at (core->io, at, buf, nb_bytes);
			i = 0;
		}

		if (limit_by == 'o') {
			if (j >= nb_opcodes) {
				break;
			}
		} else if (i >= nb_bytes) {
			break;
		}
		memset (&asmop, 0, sizeof (RAsmOp));
		ret = r_asm_disassemble (core->rasm, &asmop, buf + i, nb_bytes - i);
		if (ret < 1) {
			char *hex = r_asm_op_get_hex (&asmop);
			pj_o (pj);
			pj_kn (pj, "offset", at);
			pj_ki (pj, "size", 1);
			pj_ks (pj, "bytes", hex);
			pj_ks (pj, "type", "invalid");
			pj_end (pj);
			i++;
			k++;
			j++;
			result = true;
			free (hex);
			continue;
		}

		char opstr[256];
		r_str_ncpy (opstr, r_asm_op_get_asm (&asmop), sizeof (opstr) - 1);

		ds->has_description = false;
		r_anal_op_fini (&ds->analop);
		r_anal_op (core->anal, &ds->analop, at, buf + i, nb_bytes - i, R_ANAL_OP_MASK_ALL);

		if (ds->pseudo) {
			r_parse_parse (core->parser, opstr, opstr);
		}

		// f = r_anal_get_fcn_in (core->anal, at,
		f = fcnIn (ds, at, R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM | R_ANAL_FCN_TYPE_LOC);
		if (ds->subvar && f) {
			int ba_len = r_strbuf_length (&asmop.buf_asm) + 128;
			char *ba = malloc (ba_len);
			if (ba) {
				strcpy (ba, r_asm_op_get_asm (&asmop));
				r_parse_subvar (core->parser, f, at, ds->analop.size,
						ba, ba, ba_len);
				r_asm_op_set_asm (&asmop, ba);
				free (ba);
			}
		}
		ds->oplen = r_asm_op_get_size (&asmop);
		ds->at = at;
		skip_bytes_flag = handleMidFlags (core, ds, false);
		if (ds->midbb) {
			skip_bytes_bb = handleMidBB (core, ds);
		}
		if (skip_bytes_flag && ds->midflags > R_MIDFLAGS_SHOW) {
			ds->oplen = ret = skip_bytes_flag;
		}
		if (skip_bytes_bb && skip_bytes_bb < ret) {
			ds->oplen = ret = skip_bytes_bb;
		}
		{
			ut64 killme = UT64_MAX;
			bool be = core->print->big_endian;
			if (r_io_read_i (core->io, ds->analop.ptr, &killme, ds->analop.refptr, be)) {
				core->parser->subrel_addr = killme;
			}
		}
		{
			char *aop = r_asm_op_get_asm (&asmop);
			char *buf = malloc (strlen (aop) + 128);
			if (buf) {
				strcpy (buf, aop);
				buf = ds_sub_jumps (ds, buf);
				r_parse_filter (core->parser, ds->vat, core->flags, ds->hint, buf,
					str, sizeof (str) - 1, core->print->big_endian);
				str[sizeof (str) - 1] = '\0';
				r_asm_op_set_asm (&asmop, buf);
				free (buf);
			}
		}

		pj_o (pj);
		pj_kn (pj, "offset", at);
		if (ds->analop.ptr != UT64_MAX) {
			pj_kn (pj, "ptr", ds->analop.ptr);
		}
		if (ds->analop.val != UT64_MAX) {
			pj_kn (pj, "val", ds->analop.val);
		}
		pj_k (pj, "esil"); // split key and value to allow empty strings
		pj_s (pj, R_STRBUF_SAFEGET (&ds->analop.esil));
		pj_kb (pj, "refptr", ds->analop.refptr);
		pj_kn (pj, "fcn_addr", f ? f->addr : 0);
		pj_kn (pj, "fcn_last", f ? r_anal_function_max_addr (f) - ds->oplen : 0);
		pj_ki (pj, "size", ds->analop.size);
		pj_ks (pj, "opcode", opstr);
		pj_ks (pj, "disasm", str);
		{
			char *hex = r_asm_op_get_hex (&asmop);
			pj_ks (pj, "bytes", hex);
			free (hex);
		}
		pj_ks (pj, "family", r_anal_op_family_to_string (ds->analop.family));
		pj_ks (pj, "type", r_anal_optype_to_string (ds->analop.type));
		// indicate a relocated address
		RBinReloc *rel = r_core_getreloc (core, ds->at, ds->analop.size);
		// reloc is true if address in reloc table
		pj_kb (pj, "reloc", rel);
		// wanted the numerical values of the type information
		pj_kn (pj, "type_num", (ut64)(ds->analop.type & UT64_MAX));
		pj_kn (pj, "type2_num", (ut64)(ds->analop.type2 & UT64_MAX));
		// addr addrline info here
		{
			int line;
			char file[1024];
			bool ret = r_bin_addr2line (core->bin, at, file, sizeof (file) - 1, &line);
			if (!ret) {
				ret = r_bin_addr2line2 (core->bin, at, file, sizeof (file) - 1, &line);
			}
			if (ret) {
				pj_ko (pj, "addrline");
				pj_ks (pj, "file", file);
				pj_kn (pj, "line", line);
				pj_end (pj);
			}
		}
		// handle switch statements
		if (ds->analop.switch_op && r_list_length (ds->analop.switch_op->cases) > 0) {
			// XXX - the java caseop will still be reported in the assembly,
			// this is an artifact to make ensure the disassembly is properly
			// represented during the analysis
			RListIter *iter;
			RAnalCaseOp *caseop;
			pj_k (pj, "switch");
			pj_a (pj);
			r_list_foreach (ds->analop.switch_op->cases, iter, caseop ) {
				pj_o (pj);
				pj_kn (pj, "addr", caseop->addr);
				pj_kN (pj, "value", (st64) caseop->value);
				pj_kn (pj, "jump", caseop->jump);
				pj_end (pj);
			}
			pj_end (pj);
		}
		if (ds->analop.jump != UT64_MAX ) {
			pj_kN (pj, "jump", ds->analop.jump);
			if (ds->analop.fail != UT64_MAX) {
				pj_kn (pj, "fail", ds->analop.fail);
			}
		}
		/* add flags */
		{
			const RList *flags = r_flag_get_list (core->flags, at);
			RFlagItem *flag;
			RListIter *iter;
			if (flags && !r_list_empty (flags)) {
				pj_k (pj, "flags");
				pj_a (pj);
				r_list_foreach (flags, iter, flag) {
					pj_s (pj, flag->name);
				}
				pj_end (pj);
			}
		}
		/* add comments */
		{
			// TODO: slow because we are encoding b64
			const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, at);
			if (comment) {
				char *b64comment = sdb_encode ((const ut8*)comment, -1);
				pj_ks (pj, "comment", b64comment);
				free (b64comment);
			}
		}
		/* add refs */
		{
			RAnalRef *ref;
			RListIter *iter;
			RList *refs = r_anal_refs_get (core->anal, at);
			if (refs && !r_list_empty (refs)) {
				pj_k (pj, "refs");
				pj_a (pj);
				r_list_foreach (refs, iter, ref) {
					pj_o (pj);
					pj_kn (pj, "addr", ref->addr);
					pj_ks (pj, "type", r_anal_xrefs_type_tostring (ref->type));
					pj_end (pj);
				}
				pj_end (pj);
			}
			r_list_free (refs);
		}
		/* add xrefs */
		{
			RAnalRef *ref;
			RListIter *iter;
			RList *xrefs = r_anal_xrefs_get (core->anal, at);
			if (xrefs && !r_list_empty (xrefs)) {
				pj_k (pj, "xrefs");
				pj_a (pj);
				r_list_foreach (xrefs, iter, ref) {
					pj_o (pj);
					pj_kn (pj, "addr", ref->addr);
					pj_ks (pj, "type", r_anal_xrefs_type_tostring (ref->type));
					pj_end (pj);
				}
				pj_end (pj);
			}
			r_list_free (xrefs);
		}

		pj_end (pj);
		i += ds->oplen + asmop.payload + (ds->asmop.payload % ds->core->rasm->dataalign); // bytes
		k += ds->oplen + asmop.payload + (ds->asmop.payload % ds->core->rasm->dataalign); // delta from addr
		j++; // instructions
		line++;

		end_nbopcodes = dis_opcodes == 1 && nb_opcodes > 0 && line>=nb_opcodes;
		end_nbbytes = dis_opcodes == 0 && nb_bytes > 0 && i>=nb_bytes;
		result = true;
		if (end_nbopcodes || end_nbbytes) {
			break;
		}
	}
	core->offset = old_offset;
	r_anal_op_fini (&ds->analop);
	ds_free (ds);
	if (!result) {
		pj_o (pj);
		pj_end (pj);
		result = true;
	}
	return result;
}

R_API int r_core_print_disasm_all(RCore *core, ut64 addr, int l, int len, int mode) {
	const bool scr_color = r_config_get_i (core->config, "scr.color");
	int i, ret, count = 0;
	ut8 *buf = core->block;
	char str[128];
	RAsmOp asmop;
	if (l < 1) {
		l = len;
	}
	RDisasmState *ds = ds_init (core);
	if (l > core->blocksize || addr != core->offset) {
		buf = malloc (l + 1);
		r_io_read_at (core->io, addr, buf, l);
	}
	PJ *pj = NULL;
	if (mode == 'j') {
		pj = r_core_pj_new (core);
		if (!pj) {
			ds_free (ds);
			return 0;
		}
		pj_a (pj);
	}
	r_cons_break_push (NULL, NULL);
	for (i = 0; i < l; i++) {
		ds->at = addr + i;
		ds->vat = r_core_pava (core, ds->at);
		r_asm_set_pc (core->rasm, ds->vat);
		if (r_cons_is_breaked ()) {
			break;
		}
		ret = r_asm_disassemble (core->rasm, &asmop, buf + i, l - i);
		if (ret < 1) {
			switch (mode) {
			case 'j':
			case '=':
				break;
			case 'i':
				r_cons_printf ("???\n");
				break;
			default:
				r_cons_printf ("0x%08"PFMT64x" ???\n", ds->vat);
				break;
			}
		} else {
			count ++;
			switch (mode) {
			case 'i':
				r_parse_filter (core->parser, ds->vat, core->flags, ds->hint, r_asm_op_get_asm (&asmop),
						str, sizeof (str), core->print->big_endian);
				if (scr_color) {
					RAnalOp aop;
					RAnalFunction *f = fcnIn (ds, ds->vat, R_ANAL_FCN_TYPE_NULL);
					r_anal_op (core->anal, &aop, addr, buf+i, l-i, R_ANAL_OP_MASK_ALL);
					char *buf_asm = r_print_colorize_opcode (core->print, str,
							core->cons->context->pal.reg, core->cons->context->pal.num, false, f ? f->addr : 0);
					if (buf_asm) {
						r_cons_printf ("%s%s\n", r_print_color_op_type (core->print, aop.type), buf_asm);
						free (buf_asm);
					}
				} else {
					r_cons_println (r_asm_op_get_asm (&asmop));
				}
				break;
			case '=':
				if (i < 28) {
					char *str = r_str_newf ("0x%08"PFMT64x" %60s  %s\n", ds->vat, "", r_asm_op_get_asm (&asmop));
					char *sp = strchr (str, ' ');
					if (sp) {
						char *end = sp + 60 + 1;
						char *src = r_asm_op_get_hex (&asmop);
						char *dst = sp + 1 + (i * 2);
						int len = strlen (src);
						if (dst < end) {
							if (dst + len >= end) {
								len = end - dst;
								dst[len] = '.';
							}
							memcpy (dst, src, len);
						}
						free (src);
					}
					r_cons_strcat (str);
					free (str);
				}
				break;
			case 'j': {
				char *op_hex = r_asm_op_get_hex (&asmop);
				pj_o (pj);
				pj_kn (pj, "addr", addr + i);
				pj_ks (pj, "bytes", op_hex);
				pj_ks (pj, "inst", r_asm_op_get_asm (&asmop));
				pj_end (pj);
				free (op_hex);
				break;
			}
			default: {
				char *op_hex = r_asm_op_get_hex (&asmop);
				r_cons_printf ("0x%08"PFMT64x" %20s  %s\n",
						addr + i, op_hex,
						r_asm_op_get_asm (&asmop));
				free (op_hex);
			}
			}
		}
	}
	r_cons_break_pop ();
	if (buf != core->block) {
		free (buf);
	}
	if (mode == 'j') {
		pj_end (pj);
		r_cons_println (pj_string (pj));
		pj_free (pj);
	}
	ds_free (ds);
	return count;
}

R_API int r_core_disasm_pdi_with_buf(RCore *core, ut64 address, ut8 *buf, ut32 nb_opcodes, ut32 nb_bytes, int fmt) {
	bool show_offset = r_config_get_i (core->config, "asm.offset");
	bool show_bytes = r_config_get_i (core->config, "asm.bytes");
	int decode = r_config_get_i (core->config, "asm.decode");
	int subnames = r_config_get_i (core->config, "asm.sub.names");
	int show_color = r_config_get_i (core->config, "scr.color");
	bool asm_ucase = r_config_get_i (core->config, "asm.ucase");
	bool asm_instr = r_config_get_i (core->config, "asm.instr");
	int esil = r_config_get_i (core->config, "asm.esil");
	int flags = r_config_get_i (core->config, "asm.flags");
	bool asm_immtrim = r_config_get_i (core->config, "asm.imm.trim");
	int i = 0, j, ret, err = 0;
	ut64 old_offset = core->offset;
	RAsmOp asmop;
	const char *color_reg = R_CONS_COLOR_DEF (reg, Color_YELLOW);
	const char *color_num = R_CONS_COLOR_DEF (num, Color_CYAN);
	const size_t addrbytes = buf ? 1 : core->io->addrbytes;

	if (fmt == 'e') {
		show_bytes = false;
		decode = 1;
	}

	if (nb_opcodes < 1 && nb_bytes < 1) {
		return 0;
	}

	if (!buf) {
		r_core_seek (core, address, true);
		buf = core->block;
	}

	r_cons_break_push (NULL, NULL);
	r_core_seek (core, address, false);
	int midflags = r_config_get_i (core->config, "asm.flags.middle");
	int midbb = r_config_get_i (core->config, "asm.bbmiddle");
	bool asmmarks = r_config_get_i (core->config, "asm.marks");
	r_config_set_b (core->config, "asm.marks", false);
	i = 0;
	j = 0;
	RAnalMetaItem *meta = NULL;
toro:
	for (; check_end (nb_opcodes, nb_bytes, addrbytes * i, j); j++) {
		if (r_cons_is_breaked ()) {
			err = 1;
			break;
		}
		ut64 at = core->offset + i;
		if (flags) {
			if (fmt != 'e') { // pie
				RFlagItem *item = r_flag_get_i (core->flags, at);
				if (item) {
					if (show_offset) {
						const int show_offseg = (core->print->flags & R_PRINT_FLAGS_SEGOFF) != 0;
						const int show_offdec = (core->print->flags & R_PRINT_FLAGS_ADDRDEC) != 0;
						unsigned int seggrn = r_config_get_i (core->config, "asm.seggrn");
						r_print_offset_sg (core->print, at, 0, show_offseg, seggrn, show_offdec, 0, NULL);
					}
					r_cons_printf ("  %s:\n", item->name);
				}
			} // do not show flags in pie
		}
		if (show_offset) {
			const int show_offseg = (core->print->flags & R_PRINT_FLAGS_SEGOFF) != 0;
			const int show_offdec = (core->print->flags & R_PRINT_FLAGS_ADDRDEC) != 0;
			unsigned int seggrn = r_config_get_i (core->config, "asm.seggrn");
			r_print_offset_sg (core->print, at, 0, show_offseg, seggrn, show_offdec, 0, NULL);
		}
		ut64 meta_start = at;
		ut64 meta_size = 0;
		meta = r_meta_get_at (core->anal, meta_start, R_META_TYPE_ANY, &meta_size);
		if (meta) {
			switch (meta->type) {
			case R_META_TYPE_DATA:
				i += meta_size;
				{
					ut64 at = core->offset + i;
					int hexlen = nb_bytes - i;
					int delta = at - meta_start;
					if (meta_size < hexlen) {
						hexlen = meta_size;
					}
					core->print->flags &= ~R_PRINT_FLAGS_HEADER;
					int size = R_MIN (meta_size, nb_bytes - i);
					RDisasmState ds = {0};
					ds.core = core;
					ut8 *b = malloc (meta_size);
					if (b) {
						r_io_read_at (core->io, at, b, meta_size);
						if (size > 0 && !ds_print_data_type (&ds, b, 0, meta_size)) {
							r_cons_printf ("hex length=%d delta=%d\n", size, delta);
							r_print_hexdump (core->print, at, buf + i, hexlen - delta, 16, 1, 1);
						} else {
							r_cons_newline ();
						}
						free (b);
					}
					ret = true;
				}
				continue;
			case R_META_TYPE_STRING:
			case R_META_TYPE_FORMAT:
			case R_META_TYPE_MAGIC:
				//r_cons_printf (".magic : %s\n", meta->str);
				i += meta_size;
				continue;
			case R_META_TYPE_RUN:
				/* TODO */
				break;
			default:
				break;
			}
		}
		r_asm_set_pc (core->rasm, core->offset + i);
		ret = r_asm_disassemble (core->rasm, &asmop, buf + addrbytes * i,
			nb_bytes - addrbytes * i);
		if (midflags || midbb) {
			RDisasmState ds = {
				.oplen = ret,
				.at = core->offset + i,
				.midflags = midflags
			};
			int skip_bytes_flag = 0, skip_bytes_bb = 0;
			if (midflags) {
				skip_bytes_flag = handleMidFlags (core, &ds, true);
			}
			if (midbb) {
				skip_bytes_bb = handleMidBB (core, &ds);
			}
			if (skip_bytes_flag && midflags > R_MIDFLAGS_SHOW) {
				asmop.size = ret = skip_bytes_flag;
			}
			if (skip_bytes_bb && skip_bytes_bb < ret) {
				asmop.size = ret = skip_bytes_bb;
			}
		}
		if (fmt == 'C') {
			const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, core->offset + i);
			if (comment) {
				r_cons_printf ("0x%08" PFMT64x " %s\n", core->offset + i, comment);
			}
			i += ret;
			continue;
		}
		// r_cons_printf ("0x%08"PFMT64x"  ", core->offset+i);
		if (ret < 1) {
			err = 1;
			ret = asmop.size;
			if (ret < 1) {
				ret = 1;
			}
			if (show_bytes) {
				r_cons_printf ("%18s%02x  ", "", buf[i]);
			}
			r_cons_println ("invalid"); // ???");
		} else {
			if (show_bytes) {
				char *op_hex = r_asm_op_get_hex (&asmop);
				r_cons_printf ("%20s  ", op_hex);
				free (op_hex);
			}
			ret = asmop.size;
			if (!asm_instr) {
				r_cons_newline ();
			} else if (!asm_immtrim && (decode || esil)) {
				RAnalOp analop = {
					0
				};
				char *tmpopstr, *opstr = NULL;
				r_anal_op (core->anal, &analop, core->offset + i,
					buf + addrbytes * i, nb_bytes - addrbytes * i, R_ANAL_OP_MASK_ALL);
				tmpopstr = r_anal_op_to_string (core->anal, &analop);
				if (fmt == 'e') { // pie
					char *esil = (R_STRBUF_SAFEGET (&analop.esil));
					r_cons_println (esil);
				} else {
					if (decode) {
						opstr = tmpopstr? tmpopstr: r_asm_op_get_asm (&(asmop));
					} else if (esil) {
						opstr = (R_STRBUF_SAFEGET (&analop.esil));
					}
					if (asm_immtrim) {
						char *res = r_parse_immtrim (opstr);
						if (res) {
							opstr = res;
						}
					}
					r_cons_println (opstr);
				}
				r_anal_op_fini (&analop);
			} else {
				char opstr[128] = {
					0
				};
				char *asm_str = r_asm_op_get_asm (&asmop);
				if (asm_ucase) {
					r_str_case (asm_str, 1);
				}
				if (asm_immtrim) {
					char *res = r_parse_immtrim (asm_str);
					if (res) {
						asm_str = res;
					}
				}
				if (subnames) {
					RAnalHint *hint = r_anal_hint_get (core->anal, at);
					r_parse_filter (core->parser, at, core->flags, hint,
						asm_str, opstr, sizeof (opstr) - 1, core->print->big_endian);
					r_anal_hint_free (hint);
					asm_str = (char *)&opstr;
				}
				if (show_color) {
					RAnalOp aop = {
						0
					};
					RAnalFunction *f = r_anal_get_fcn_in (core->anal, core->offset + i, R_ANAL_FCN_TYPE_NULL);
					r_anal_op (core->anal, &aop, core->offset + i,
						buf + addrbytes * i, nb_bytes - addrbytes * i, R_ANAL_OP_MASK_BASIC);
					asm_str = r_print_colorize_opcode (core->print, asm_str, color_reg, color_num, false, f ? f->addr : 0);
					r_cons_printf ("%s%s"Color_RESET "\n",
						r_print_color_op_type (core->print, aop.type),
						asm_str);
					free (asm_str);
					r_anal_op_fini (&aop);
				} else {
					r_cons_println (asm_str);
				}
			}
		}
		i += ret;
	}
	if (buf == core->block && nb_opcodes > 0 && j < nb_opcodes) {
		r_core_seek (core, core->offset + i, true);
		i = 0;
		goto toro;
	}
	r_config_set_b (core->config, "asm.marks", asmmarks);
	r_cons_break_pop ();
	r_core_seek (core, old_offset, true);
	return err;
}

R_API int r_core_disasm_pdi(RCore *core, int nb_opcodes, int nb_bytes, int fmt) {
	const ut64 ocore_offset = core->offset;
	int ret = -1;
	if (handle_backwards_disasm(core, &nb_opcodes, &nb_bytes)) {
		ret = r_core_disasm_pdi_with_buf (core, core->offset, NULL, nb_opcodes, nb_bytes, fmt);
	}
	r_core_seek (core, ocore_offset, true);
	return ret;
}

static bool read_ahead(RIO *io, ut8 **buf, size_t *buf_sz, ut64 address, size_t offset_into_buf, size_t bytes_to_read) {
	if (offset_into_buf + bytes_to_read > *buf_sz) {
		const size_t new_sz = *buf_sz * 2;
		ut8 *tmp = realloc (*buf, new_sz);
		if (!tmp) {
			return false;
		}
		*buf_sz = new_sz;
		*buf = tmp;
	}
	return r_io_read_at_mapped (io, address, *buf + offset_into_buf, bytes_to_read);
}

R_API int r_core_disasm_pde(RCore *core, int nb_opcodes, int mode) {
	if (nb_opcodes < 1) {
		return 0;
	}
	RReg *reg = core->anal->reg;
	RRegItem *pc = r_reg_get (reg, "PC", R_REG_TYPE_ALL);
	if (!pc) {
		return -1;
	}
	PJ *pj = NULL;
	if (mode == R_MODE_JSON) {
		pj = r_core_pj_new (core);
		if (!pj) {
			return -1;
		}
		pj_a (pj);
	}
	if (!core->anal->esil) {
		r_core_cmd0 (core, "aei");
		if (!r_config_get_b (core->config, "cfg.debug")) {
			r_core_cmd0 (core, "aeim");
		}
	}
	RAnalEsil *esil = core->anal->esil;
	RPVector ocache = core->io->cache;
	RCache *ocacheb = core->io->buffer;
	const int ocached = core->io->cached;
	if (ocache.v.a) {
		if (ocacheb && ocacheb->len) {
			RCache *c = r_cache_new ();
			r_cache_set (c, ocacheb->base, ocacheb->buf, ocacheb->len);
			core->io->buffer = c;
		}
		RPVector *vec = (RPVector *)r_vector_clone ((RVector *)&ocache);
		vec->v.free = NULL;
		core->io->cache = *vec;
		free (vec);
	} else {
		r_io_cache_init (core->io);
	}
	r_reg_arena_push (reg);
	RConfigHold *chold = r_config_hold_new (core->config);
	r_config_hold (chold, "io.cache", "asm.lines", NULL);
	r_config_set_b (core->config, "io.cache", true);
	r_config_set_b (core->config, "asm.lines", false);
	const char *strip = r_config_get (core->config, "asm.strip");
	const int max_op_size = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_MAX_OP_SIZE);
	int min_op_size = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_MIN_OP_SIZE);
	min_op_size = min_op_size > 0 ? min_op_size : 1;
	const ut64 read_len = max_op_size > 0 ? max_op_size : 32;
	size_t buf_sz = 0x100, block_sz = 0, block_instr = 0;
	ut64 block_start = r_reg_get_value (reg, pc);
	ut8 *buf = malloc (buf_sz);
	size_t i;
	for (i = 0; i < nb_opcodes; i++) {
		const ut64 op_addr = r_reg_get_value (reg, pc);
		if (!read_ahead (core->io, &buf, &buf_sz, op_addr, block_sz, read_len)) {
			break;
		}
		RAnalOp op;
		int ret = r_anal_op (core->anal, &op, op_addr, buf + block_sz, read_len, R_ANAL_OP_MASK_ESIL);
		const bool invalid_instr = ret < 1 || op.size < 1 || op.type == R_ANAL_OP_TYPE_ILL;
		bool end_of_block = false;
		switch (op.type & R_ANAL_OP_TYPE_MASK & ~R_ANAL_OP_HINT_MASK) {
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_UJMP:
		case R_ANAL_OP_TYPE_CALL:
		case R_ANAL_OP_TYPE_UCALL:
		case R_ANAL_OP_TYPE_RET:
			end_of_block = true;
			break;
		}
		if (R_STR_ISNOTEMPTY (strip) && strstr (strip, r_anal_optype_to_string (op.type))) {
			i--;
		} else {
			if (invalid_instr) {
				block_sz += min_op_size;
			} else {
				block_sz += op.size;
			}
			if (invalid_instr || (i + 1 >= nb_opcodes)) {
				end_of_block = true;
			}
			block_instr++;
		}
		if (end_of_block) {
			if (op.delay) {
				const ut64 ops_to_read = R_MIN (op.delay, nb_opcodes - (i + 1));
				const ut64 bytes_to_read = ops_to_read * read_len;
				if (!read_ahead (core->io, &buf, &buf_sz, op_addr + op.size, block_sz, bytes_to_read)) {
					break;
				}
				block_instr += ops_to_read;
				block_sz += bytes_to_read;
				i += ops_to_read;
			}
			if (block_instr) {
				switch (mode) {
				case R_MODE_JSON:
					r_core_print_disasm_json (core, block_start, buf, block_sz, block_instr, pj);
					break;
				case R_MODE_SIMPLE:
					r_core_disasm_pdi_with_buf (core, block_start, buf, block_instr, block_sz, 0);
					break;
				case R_MODE_SIMPLEST:
					r_core_print_disasm_instructions_with_buf (core, block_start, buf, block_sz, block_instr);
					break;
				default:
					r_core_print_disasm (core->print, core, block_start, buf, block_sz, block_instr, 0, 0, false, NULL, NULL);
					break;
				}
			}
			block_sz = 0;
			block_instr = 0;
		}
		if (invalid_instr) {
			break;
		}
		r_anal_esil_set_pc (core->anal->esil, op_addr);
		r_reg_set_value (reg, pc, op_addr + op.size);
		const char *e = r_strbuf_get (&op.esil);
		if (R_STR_ISNOTEMPTY (e)) {
			r_anal_esil_parse (esil, e);
		}
		r_anal_op_fini (&op);

		if (end_of_block) {
			block_start = r_reg_get_value (reg, pc);
			r_core_seek_arch_bits (core, block_start);
		}
	}
	if (mode == R_MODE_JSON) {
		pj_end (pj);
		r_cons_print (pj_string (pj));
		pj_free (pj);
	}
	free (buf);
	r_reg_arena_pop (reg);
	int len = r_pvector_len (&ocache);
	if (r_pvector_len (&core->io->cache) > len) {
		// TODO: Implement push/pop for IO.cache
		while (len > 0) {
			(void)r_pvector_pop_front (&core->io->cache);
			len--;
		}
		core->io->cache.v.free = ocache.v.free;
	}
	r_io_cache_fini (core->io);
	core->io->cache = ocache;
	r_skyline_clear (&core->io->cache_skyline);
	void **it;
	r_pvector_foreach (&ocache, it) {
		RIOCache *c = (RIOCache *)*it;
		r_skyline_add (&core->io->cache_skyline, c->itv, c);
	}
	core->io->buffer = ocacheb;
	core->io->cached = ocached;
	r_config_hold_restore (chold);
	r_config_hold_free (chold);
	return i;
}
