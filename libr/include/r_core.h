/* radare - LGPL - Copyright 2009-2020 - pancake */

#ifndef R2_CORE_H
#define R2_CORE_H

#include <r_main.h>
#include "r_socket.h"
#include "r_types.h"
#include "r_magic.h"
#include "r_agraph.h"
#include "r_io.h"
#include "r_fs.h"
#include "r_lib.h"
#include "r_diff.h"
#include "r_egg.h"
#include "r_lang.h"
#include "r_asm.h"
#include "r_parse.h"
#include "r_anal.h"
#include "r_cmd.h"
#include "r_cons.h"
#include "r_search.h"
#include "r_sign.h"
#include "r_debug.h"
#include "r_flag.h"
#include "r_config.h"
#include "r_bin.h"
#include "r_hash.h"
#include "r_util.h"
#include "r_util/r_print.h"
#include "r_crypto.h"
#include "r_bind.h"

#ifdef __cplusplus
extern "C" {
#endif
R_LIB_VERSION_HEADER(r_core);

#define R_CORE_CMD_OK 0
#define R_CORE_CMD_INVALID -1
#define R_CORE_CMD_EXIT -2

#define R_CORE_BLOCKSIZE 0x100
#define R_CORE_BLOCKSIZE_MAX 0x3200000 /* 32MB */

#define R_CORE_ANAL_GRAPHLINES          1
#define R_CORE_ANAL_GRAPHBODY           2
#define R_CORE_ANAL_GRAPHDIFF           4
#define R_CORE_ANAL_JSON                8
#define R_CORE_ANAL_KEYVALUE            16
#define R_CORE_ANAL_JSON_FORMAT_DISASM  32
#define R_CORE_ANAL_STAR                64

#define R_FLAGS_FS_CLASSES "classes"
#define R_FLAGS_FS_FUNCTIONS "functions"
#define R_FLAGS_FS_IMPORTS "imports"
#define R_FLAGS_FS_RELOCS "relocs"
#define R_FLAGS_FS_RESOURCES "resources"
#define R_FLAGS_FS_SECTIONS "sections"
#define R_FLAGS_FS_SEGMENTS "segments"
#define R_FLAGS_FS_SIGNS "sign"
#define R_FLAGS_FS_STRINGS "strings"
#define R_FLAGS_FS_SYMBOLS "symbols"
#define R_FLAGS_FS_SYMBOLS_SECTIONS "symbols.sections"
#define R_FLAGS_FS_SYSCALLS "syscalls"

#define R_GRAPH_FORMAT_NO           0
#define R_GRAPH_FORMAT_GMLFCN       1
#define R_GRAPH_FORMAT_JSON         2
#define R_GRAPH_FORMAT_GML          3
#define R_GRAPH_FORMAT_DOT          4
#define R_GRAPH_FORMAT_CMD          5

///
#define R_CONS_COLOR_DEF(x, def) ((core->cons && core->cons->context->pal.x)? core->cons->context->pal.x: def)
#define R_CONS_COLOR(x) R_CONS_COLOR_DEF (x, "")

/* rtr */
#define RTR_PROTOCOL_RAP 0
#define RTR_PROTOCOL_TCP 1
#define RTR_PROTOCOL_UDP 2
#define RTR_PROTOCOL_HTTP 3
#define RTR_PROTOCOL_UNIX 4

#define RTR_MAX_HOSTS 255

/* visual mode */
typedef enum {
	R_CORE_VISUAL_MODE_PX = 0,
	R_CORE_VISUAL_MODE_PD = 1,
	R_CORE_VISUAL_MODE_DB = 2,
	R_CORE_VISUAL_MODE_OV = 3,
	R_CORE_VISUAL_MODE_CD = 4
} RCoreVisualMode;

/*
#define R_CORE_VISUAL_MODE_PC    4
#define R_CORE_VISUAL_MODE_PXA   5
#define R_CORE_VISUAL_MODE_PSS   6
#define R_CORE_VISUAL_MODE_PRC   7
#define R_CORE_VISUAL_MODE_PXa   8
#define R_CORE_VISUAL_MODE_PXR   9
*/

typedef struct r_core_rtr_host_t {
	int proto;
	char host[512];
	int port;
	char file[1024];
	RSocket *fd;
} RCoreRtrHost;

typedef struct r_core_undo_t {
	char *action;
	char *revert;
	ut64 tstamp;
	ut64 offset;
} RCoreUndo;

typedef enum {
	AUTOCOMPLETE_DEFAULT,
	AUTOCOMPLETE_MS
} RAutocompleteType;

typedef struct {
	ut64 addr;
	const char *glob;
	ut64 minstamp;
} RCoreUndoCondition;

typedef struct r_core_log_t {
	int first;
	int last;
	RStrpool *sp;
} RCoreLog;

typedef struct r_core_file_t {
	int dbg;
	int fd;
	RBinBind binb;
	const struct r_core_t *core;
	ut8 alive;
} RCoreFile;


typedef struct r_core_times_t {
	ut64 loadlibs_init_time;
	ut64 loadlibs_time;
	ut64 file_open_time;
} RCoreTimes;

#define R_CORE_ASMQJMPS_NUM 10
#define R_CORE_ASMQJMPS_LETTERS 26
#define R_CORE_ASMQJMPS_MAX_LETTERS (26 * 26 * 26 * 26 * 26)
#define R_CORE_ASMQJMPS_LEN_LETTERS 5

typedef enum r_core_autocomplete_types_t {
	R_CORE_AUTOCMPLT_DFLT = 0,
	R_CORE_AUTOCMPLT_FLAG,
	R_CORE_AUTOCMPLT_FLSP,
	R_CORE_AUTOCMPLT_SEEK,
	R_CORE_AUTOCMPLT_FCN,
	R_CORE_AUTOCMPLT_ZIGN,
	R_CORE_AUTOCMPLT_EVAL,
	R_CORE_AUTOCMPLT_PRJT,
	R_CORE_AUTOCMPLT_MINS,
	R_CORE_AUTOCMPLT_BRKP,
	R_CORE_AUTOCMPLT_MACR,
	R_CORE_AUTOCMPLT_FILE,
	R_CORE_AUTOCMPLT_THME,
	R_CORE_AUTOCMPLT_OPTN,
	R_CORE_AUTOCMPLT_MS,
	R_CORE_AUTOCMPLT_SDB,
// --- left as last always
	R_CORE_AUTOCMPLT_END,
} RCoreAutocompleteType;

typedef struct r_core_autocomplete_t {
	const char* cmd;
	int length;
	int n_subcmds;
	bool locked;
	int type;
	struct r_core_autocomplete_t** subcmds;
} RCoreAutocomplete;

typedef struct r_core_visual_tab_t {
	int printidx;
	ut64 offset;
	bool cur_enabled;
	int cur;
	int ocur;
	int cols;
	int disMode;
	int hexMode;
	int asm_offset;
	int asm_instr;
	int asm_indent;
	int asm_bytes;
	int asm_cmt_col;
	int printMode;
	int current3format;
	int current4format;
	int current5format;
	int dumpCols;
	char name[32]; // XXX leak because no  r_core_visual_tab_free
	// TODO: cursor and such
} RCoreVisualTab;
// #define RCoreVisualTab Tab

typedef struct r_core_visual_t {
	RList *tabs;
	int tab;
} RCoreVisual;
// #define RCoreVisual Visual

typedef struct {
	int x;
	int y;
	int w;
	int h;
	char *cmd;
} RCoreGadget;

R_API void r_core_gadget_free (RCoreGadget *g);

typedef struct r_core_tasks_t {
	int task_id_next;
	RList *tasks;
	RList *tasks_queue;
	RList *oneshot_queue;
	int oneshots_enqueued;
	struct r_core_task_t *current_task;
	struct r_core_task_t *main_task;
	RThreadLock *lock;
	int tasks_running;
	bool oneshot_running;
} RCoreTaskScheduler;

typedef struct r_core_t {
	RBin *bin;
	RArch *arch;
	RConfig *config;
	ut64 offset; // current seek
	ut64 prompt_offset; // temporarily set to offset to have $$ in expressions always stay the same during temp seeks
	ut32 blocksize;
	ut32 blocksize_max;
	ut8 *block;
	RBuffer *yank_buf;
	ut64 yank_addr;
	bool tmpseek;
	bool vmode;
	int interrupted; // XXX IS THIS DUPPED SOMEWHERE?
	/* files */
	RCons *cons;
	RIO *io;
	RCoreFile *file;
	RList *files;
	RNum *num;
	ut64 rc; // command's return code .. related to num->value;
	RLib *lib;
	RCmd *rcmd;
	RCmdDescriptor root_cmd_descriptor;
	RList/*<RCmdDescriptor>*/ *cmd_descriptors;
	RAnal *anal;
	RAsm *rasm;
	/* ^^ */
	RCoreTimes *times;
	RParse *parser;
	RPrint *print;
	RLang *lang;
	RDebug *dbg;
	RFlag *flags;
	RSearch *search;
	RFS *fs;
	RFSShell *rfs;
	REgg *egg;
	RCoreLog *log;
	RAGraph *graph;
	RPanelsRoot *panels_root;
	RPanels* panels;
	char *cmdqueue;
	char *lastcmd;
	char *cmdlog;
	bool cfglog; // cfg.corelog
	int cmdrepeat; // cmd.repeat
	const char *cmdtimes; // cmd.times
	R_DEPRECATE bool cmd_in_backticks; // whether currently executing a cmd out of backticks
	int rtr_n;
	RCoreRtrHost rtr_host[RTR_MAX_HOSTS];
	ut64 *asmqjmps;
	int asmqjmps_count;
	int asmqjmps_size;
	bool is_asmqjmps_letter;
	bool keep_asmqjmps;
	RCoreVisual visual;
	// visual // TODO: move them into RCoreVisual
	int http_up;
	int gdbserver_up;
	RCoreVisualMode printidx;
	char *stkcmd;
	bool in_search;
	RList *watchers;
	RList *scriptstack;
	RCoreTaskScheduler tasks;
	int max_cmd_depth;
	ut8 switch_file_view;
	Sdb *sdb;
	int incomment;
	int curtab; // current tab
	int seltab; // selected tab
	int cmdremote;
	char *lastsearch;
	char *cmdfilter;
	bool break_loop;
	RList *undos;
	bool binat;
	bool fixedbits; // will be true when using @b:
	bool fixedarch; // will be true when using @a:
	bool fixedblock;
	char *table_query;
	int sync_index; // used for http.sync and T=
	struct r_core_t *c2;
	RCoreAutocomplete *autocomplete;
	int autocomplete_type;
	int maxtab;
	REvent *ev;
	RList *gadgets;
	bool scr_gadgets;
	bool log_events; // core.c:cb_event_handler : log actions from events if cfg.log.events is set
	RList *ropchain;
	bool use_tree_sitter_r2cmd;
	RArchSessionPool *arch_pool;
	RMainCallback r_main_radare2;
	// int (*r_main_radare2)(int argc, char **argv);
	int (*r_main_rafind2)(int argc, const char **argv);
	int (*r_main_radiff2)(int argc, const char **argv);
	int (*r_main_rabin2)(int argc, const char **argv);
	int (*r_main_rarun2)(int argc, const char **argv);
	int (*r_main_ragg2)(int argc, const char **argv);
	int (*r_main_rasm2)(int argc, const char **argv);
	int (*r_main_rax2)(int argc, const char **argv);
} RCore;

// maybe move into RAnal
typedef struct r_core_item_t {
	const char *type;
	ut64 addr;
	ut64 next;
	ut64 prev;
	int size;
	int perm;
	char *data;
	char *comment;
	char *sectname;
	char *fcnname;
} RCoreItem;


R_API RCoreItem *r_core_item_at (RCore *core, ut64 addr);
R_API void r_core_item_free (RCoreItem *ci);

R_API int r_core_bind(RCore *core, RCoreBind *bnd);

typedef struct r_core_cmpwatch_t {
	ut64 addr;
	int size;
	char cmd[32];
	ut8 *odata;
	ut8 *ndata;
} RCoreCmpWatcher;

typedef int (*RCoreSearchCallback)(RCore *core, ut64 from, ut8 *buf, int len);

#ifdef R_API
//#define r_core_ncast(x) (RCore*)(size_t)(x)
R_API RList *r_core_list_themes(RCore *core);
R_API char *r_core_get_theme(void);
R_API const char *r_core_get_section_name(RCore *core, ut64 addr);
R_API RCons *r_core_get_cons(RCore *core);
R_API RBin *r_core_get_bin(RCore *core);
R_API RConfig *r_core_get_config (RCore *core);
R_API bool r_core_init(RCore *core);
R_API void r_core_bind_cons(RCore *core); // to restore pointers in cons
R_API RCore *r_core_new(void);
R_API void r_core_free(RCore *core);
R_API void r_core_fini(RCore *c);
R_API void r_core_wait(RCore *core);
R_API RCore *r_core_ncast(ut64 p);
R_API RCore *r_core_cast(void *p);
R_API bool r_core_bin_load_structs(RCore *core, const char *file);
R_API int r_core_config_init(RCore *core);
R_API void r_core_config_update(RCore *core);
R_API void r_core_parse_radare2rc(RCore *r);
R_API int r_core_prompt(RCore *core, int sync);
R_API int r_core_prompt_exec(RCore *core);
R_API int r_core_lines_initcache (RCore *core, ut64 start_addr, ut64 end_addr);
R_API int r_core_lines_currline (RCore *core);
R_API void r_core_prompt_loop(RCore *core);
R_API ut64 r_core_pava(RCore *core, ut64 addr);
R_API int r_core_cmd(RCore *core, const char *cmd, int log);
R_API int r_core_cmd_task_sync(RCore *core, const char *cmd, bool log);
R_API char *r_core_editor(const RCore *core, const char *file, const char *str);
R_API int r_core_fgets(char *buf, int len);
R_API RFlagItem *r_core_flag_get_by_spaces(RFlag *f, ut64 off);
R_API int r_core_cmdf(RCore *core, const char *fmt, ...);
R_API int r_core_flush(RCore *core, const char *cmd);
R_API int r_core_cmd0(RCore *core, const char *cmd);
R_API void r_core_cmd_init(RCore *core);
R_API int r_core_cmd_pipe(RCore *core, char *radare_cmd, char *shell_cmd);
R_API char *r_core_cmd_str(RCore *core, const char *cmd);
R_API char *r_core_cmd_strf(RCore *core, const char *fmt, ...);
R_API char *r_core_cmd_str_pipe(RCore *core, const char *cmd);
R_API int r_core_cmd_file(RCore *core, const char *file);
R_API int r_core_cmd_lines(RCore *core, const char *lines);
R_API int r_core_cmd_command(RCore *core, const char *command);
R_API bool r_core_run_script (RCore *core, const char *file);
R_API bool r_core_seek(RCore *core, ut64 addr, bool rb);
R_API bool r_core_visual_bit_editor(RCore *core);
R_API int r_core_seek_base (RCore *core, const char *hex);
R_API void r_core_seek_previous (RCore *core, const char *type);
R_API void r_core_seek_next (RCore *core, const char *type);
R_API int r_core_seek_align(RCore *core, ut64 align, int count);
R_API void r_core_arch_bits_at(RCore *core, ut64 addr, R_OUT R_NULLABLE int *bits, R_OUT R_BORROW R_NULLABLE const char **arch);
R_API void r_core_seek_arch_bits(RCore *core, ut64 addr);
R_API int r_core_block_read(RCore *core);
R_API int r_core_block_size(RCore *core, int bsize);
R_API int r_core_seek_size(RCore *core, ut64 addr, int bsize);
R_API int r_core_is_valid_offset (RCore *core, ut64 offset);
R_API int r_core_shift_block(RCore *core, ut64 addr, ut64 b_size, st64 dist);
R_API void r_core_autocomplete(R_NULLABLE RCore *core, RLineCompletion *completion, RLineBuffer *buf, RLinePromptType prompt_type);
R_API void r_core_print_scrollbar(RCore *core);
R_API void r_core_print_scrollbar_bottom(RCore *core);
R_API void r_core_visual_prompt_input (RCore *core);
R_API void r_core_visual_toggle_decompiler_disasm(RCore *core, bool for_graph, bool reset);
R_API void r_core_visual_applyDisMode(RCore *core, int disMode);
R_API void r_core_visual_applyHexMode(RCore *core, int hexMode);
R_API int r_core_visual_refs(RCore *core, bool xref, bool fcnInsteadOfAddr);
R_API void r_core_visual_append_help(RStrBuf *p, const char *title, const char **help);
R_API bool r_core_prevop_addr(RCore* core, ut64 start_addr, int numinstrs, ut64* prev_addr);
R_API ut64 r_core_prevop_addr_force(RCore *core, ut64 start_addr, int numinstrs);
R_API bool r_core_visual_hudstuff(RCore *core);
R_API int r_core_visual_classes(RCore *core);
R_API int r_core_visual_anal_classes(RCore *core);
R_API int r_core_visual_types(RCore *core);
R_API int r_core_visual(RCore *core, const char *input);
R_API int r_core_visual_graph(RCore *core, RAGraph *g, RAnalFunction *_fcn, int is_interactive);
R_API bool r_core_visual_panels_root(RCore *core, RPanelsRoot *panels_root);
R_API void r_core_visual_browse(RCore *core, const char *arg);
R_API int r_core_visual_cmd(RCore *core, const char *arg);
R_API void r_core_visual_seek_animation (RCore *core, ut64 addr);
R_API void r_core_visual_asm(RCore *core, ut64 addr);
R_API void r_core_visual_colors(RCore *core);
R_API int r_core_visual_xrefs_x(RCore *core);
R_API int r_core_visual_xrefs_X(RCore *core);
R_API void r_core_visual_showcursor(RCore *core, int x);
R_API void r_core_visual_offset(RCore *core);
R_API int r_core_visual_hud(RCore *core);
R_API void r_core_visual_jump(RCore *core, ut8 ch);
R_API void r_core_visual_disasm_up(RCore *core, int *cols);
R_API void r_core_visual_disasm_down(RCore *core, RAsmOp *op, int *cols);
R_API RBinReloc *r_core_getreloc(RCore *core, ut64 addr, int size);
R_API ut64 r_core_get_asmqjmps(RCore *core, const char *str);
R_API void r_core_set_asmqjmps(RCore *core, char *str, size_t len, int i);
R_API char* r_core_add_asmqjmp(RCore *core, ut64 addr);

R_API void r_core_anal_type_init(RCore *core);
R_API void r_core_link_stroff(RCore *core, RAnalFunction *fcn);
R_API void r_core_anal_inflags (RCore *core, const char *glob);
R_API int cmd_anal_objc (RCore *core, const char *input, bool auto_anal);
R_API void r_core_anal_cc_init(RCore *core);
R_API void r_core_anal_paths(RCore *core, ut64 from, ut64 to, bool followCalls, int followDepth, bool is_json);
R_API void r_core_anal_esil_graph(RCore *core, const char *expr);

R_API void r_core_list_io(RCore *core);
R_API RListInfo *r_listinfo_new (const char *name, RInterval pitv, RInterval vitv, int perm, const char *extra);
R_API void r_listinfo_free (RListInfo *info);
/* visual marks */
R_API void r_core_visual_mark_seek(RCore *core, ut8 ch);
R_API void r_core_visual_mark(RCore *core, ut8 ch);
R_API void r_core_visual_mark_set(RCore *core, ut8 ch, ut64 addr);
R_API void r_core_visual_mark_del(RCore *core, ut8 ch);
R_API bool r_core_visual_mark_dump(RCore *core);
R_API void r_core_visual_mark_reset(RCore *core);

R_API int r_core_search_cb(RCore *core, ut64 from, ut64 to, RCoreSearchCallback cb);
R_API bool r_core_serve(RCore *core, RIODesc *fd);
R_API int r_core_file_reopen(RCore *core, const char *args, int perm, int binload);
R_API void r_core_file_reopen_debug(RCore *core, const char *args);
R_API void r_core_file_reopen_remote_debug(RCore *core, char *uri, ut64 addr);
R_API RCoreFile * r_core_file_find_by_fd(RCore* core, ut64 fd);
R_API RCoreFile * r_core_file_find_by_name (RCore * core, const char * name);
R_API RCoreFile * r_core_file_cur (RCore *r);
R_API int r_core_file_set_by_fd(RCore *core, ut64 fd);
R_API int r_core_file_set_by_name(RCore *core, const char * name);
R_API int r_core_file_set_by_file (RCore * core, RCoreFile *cf);
R_API int r_core_setup_debugger (RCore *r, const char *debugbackend, bool attach);

R_API void r_core_file_free(RCoreFile *cf);
R_API RCoreFile *r_core_file_open(RCore *core, const char *file, int flags, ut64 loadaddr);
R_API RCoreFile *r_core_file_open_many(RCore *r, const char *file, int flags, ut64 loadaddr);
R_API RCoreFile *r_core_file_get_by_fd(RCore *core, int fd);
R_API int r_core_file_close(RCore *core, RCoreFile *fh);
R_API bool r_core_file_close_fd(RCore *core, int fd);
R_API bool r_core_file_close_all_but(RCore *core);
R_API int r_core_file_list(RCore *core, int mode);
R_API int r_core_file_binlist(RCore *core);
R_API bool r_core_file_bin_raise(RCore *core, ut32 num);
R_API int r_core_seek_delta(RCore *core, st64 addr);
R_API bool r_core_extend_at(RCore *core, ut64 addr, int size);
R_API bool r_core_write_at(RCore *core, ut64 addr, const ut8 *buf, int size);
R_API int r_core_write_op(RCore *core, const char *arg, char op);
R_API ut8* r_core_transform_op(RCore *core, const char *arg, char op);
R_API int r_core_set_file_by_fd (RCore * core, ut64 bin_fd);
R_API int r_core_set_file_by_name (RBin * bin, const char * name);
R_API ut32 r_core_file_cur_fd (RCore *core);

R_API void r_core_debug_rr (RCore *core, RReg *reg, int mode);

/* fortune */
R_API void r_core_fortune_list_types(void);
R_API void r_core_fortune_list(RCore *core);
R_API void r_core_fortune_print_random(RCore *core);

/* project */
R_API bool r_core_project_load(RCore *core, const char *prjfile, const char *rcfile);
R_API RThread *r_core_project_load_bg(RCore *core, const char *prjfile, const char *rcfile);
R_API void r_core_project_execute_cmds(RCore *core, const char *prjfile);

#define R_CORE_FOREIGN_ADDR -1
R_API int r_core_yank(RCore *core, ut64 addr, int len);
R_API int r_core_yank_string(RCore *core, ut64 addr, int maxlen);
R_API bool r_core_yank_hexpair(RCore *core, const char *input);
R_API int r_core_yank_paste(RCore *core, ut64 addr, int len);
R_API int r_core_yank_set (RCore *core, ut64 addr, const ut8 *buf, ut32 len);  // set yank buffer bytes
R_API int r_core_yank_set_str (RCore *core, ut64 addr, const char *buf, ut32 len); // Null terminate the bytes
R_API int r_core_yank_to(RCore *core, const char *arg);
R_API bool r_core_yank_dump (RCore *core, ut64 pos, int format);
R_API int r_core_yank_hexdump (RCore *core, ut64 pos);
R_API int r_core_yank_cat (RCore *core, ut64 pos);
R_API int r_core_yank_cat_string (RCore *core, ut64 pos);
R_API int r_core_yank_hud_file (RCore *core, const char *input);
R_API int r_core_yank_hud_path (RCore *core, const char *input, int dir);
R_API bool r_core_yank_file_ex (RCore *core, const char *input);
R_API int r_core_yank_file_all (RCore *core, const char *input);

#define R_CORE_LOADLIBS_ENV 1
#define R_CORE_LOADLIBS_HOME 2
#define R_CORE_LOADLIBS_SYSTEM 4
#define R_CORE_LOADLIBS_CONFIG 8
#define R_CORE_LOADLIBS_ALL UT32_MAX

R_API void r_core_loadlibs_init(RCore *core);
R_API int r_core_loadlibs(RCore *core, int where, const char *path);
R_API int r_core_cmd_buffer(RCore *core, const char *buf);
R_API int r_core_cmdf(RCore *core, const char *fmt, ...);
R_API int r_core_cmd0(RCore *core, const char *cmd);
R_API char *r_core_cmd_str(RCore *core, const char *cmd);
R_API int r_core_cmd_foreach(RCore *core, const char *cmd, char *each);
R_API int r_core_cmd_foreach3(RCore *core, const char *cmd, char *each);
R_API char *r_core_op_str(RCore *core, ut64 addr);
R_API RAnalOp *r_core_op_anal(RCore *core, ut64 addr, RAnalOpMask mask);
R_API char *r_core_disassemble_instr(RCore *core, ut64 addr, int l);
R_API char *r_core_disassemble_bytes(RCore *core, ut64 addr, int b);

/* carg.c */
R_API RList *r_core_get_func_args(RCore *core, const char *func_name);
R_API void r_core_print_func_args(RCore *core);
R_API char *resolve_fcn_name(RAnal *anal, const char * func_name);
R_API int r_core_get_stacksz(RCore *core, ut64 from, ut64 to);

/* anal.c */
R_API RAnalOp* r_core_anal_op(RCore *core, ut64 addr, int mask);
R_API void r_core_anal_esil(RCore *core, const char *str, const char *addr);
R_API void r_core_anal_fcn_merge (RCore *core, ut64 addr, ut64 addr2);
R_API const char *r_core_anal_optype_colorfor(RCore *core, ut64 addr, bool verbose);
R_API ut64 r_core_anal_address (RCore *core, ut64 addr);
R_API void r_core_anal_undefine (RCore *core, ut64 off);
R_API void r_core_anal_hint_print (RAnal* a, ut64 addr, int mode);
R_API void r_core_anal_hint_list (RAnal *a, int mode);
R_API int r_core_anal_search(RCore *core, ut64 from, ut64 to, ut64 ref, int mode);
R_API int r_core_anal_search_xrefs(RCore *core, ut64 from, ut64 to, int rad);
R_API int r_core_anal_data (RCore *core, ut64 addr, int count, int depth, int wordsize);
R_API void r_core_anal_datarefs(RCore *core, ut64 addr);
R_API void r_core_anal_coderefs(RCore *core, ut64 addr);
R_API void r_core_anal_codexrefs(RCore *core, ut64 addr);
R_API void r_core_anal_importxrefs(RCore *core);
R_API void r_core_anal_callgraph(RCore *core, ut64 addr, int fmt);
R_API int r_core_anal_refs(RCore *core, const char *input);
R_API void r_core_agraph_print(RCore *core, int use_utf, const char *input);
R_API bool r_core_esil_cmd(RAnalEsil *esil, const char *cmd, ut64 a1, ut64 a2);
R_API int r_core_esil_step(RCore *core, ut64 until_addr, const char *until_expr, ut64 *prev_addr, bool stepOver);
R_API int r_core_esil_step_back(RCore *core);
R_API ut64 r_core_anal_get_bbaddr(RCore *core, ut64 addr);
R_API bool r_core_anal_bb_seek(RCore *core, ut64 addr);
R_API int r_core_anal_fcn(RCore *core, ut64 at, ut64 from, int reftype, int depth);
R_API char *r_core_anal_fcn_autoname(RCore *core, ut64 addr, int dump, int mode);
R_API void r_core_anal_autoname_all_fcns(RCore *core);
R_API void r_core_anal_autoname_all_golang_fcns(RCore *core);
R_API int r_core_anal_fcn_list(RCore *core, const char *input, const char *rad);
R_API char *r_core_anal_fcn_name(RCore *core, RAnalFunction *fcn);
R_API ut64 r_core_anal_fcn_list_size(RCore *core);
R_API void r_core_anal_fcn_labels(RCore *core, RAnalFunction *fcn, int rad);
R_API int r_core_anal_fcn_clean(RCore *core, ut64 addr);
R_API int r_core_print_bb_custom(RCore *core, RAnalFunction *fcn);
R_API int r_core_print_bb_gml(RCore *core, RAnalFunction *fcn);
R_API int r_core_anal_graph(RCore *core, ut64 addr, int opts);
R_API int r_core_anal_graph_fcn(RCore *core, char *input, int opts);
R_API RList* r_core_anal_graph_to(RCore *core, ut64 addr, int n);
R_API int r_core_anal_ref_list(RCore *core, int rad);
R_API int r_core_anal_all(RCore *core);
R_API RList* r_core_anal_cycles (RCore *core, int ccl);
R_API RList *r_core_anal_fcn_get_calls (RCore *core, RAnalFunction *fcn); // get all calls from a function

/*tp.c*/
R_API void r_core_anal_type_match(RCore *core, RAnalFunction *fcn);
R_API RStrBuf *var_get_constraint(RAnal *a, RAnalFunction *fcn, RAnalVar *var);

/* asm.c */
#define R_MIDFLAGS_SHOW 1
#define R_MIDFLAGS_REALIGN 2
#define R_MIDFLAGS_SYMALIGN 3

typedef struct r_core_asm_hit {
	char *code;
	int len;
	ut64 addr;
	ut8 valid;
} RCoreAsmHit;

R_API RBuffer *r_core_syscall (RCore *core, const char *name, const char *args);
R_API RBuffer *r_core_syscallf (RCore *core, const char *name, const char *fmt, ...);
R_API RCoreAsmHit *r_core_asm_hit_new(void);
R_API RList *r_core_asm_hit_list_new(void);
R_API void r_core_asm_hit_free(void *_hit);
R_API void r_core_set_asm_configs(RCore *core, char *arch, ut32 bits, int segoff);
R_API char* r_core_asm_search(RCore *core, const char *input);
R_API RList *r_core_asm_strsearch(RCore *core, const char *input, ut64 from, ut64 to, int maxhits, int regexp, int everyByte, int mode);
R_API RList *r_core_asm_bwdisassemble (RCore *core, ut64 addr, int n, int len);
R_API RList *r_core_asm_back_disassemble_instr (RCore *core, ut64 addr, int len, ut32 hit_count, ut32 extra_padding);
R_API RList *r_core_asm_back_disassemble_byte (RCore *core, ut64 addr, int len, ut32 hit_count, ut32 extra_padding);
R_API ut32 r_core_asm_bwdis_len (RCore* core, int* len, ut64* start_addr, ut32 l);
R_API int r_core_print_disasm(RPrint *p, RCore *core, ut64 addr, ut8 *buf, int len, int lines, int invbreak, int nbytes, bool json, PJ *pj, RAnalFunction *pdf);
R_API int r_core_print_disasm_json(RCore *core, ut64 addr, ut8 *buf, int len, int lines, PJ *pj);
R_API int r_core_print_disasm_instructions (RCore *core, int len, int l);
R_API int r_core_print_disasm_all (RCore *core, ut64 addr, int l, int len, int mode);
R_API int r_core_disasm_pdi(RCore *core, int nb_opcodes, int nb_bytes, int fmt);
R_API int r_core_print_fcn_disasm(RPrint *p, RCore *core, ut64 addr, int l, int invbreak, int cbytes);
R_API int r_core_get_prc_cols(RCore *core);
R_API int r_core_flag_in_middle(RCore *core, ut64 at, int oplen, int *midflags);
R_API int r_core_bb_starts_in_middle(RCore *core, ut64 at, int oplen);

R_API bool r_core_bin_raise (RCore *core, ut32 bfid);

R_API int r_core_bin_set_env (RCore *r, RBinFile *binfile);
R_API int r_core_bin_set_by_fd (RCore *core, ut64 bin_fd);
R_API int r_core_bin_set_by_name (RCore *core, const char *name);
R_API int r_core_bin_reload(RCore *core, const char *file, ut64 baseaddr);
R_API bool r_core_bin_load(RCore *core, const char *file, ut64 baseaddr);
R_API int r_core_bin_rebase(RCore *core, ut64 baddr);
R_API void r_core_bin_export_info_rad(RCore *core);
R_API int r_core_bin_list(RCore *core, int mode);
R_API bool r_core_bin_delete (RCore *core, ut32 binfile_idx);
R_API ut64 r_core_bin_impaddr(RBin *bin, int va, const char *name);

// XXX - this is kinda hacky, maybe there should be a way to
// refresh the bin environment without specific calls?
R_API int r_core_pseudo_code (RCore *core, const char *input);

/* gdiff.c */
R_API int r_core_zdiff(RCore *c, RCore *c2);
R_API int r_core_gdiff(RCore *core1, RCore *core2);
R_API int r_core_gdiff_fcn(RCore *c, ut64 addr, ut64 addr2);

R_API bool r_core_project_open(RCore *core, const char *file, bool thready);
R_API int r_core_project_cat(RCore *core, const char *name);
R_API int r_core_project_delete(RCore *core, const char *prjfile);
R_API int r_core_project_list(RCore *core, int mode);
R_API bool r_core_project_save_rdb(RCore *core, const char *file, int opts);
R_API bool r_core_project_save(RCore *core, const char *file);
R_API char *r_core_project_info(RCore *core, const char *file);
R_API char *r_core_project_notes_file (RCore *core, const char *file);

R_API char *r_core_sysenv_begin(RCore *core, const char *cmd);
R_API void r_core_sysenv_end(RCore *core, const char *cmd);

R_API void r_core_recover_vars(RCore *core, RAnalFunction *fcn, bool argonly);
// XXX dupe from r_bin.h
/* bin.c */
#define R_CORE_BIN_ACC_STRINGS	0x001
#define R_CORE_BIN_ACC_INFO	0x002
#define R_CORE_BIN_ACC_MAIN	0x004
#define R_CORE_BIN_ACC_ENTRIES	0x008
#define R_CORE_BIN_ACC_RELOCS	0x010
#define R_CORE_BIN_ACC_IMPORTS	0x020
#define R_CORE_BIN_ACC_SYMBOLS	0x040
#define R_CORE_BIN_ACC_SECTIONS	0x080
#define R_CORE_BIN_ACC_FIELDS	0x100
#define R_CORE_BIN_ACC_LIBS	0x200
#define R_CORE_BIN_ACC_CLASSES	0x400
#define R_CORE_BIN_ACC_DWARF	0x800
#define R_CORE_BIN_ACC_SIZE     0x1000
#define R_CORE_BIN_ACC_PDB	0x2000
#define R_CORE_BIN_ACC_MEM	0x4000
#define R_CORE_BIN_ACC_EXPORTS  0x8000
#define R_CORE_BIN_ACC_VERSIONINFO 0x10000
#define R_CORE_BIN_ACC_SIGNATURE 0x20000
#define R_CORE_BIN_ACC_RAW_STRINGS	0x40000
#define R_CORE_BIN_ACC_HEADER 0x80000
#define R_CORE_BIN_ACC_RESOURCES 0x100000
#define R_CORE_BIN_ACC_INITFINI 0x200000
#define R_CORE_BIN_ACC_SEGMENTS 0x400000
#define R_CORE_BIN_ACC_SOURCE 0x800000
#define R_CORE_BIN_ACC_HASHES 0x10000000
#define R_CORE_BIN_ACC_TRYCATCH 0x20000000
#define R_CORE_BIN_ACC_SECTIONS_MAPPING 0x40000000
#define R_CORE_BIN_ACC_ALL	0x504FFF

#define R_CORE_PRJ_FLAGS	0x0001
#define R_CORE_PRJ_EVAL		0x0002
#define R_CORE_PRJ_IO_MAPS	0x0004
#define R_CORE_PRJ_SECTIONS	0x0008
#define R_CORE_PRJ_META		0x0010
#define R_CORE_PRJ_XREFS	0x0020
#define R_CORE_PRJ_FCNS		0x0040
#define R_CORE_PRJ_ANAL_HINTS	0x0080
#define R_CORE_PRJ_ANAL_TYPES	0x0100
#define R_CORE_PRJ_ANAL_MACROS	0x0200
#define R_CORE_PRJ_ANAL_SEEK	0x0400
#define R_CORE_PRJ_DBG_BREAK   0x0800
#define R_CORE_PRJ_ALL		0xFFFF

typedef struct r_core_bin_filter_t {
	ut64 offset;
	const char *name;
} RCoreBinFilter;

R_API int r_core_bin_info (RCore *core, int action, int mode, int va, RCoreBinFilter *filter, const char *chksum);
R_API int r_core_bin_set_arch_bits (RCore *r, const char *name, const char * arch, ut16 bits);
R_API int r_core_bin_update_arch_bits (RCore *r);
R_API char *r_core_bin_method_flags_str(ut64 flags, int mode);
R_API int r_core_pdb_info(RCore *core, const char *file, ut64 baddr, int mode);

/* rtr */
R_API int r_core_rtr_cmds (RCore *core, const char *port);
R_API char *r_core_rtr_cmds_query (RCore *core, const char *host, const char *port, const char *cmd);
R_API void r_core_rtr_help(RCore *core);
R_API void r_core_rtr_pushout(RCore *core, const char *input);
R_API void r_core_rtr_list(RCore *core);
R_API void r_core_rtr_add(RCore *core, const char *input);
R_API void r_core_rtr_remove(RCore *core, const char *input);
R_API void r_core_rtr_session(RCore *core, const char *input);
R_API void r_core_rtr_cmd(RCore *core, const char *input);
R_API int r_core_rtr_http(RCore *core, int launch, int browse, const char *path);
R_API int r_core_rtr_http_stop(RCore *u);
R_API int r_core_rtr_gdb(RCore *core, int launch, const char *path);

R_API int r_core_visual_prevopsz(RCore *core, ut64 addr);
R_API void r_core_visual_config(RCore *core);
R_API void r_core_visual_mounts(RCore *core);
R_API void r_core_visual_anal(RCore *core, const char *input);
R_API void r_core_visual_debugtraces(RCore *core, const char *input);
R_API void r_core_seek_next(RCore *core, const char *type);
R_API void r_core_seek_previous(RCore *core, const char *type);
R_API void r_core_visual_define(RCore *core, const char *arg, int distance);
R_API int r_core_visual_trackflags(RCore *core);
R_API int r_core_visual_view_graph(RCore *core);
R_API int r_core_visual_view_zigns(RCore *core);
R_API int r_core_visual_view_rop(RCore *core);
R_API int r_core_visual_comments(RCore *core);
R_API int r_core_visual_prompt(RCore *core);
R_API bool r_core_visual_esil (RCore *core);
R_API int r_core_search_preludes(RCore *core, bool log);
R_API int r_core_search_prelude(RCore *core, ut64 from, ut64 to, const ut8 *buf, int blen, const ut8 *mask, int mlen);
R_API RList* /*<RIOMap*>*/ r_core_get_boundaries_prot (RCore *core, int protection, const char *mode, const char *prefix);

R_API int r_core_patch (RCore *core, const char *patch);

R_API void r_core_hack_help(const RCore *core);
R_API int r_core_hack(RCore *core, const char *op);
R_API bool r_core_dump(RCore *core, const char *file, ut64 addr, ut64 size, int append);
R_API void r_core_diff_show(RCore *core, RCore *core2);
R_API void r_core_clippy(RCore *core, const char *msg);

/* watchers */
R_API void r_core_cmpwatch_free (RCoreCmpWatcher *w);
R_API RCoreCmpWatcher *r_core_cmpwatch_get (RCore *core, ut64 addr);
R_API int r_core_cmpwatch_add (RCore *core, ut64 addr, int size, const char *cmd);
R_API int r_core_cmpwatch_del (RCore *core, ut64 addr);
R_API int r_core_cmpwatch_update (RCore *core, ut64 addr);
R_API int r_core_cmpwatch_show (RCore *core, ut64 addr, int mode);
R_API int r_core_cmpwatch_revert (RCore *core, ut64 addr);

/* undo */
R_API RCoreUndo *r_core_undo_new(ut64 offset, const char *action, const char *revert);
R_API void r_core_undo_print(RCore *core, int mode, RCoreUndoCondition *cond);
R_API void r_core_undo_free(RCoreUndo *cu);
R_API void r_core_undo_push(RCore *core, RCoreUndo *cu);
R_API void r_core_undo_pop(RCore *core);

/* logs */
typedef int (*RCoreLogCallback)(RCore *core, int count, const char *message);
R_API void r_core_log_free(RCoreLog *log);
R_API void r_core_log_init (RCoreLog *log);
R_API char *r_core_log_get(RCore *core, int index);
R_API RCoreLog *r_core_log_new (void);
R_API bool r_core_log_run(RCore *core, const char *buf, RCoreLogCallback cb);
R_API int r_core_log_list(RCore *core, int n, int count, char fmt);
R_API void r_core_log_add(RCore *core, const char *msg);
R_API void r_core_log_del(RCore *core, int n);

// TODO MOVE SOMEWHERE ELSE
typedef char *(*PrintItemCallback)(void *user, void *p, bool selected);
R_API char *r_str_widget_list(void *user, RList *list, int rows, int cur, PrintItemCallback cb);
/* help */
R_API void r_core_cmd_help(const RCore *core, const char * help[]);

/* anal stats */

typedef struct {
	ut32 youarehere;
	ut32 flags;
	ut32 comments;
	ut32 functions;
	ut32 blocks;
	ut32 in_functions;
	ut32 symbols;
	ut32 strings;
	ut32 perm;
} RCoreAnalStatsItem;
typedef struct {
	RCoreAnalStatsItem *block;
} RCoreAnalStats;

R_API bool core_anal_bbs(RCore *core, const char* input);
R_API bool core_anal_bbs_range (RCore *core, const char* input);
R_API char *r_core_anal_hasrefs(RCore *core, ut64 value, bool verbose);
R_API char *r_core_anal_get_comments(RCore *core, ut64 addr);
R_API RCoreAnalStats* r_core_anal_get_stats (RCore *a, ut64 from, ut64 to, ut64 step);
R_API void r_core_anal_stats_free (RCoreAnalStats *s);

R_API void r_core_syscmd_ls(const char *input);
R_API void r_core_syscmd_cat(const char *file);
R_API void r_core_syscmd_mkdir(const char *dir);

R_API int r_line_hist_offset_up(RLine *line);
R_API int r_line_hist_offset_down(RLine *line);

// TODO : move into debug or syscall++
R_API char *cmd_syscall_dostr(RCore *core, st64 num, ut64 addr);

/* tasks */

typedef void (*RCoreTaskCallback)(void *user, char *out);

typedef enum {
	R_CORE_TASK_STATE_BEFORE_START,
	R_CORE_TASK_STATE_RUNNING,
	R_CORE_TASK_STATE_SLEEPING,
	R_CORE_TASK_STATE_DONE
} RTaskState;

typedef struct r_core_task_t {
	int id;
	RTaskState state;
	bool transient; // delete when finished
	int refcount;
	RThreadSemaphore *running_sem;
	void *user;
	RCore *core;
	bool dispatched;
	RThreadCond *dispatch_cond;
	RThreadLock *dispatch_lock;
	RThread *thread;
	char *cmd;
	char *res;
	bool cmd_log;
	RConsContext *cons_context;
	RCoreTaskCallback cb;
} RCoreTask;

typedef void (*RCoreTaskOneShot)(void *);

R_API void r_core_echo(RCore *core, const char *msg);
R_API RTable *r_core_table(RCore *core);

R_API void r_core_task_scheduler_init (RCoreTaskScheduler *tasks, RCore *core);
R_API void r_core_task_scheduler_fini (RCoreTaskScheduler *tasks);
R_API RCoreTask *r_core_task_get(RCoreTaskScheduler *scheduler, int id);
R_API RCoreTask *r_core_task_get_incref(RCoreTaskScheduler *scheduler, int id);
R_API void r_core_task_print(RCore *core, RCoreTask *task, int mode);
R_API void r_core_task_list(RCore *core, int mode);
R_API int r_core_task_running_tasks_count(RCoreTaskScheduler *scheduler);
R_API const char *r_core_task_status(RCoreTask *task);
R_API RCoreTask *r_core_task_new(RCore *core, bool create_cons, const char *cmd, RCoreTaskCallback cb, void *user);
R_API void r_core_task_incref(RCoreTask *task);
R_API void r_core_task_decref(RCoreTask *task);
R_API void r_core_task_enqueue(RCoreTaskScheduler *scheduler, RCoreTask *task);
R_API void r_core_task_enqueue_oneshot(RCoreTaskScheduler *scheduler, RCoreTaskOneShot func, void *user);
R_API int r_core_task_run_sync(RCoreTaskScheduler *scheduler, RCoreTask *task);
R_API void r_core_task_sync_begin(RCoreTaskScheduler *scheduler);
R_API void r_core_task_sync_end(RCoreTaskScheduler *scheduler);
R_API void r_core_task_yield(RCoreTaskScheduler *scheduler);
R_API void r_core_task_sleep_begin(RCoreTask *task);
R_API void r_core_task_sleep_end(RCoreTask *task);
R_API void r_core_task_break(RCoreTaskScheduler *scheduler, int id);
R_API void r_core_task_break_all(RCoreTaskScheduler *scheduler);
R_API int r_core_task_del(RCoreTaskScheduler *scheduler, int id);
R_API void r_core_task_del_all_done(RCoreTaskScheduler *scheduler);
R_API RCoreTask *r_core_task_self(RCoreTaskScheduler *scheduler);
R_API void r_core_task_join(RCoreTaskScheduler *scheduler, RCoreTask *current, int id);
typedef void (*inRangeCb) (RCore *core, ut64 from, ut64 to, int vsize,
		int count, void *cb_user);
R_API int r_core_search_value_in_range (RCore *core, RInterval search_itv,
		ut64 vmin, ut64 vmax, int vsize, inRangeCb cb, void *cb_user);

R_API RCoreAutocomplete *r_core_autocomplete_add(RCoreAutocomplete *parent, const char* cmd, int type, bool lock);
R_API void r_core_autocomplete_free(RCoreAutocomplete *obj);
R_API void r_core_autocomplete_reload (RCore *core);
R_API RCoreAutocomplete *r_core_autocomplete_find(RCoreAutocomplete *parent, const char* cmd, bool exact);
R_API bool r_core_autocomplete_remove(RCoreAutocomplete *parent, const char* cmd);
R_API void r_core_anal_propagate_noreturn(RCore *core, ut64 addr);

/* PLUGINS */
extern RCorePlugin r_core_plugin_java;
extern RCorePlugin r_core_plugin_a2f;

#endif

#ifdef __cplusplus
}
#endif

#endif
