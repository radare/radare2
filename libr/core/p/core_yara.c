/* radare - GPLv2 - Copyright 2014 jvoisin <julien.voisin@dustri.org> */

#include <dirent.h>

#include <r_core.h>
#include <r_lib.h>

#include "r_yara.h"

#undef R_API
#define R_API static
#undef R_IPI
#define R_IPI static

static YR_COMPILER* compiler;
static void* libyara;

static void (*r_yr_initialize)(void) = NULL;
static int (*r_yr_compiler_add_file)(
    YR_COMPILER* compiler,
    FILE* rules_file,
    const char* namespace_);
static int (*r_yr_compiler_add_string)(
    YR_COMPILER* compiler,
    const char* rules_string,
    const char* namespace_);
static void (*r_yr_finalize)(void);
static int (*r_yr_compiler_create)( YR_COMPILER** compiler);
static void (*r_yr_compiler_destroy)( YR_COMPILER* compiler);
static int (*r_yr_rules_destroy) (YR_RULES* rules);
static char* (*r_yr_compiler_get_error_message)
    (YR_COMPILER* compiler, char* buf, int buff_size);

static int (*r_yr_compiler_push_file_name)(
    YR_COMPILER* compiler,
    const char* file_name);
static int (*r_yr_compiler_get_rules)(
    YR_COMPILER* compiler,
    YR_RULES** rules);
static int (*r_yr_rules_scan_mem)(
    YR_RULES* rules,
    uint8_t* buffer,
    size_t buffer_size,
    YR_CALLBACK_FUNC callback,
    void* user_data,
    int fast_scan_mode,
    int timeout) = NULL;


/* ---- */

static int callback(int message, YR_RULE* rule, void* data);
static int r_cmd_yara_add (const RCore* core, const char* input);
static int r_cmd_yara_add_file (const char* rules_path);
static int r_cmd_yara_call(void *user, const char *input);
static int r_cmd_yara_clear();
static int r_cmd_yara_help(const RCore* core);
static int r_cmd_yara_init(const RCore* core);
static int r_cmd_yara_process(const RCore* core, const char* input);
static int r_cmd_yara_scan(const RCore* core);
static int r_cmd_yara_load_default_rules (const RCore* core);

static const char* yara_rule_template = "rule RULE_NAME {\n\tstrings:\n\n\tcondition:\n}";

static int callback (int message, YR_RULE* rule, void* data) {
    (void)data; // avoid Unused parameter warning
    if (message == CALLBACK_MSG_RULE_MATCHING)
        r_cons_printf ("%s\n", rule->identifier);
    return CALLBACK_CONTINUE;
}

static int r_cmd_yara_scan(const RCore* core) {
	YR_RULES* rules;
	void* buffer;
	int result;
	const unsigned int buffer_size = r_io_size (core->io);
	if (buffer_size < 1) {
		eprintf ("Invalid file size\n");
		return R_FALSE;
	}

	result = r_yr_compiler_get_rules (compiler, &rules);
	if (result < 0) {
		eprintf ("Unable to get rules\n");
		return R_FALSE;
	}

	buffer = malloc (buffer_size);
	if (!buffer) {
		eprintf ("Something went wrong during memory allocation\n");
		r_yr_rules_destroy (rules);
		return R_FALSE;
	}
	result = r_io_read_at (core->io, 0L, buffer, buffer_size);
	if (!result) {
		eprintf ("Something went wrong during r_io_read_at\n");
		free (buffer);
		r_yr_rules_destroy (rules);
		return result;
	}

	r_yr_rules_scan_mem (rules, buffer, buffer_size, callback, NULL, 0, 0);

	r_yr_rules_destroy (rules);
	free (buffer);

	return R_TRUE;
}

static int r_cmd_yara_show(const char * name) {
	YR_RULES* rules;
	YR_RULE* rule;
	if (r_yr_compiler_get_rules (compiler, &rules) < 0) {
		eprintf ("Unable to get rules\n");
		return R_FALSE;
	}

	rule = rules->rules_list_head;
	while (!RULE_IS_NULL(rule)) {
		if(r_str_casestr (rule->identifier, name)) {
			r_cons_printf ("%s\n", rule->identifier);
		}
		++rule;
	}
	r_yr_rules_destroy (rules);

	return R_TRUE;
}

static int r_cmd_yara_tag(const char * search_tag) {
	/* List rules with tag search_tag */
	YR_RULES* rules;
	YR_RULE* rule;
	int tag_length, show_rule = R_FALSE;
	char * tag_name;

	if (r_yr_compiler_get_rules (compiler, &rules) < 0) {
		eprintf ("Unable to get rules\n");
		return R_FALSE;
	}

	rule = rules->rules_list_head;
	while (!RULE_IS_NULL(rule)) {
		tag_name = rule->tags;
		tag_length = tag_name != NULL ? strlen(tag_name) : 0;

		while (tag_length > 0) {
			if(r_str_casestr (tag_name, search_tag)) {
				show_rule = R_TRUE;
				break;
			}
			tag_name += tag_length + 1;
			tag_length = strlen(tag_name);
		}

		if (show_rule) {
			r_cons_printf("%s\n", rule->identifier);
			show_rule = R_FALSE;
		}
		++rule;
	}
	r_yr_rules_destroy (rules);

	return R_TRUE;
}

static int r_cmd_yara_list () {
	YR_RULES* rules;
	YR_RULE* rule;
	if (r_yr_compiler_get_rules (compiler, &rules) < 0) {
		eprintf ("Unable to get rules\n");
		return R_FALSE;
	}

	rule = rules->rules_list_head;
	while (!RULE_IS_NULL(rule)) {
		r_cons_printf ("%s\n", rule->identifier);
		++rule;
	}
	r_yr_rules_destroy (rules);

	return R_TRUE;
}

static int r_cmd_yara_clear () {
	r_yr_compiler_destroy (compiler);
	if (r_yr_compiler_create (&compiler) != ERROR_SUCCESS) {
		eprintf ("Unable to re-create the yara compiler\n");
		return R_FALSE;
	}
    eprintf ("Rules cleared\n");
    return R_TRUE;
}

static int r_cmd_yara_add(const RCore* core, const char* input) {
	char* ret;
	int result;
	if ( *input == ' ' ) {
		return r_cmd_yara_add_file (input + 1);
	}

	ret = r_core_editor (core, yara_rule_template);
	result = r_yr_compiler_add_string (compiler, ret, NULL);
	if (result > 0) {
		char buf[64];
		eprintf ("Error: %s : \n",
		r_yr_compiler_get_error_message (compiler, buf, sizeof (buf)));
		r_cmd_yara_clear (); // The compiler is screwed :|
		return R_FALSE;
	} else {
		r_cons_printf ("Rule successfully added.\n");
	}

	return R_TRUE;
}

static int r_cmd_yara_add_file(const char* rules_path) {
	FILE* rules_file;
	int result;

	if (!rules_path){
		eprintf ("Please tell me what am I supported to load\n");
		return R_FALSE;
	}

	rules_file = r_sandbox_fopen (rules_path, "r");
	if (!rules_file) {
		eprintf ("Unable to open %s\n", rules_path);
		return R_FALSE;
	}

	r_yr_compiler_push_file_name (compiler, rules_path);
	result = r_yr_compiler_add_file (compiler, rules_file, NULL);
	fclose (rules_file);
	if (result > 0) {
		char buf[64];
		eprintf ("Error: %s : %s\n",
		r_yr_compiler_get_error_message (compiler, buf, sizeof (buf)),
			rules_path);
		r_cmd_yara_clear (); // The compiler is screwed :|
		return R_FALSE;
	}

	r_cons_printf ("%s added\n", rules_path);

	return R_TRUE;
}

static int r_cmd_yara_help(const RCore* core) {
	const char * help_message[] = {
		"Usage: yara", "", " Yara plugin",
		"add", " [file]", "Add yara rules from file, or open $EDITOR with yara rule template",
		"clear", "", "Clear all rules",
		"help", "", "Show this help",
		"list", "", "List all rules",
		"scan", "", "Scan the current file",
		"show", " name", "Show rules containing name",
		"tag", " name", "List rules with tag 'name'",
		NULL
	};

	r_core_cmd_help (core, help_message);

    return R_TRUE;
}

static int r_cmd_yara_process(const RCore* core, const char* input) {
    if (!strncmp (input, "add", 3))
        return r_cmd_yara_add (core, input + 3);
    else if (!strncmp (input, "clear", 4))
        return r_cmd_yara_clear ();
    else if (!strncmp (input, "list", 4))
        return r_cmd_yara_list ();
    else if (!strncmp (input, "scan", 4))
        return r_cmd_yara_scan (core);
    else if (!strncmp (input, "show", 4))
        return r_cmd_yara_show (input + 5);
    else if (!strncmp (input, "tag ", 4))
        return r_cmd_yara_tag (input + 4);
    else
        return r_cmd_yara_help (core);
}

static int r_cmd_yara_call(void *user, const char *input) {
	const RCore* core = (RCore*) user;
	if (strncmp (input, "yara", 4))
		return R_FALSE;
	else if (strncmp (input, "yara ", 5))
		return r_cmd_yara_help (core);
	const char *args = input+4;
	if (r_yr_initialize == NULL)
		if (!r_cmd_yara_init (core))
			return R_TRUE;
	if (*args)
		args++;
	r_cmd_yara_process (core, args);

	return R_TRUE;
}

static int r_cmd_yara_load_default_rules(const RCore* core) {
#define YARA_PATH R2_PREFIX "/share/radare2/" R2_VERSION "/yara/"
	RListIter* iter = NULL;
	char* filename, *complete_path;
	RList* list = r_sys_dir (YARA_PATH);
	r_list_foreach (list, iter, filename) {
		if (filename[0] != '.') { // skip '.', '..' and hidden files
			complete_path = r_str_concat (strdup (YARA_PATH), filename);
			r_cmd_yara_add_file (complete_path);
			free (complete_path);
		}
	}
	r_list_free (list);

	return R_TRUE;
}

static int r_cmd_yara_init(const RCore* core) {
	libyara = r_lib_dl_open ("libyara."R_LIB_EXT);
	if (!libyara) {
		eprintf ("Cannot find libyara\n");
		return R_FALSE;
	}
#define CHECKSYM(x)\
	r_##x = r_lib_dl_sym (libyara, #x);
#define LOADSYM(x) { \
	CHECKSYM(x);\
	if (!r_##x) { \
		eprintf ("dlsym: cannot find r_"#x);\
		return R_FALSE;\
	} \
}
	CHECKSYM (yr_initialize);
	if (!r_yr_initialize) {
		eprintf ("Cannot find yr_initialize in libyara (<2.1 ?)\n");
		return R_FALSE;
	}
	LOADSYM (yr_compiler_add_file);
	LOADSYM (yr_compiler_add_string);
	LOADSYM (yr_compiler_create);
	LOADSYM (yr_compiler_destroy);
	LOADSYM (yr_compiler_get_error_message)
	LOADSYM (yr_compiler_get_rules);
	LOADSYM (yr_compiler_push_file_name);
	LOADSYM (yr_finalize);
	LOADSYM (yr_rules_scan_mem);
	LOADSYM (yr_rules_destroy);

	r_yr_initialize ();

	if (r_yr_compiler_create (&compiler) != ERROR_SUCCESS) {
		eprintf ("Unable to create the yara compiler\n");
		r_yr_finalize ();
		return R_FALSE;
	}

	r_cmd_yara_load_default_rules (core);

	return R_TRUE;
}

static int r_cmd_yara_deinit(){
	if (r_yr_initialize != NULL) {
		r_yr_compiler_destroy(compiler);
		r_yr_finalize();
		r_yr_initialize = NULL;
		r_lib_dl_close (libyara);
	}
	return R_TRUE;
}

RCorePlugin r_core_plugin_yara = {
	.name = "yara",
	.desc = "YARA integration",
	.license = "LGPL",
	.call = r_cmd_yara_call,
	.init = NULL, // init is performed in call if needed
	.deinit = r_cmd_yara_deinit
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_yara,
};
#endif
