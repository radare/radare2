/* radare - GPLv2 - Copyright 2014 jvoisin <julien.voisin@dustri.org> */

#include <r_core.h>
#include <r_lib.h>

#include "r_yara.h"

#undef R_API
#define R_API static
#undef R_IPI
#define R_IPI static

static void (*r_yr_initialize)(void) = NULL;
static int (*r_yr_compiler_add_file)(
    YR_COMPILER* compiler,
    FILE* rules_file,
    const char* namespace_);
static void (*r_yr_finalize)(void);
static int (*r_yr_compiler_create)( YR_COMPILER** compiler);
static void (*r_yr_compiler_destroy)( YR_COMPILER* compiler);

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
static int (*r_yr_get_tidx)(void);


/* ---- */ 

static int show_offset = 0;
static int fast_scan = 0;
static int timeout = 0;

static int r_cmd_yara_call(void *user, const char *input);
static int r_cmd_yara_init(void *user, const char *input);
static int r_cmd_yara_process(const RCore* core, const char* input);
static int callback(int message, YR_RULE* rule, void* data);

static int callback (int message, YR_RULE* rule, void* data) {
	if (message == CALLBACK_MSG_RULE_MATCHING) {
		eprintf ("%s\n", rule->identifier);
		if (show_offset) {
			const YR_STRING* string = rule->strings;
			while (!STRING_IS_NULL(string)) {
				if (STRING_FOUND (string)) {
					YR_MATCH* match = STRING_MATCHES(string).head;
					while (match != NULL) {
						eprintf("\t0x%llx\n", match->offset);
						match = match->next;
					}
				}
				string++;
			}
			eprintf ("\n");
		}
	}
	return CALLBACK_CONTINUE;
}

static int r_cmd_yara_process(const RCore* core, const char* input) {
	YR_RULES* rules;
	YR_COMPILER* compiler;
	FILE* rules_file;
	void* buffer;
	int result;
	const unsigned int buffer_size = r_io_size (core->io);
	const char *rules_path = r_config_get (core->config, "yara.rules");

	if (!r_cmd_yara_init (core, input)) {
		return 1;
	}
	if (buffer_size < 1) {
		eprintf ("Invalid file size\n");
		return 1;
	}

	if (!rules_path){
		eprintf ("Please set `yara.rules` in your radare2rc\n");
		return 1;
	}

	rules_file = fopen (rules_path, "r");
	if (!rules_file) {
		eprintf ("Unable to open the rules file\n");
		return 1;
	}

	r_yr_initialize ();

	if (r_yr_compiler_create (&compiler) != ERROR_SUCCESS) {
		eprintf ("Unable to create the yara compiler\n");
		r_yr_finalize ();
		return 1;
	}

	r_yr_compiler_push_file_name (compiler, rules_path);
	result = r_yr_compiler_add_file (compiler, rules_file, NULL);
	fclose (rules_file);
	if (result > 0) {
		r_yr_compiler_destroy (compiler);
		r_yr_finalize ();
		eprintf ("Something went wrong during the compilation of %s\n", rules_path);
		return result;
	}

	result = r_yr_compiler_get_rules (compiler, &rules);
	r_yr_compiler_destroy (compiler);
	if (result > 0) {
		r_yr_finalize ();
		eprintf ("Something went wrong during the import of %s\n", rules_path);
		return result;
	}

	buffer = malloc (buffer_size);
	if (!buffer) {
		eprintf ("Something went wrong during memory allocation\n");
		return 1;
	}
	result = r_io_read_at (core->io, 0L, buffer, buffer_size);
	if (!result) {
		eprintf ("Something went wrong during r_io_read_at\n");
		return result;
	}

	fast_scan = r_config_get_i (core->config, "yara.fast_scan");
	timeout = r_config_get_i (core->config, "yara.timeout");
	show_offset = r_config_get_i (core->config, "yara.offset");

	r_yr_rules_scan_mem (rules, buffer, buffer_size, callback, NULL, fast_scan, timeout);

	free (buffer);

	return 0;
}

static int r_cmd_yara_call(void *user, const char *input) {
	const RCore* core = (RCore*) user;
	if (!strncmp (input, "yara", 4)) {
		const char *args = input+4;
		if (!r_yr_initialize)
			if (!r_cmd_yara_init (user, input))
				return R_TRUE;
		if (*args) args++;
		r_cmd_yara_process (core, args);
		return R_TRUE;
	}
	return R_FALSE;
}

static int r_cmd_yara_init(void *user, const char *input) {
	const RCore* core = (RCore*) user;
	void *libyara = r_lib_dl_open ("libyara."R_LIB_EXT);
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
	LOADSYM (yr_finalize);
	LOADSYM (yr_compiler_create);
	LOADSYM (yr_compiler_destroy);
	LOADSYM (yr_compiler_push_file_name);
	LOADSYM (yr_compiler_get_rules);
	LOADSYM (yr_rules_scan_mem);
	LOADSYM (yr_get_tidx);
	return R_TRUE;
}

RCorePlugin r_core_plugin_yara = {
	.name = "yara",
	.desc = "YARA integration",
	.license = "LGPL",
	.call = r_cmd_yara_call,
	.init = NULL // init is performed in call if needed
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CORE,
	.data = &r_core_plugin_yara
};
#endif
