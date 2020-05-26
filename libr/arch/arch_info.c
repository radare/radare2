/* radare - LGPL - Copyright 2020 - pancake */

#include <r_arch.h>
#include <r_asm.h>
#include "../config.h"

// arch_info.c
R_API RArchInfo *r_arch_info_new(void) {
	RArchInfo *ai = R_NEW0 (RArchInfo);
	return ai;
}

R_API void r_arch_info_free(RArchInfo *info) {
	free (info->regprofile);
	free (info);
}


