/* radare - LGPL - Copyright 2014 - condret */

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_lib.h>
#define WS_API static
#include "../arch/whitespace/wsdis.c"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	return wsdis (op, buf, len);
}

static char *instructions() {
	//TODO(lowlyw): fill in instructions.
	return NULL;
}

RAsmPlugin r_asm_plugin_ws = {
	.name = "ws",
	.desc = "Whitespace esotheric VM",
	.arch = "whitespace",
	.license = "LGPL3",
	.bits = 32,
	.endian = R_SYS_ENDIAN_NONE,
	.disassemble = &disassemble,
	.instructions = &instructions,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_ws,
	.version = R2_VERSION
};
#endif
