/* radare2 - LGPL - Copyright 2020-2021 - pancake, aemmitt */

#include <r_asm.h>
#include <r_lib.h>

#include "operations.h"
#include "encodings_fmt.h"
#include "encodings_dec.h"
#include "arm64dis.h"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	Instruction inst = {0};
	char output[256];
	op->size = 4;
	if (len < 4) {
		return -1;
	}
	ut32 n = r_read_le32 (buf);
	// FailureCodes 
	int fc = aarch64_decompose (n, &inst, a->pc);
	if (fc != DISASM_SUCCESS) {
		return -1;
	}
	output[0] = 0;
	fc = aarch64_disassemble (&inst, output, sizeof (output));
	if (fc == DISASM_SUCCESS) {
		if (*output) {
			// XXX trim tailing newline on UNDEFINED string
			/// output[strlen (output) - 2] = 0;
		}
		r_str_trim_tail (output);
		r_str_replace_char (output, '\t', ' ');
		r_str_replace_char (output, '#', ' ');
		if (r_str_startswith (output, "UNDEF")) {
			r_strbuf_set (&op->buf_asm, "undefined");
			return 4 - (a->pc % 4);
		}
		r_strbuf_set (&op->buf_asm, output);
		return op->size;
	}
	r_strbuf_set (&op->buf_asm, "invalid");
	return 4 - (a->pc % 4);
}

static const char* v35_insn_name(int id) {
	Instruction insn = { .operation = id };
	return get_operation (&insn);
}

static char *mnemonics(RAsm *a, int id, bool json) {
	int i;
	if (id != -1) {
		const char *name = v35_insn_name (id);
		if (json) {
			return name? r_str_newf ("[\"%s\"]\n", name): NULL;
		}
		return name? strdup (name): NULL;
	}
	RStrBuf *buf = r_strbuf_new ("");
	if (json) {
		r_strbuf_append (buf, "[");
	}
	for (i = 1; ; i++) {
		const char *op = v35_insn_name (i);
		if (!op) {
			break;
		}
		if (json) {
			r_strbuf_append (buf, "\"");
		}
		r_strbuf_append (buf, op);
		if (json) {
			if (v35_insn_name (i + 1)) {
				r_strbuf_append (buf, "\",");
			} else {
				r_strbuf_append (buf, "\"]\n");
			}
		} else {
			r_strbuf_append (buf, "\n");
		}
	}
	return r_strbuf_drain (buf);
}

RAsmPlugin r_asm_plugin_arm_v35 = {
	.name = "arm.v35",
	.desc = "Vector35 ARM64 disassembler",
	.license = "Apache",
	.arch = "arm",
	.bits = 64,
	.endian = R_SYS_ENDIAN_LITTLE,
	.mnemonics = mnemonics,
	.disassemble = &disassemble,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_arm_v35,
	.version = R2_VERSION
};
#endif
