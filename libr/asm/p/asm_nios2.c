/* radare2 - LGPL - Copyright 2014-2018 - pancake */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>

#include "disas-asm.h"


int print_insn_big_nios2 (bfd_vma address, disassemble_info *info);
int print_insn_little_nios2 (bfd_vma address, disassemble_info *info);
static unsigned long Offset = 0;
static char *buf_global = NULL;
static unsigned char bytes[4];

static int nios2_buffer_read_memory (bfd_vma memaddr, bfd_byte *myaddr, ut32 length, struct disassemble_info *info) {
	memcpy (myaddr, bytes, length);
	return 0;
}

static int symbol_at_address(bfd_vma addr, struct disassemble_info * info) {
	return 0;
}

static void memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info) {
	//--
}

static void print_address(bfd_vma address, struct disassemble_info *info) {
	if (buf_global) {
		char tmp[32];
		snprintf (tmp, sizeof (tmp), "0x%08"PFMT64x"", (ut64)address);
		strcat (buf_global, tmp);
	}
}

static int buf_fprintf(void *stream, const char *format, ...) {
	int flen, glen;
	va_list ap;
	char *tmp;
	if (!buf_global) {
		return 0;
	}
	va_start (ap, format);
	flen = strlen (format);
	glen = strlen (buf_global);
	tmp = malloc (flen + glen + 2);
	if (!tmp) {
		return 0;
	}
	memcpy (tmp, buf_global, glen);
	memcpy (tmp+glen, format, flen);
	tmp[flen + glen] = 0;
	// XXX: overflow here?
	vsprintf (buf_global, tmp, ap);
	va_end (ap);
	free (tmp);
	return 0;
}

static int disassemble(RAsm *a, struct r_asm_op_t *op, const ut8 *buf, int len) {
	struct disassemble_info disasm_obj;
	if (len < 4) {
		return -1;
	}
	buf_global = r_strbuf_get (&op->buf_asm);
	Offset = a->pc;
	memcpy (bytes, buf, 4); // TODO handle thumb

	/* prepare disassembler */
	memset (&disasm_obj, '\0', sizeof (struct disassemble_info));
	disasm_obj.disassembler_options = "";
	disasm_obj.buffer = bytes;
	disasm_obj.read_memory_func = &nios2_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &print_address;
	disasm_obj.endian = !a->big_endian;
	disasm_obj.fprintf_func = &buf_fprintf;
	disasm_obj.stream = stdout;

	if (disasm_obj.endian == BFD_ENDIAN_BIG) {
		op->size = print_insn_big_nios2 ((bfd_vma)Offset, &disasm_obj);
	} else {
		op->size = print_insn_little_nios2 ((bfd_vma)Offset, &disasm_obj);
	}
	if (op->size == -1) {
		r_asm_op_set_asm (op, "(data)");
	}
	return op->size;
}

RAsmPlugin r_asm_plugin_nios2 = {
	.name = "nios2",
	.arch = "nios2",
	.license = "GPL3",
	.bits = 32,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.desc = "NIOS II Embedded Processor",
	.disassemble = &disassemble
};

#ifndef CORELIB
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_nios2,
	.version = R2_VERSION
};
#endif
