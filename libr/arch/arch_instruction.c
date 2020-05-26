/* radare - LGPL - Copyright 2020 - pancake */

#include <r_arch.h>
#include <r_asm.h>
#include "../config.h"

R_API RArchInstruction *r_arch_instruction_new() {
	RArchInstruction *ins = R_NEW0 (RArchInstruction);
	if (ins) {
		r_arch_instruction_init (ins);
	}
	return ins;
}

R_API void r_arch_instruction_free(RArchInstruction *ins) {
	r_arch_instruction_fini (ins);
	free (ins);
}

R_API void r_arch_instruction_fini(RArchInstruction *ins) {
	if (ins) {
		r_strbuf_fini (&ins->code);
		r_strbuf_fini (&ins->data);
		r_strbuf_fini (&ins->esil);
		r_vector_fini (&ins->dest);
	}
}

R_API void r_arch_instruction_init(RArchInstruction *ins) {
	r_return_if_fail (ins);
	memset (ins, 0, sizeof (RArchInstruction));
	r_strbuf_init (&ins->esil);
	r_strbuf_init (&ins->code);
	r_strbuf_init (&ins->data);
	r_vector_init (&ins->dest, sizeof (ut64), NULL, NULL);
}

// Alternative init methods
R_API void r_arch_instruction_init_data(RArchInstruction *ins, ut64 addr, const ut8 *buf, size_t size) {
	r_arch_instruction_init (ins);
	ins->addr = addr;
	ins->size = size;
	r_strbuf_init (&ins->esil);
	r_strbuf_setbin (&ins->data, buf, size);
}

R_API void r_arch_instruction_init_code(RArchInstruction *ins, ut64 addr, const char *opstr) {
	r_arch_instruction_init (ins);
	ins->addr = addr;
	r_strbuf_set (&ins->code, opstr);
}

// NEW PROPOSAL API

R_API void r_arch_instruction_set_bytes(RArchInstruction *ins, ut64 addr, const ut8 *buf, size_t size) {
	ins->addr = addr;
	ins->size = size;
	r_strbuf_setbin (&ins->data, buf, size);
}

R_API void r_arch_instruction_set_opstr(RArchInstruction *ins, ut64 addr, const char *opstr) {
	ins->addr = addr;
	r_strbuf_set (&ins->code, opstr);
}

// Getters

R_API const char *r_arch_instruction_get_esil(RArchInstruction *ins) {
	return r_strbuf_get (&ins->esil);
}

R_API const char *r_arch_instruction_get_string(RArchInstruction *ins) {
	return r_strbuf_get (&ins->code);
}

