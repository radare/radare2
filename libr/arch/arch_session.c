/* radare - LGPL - Copyright 2020 - pancake */

#include <r_arch.h>
#include <r_asm.h>
#include "../config.h"


static bool r_arch_session_set_cpu(RArchSession *ai, const char *cpu) {
	r_return_val_if_fail (ai && cpu, false);
	if (ai && *cpu) {
		RArchPlugin *ap = ai->setup.plugin;
		// TODO: improve the check with r_str_split_list()
		if (R_STR_ISEMPTY (ap->cpus) || strstr (ap->cpus, cpu)) {
			free (ai->setup.cpu);
			ai->setup.cpu = cpu? strdup (cpu): NULL;
		}
		return true;
	}
	return false;
}

static bool r_arch_session_set_syntax(RArchSession *ai, RArchSyntax syntax) {
	r_return_val_if_fail (ai, false);
	RArchPlugin *ap = ai->setup.plugin;
	switch (syntax) {
	case R_ASM_SYNTAX_REGNUM:
	case R_ASM_SYNTAX_INTEL:
	case R_ASM_SYNTAX_MASM:
	case R_ASM_SYNTAX_ATT:
	case R_ASM_SYNTAX_JZ:
		if (ap->syntax & syntax) {
			ai->setup.syntax = syntax;
			return true;
		}
		break;
	default:
		return false;
	}
	return false;
}

static bool r_arch_session_set_endian(RArchSession *ai, RArchEndian endian) {
	r_return_val_if_fail (ai && ai->setup.plugin, false);
	switch (endian) {
	case R_SYS_ENDIAN_LITTLE:
	case R_SYS_ENDIAN_BIG:
	case R_SYS_ENDIAN_NONE:
	case R_SYS_ENDIAN_BI:
		if (ai->setup.plugin->endian & endian) {
			ai->setup.endian = endian;
			return true;
		}
		break;
	}
	return false;
}

R_API bool r_arch_plugin_has_bits(RArchPlugin *h, RArchBits bits) {
        return (h && h->bits && (bits & h->bits));
}

static bool r_arch_session_set_bits(RArchSession *ai, RArchBits bits) {
	r_return_val_if_fail (ai && ai->setup.plugin, false);
	if (r_arch_plugin_has_bits (ai->setup.plugin, bits)) {
		ai->setup.bits = bits;
		return true;
	}
	return false;
}

//  this should be a method for RArchPlugin imho

R_API bool r_arch_plugin_setup(RArchPlugin *ap, RArchSetup *setup) {
	return false;
}

// this function must replace the can_decode/encode ones
R_API bool r_arch_plugin_can(RArchPlugin *ap, RArchCan action) {
	r_return_val_if_fail (ap, false);
	// check if plugin have the requested capabilities
	switch (action) {
	case R_ARCH_CAN_ANALYZE:
		return ap->decode;
	case R_ARCH_CAN_ASSEMBLE:
		return ap->encode;
	case R_ARCH_CAN_DISASM:
		return ap->decode;
	case R_ARCH_CAN_ESIL:
		break;
	case R_ARCH_CAN_ALL:
		break;
	}
	return false;
}

R_API bool r_arch_session_can(RArchSession *ai, RArchCan caps) {
	r_return_val_if_fail (ai, false);
	return r_arch_plugin_can (ai->setup.plugin, caps);
}

R_API bool r_arch_session_can_decode(RArchSession *ai) {
	r_return_val_if_fail (ai && ai->setup.plugin, false);
	return ai->setup.plugin->decode;
}

R_API bool r_arch_session_can_encode(RArchSession *ai) {
	r_return_val_if_fail (ai && ai->setup.plugin, false);
	return ai->setup.plugin->encode;
}

R_API bool r_arch_session_encode(RArchSession *ai, RArchInstruction *ins, RArchEncodeOptions opt) {
	r_return_val_if_fail (ai && ai->setup.plugin, false);
	if (ai->setup.plugin->encode) {
		return ai->setup.plugin->encode (ai, ins, opt);
	}
	return false;
}

R_API bool r_arch_session_decode(RArchSession *ai, RArchInstruction *ins, RArchDecodeOptions opt) {
	r_return_val_if_fail (ai && ai->setup.plugin, false);
	if (ai->setup.plugin->decode) {
		return ai->setup.plugin->decode (ai, ins, opt);
	}
	return false;
}

R_API void r_arch_session_free(RArchSession *as) {
	// something more
	free (as);
}

R_API RArchSession *r_arch_session_new(RArch *a, RArchSetup *setup) {
	r_return_val_if_fail (a && setup, NULL);
	if (!setup->plugin) {
		return NULL;
	}
	RArchSession *as = R_NEW0 (RArchSession);
	if (as) {
		RArchPlugin *ap = setup->plugin;
		as->setup.plugin = ap;
		if (!setup) {
			RArchSetup _setup = {
				.endian = R_SYS_ENDIAN,
				.bits = R_SYS_BITS
			};
			memcpy (&as->setup, &_setup, sizeof (RArchSetup));
			setup = &as->setup;
		} else {
			memcpy (&as->setup, setup, sizeof (RArchSetup));
		}
		if (ap && ap->init_session) {
			ap->init_session (as);
		}
		as->cbs = &a->cbs; // use ref maybe
		// call RArchPlugin.setup() to know if the setup is valid.
		// it is very easy to get into an invalid setup
		bool ok = r_arch_session_set_syntax (as, setup->syntax);
		ok &= r_arch_session_set_bits (as, setup->bits);
		ok &= r_arch_session_set_endian (as, setup->endian);
		if (setup->cpu) {
			ok &= r_arch_session_set_cpu (as, setup->cpu);
		}
		if (ok) {
			return as;
		}
		// return session even if configuration is not ok
		// otherwise its too picky to setup 8bit archs and such
		return as;
		r_arch_session_free (as);
	}
	return NULL;
}

// user frendly apis

R_API bool r_arch_session_encode_instruction (RArchSession *as, RArchInstruction *ins, ut64 addr, const char *opstr) {
	r_return_val_if_fail (as && ins && opstr, false);
	r_strbuf_set (&ins->code, opstr);
	return r_arch_session_encode (as, ins, R_ARCH_OPTION_CODE);
}

R_API bool r_arch_session_decode_bytes (RArchSession *as, RArchInstruction *ins, ut64 addr, const ut8 *buf, size_t len) {
	r_return_val_if_fail (as && ins, false);
	if (buf) {
		r_strbuf_setbin (&ins->data, (const ut8*)buf, len);
	}
	return r_arch_session_decode (as, ins, R_ARCH_OPTION_CODE);
}

R_API bool r_arch_session_decode_esil (RArchSession *as, RArchInstruction *ins, ut64 addr, const ut8 *buf, size_t len) {
	r_return_val_if_fail (as && ins, false);
	if (buf) {
		r_strbuf_setbin (&ins->data, (const ut8*)buf, len);
	}
	return r_arch_session_decode (as, ins, R_ARCH_OPTION_CODE|R_ARCH_OPTION_ESIL|R_ARCH_OPTION_ANAL);
}

