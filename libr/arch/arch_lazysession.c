/* radare - LGPL - Copyright 2020 - pancake */

#include <r_arch.h>
#include <r_asm.h>
#include "../config.h"

R_API RArchLazySession *r_arch_lazysession_new(RArchSessionPool *pool) {
	r_return_val_if_fail (pool && pool->arch, NULL);
	RArchLazySession *ls = R_NEW0 (RArchLazySession);
	if (ls) {
		ls->setup.plugin = r_arch_get_plugin (pool->arch, R_SYS_ARCH);
		ls->setup.bits = R_SYS_BITS;
		ls->setup.endian = R_SYS_ENDIAN_LITTLE;
		ls->pool = pool;
		ls->dirty = true;
	}
	return ls;
}

R_API bool r_arch_lazysession_set_bits(RArchLazySession *ls, RArchBits bits) {
	r_return_val_if_fail (ls, false);
	if (!ls->setup.plugin) {
		return false;
	}
	if (r_arch_plugin_has_bits (ls->setup.plugin, bits)) {
		if (ls->setup.bits != bits) {
			ls->setup.bits = bits;
			ls->dirty = true;
		}
		return true;
	}
	return false;
}

R_API bool r_arch_lazysession_set_plugin(RArchLazySession *ls, const char *name) {
	r_return_val_if_fail (ls && name, false);
	if (ls->setup.plugin) {
		if (!strcmp (name, ls->setup.plugin->name)) {
			return true;
		}
	}
	RArchPlugin *ap = r_arch_get_plugin (ls->pool->arch, name);
	if (ap) {
		if (ls->setup.plugin != ap) {
			ls->setup.plugin = ap;
			ls->dirty = true;
		}
		return true;
	}
	ls->setup.plugin = NULL;
	return false;
}

R_API bool r_arch_lazysession_can_regprofile(RArchLazySession *ls) {
	return ls && ls->session && ls->session->info.regprofile;
}

R_API bool r_arch_lazysession_can_encode(RArchLazySession *ls) {
	return ls && ls->session && ls->session->setup.plugin && ls->session->setup.plugin->encode;
}

R_API bool r_arch_lazysession_can_decode(RArchLazySession *ls) {
	return ls && ls->session && ls->session->setup.plugin && ls->session->setup.plugin->decode;
}

static bool r_arch_plugin_has_cpu (RArchPlugin *ap, const char *cpu) {
	// TODO implement
	return true;
}

R_API bool r_arch_lazysession_set_cpu(RArchLazySession *ls, const char *cpu) {
	r_return_val_if_fail (ls && cpu, false);
	if (!ls->setup.plugin) {
		return false;
	}
	if (r_arch_plugin_has_cpu (ls->setup.plugin, cpu)) {
		if (strcmp (ls->setup.cpu, cpu)) {
			free (ls->setup.cpu);
			ls->setup.cpu = strdup (cpu);
			ls->dirty = true;
		}
		return true;
	}
	return false;
}

R_API RArchSession *r_arch_lazysession_get_session(RArchLazySession *ls) {
	r_return_val_if_fail (ls, NULL);
	if (!ls->dirty && ls->session) {
		return ls->session;
	}
	ls->dirty = false;
	ls->session = r_arch_sessionpool_get_session (ls->pool, &ls->setup);
	return ls->session;
}
