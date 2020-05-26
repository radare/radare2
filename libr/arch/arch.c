/* radare - LGPL - Copyright 2020 - pancake */

#include <r_arch.h>
#include <r_asm.h>
#include "../config.h"

static RArchPlugin *arch_static_plugins[] = { R_ARCH_STATIC_PLUGINS };

static void plugin_free(RArchPlugin *p) {
	if (p && p->fini) {
		p->fini (NULL);
	}
}

R_API RArch *r_arch_new(void) {
	RArch *a = R_NEW0 (RArch);
	if (!a) {
		return NULL;
	}
	a->plugins = r_list_newf ((RListFree)plugin_free);
	if (!a->plugins) {
		free (a);
		return NULL;
	}
	size_t i;
	for (i = 0; arch_static_plugins[i]; i++) {
		r_arch_add (a, arch_static_plugins[i]);
	}
	return a;
}

R_API void r_arch_free(RArch *arch) {
	r_list_free (arch->plugins);
	free (arch);
}

R_API bool r_arch_add(RArch *a, RArchPlugin *foo) {
	r_return_val_if_fail (a && foo, false);
	if (foo->init) {
		foo->init (a);
	}
	if (!r_arch_get_plugin (a, foo->name)) {
		r_list_append (a->plugins, foo);
		return true;
	}
	return false;
}

R_API bool r_arch_del(RArch *a, RArchPlugin *ap) {
	r_return_val_if_fail (a, false);
	if (ap->fini) {
		ap->fini (a);
	}
	return r_list_delete_data (a->plugins, ap);
}

R_API RArchPlugin *r_arch_get_plugin(RArch *a, const char *name) {
	r_return_val_if_fail (a && a->plugins, false);
	RArchPlugin *h;
	RListIter *iter;
	r_list_foreach (a->plugins, iter, h) {
		if (!strcmp (h->name, name) && h->arch) {
			return h;
		}
	}
	return NULL;
}

