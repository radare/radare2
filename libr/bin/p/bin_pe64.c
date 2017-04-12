/* radare - LGPL - Copyright 2009-2015 - nibble, pancake */

#define R_BIN_PE64 1
#include "bin_pe.c"

static bool check_bytes(const ut8 *buf, ut64 length) {
	int idx, ret = false;
	if (!buf || length <= 0x3d) {
		return false;
	}
	idx = buf[0x3c] | (buf[0x3d] << 8);
	if (length >= idx + 0x20)
		if (!memcmp (buf, "MZ", 2) && !memcmp (buf + idx, "PE", 2) &&
		    !memcmp (buf + idx + 0x18, "\x0b\x02", 2))
			ret = true;
	return ret;
}

extern struct r_bin_write_t r_bin_write_pe64;

RBinPlugin r_bin_plugin_pe64 = {
	.name = "pe64",
	.desc = "PE64 (PE32+) bin plugin",
	.license = "LGPL3",
	.get_sdb = &get_sdb,
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.info = &info,
	.libs = &libs,
	.relocs = &relocs,
	.get_vaddr = &get_vaddr,
	.write = &r_bin_write_pe64
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pe64,
	.version = R2_VERSION
};
#endif
