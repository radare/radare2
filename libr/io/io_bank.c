/* radare - LGPL - Copyright 2020 - pancake */

#include <r_io.h>

R_API RIOBank* r_io_new_bank(RIO *io, const char *name) {
	RIOBank *bank = R_NEW0 (RIOBank);
	if (bank) {
		bank->name = strdup (name);
		r_pvector_init (&bank->maps, NULL);
		// bank->id is defined by r_io_banks_add()
		bank->map_ids = r_id_pool_new (0, UT32_MAX);
	}
	return bank;
}

R_API void r_io_bank_add_map(RIOBank *bank, RIOMap *map) {
	r_pvector_push (&bank->maps, (void*)(size_t)map->id);
}

R_API void r_io_bank_free(RIOBank *bank) {
	free (bank->name);
	free (bank);
}

R_API void r_io_bank_rename(RIOBank *bank, const char *name) {
	free (bank->name);
	bank->name = strdup (name);
}

