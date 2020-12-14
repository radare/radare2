/* radare - LGPL - Copyright 2020 - pancake */

#include <r_io.h>

R_API bool r_io_banks_add(RIO *io, RIOBank *bank) {
	r_return_val_if_fail (io && bank, false);
	// TODO: check if its registered first
	return r_id_storage_add (io->banks, bank, &bank->id);
}

R_API bool r_io_banks_del(RIO *io, RIOBank *bank) {
	r_return_val_if_fail (io && io->banks && bank, false);
	// check if bank is a bank of this instance of io
	r_return_val_if_fail (r_id_storage_get (io->banks, bank->id) == bank, false);
	r_id_storage_delete (io->banks, bank->id);
	r_io_bank_free (bank);
	return true;
}

R_API bool r_io_banks_use(RIO *io, ut32 id) {
	r_return_val_if_fail (io, false);
	if (id == 0) {
		r_io_banks_reset (io);
		return true;
	}
	RIOBank *bank = (RIOBank *)r_id_storage_get (io->banks, id);
	if (!bank) {
		return false;
	}
	r_io_map_bank (io, bank);
	return true;
}

static bool bank_free_cb(void *user, void *data, ut32 id) {
	r_io_bank_free ((RIOBank *)data);
	return true;
}

R_API void r_io_banks_reset(RIO *io) {
	r_return_if_fail (io);
	io->curbank = 0;
	r_id_storage_foreach (io->banks, bank_free_cb, NULL);
	r_id_storage_free (io->banks);
	io->banks = r_id_storage_new (1, UT32_MAX);
}

typedef struct bank_finder_t {
	const char *name;
	RIOBank *bank;
} BankFinder;

static bool bank_find_by_name_cb(void *user, void *data, ut32 id) {
	BankFinder *bf = (BankFinder *)user;
	RIOBank *bank = (RIOBank *)data;
	if (!strcmp (bank->name, bf->name)) {
		bf->bank = bank;
		return false;
	}
	return true;
}

R_API RIOBank *r_io_bank_get_by_name(RIO *io, const char *name) {
	r_return_val_if_fail (io && io->banks, NULL);
	if (R_STR_ISEMPTY (name)) {
		return NULL;
	}
	BankFinder bf = { name, NULL };
	r_id_storage_foreach (io->banks, bank_find_by_name_cb, &bf);
	return bf.bank;
}

R_API RIOBank *r_io_bank_get_by_id(RIO *io, ut32 id) {
	return (RIOBank *)r_id_storage_get (io->banks, id);
}
