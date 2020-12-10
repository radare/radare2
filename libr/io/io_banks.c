/* radare - LGPL - Copyright 2020 - pancake */

#include <r_io.h>

R_API RIOBanks *r_io_banks_new() {
	RIOBanks *banks = R_NEW0 (RIOBanks);
	banks->curbank = NULL;
	banks->list = r_list_newf ((RListFree)r_io_bank_free);
	banks->ids = r_id_storage_new (1, UT32_MAX);
	return banks;
}

R_API void r_io_banks_add(RIO *io, RIOBank *bank) {
	r_return_if_fail (io && bank);
	// TODO: check if its registered first
	ut32 id;
	r_id_storage_add (io->banks->ids, bank, &id);
	bank->id = id;
	r_list_append (io->banks->list, bank);
}

R_API bool r_io_banks_del(RIO *io, RIOBank *bank) {
	r_id_storage_delete (io->banks->ids, bank->id);
	r_list_delete_data (io->banks->list, bank);
	if (bank == io->banks->curbank) {
		io->banks->curbank = NULL;
	}
	// r_io_bank_free (bank);
	return false;
}

R_API char *r_io_banks_list(RIO *io, int mode) {
	RStrBuf *sb = r_strbuf_new ("");
	RListIter *iter;
	RIOBank *bank;
	r_list_foreach (io->banks->list, iter, bank) {
		r_strbuf_appendf (sb, "bank %d (%s)\n", bank->id, bank->name);
		void **it;
		r_pvector_foreach (&bank->maps, it) {
			int id = (int)(size_t)*it;
			r_strbuf_appendf (sb, " map %d\n", id);
		}
	}
	return r_strbuf_drain (sb);
}

R_API bool r_io_banks_use(RIO *io, int id) {
	if (id < 0) {
		if (io->banks->curbank) {
			r_io_map_bank (io, io->banks->curbank);
			io->banks->curbank = NULL;
			return true;
		}
		return false;
	}
	RIOBank *bank = r_id_storage_get (io->banks->ids, id);
	if (bank) {
		io->banks->curbank = bank;
		if (r_pvector_len (&io->banks->maps)) {
			io->banks->maps = io->maps;
			io->banks->map_ids = io->map_ids;
		}
		io->maps = bank->maps;
		io->map_ids = bank->map_ids;
		return true;
	}
	return false;
}

R_API void r_io_banks_reset(RIO *io) {
	r_io_banks_use (io, -1);
	r_list_free (io->banks->list);
	io->banks->list = r_list_newf ((RListFree)r_io_bank_free);
	r_id_storage_free (io->banks->ids);
	io->banks->ids = r_id_storage_new (0, UT32_MAX);
}

R_API RIOBank* r_io_bank_get_by_name(RIO *io, const char *name) {
	RListIter *iter;
	RIOBank *bank;
	r_list_foreach (io->banks->list, iter, bank) {
		if (!strcmp (bank->name, name)) {
			return bank;
		}
	}
	return NULL;
}

R_API RIOBank* r_io_bank_get_by_id(RIO *io, int id) {
	return r_id_storage_get (io->banks->ids, id);
}
