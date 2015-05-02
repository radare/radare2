/* radare - LGPL - Copyright 2015 nodepad */

#include <r_types.h>
#include <r_list.h>
#include <r_util.h>
#include <r_bin.h>
#include "mz_specs.h"

struct r_bin_mz_segment_t {
	ut64 paddr;
	ut64 size;
	int last;
};

struct r_bin_mz_reloc_t {
	ut64 paddr;
	int last;
};

struct r_bin_mz_obj_t {
	MZ_image_dos_header *dos_header;
	void *dos_extended_header;
	MZ_image_relocation_entry *relocation_entries;

	int dos_extended_header_size;

	int size;
	const char *file;
	struct r_buf_t *b;
	Sdb *kv;
};

int r_bin_mz_get_entrypoint(struct r_bin_mz_obj_t *bin);
struct r_bin_mz_segment_t *r_bin_mz_get_segments(struct r_bin_mz_obj_t *bin);
struct r_bin_mz_reloc_t *r_bin_mz_get_relocs(struct r_bin_mz_obj_t *bin);
void *r_bin_mz_free(struct r_bin_mz_obj_t* bin);
struct r_bin_mz_obj_t* r_bin_mz_new(const char* file);
struct r_bin_mz_obj_t* r_bin_mz_new_buf(struct r_buf_t *buf);
