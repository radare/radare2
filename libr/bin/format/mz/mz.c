/* radare - LGPL - Copyright 2015 nodepad */

#include "mz.h"
#include <btree.h>

static ut64 r_bin_mz_seg_to_paddr(struct r_bin_mz_obj_t *bin, ut16 segment)
{
	return (bin->dos_header->header_paragraphs + segment) << 4;
}

int r_bin_mz_get_entrypoint(struct r_bin_mz_obj_t *bin)
{
	/* Value of CS in DOS header may be negative */
	short cs = (short)bin->dos_header->cs;
	int paddr = ((bin->dos_header->header_paragraphs + cs) << 4) + \
            bin->dos_header->ip;
	if (paddr >= 0 && paddr < bin->size)
		return paddr;
	else
		return -1;
}

int cmp_segs(const void *a, const void *b) {
	ut16 *ma = (ut16 *)a;
	ut16 *mb = (ut16 *)b;
	if (ma == NULL || mb == NULL)
		return 0;
	return (int)(*ma-*mb);
}

void trv_segs(const void *seg, const void *segs)
{
	ut16 *mseg = (ut16 *)seg;
	ut16 **msegs = (ut16 **)segs;
	if (mseg != NULL && msegs != NULL && *msegs != NULL) {
		**msegs = *mseg;
		*msegs = *msegs + 1;
	}
}

struct r_bin_mz_segment_t * r_bin_mz_get_segments(struct r_bin_mz_obj_t *bin)
{
	struct btree_node *tree;
	struct r_bin_mz_segment_t *ret;
	ut16 *segments, *curr_seg;
	int i, num_segs;
	ut64 paddr;
	ut16 first_segment = 0;
	ut16 stack_segment = bin->dos_header->ss;
	MZ_image_relocation_entry *relocs = bin->relocation_entries;
	int num_relocs = bin->dos_header->num_relocs;
	ut64 last_parag = ((bin->size + 0xF) >> 4) - \
            bin->dos_header->header_paragraphs;

	btree_init(&tree);

	for (i = 0; i < num_relocs; i++) {
		paddr = r_bin_mz_seg_to_paddr(bin, relocs[i].segment) + \
                relocs[i].offset;
		if ((paddr + 2) < bin->size) {
			curr_seg = (ut16 *) (bin->b->buf + paddr);
			/* Add segment only if it's located inside executable data */
			if (*curr_seg <= last_parag)
				btree_add(&tree, curr_seg, cmp_segs);
		}
	}

	/* Add segment address of first segment to make sure that it will be
    added. If relocations empty or there isn't first segment in relocations.)
    */
	btree_add(&tree, &first_segment, cmp_segs);
	/* Add segment address of stack segment if it's resides inside executable
    */
	if (r_bin_mz_seg_to_paddr(bin, stack_segment) < bin->size) {
		btree_add(&tree, &stack_segment, cmp_segs);
	}

	segments = calloc (num_relocs, sizeof(*segments));
	if (segments == NULL) {
		eprintf ("Error: calloc (segments)\n");
		return NULL;
	}

	curr_seg = segments;
	btree_traverse(tree, 0, &curr_seg, trv_segs);

	num_segs = curr_seg - segments;
	ret = calloc (num_segs + 1, sizeof(struct r_bin_mz_segment_t));
	if (ret == NULL) {
		free(segments);
		btree_cleartree(tree, NULL);
		eprintf ("Error: calloc (struct r_bin_mz_segment_t)\n");
		return NULL;
	}

	btree_cleartree(tree, NULL);

	ret[0].paddr = r_bin_mz_seg_to_paddr(bin, segments[0]);
	for (i = 1; i < num_segs; i++) {
		ret[i].paddr = r_bin_mz_seg_to_paddr(bin, segments[i]);
		ret[i - 1].size = ret[i].paddr - ret[i - 1].paddr;
	}
	ret[i - 1].size = bin->size - ret[i - 1].paddr;
	ret[i].last = 1;

	free (segments);
	return ret;
}

struct r_bin_mz_reloc_t *r_bin_mz_get_relocs(struct r_bin_mz_obj_t *bin)
{
	struct r_bin_mz_reloc_t *relocs;
	int i, j;
	int num_relocs = bin->dos_header->num_relocs;
	MZ_image_relocation_entry *rel_entry = bin->relocation_entries;

	relocs = calloc (num_relocs + 1, sizeof(*relocs));
	if (relocs == NULL) {
		eprintf ("Error: calloc (struct r_bin_mz_reloc_t)\n");
		return NULL;
	}

	for (i = 0, j = 0; i < num_relocs; i++) {
		relocs[j].paddr = r_bin_mz_seg_to_paddr(bin, rel_entry[i].segment) + \
                rel_entry[i].offset;
		/* Add only relocations which resides inside executable */
		if (relocs[j].paddr < bin->size) j++;
	}
	relocs[j].last = 1;

	return relocs;
}

void *r_bin_mz_free(struct r_bin_mz_obj_t* bin) {
	if (!bin) return NULL;
	free (bin->dos_header);
	free (bin->dos_extended_header);
	free (bin->relocation_entries);
	r_buf_free (bin->b);
	bin->b = NULL;
	free (bin);
	return NULL;
}

static int r_bin_mz_init_hdr(struct r_bin_mz_obj_t* bin) {
	int relocations_size;

	if (!(bin->dos_header = malloc(sizeof(MZ_image_dos_header)))) {
		r_sys_perror ("malloc (MZ_image_dos_header)");
		return R_FALSE;
	}
	if (r_buf_read_at (bin->b, 0, (ut8*)bin->dos_header,
            sizeof(*bin->dos_header)) == -1) {
		eprintf("Error: read (MZ_image_dos_header)\n");
		return R_FALSE;
	}

    relocations_size = bin->dos_header->num_relocs * \
            sizeof(MZ_image_relocation_entry);

    /* Check if relocation table doesn't exceed binary size */
	if ((bin->dos_header->reloc_table_offset + relocations_size) > bin->size)
		return R_FALSE;

	sdb_num_set (bin->kv, "mz.initial.cs", bin->dos_header->cs, 0);
	sdb_num_set (bin->kv, "mz.initial.ip", bin->dos_header->ip, 0);
	sdb_num_set (bin->kv, "mz.initial.ss", bin->dos_header->ss, 0);
	sdb_num_set (bin->kv, "mz.initial.sp", bin->dos_header->sp, 0);
	sdb_num_set (bin->kv, "mz.overlay_number",
            bin->dos_header->overlay_number, 0);
	sdb_num_set (bin->kv, "mz.dos_header.offset", 0, 0);
	sdb_set (bin->kv, "mz.dos_header.format", "[2]zwwwwwwwwwwwww"
			" signature bytes_in_last_block blocks_in_file num_relocs "
			" header_paragraphs min_extra_paragraphs max_extra_paragraphs "
			" ss sp checksum ip cs reloc_table_offset overlay_number ", 0);

	bin->dos_extended_header_size = bin->dos_header->reloc_table_offset - \
            sizeof(MZ_image_dos_header);

	if (bin->dos_extended_header_size > 0)
	{
		if (!(bin->dos_extended_header = \
                malloc(bin->dos_extended_header_size))) {
			r_sys_perror ("malloc (dos extended header)");
			return R_FALSE;
		}
		if (r_buf_read_at (bin->b, sizeof(MZ_image_dos_header),
                (ut8*)bin->dos_extended_header,
				bin->dos_extended_header_size) == -1) {
			eprintf("Error: read (dos extended header)\n");
			return R_FALSE;
		}
	}

	if (relocations_size > 0)
	{
		if (!(bin->relocation_entries = malloc(relocations_size))) {
			r_sys_perror ("malloc (dos relocation entries)");
			return R_FALSE;
		}
		if (r_buf_read_at (bin->b, bin->dos_header->reloc_table_offset,
				(ut8*)bin->relocation_entries, relocations_size) == -1) {
			eprintf("Error: read (dos relocation entries)\n");
			return R_FALSE;
		}
	}

	return R_TRUE;
}

static int r_bin_mz_init(struct r_bin_mz_obj_t* bin) {
	bin->dos_header = NULL;
	bin->dos_extended_header = NULL;
	bin->relocation_entries = NULL;
	bin->kv = sdb_new0();

	if (!r_bin_mz_init_hdr(bin)) {
		eprintf ("Warning: File is not MZ\n");
		return R_FALSE;
	}

	return R_TRUE;
}

struct r_bin_mz_obj_t* r_bin_mz_new(const char* file)
{
	ut8 *buf;
	struct r_bin_mz_obj_t *bin = R_NEW0 (struct r_bin_mz_obj_t);
	if (!bin) return NULL;
	bin->file = file;
	if (!(buf = (ut8*)r_file_slurp(file, &bin->size)))
		return r_bin_mz_free(bin);
	bin->b = r_buf_new ();
	if (!r_buf_set_bytes (bin->b, buf, bin->size)) {
		free (buf);
		return r_bin_mz_free(bin);
	}
	free (buf);
	if (!r_bin_mz_init(bin))
		return r_bin_mz_free(bin);
	return bin;
}

struct r_bin_mz_obj_t* r_bin_mz_new_buf(struct r_buf_t *buf)
{
	struct r_bin_mz_obj_t *bin = R_NEW0 (struct r_bin_mz_obj_t);
	if (!bin) return NULL;
	bin->b = r_buf_new ();
	bin->size = buf->length;
	if (!r_buf_set_bytes (bin->b, buf->buf, bin->size)){
		return r_bin_mz_free(bin);
	}
	if (!r_bin_mz_init(bin))
		return r_bin_mz_free(bin);
	return bin;
}
