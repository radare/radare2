/* radare - LGPL3 - 2021 - murphy */

#include <r_bin.h>
#include <r_lib.h>
#include "wad/wad.h"

typedef struct {
	Sdb *kv;
	WADHeader hdr;
	RBuffer *buf;
} WadObj;

static int wad_header_load(WadObj *wo, Sdb *kv) {
	if (r_buf_size (wo->buf) < sizeof (WADHeader)) {
		return false;
	}
	WADHeader *hdr = &wo->hdr;
	(void) r_buf_fread_at (wo->buf, 0, (ut8 *) hdr, "uuu", 1);
	sdb_set (kv, "header.num_lumps", sdb_fmt ("%u", hdr->numlumps), 0);
	sdb_set (kv, "header.diroffset", sdb_fmt ("0x%x", hdr->diroffset), 0);
	ut32 numlumps = sdb_get (kv, "header.diroffset", 0);
	eprintf("NumLumps: %x", numlumps);
	return true;
}

static Sdb *get_sdb(RBinFile *bf) {
	RBinObject *o = bf->o;
	if (!o) {
		return NULL;
	}
	WadObj *wo = o->bin_obj;
	return wo? wo->kv: NULL;
}

static bool check_buffer(RBuffer *b) {
	r_return_val_if_fail (b, false);
	ut8 sig[4];
	if (r_buf_read_at (b, 0, sig, sizeof (sig)) != 4) {
		return false;
	}
	if (memcmp (sig, "IWAD", 4) && memcmp (sig, "PWAD", 4)) {
		return false;
	}
	return true;
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	WadObj *wo = R_NEW0 (WadObj);
	r_return_val_if_fail (wo, false);
	wo->kv = sdb_new0 ();
	if (!wo->kv) {
		free (wo);
		return false;
	}
	wo->buf = r_buf_ref (buf);
	wad_header_load (wo, wo->kv);
	sdb_ns_set (sdb, "info", wo->kv);
	*bin_obj = wo;
	return true;
}

static RBinInfo *info(RBinFile *bf) {
	r_return_val_if_fail (bf, NULL);
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	ret->file = strdup (bf->file);
	ret->type = strdup ("WAD");
	ret->machine = strdup ("DOOM Engine");
	ret->os = strdup ("DOOM Engine");
	ret->arch = strdup ("any");
	ret->bits = 32;
	ret->has_va = false;
	return ret;
}

static ut64 baddr(RBinFile *bf) {
	return 0;
}

static void addsym(RList *ret, const char *name, ut64 addr, ut32 size) {
	RBinSymbol *ptr = R_NEW0 (RBinSymbol);
	if (!ptr) {
		return;
	}
	ptr->name = strdup (r_str_get (name));
	ptr->paddr = ptr->vaddr = addr;
	ptr->size = size;
	ptr->ordinal = 0;
	r_list_append (ret, ptr);
}

static RList *symbols(RBinFile *bf) {
	RList *ret = NULL;
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	WAD_DIR_Entry dir;
	size_t i = 0;
	WadObj *wo = bf->o->bin_obj;
	while (i < wo->hdr.numlumps) {
		memset (&dir, 0, sizeof (dir));
		r_buf_read_at (bf->buf, wo->hdr.diroffset + (i * 16), (ut8*)&dir, sizeof (dir));
		addsym (ret, strndup(dir.name, 8), dir.filepos, dir.size);
		i++;
	}
	return ret;
}

// Prints header info using iH
static void wad_header_fields(RBinFile *bf) {
	PrintfCallback cb_printf = bf->rbin->cb_printf;
	cb_printf ("pf.wad_header @ 0x%08"PFMT64x"\n", 0);
	cb_printf ("0x00000000  Magic           0x%x\n", r_buf_read_le32_at (bf->buf, 0));
	cb_printf ("0x00000004  Numlumps        %d\n", r_buf_read_le32_at (bf->buf, 0x04));
	cb_printf ("0x00000008  TableOffset     0x%x\n", r_buf_read_le32_at (bf->buf, 0x08));
}

static RList *wad_fields(RBinFile *bf) {
	RBuffer *buf = bf->buf;
	RList *ret = r_list_new ();
	if (!ret) {
		return NULL;
	}
	ret->free = free;
	ut64 addr = 0;
	#define ROW(nam,siz,val,fmt) \
	r_list_append (ret, r_bin_field_new (addr, addr, siz, nam, sdb_fmt ("0x%04"PFMT32x, (ut32)val), fmt, false)); \
	addr += siz;
	ut32 magic = r_buf_read_le32 (bf->buf);
	ut32 numlumps = r_buf_read_le32 (bf->buf);
	ut32 table_offset = r_buf_read_le32 (bf->buf);
	ROW ("wad_magic", 4, magic, "[4]c");
	ROW ("numlumps", 4, numlumps, "d");
	ROW ("table_offset", 4, table_offset, "x");
	return ret;
}

static void destroy(RBinFile *bf) {
	WadObj *obj = bf->o->bin_obj;
	r_buf_free (obj->buf);
	free (obj);
}

RBinPlugin r_bin_plugin_wad = {
	.name = "wad",
	.desc = "DOOM WAD format r_bin plugin",
	.license = "LGPL3",
	.author = "murphy",
	.get_sdb = &get_sdb,
	.entries = NULL,
	.sections = NULL,
	.symbols = &symbols,
	.check_buffer = &check_buffer,
	.load_buffer = &load_buffer,
	.baddr = &baddr,
	.info = &info,
	.header = &wad_header_fields,
	.fields = &wad_fields,
	.destroy = &destroy
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_wad,
	.version = R2_VERSION
};
#endif
