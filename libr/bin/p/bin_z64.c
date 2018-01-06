/* radare2 - LGPL - Copyright 2018 - lowlyw */

/*
 * info comes from here.
 * https://github.com/mikeryan/n64dev
 * http://en64.shoutwiki.com/wiki/N64_Memory
 */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <r_io.h>
#include <r_cons.h>

//#define NSO_OFF(x) r_offsetof (NSOHeader, x)

// starting at 0
/*
0000h              (1 byte): initial PI_BSB_DOM1_LAT_REG value (0x80)
0001h              (1 byte): initial PI_BSB_DOM1_PGS_REG value (0x37)
0002h              (1 byte): initial PI_BSB_DOM1_PWD_REG value (0x12)
0003h              (1 byte): initial PI_BSB_DOM1_PGS_REG value (0x40)
0004h - 0007h     (1 dword): ClockRate
0008h - 000Bh     (1 dword): Program Counter (PC)
000Ch - 000Fh     (1 dword): Release
0010h - 0013h     (1 dword): CRC1
0014h - 0017h     (1 dword): CRC2
0018h - 001Fh    (2 dwords): Unknown (0x0000000000000000)
0020h - 0033h    (20 bytes): Image name
                             Padded with 0x00 or spaces (0x20)
0034h - 0037h     (1 dword): Unknown (0x00000000)
0038h - 003Bh     (1 dword): Manufacturer ID
                             0x0000004E = Nintendo ('N')
003Ch - 003Dh      (1 word): Cartridge ID
003Eh - 003Fh      (1 word): Country code
                             0x4400 = Germany ('D')
                             0x4500 = USA ('E')
                             0x4A00 = Japan ('J')
                             0x5000 = Europe ('P')
                             0x5500 = Australia ('U')
0040h - 0FFFh (1008 dwords): Boot code
*/
typedef struct {
	ut8 x1; /* initial PI_BSB_DOM1_LAT_REG value */
	ut8 x2; /* initial PI_BSB_DOM1_PGS_REG value */
	ut8 x3; /* initial PI_BSB_DOM1_PWD_REG value */
	ut8 x4; /* initial PI_BSB_DOM1_RLS_REG value */
	ut32 ClockRate;
	ut32 BootAddress;
	ut32 Release;
	ut32 CRC1;
	ut32 CRC2;
	ut64 UNK1;
	char Name[20];
	ut32 UNK2;
	ut16 UNK3;
	ut8 UNK4;
	ut8 ManufacturerID; // 0x0000004E ('N') ?
	ut16 CartridgeID;
	char CountryCode;
	ut8 UNK5;
	// BOOT CODE?
} N64Header;

static N64Header n64_header;

static ut64 baddr(RBinFile *bf) {
	return (ut64) r_read_be32(&n64_header.BootAddress);
}

static bool check_bytes (const ut8 *buf, ut64 length) {
	// XXX just based on size? we should validate the struct too
	if (length < 0x1000) {
		return false;
	}
	return true;
}

static void *load_bytes(RBinFile *bf, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb) {
	if (check_bytes (r_buf_buffer (bf->buf), sz)) {
		return memcpy (&n64_header, buf, sizeof (N64Header));
	}
	return NULL;
}

static bool load(RBinFile *bf) {
	const ut8 *bytes = bf ? r_buf_buffer (bf->buf) : NULL;
	char *fname = bf->file;
	ut64 sz = bf ? r_buf_size (bf->buf) : 0;
	if (!bf || !bf->o) {
		return false;
	}
	// XXX hack based on name?
	if(strlen(fname) > 4 && !strcmp(fname + strlen(fname) - 4, ".z64")) {
		bf->o->bin_obj = load_bytes (bf, bytes, sz, bf->o->loadaddr, bf->sdb);
		return check_bytes (bytes, sz);
	} else {
		return false;
	}
}

static int destroy(RBinFile *bf) {
	return true;
}

static RList *entries(RBinFile *bf) {
	RList /*<RBinAddr>*/ *ret = r_list_new ();
	RBinAddr *ptr = NULL;
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;
	if ((ptr = R_NEW0 (RBinAddr))) {
		ptr->paddr = 0x1000;
		ptr->vaddr = baddr (bf);
		r_list_append (ret, ptr);
	}
	return ret;
}

static RList *sections(RBinFile *bf) {
	RList /*<RBinSection>*/ *ret = r_list_new ();
	if (!ret) {
		return NULL;
	}
	RBinSection *text = R_NEW0 (RBinSection);
	if (!text) {
		r_list_free (ret);
		return NULL;
	}
	strncpy (text->name, "text", R_BIN_SIZEOF_STRINGS);
	text->size = bf->buf->length - sizeof (N64Header);
	text->vsize = text->size;
	text->paddr = 0x1000;
	text->vaddr = baddr (bf);
	text->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_EXECUTABLE | R_BIN_SCN_MAP; // r-x
	text->add = true;
	r_list_append (ret, text);
	return ret;
}

static ut64 boffset(RBinFile *bf) {
	return 0LL;
}

static RBinInfo *info(RBinFile *bf) {
	char GameName[21] = {0};
	RBinInfo *ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}
	memcpy (GameName, n64_header.Name, sizeof (n64_header.Name));
	ret->file = strdup (GameName);
	ret->os = strdup ("n64");
	ret->arch = strdup ("mips");
	ret->machine = strdup ("Nintendo 64");
	ret->type = strdup ("ROM");
	ret->bits = 32;
	ret->has_va = true;
	ret->big_endian = true;
	return ret;
}

#if !R_BIN_Z64

RBinPlugin r_bin_plugin_z64 = {
	.name = "z64",
	.desc = "Nintendo 64 binaries big endian r_bin plugin",
	.license = "LGPL2",
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check_bytes = &check_bytes,
	.baddr = baddr,
	.boffset = &boffset,
	.entries = &entries,
	.sections = &sections,
	.info = &info
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_z64,
	.version = R2_VERSION
};
#endif
#endif
