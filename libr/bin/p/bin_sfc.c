/* radare - LGPL3 - 2015-2017 - usr_share */

#include <r_bin.h>
#include <r_lib.h>
#include "sfc/sfc_specs.h"
#include <r_endian.h>

static bool check_bytes(const ut8 *buf, ut64 length) {

	const ut8* buf_hdr = buf;
	ut16 cksum1, cksum2;

	if ((length & LOROM_PAGE_SIZE) == SMC_HEADER_SIZE) buf_hdr += SMC_HEADER_SIZE;

	//determine if ROM is headered, and add a SMC_HEADER_SIZE gap if so. 
	cksum1 = r_read_le16(buf_hdr + LOROM_HDR_LOC + 0x1C);
	cksum2 = r_read_le16(buf_hdr + LOROM_HDR_LOC + 0x1E);

	if (cksum1 == (ut16)~cksum2) return true;
	
	cksum1 = r_read_le16(buf_hdr + HIROM_HDR_LOC + 0x1C);
	cksum2 = r_read_le16(buf_hdr + HIROM_HDR_LOC + 0x1E);
	
	if (cksum1 == (ut16)~cksum2) return true;
	return false;
}

static bool check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);
}

static void * load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	check_bytes (buf, sz);
	return R_NOTNULL;
}

static RBinInfo* info(RBinFile *arch) {
	RBinInfo *ret = NULL;

	int hdroffset = 0;
	if ((arch->size & LOROM_PAGE_SIZE) == SMC_HEADER_SIZE) hdroffset = SMC_HEADER_SIZE;

	sfc_int_hdr sfchdr;
	memset (&sfchdr, 0, SFC_HDR_SIZE);

	int reat = r_buf_read_at (arch->buf, LOROM_HDR_LOC + hdroffset, (ut8*)&sfchdr, SFC_HDR_SIZE);
	if (reat != SFC_HDR_SIZE) {
		eprintf ("Unable to read SFC/SNES header\n");
		return NULL;
	}

	if ( (sfchdr.comp_check != (ut16)~(sfchdr.checksum)) || ((sfchdr.rom_setup & 0x1) != 0) ){

		// if the fixed 0x33 byte or the LoROM indication are not found, then let's try interpreting the ROM as HiROM
		
		reat = r_buf_read_at (arch->buf, HIROM_HDR_LOC + hdroffset, (ut8*)&sfchdr, SFC_HDR_SIZE);
		if (reat != SFC_HDR_SIZE) {
			eprintf ("Unable to read SFC/SNES header\n");
			return NULL;
		}
	
		if ( (sfchdr.comp_check != (ut16)~(sfchdr.checksum)) || ((sfchdr.rom_setup & 0x1) != 1) ) {

			eprintf ("Cannot determine if this is a LoROM or HiROM file\n");
			return NULL;
		}
	}
	
	if (!(ret = R_NEW0 (RBinInfo)))
		return NULL;

	ret->file = strdup (arch->file);
	ret->type = strdup ("ROM");
	ret->machine = strdup ("Super NES / Super Famicom");
	ret->os = strdup ("snes");
	ret->arch = strdup ("snes");
	ret->bits = 16;
	ret->has_va = 1;

	return ret;
}

static void addrom(RList *ret, const char *name, int i, ut64 paddr, ut64 vaddr, ut32 size) {
	RBinSection *ptr = R_NEW0 (RBinSection);
	if (!ptr) return;
	sprintf(ptr->name,"%s_%02x",name,i);
	ptr->paddr = paddr;
	ptr->vaddr = vaddr;
	ptr->size = ptr->vsize = size;
	ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_EXECUTABLE | R_BIN_SCN_MAP;
	ptr->add = true;
	r_list_append (ret, ptr);
}

static void addsym(RList *ret, const char *name, ut64 addr, ut32 size) {
	RBinSymbol *ptr = R_NEW0 (RBinSymbol);
	if (!ptr) return;
	ptr->name = strdup (name? name: "");
	ptr->paddr = ptr->vaddr = addr;
	ptr->size = size;
	ptr->ordinal = 0;
	r_list_append (ret, ptr);
}

static RList* symbols(RBinFile *arch) {
	RList *ret = NULL;
	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	return ret;
}

static RList* sections(RBinFile *arch) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;
	int hdroffset = 0;
	ut8 is_hirom = 0;
	int i=0; //0x8000-long bank number for loops
	
	if ((arch->size & LOROM_PAGE_SIZE) == SMC_HEADER_SIZE) hdroffset = SMC_HEADER_SIZE;

	sfc_int_hdr sfchdr;
	memset (&sfchdr, 0, SFC_HDR_SIZE);

	int reat = r_buf_read_at (arch->buf, LOROM_HDR_LOC + hdroffset, (ut8*)&sfchdr, SFC_HDR_SIZE);
	if (reat != SFC_HDR_SIZE) {
		eprintf ("Unable to read SFC/SNES header\n");
		return NULL;
	}

	if ( (sfchdr.comp_check != (ut16)~(sfchdr.checksum)) || ((sfchdr.rom_setup & 0x1) != 0) ){

		// if the fixed 0x33 byte or the LoROM indication are not found, then let's try interpreting the ROM as HiROM
		
		reat = r_buf_read_at (arch->buf, HIROM_HDR_LOC + hdroffset, (ut8*)&sfchdr, SFC_HDR_SIZE);
		if (reat != SFC_HDR_SIZE) {
			eprintf ("Unable to read SFC/SNES header\n");
			return NULL;
		}
	
		if ( (sfchdr.comp_check != (ut16)~(sfchdr.checksum)) || ((sfchdr.rom_setup & 0x1) != 1) ) {

			eprintf ("Cannot determine if this is a LoROM or HiROM file\n");
			return NULL;
		}
		is_hirom = 1;
	}
	
	if (!(ret = r_list_new ()))
		return NULL;
	if (is_hirom) {
		
		for (i=0; i < ((arch->size - hdroffset)/ 0x8000) ; i++) {
			
			addrom(ret,"ROM",i,hdroffset + i*0x8000,0x400000 + (i*0x8000), 0x8000);
			if (i % 2) addrom(ret,"ROM_MIRROR",i,hdroffset + i*0x8000,(i*0x8000), 0x8000);
		}
	} else {
		for (i=0; i < ((arch->size - hdroffset)/ 0x8000) ; i++) {

			addrom(ret,"ROM",i,hdroffset + i*0x8000,0x8000 + (i*0x10000), 0x8000);
		}
	}
	return ret;
}

static RList *mem (RBinFile *arch) {
	RList *ret;
	RBinMem *m, *n;
	if (!(ret = r_list_new()))
		return NULL;
	ret->free = free;
	if (!(m = R_NEW0 (RBinMem))) {
		r_list_free (ret);
		return NULL;
	}

	m->name = strdup ("LOWRAM");
	m->addr = LOWRAM_START_ADDRESS;
	m->size = LOWRAM_SIZE;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);
	if (!(n = R_NEW0 (RBinMem)))
		return ret;
	
	m->mirrors = r_list_new();

	n->name = strdup ("LOWRAM_MIRROR");
	n->addr = LOWRAM_MIRROR_START_ADDRESS;
	n->size = LOWRAM_MIRROR_SIZE;
	n->perms = r_str_rwx ("rwx");
	r_list_append (m->mirrors, n);
	if (!(n = R_NEW0 (RBinMem))) {
		r_list_free (m->mirrors);
		m->mirrors = NULL;
		return ret;
	}

	m->name = strdup ("HIRAM");
	m->addr = HIRAM_START_ADDRESS;
	m->size = HIRAM_SIZE;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);
	if (!(n = R_NEW0 (RBinMem)))
		return ret;
	
	m->name = strdup ("EXTRAM");
	m->addr = EXTRAM_START_ADDRESS;
	m->size = EXTRAM_SIZE;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);
	if (!(n = R_NEW0 (RBinMem)))
		return ret;


	m->name = strdup ("PPU1_REG");
	m->addr = PPU1_REG_ADDRESS;
	m->size = PPU1_REG_SIZE;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);
	if (!(m = R_NEW0 (RBinMem))) {
		r_list_free (ret);
		return NULL;
	}

	m->name = strdup ("DSP_REG");
	m->addr = DSP_REG_ADDRESS;
	m->size = DSP_REG_SIZE;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);
	if (!(m = R_NEW0 (RBinMem))) {
		r_list_free (ret);
		return NULL;
	}
	
	m->name = strdup ("OLDJOY_REG");
	m->addr = OLDJOY_REG_ADDRESS;
	m->size = OLDJOY_REG_SIZE;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);
	if (!(m = R_NEW0 (RBinMem))) {
		r_list_free (ret);
		return NULL;
	}
	
	m->name = strdup ("PPU2_REG");
	m->addr = PPU2_REG_ADDRESS;
	m->size = PPU2_REG_SIZE;
	m->perms = r_str_rwx ("rwx");
	r_list_append (ret, m);
	if (!(m = R_NEW0 (RBinMem))) {
		r_list_free (ret);
		return NULL;
	}

	return ret;
}

static RList* entries(RBinFile *arch) { //Should be 3 offsets pointed by NMI, RESET, IRQ after mapping && default = 1st CHR
	RList *ret;
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	return ret;
}

RBinPlugin r_bin_plugin_sfc = {
	.name = "sfc",
	.desc = "Super NES / Super Famicom ROM file",
	.license = "LGPL3",
	.load_bytes = &load_bytes,
	.check = &check,
	.check_bytes = &check_bytes,
	.entries = &entries,
	.sections = sections,
	.symbols = &symbols,
	.info = &info,
	.mem = &mem,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_sfc,
	.version = R2_VERSION
};
#endif
