/* radare - LGPL - Copyright 2009-2019 - nibble, pancake */
#define R_BIN_PE64 1
#include "bin_pe.inc"

static bool check_buffer(RBuffer *b) {
	ut64 length = r_buf_size (b);
	if (length <= 0x3d) {
		return false;
	}
	ut16 idx = r_buf_read_le16_at (b, 0x3c);
	if (idx + 26 < length) {
		/* Here PE signature for usual PE files
		 * and PL signature for Phar Lap TNT DOS extender 32bit executables
		 */
		ut8 buf[2];
		r_buf_read_at (b, 0, buf, sizeof (buf));
		if (!memcmp (buf, "MZ", 2)) {
			r_buf_read_at (b, idx, buf, sizeof (buf));
			// TODO: Add one more indicator, to prevent false positives
			// if (!memcmp (buf, "PL", 2)) { return true; }
			if (!memcmp (buf, "PE", 2)) {
				r_buf_read_at (b, idx + 0x18, buf, sizeof (buf));
				return !memcmp (buf, "\x0b\x02", 2);
			}
		}
	}
	return false;
}

static void header(RBinFile *bf) {
	struct PE_(r_bin_pe_obj_t) * bin = bf->o->bin_obj;
	struct r_bin_t *rbin = bf->rbin;
	rbin->cb_printf ("PE file header:\n");
	rbin->cb_printf ("IMAGE_NT_HEADERS\n");
	rbin->cb_printf ("  Signature : 0x%x\n", bin->nt_headers->Signature);
	rbin->cb_printf ("IMAGE_FILE_HEADERS\n");
	rbin->cb_printf ("  Machine : 0x%x\n", bin->nt_headers->file_header.Machine);
	rbin->cb_printf ("  NumberOfSections : 0x%x\n", bin->nt_headers->file_header.NumberOfSections);
	rbin->cb_printf ("  TimeDateStamp : 0x%x\n", bin->nt_headers->file_header.TimeDateStamp);
	rbin->cb_printf ("  PointerToSymbolTable : 0x%x\n", bin->nt_headers->file_header.PointerToSymbolTable);
	rbin->cb_printf ("  NumberOfSymbols : 0x%x\n", bin->nt_headers->file_header.NumberOfSymbols);
	rbin->cb_printf ("  SizeOfOptionalHeader : 0x%x\n", bin->nt_headers->file_header.SizeOfOptionalHeader);
	rbin->cb_printf ("  Characteristics : 0x%x\n", bin->nt_headers->file_header.Characteristics);
	rbin->cb_printf ("IMAGE_OPTIONAL_HEADERS\n");
	rbin->cb_printf ("  Magic : 0x%x\n", bin->nt_headers->optional_header.Magic);
	rbin->cb_printf ("  MajorLinkerVersion : 0x%x\n", bin->nt_headers->optional_header.MajorLinkerVersion);
	rbin->cb_printf ("  MinorLinkerVersion : 0x%x\n", bin->nt_headers->optional_header.MinorLinkerVersion);
	rbin->cb_printf ("  SizeOfCode : 0x%x\n", bin->nt_headers->optional_header.SizeOfCode);
	rbin->cb_printf ("  SizeOfInitializedData : 0x%x\n", bin->nt_headers->optional_header.SizeOfInitializedData);
	rbin->cb_printf ("  SizeOfUninitializedData : 0x%x\n", bin->nt_headers->optional_header.SizeOfUninitializedData);
	rbin->cb_printf ("  AddressOfEntryPoint : 0x%x\n", bin->nt_headers->optional_header.AddressOfEntryPoint);
	rbin->cb_printf ("  BaseOfCode : 0x%x\n", bin->nt_headers->optional_header.BaseOfCode);
	rbin->cb_printf ("  ImageBase : 0x%x\n", bin->nt_headers->optional_header.ImageBase);
	rbin->cb_printf ("  SectionAlignment : 0x%x\n", bin->nt_headers->optional_header.SectionAlignment);
	rbin->cb_printf ("  FileAlignment : 0x%x\n", bin->nt_headers->optional_header.FileAlignment);
	rbin->cb_printf ("  MajorOperatingSystemVersion : 0x%x\n", bin->nt_headers->optional_header.MajorOperatingSystemVersion);
	rbin->cb_printf ("  MinorOperatingSystemVersion : 0x%x\n", bin->nt_headers->optional_header.MinorOperatingSystemVersion);
	rbin->cb_printf ("  MajorImageVersion : 0x%x\n", bin->nt_headers->optional_header.MajorImageVersion);
	rbin->cb_printf ("  MinorImageVersion : 0x%x\n", bin->nt_headers->optional_header.MinorImageVersion);
	rbin->cb_printf ("  MajorSubsystemVersion : 0x%x\n", bin->nt_headers->optional_header.MajorSubsystemVersion);
	rbin->cb_printf ("  MinorSubsystemVersion : 0x%x\n", bin->nt_headers->optional_header.MinorSubsystemVersion);
	rbin->cb_printf ("  Win32VersionValue : 0x%x\n", bin->nt_headers->optional_header.Win32VersionValue);
	rbin->cb_printf ("  SizeOfImage : 0x%x\n", bin->nt_headers->optional_header.SizeOfImage);
	rbin->cb_printf ("  SizeOfHeaders : 0x%x\n", bin->nt_headers->optional_header.SizeOfHeaders);
	rbin->cb_printf ("  CheckSum : 0x%x\n", bin->nt_headers->optional_header.CheckSum);
	rbin->cb_printf ("  Subsystem : 0x%x\n", bin->nt_headers->optional_header.Subsystem);
	rbin->cb_printf ("  DllCharacteristics : 0x%x\n", bin->nt_headers->optional_header.DllCharacteristics);
	rbin->cb_printf ("  SizeOfStackReserve : 0x%x\n", bin->nt_headers->optional_header.SizeOfStackReserve);
	rbin->cb_printf ("  SizeOfStackCommit : 0x%x\n", bin->nt_headers->optional_header.SizeOfStackCommit);
	rbin->cb_printf ("  SizeOfHeapReserve : 0x%x\n", bin->nt_headers->optional_header.SizeOfHeapReserve);
	rbin->cb_printf ("  SizeOfHeapCommit : 0x%x\n", bin->nt_headers->optional_header.SizeOfHeapCommit);
	rbin->cb_printf ("  LoaderFlags : 0x%x\n", bin->nt_headers->optional_header.LoaderFlags);
	rbin->cb_printf ("  NumberOfRvaAndSizes : 0x%x\n", bin->nt_headers->optional_header.NumberOfRvaAndSizes);
	RListIter *it;
	Pe_image_rich_entry *entry;
	rbin->cb_printf ("RICH_FIELDS\n");
	r_list_foreach (bin->rich_entries, it, entry) {
		rbin->cb_printf ("  Product: %d Name: %s Version: %d Times: %d\n", entry->productId, entry->productName, entry->minVersion, entry->timesUsed);
	}
	int i;
	for (i = 0; i < PE_IMAGE_DIRECTORY_ENTRIES - 1; i++) {
		if (bin->nt_headers->optional_header.DataDirectory[i].Size > 0) {
			switch (i) {
			case PE_IMAGE_DIRECTORY_ENTRY_EXPORT:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_EXPORT\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_IMPORT:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_IMPORT\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_RESOURCE:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_RESOURCE\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_EXCEPTION:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_EXCEPTION\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_SECURITY:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_SECURITY\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_BASERELOC:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_BASERELOC\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_DEBUG:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_DEBUG\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_COPYRIGHT:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_COPYRIGHT\n");
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_ARCHITECTURE\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_GLOBALPTR:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_GLOBALPTR\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_TLS:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_TLS\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_IAT:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_IAT\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT\n");
				break;
			case PE_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR:
				rbin->cb_printf ("IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR\n");
				break;
			}
			rbin->cb_printf ("\tVirtualAddress : 0x%x\n", bin->nt_headers->optional_header.DataDirectory[i].VirtualAddress);
			rbin->cb_printf ("\tSize : 0x%x\n", bin->nt_headers->optional_header.DataDirectory[i].Size);
		}
	}
}

extern struct r_bin_write_t r_bin_write_pe64;

RBinPlugin r_bin_plugin_pe64 = {
	.name = "pe64",
	.desc = "PE64 (PE32+) bin plugin",
	.license = "LGPL3",
	.get_sdb = &get_sdb,
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.info = &info,
	.header = &header,
	.libs = &libs,
	.relocs = &relocs,
	.get_vaddr = &get_vaddr,
	.write = &r_bin_write_pe64
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pe64,
	.version = R2_VERSION
};
#endif
