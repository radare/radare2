#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

#include "mdmp/mdmp.h"

static Sdb *get_sdb(RBinObject *o)
{
	struct r_bin_mdmp_obj *bin;

	if (!o)
		return NULL;
	bin = (struct r_bin_mdmp_obj *) o->bin_obj;

	if (bin->kv)
		return bin->kv;
	return NULL;
}

static void *load_bytes(const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb)
{
	RBuffer *tbuf;
	void *res;

	if (!buf || sz == 0 || sz == UT64_MAX)
		return NULL;

	tbuf = r_buf_new();
	r_buf_set_bytes(tbuf, buf, sz);

	res = r_bin_mdmp_new_buf(tbuf);

	r_buf_free(tbuf);
	return res;
}

static int load(RBinFile *arch)
{
	if (!arch || !arch->o || !arch->buf)
		return R_FALSE;

	const ut8 *bytes = r_buf_buffer(arch->buf);
	ut64 sz = r_buf_size(arch->buf);

	arch->o->bin_obj = load_bytes(bytes, sz, arch->o->loadaddr, arch->sdb);
	return arch->o->bin_obj ? R_TRUE : R_FALSE;
}

static int destroy(RBinFile *arch)
{
	r_bin_mdmp_free((struct r_bin_mdmp_obj *)arch->o->bin_obj);
	return R_TRUE;
}

static int check_bytes(const ut8 *buf, ut64 size)
{
	return (size > sizeof(MINIDUMP_HEADER) && ((PMINIDUMP_HEADER)buf)->Signature == MINIDUMP_SIGNATURE);
}

static int check(RBinFile *arch)
{
	if (!arch || !arch->o || !arch->buf)
		return R_FALSE;

	return check_bytes(r_buf_buffer(arch->buf), r_buf_size(arch->buf));
}

static ut64 baddr(RBinFile *arch)
{
	return 0;
}

static RBinAddr *binsym(RBinFile *arch, int sym)
{
	return NULL;
}

static RList *entries(RBinFile *arch)
{
	RList *ret;
	if (!(ret = r_list_newf(free)))
		return NULL;

	return ret;
}

static RList *sections(RBinFile *arch)
{
	RList *ret = NULL;
	RListIter *it;
	RBinSection *ptr = NULL;
	struct r_bin_mdmp_obj *obj = arch->o->bin_obj;
	PMINIDUMP_MODULE module;
	PMINIDUMP_STRING str;

	if (!(ret = r_list_newf(free)))
		return NULL;

	r_list_foreach (obj->modules, it, module) {
		if (!(ptr = R_NEW0(RBinSection))) {
			eprintf("Warning in mdmp sections: R_NEW0 failed\n");
			break;
		}
		if ((str = r_bin_mdmp_locate_string(obj, module->ModuleNameRva))) {
			//strncpy(ptr->name, (char *)str->Buffer, R_MIN(str->Length, R_BIN_SIZEOF_STRINGS));
		}
		ptr->size = module->SizeOfImage;
		ptr->vsize = module->SizeOfImage;
		ptr->paddr = (unsigned char *)module - obj->b->buf;
		//ptr->paddr = 0;//module->BaseOfImage;
		ptr->vaddr = module->BaseOfImage;
		ptr->srwx = 0;
		r_list_append(ret, ptr);
	}
	return ret;
}

static RList *imports(RBinFile *arch)
{
	return NULL;
}

static RList *libs(RBinFile *arch)
{
	return NULL;
}

static RList *relocs(RBinFile *arch)
{
	return NULL;
}

static RBinInfo *info(RBinFile *arch)
{
	RBinInfo *ret = R_NEW0(RBinInfo);
	struct r_bin_mdmp_obj *obj = (struct r_bin_mdmp_obj *)arch->o->bin_obj;

	strncpy(ret->file, arch->file, R_BIN_SIZEOF_STRINGS);
	strncpy(ret->rpath, "NONE", R_BIN_SIZEOF_STRINGS);

	switch (obj->system_info->ProcessorArchitecture) {
		case PROCESSOR_ARCHITECTURE_INTEL:
			strncpy(ret->machine, "i386", R_BIN_SIZEOF_STRINGS);
			strncpy(ret->arch, "x86", R_BIN_SIZEOF_STRINGS);
			ret->bits = 32;
			ret->big_endian = R_FALSE;
			break;
		case PROCESSOR_ARCHITECTURE_ARM:
			strncpy(ret->machine, "ARM", R_BIN_SIZEOF_STRINGS);
			strncpy(ret->arch, "h8300", R_BIN_SIZEOF_STRINGS);
			ret->bits = 16;
			ret->big_endian = R_FALSE;
			break;
		case PROCESSOR_ARCHITECTURE_IA64:
			strncpy(ret->machine, "IA64", R_BIN_SIZEOF_STRINGS);
			strncpy(ret->arch, "IA64", R_BIN_SIZEOF_STRINGS);
			ret->bits = 64;
			ret->big_endian = R_FALSE;
			break;
		case PROCESSOR_ARCHITECTURE_AMD64:
			strncpy(ret->machine, "AMD 64", R_BIN_SIZEOF_STRINGS);
			strncpy(ret->arch, "x86", R_BIN_SIZEOF_STRINGS);
			ret->bits = 64;
			ret->big_endian = R_FALSE;
			break;
		default:
			strncpy(ret->machine, "unknown", R_BIN_SIZEOF_STRINGS);
	}
	switch (obj->system_info->ProductType) {
		case VER_NT_WORKSTATION:
			snprintf (ret->os, R_BIN_SIZEOF_STRINGS, "Windows NT Workstation %d.%d.%d", obj->system_info->MajorVersion,
					  obj->system_info->MinorVersion, obj->system_info->BuildNumber);
			break;
		case VER_NT_DOMAIN_CONTROLLER:
			snprintf (ret->os, R_BIN_SIZEOF_STRINGS, "Windows NT Server Domain Controller %d.%d.%d", obj->system_info->MajorVersion,
					  obj->system_info->MinorVersion, obj->system_info->BuildNumber);
			break;
		case VER_NT_SERVER:
			snprintf (ret->os, R_BIN_SIZEOF_STRINGS, "Windows NT Server %d.%d.%d", obj->system_info->MajorVersion,
					  obj->system_info->MinorVersion, obj->system_info->BuildNumber);
			break;
		default:
			strncpy(ret->os, "unknown", R_BIN_SIZEOF_STRINGS);
	}

	return ret;
}

static RList *fields(RBinFile *arch)
{
	return NULL;
}

static RBuffer *create(RBin *bin, const ut8 *code, int codelen,
                       const ut8 *data, int datalen)
{
	return NULL;
}

static int size(RBinFile *arch)
{
	return 0;
}


RBinPlugin r_bin_plugin_mdmp = {
	.name = "mdmp",
	.desc = "Minidump format r_bin plugin",
	.license = "UNLICENSE",
	.init = NULL,
	.fini = NULL,
	.get_sdb = &get_sdb,
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check = &check,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.boffset = NULL,
	.binsym = &binsym,
	.entries = &entries,
	.sections = &sections,
	.symbols = NULL,
	.imports = &imports,
	.strings = NULL,
	.info = &info,
	.fields = &fields,
	.size = &size,
	.libs = &libs,
	.relocs = &relocs,
	.dbginfo = NULL,
	.create = &create,
	.write = NULL,
	.get_vaddr = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_mdmp
};
#endif
