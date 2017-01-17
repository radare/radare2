#define VTABLE_BUFF_SIZE 10

typedef struct vtable_info_t {
	ut64 saddr; //starting address
	int methods;
	RList* funtions;
} vtable_info;

typedef struct type_descriptor_t {
	ut64 pVFTable;//Always point to type_info's vftable
	int spare;
	char* className;
} type_descriptor;

typedef struct class_hierarchy_descriptor_t {
	int signature;//always 0
	
	//bit 0 --> Multiple inheritance
	//bit 1 --> Virtual inheritance
	int attributes;
	
	//total no of base classes
	// including itself
	int numBaseClasses;

	//Array of base class descriptor's
	RList* baseClassArray;
} class_hierarchy_descriptor;

typedef struct base_class_descriptor_t {
	//Type descriptor of current base class
	type_descriptor* typeDescriptor;
	
	//Number of direct bases 
	//of this base class 
	int numContainedBases;
	
	//vftable offset
	int mdisp;
	
	// vbtable offset
	int pdisp;
	
	//displacement of the base class 
	//vftable pointer inside the vbtable
	int vdisp;

	//don't know what's this
	int attributes;
	
	//class hierarchy descriptor
	//of this base class 
	class_hierarchy_descriptor* classDescriptor;
} base_class_descriptor;

typedef struct rtti_complete_object_locator_t {
	int signature;
	
	//within class offset
	int vftableOffset;
	
	//don't know what's this
	int cdOffset;
	
	//type descriptor for the current class
	type_descriptor* typeDescriptor;
	
	//hierarchy descriptor for current class
	class_hierarchy_descriptor* hierarchyDescriptor;
} rtti_complete_object_locator;

typedef struct run_time_type_information_t {
	ut64 vtable_start_addr;
	ut64 rtti_addr;
} rtti_struct;


static RList* getVtableMethods(RCore *core, vtable_info *table) {
	RList* vtableMethods = r_list_new ();
	if (table && core && vtableMethods) {
		int curMethod = 0;
		int totalMethods = table->methods;
		ut64 startAddress = table->saddr;
		int bits = r_config_get_i (core->config, "asm.bits");
		int wordSize = bits / 8;
		while (curMethod < totalMethods) {
			ut64 curAddressValue = r_io_read_i (core->io, startAddress, 8);
			RAnalFunction *curFuntion = r_anal_get_fcn_in (core->anal, curAddressValue, 0);
			r_list_append (vtableMethods, curFuntion);
			startAddress += wordSize;
			curMethod++;
		}
		table->funtions = vtableMethods;
		return vtableMethods;
	}
	r_list_free (vtableMethods);
	return NULL;
}

static int inTextSection(RCore *core, ut64 curAddress) {
	//section of the curAddress
	RBinSection* value = r_bin_get_section_at (core->bin->cur->o, curAddress, true);
	//If the pointed value lies in .text section
	return value && !strcmp (value->name, ".text");
}

static int valueInTextSection(RCore *core, ut64 curAddress) {
	//value at the current address
	ut64 curAddressValue = r_io_read_i (core->io, curAddress, 8);
	//if the value is in text section
	return inTextSection (core, curAddressValue);
}

static int isVtableStart(RCore *core, ut64 curAddress) {
	RAsmOp asmop = {0};
	RAnalRef *xref;
	RListIter *xrefIter;
	ut8 buf[VTABLE_BUFF_SIZE];
	if (!curAddress || curAddress == UT64_MAX) {
		return false;
	}
	if (valueInTextSection (core, curAddress)) {
		// total xref's to curAddress
		RList *xrefs = r_anal_xrefs_get (core->anal, curAddress);
		if (!r_list_empty (xrefs)) {
			r_list_foreach (xrefs, xrefIter, xref) {
				// section in which currenct xref lies
				if (inTextSection (core, xref->addr)) {
					r_io_read_at (core->io, xref->addr, buf, VTABLE_BUFF_SIZE);
					if (r_asm_disassemble (core->assembler, &asmop, buf, VTABLE_BUFF_SIZE) > 0) {
						if ((!strncmp (asmop.buf_asm, "mov", 3)) ||
						    (!strncmp (asmop.buf_asm, "lea", 3))) {
							return true;
						}
					}
				}
			}
		}
	}
	return false;
}

RList* search_virtual_tables(RCore *core){
	if (!core) {
		return NULL;
	}
	ut64 startAddress;
	ut64 endAddress;
	RListIter * iter;
	RIOSection *section;
	RList *vtables = r_list_newf ((RListFree)free);
	if (!vtables) {
		return NULL;
	}
	ut64 bits = r_config_get_i (core->config, "asm.bits");
	int wordSize = bits / 8;
	r_list_foreach (core->io->sections, iter, section) {
		if (!strcmp (section->name, ".rodata")) {
			ut8 *segBuff = calloc (1, section->size);
			r_io_read_at (core->io, section->offset, segBuff, section->size);
			startAddress = section->vaddr;
			endAddress = startAddress + (section->size) - (bits/8);
			while (startAddress <= endAddress) {
				if (isVtableStart (core, startAddress)) {
					vtable_info *vtable = calloc (1, sizeof(vtable_info));
					vtable->saddr = startAddress;
					int noOfMethods = 0;
					while (valueInTextSection (core, startAddress)) {
						noOfMethods++;
						startAddress += wordSize;
					}
					vtable->methods = noOfMethods;
					r_list_append (vtables, vtable);
					continue;
				}
				startAddress += 1;
			}
		}
	}

	if (r_list_empty (vtables)) {
		// stripped binary?
		eprintf ("No virtual tables found\n");
		r_list_free (vtables);
		return NULL;
	}
	return vtables;
}

R_API void r_core_anal_list_vtables(void *core, bool printJson) {
	ut64 bits = r_config_get_i (((RCore *)core)->config, "asm.bits");
	RList* vtables = search_virtual_tables ((RCore *)core);
	const char *noMethodName = "No Name found";
	RListIter* vtableMethodNameIter;
	RAnalFunction *curMethod;
	int wordSize = bits / 8;
	RListIter* vtableIter;
	vtable_info* table;

	if (!vtables) {
		return;
	}
	if (printJson) {
		bool isFirstElement = true;
		r_cons_print ("[");
		r_list_foreach (vtables, vtableIter, table) {
			if (!isFirstElement) {
				r_cons_print (",");
			}
			r_cons_printf ("{\"offset\":%"PFMT64d",\"methods\":%d}",
			  		table->saddr, table->methods);
			isFirstElement = false;
		}
		r_cons_println ("]");
	} else {
		r_list_foreach (vtables, vtableIter, table) {
			ut64 vtableStartAddress = table->saddr;
			RList *vtableMethods = getVtableMethods ((RCore *)core, table);
			if (vtableMethods) {
				r_cons_printf ("\nVtable Found at 0x%08"PFMT64x"\n", 
				  		vtableStartAddress);
				r_list_foreach (vtableMethods, vtableMethodNameIter, curMethod) {
					if (curMethod->name) {
						r_cons_printf ("0x%08"PFMT64x" : %s\n", 
						  		vtableStartAddress, curMethod->name);
					} else {
						r_cons_printf ("0x%08"PFMT64x" : %s\n", 
						  		vtableStartAddress, noMethodName);
					}
					vtableStartAddress += wordSize;
				}
				r_cons_newline ();
			}
		}
	}
	r_list_free (vtables);
}

static void r_core_anal_list_vtables_all(void *core) {
	RList* vtables = search_virtual_tables ((RCore *)core);
	RListIter* vtableIter;
	RListIter* vtableMethodNameIter;
	RAnalFunction* function;
	vtable_info* table;

	r_list_foreach (vtables, vtableIter, table) {
		RList *vtableMethods = getVtableMethods ((RCore *)core, table);
		r_list_foreach (vtableMethods, vtableMethodNameIter, function) {
			// char *ret = r_str_newf ("vtable.%s", table->funtio);
			r_cons_printf ("f %s=0x%08"PFMT64x"\n", function->name, function->addr);
		}
	}
	r_list_free (vtables);
}

rtti_struct* get_rtti_data (RCore *core, ut64 atAddress) {
	ut64 bits = r_config_get_i (core->config, "asm.bits");
	int wordSize = bits / 8;
	ut64 curRTTIBaseLocatorAddr = r_io_read_i (core->io, atAddress - wordSize, wordSize);
	r_cons_printf ("trying to parse rtti at 0x%08"PFMT64x"\n", curRTTIBaseLocatorAddr);
	return NULL;
}

RList* r_core_anal_parse_rtti (void *core, bool printJson) {
	RList* vtables = search_virtual_tables ((RCore *)core);
	RListIter* vtableIter;
	vtable_info* table;
	RList* rtti_structures = r_list_new();
	r_list_foreach (vtables, vtableIter, table) {
		rtti_struct* current_rtti = get_rtti_data ((RCore *)core, table->saddr);
		if (current_rtti) {
			current_rtti->vtable_start_addr = table->saddr;
			r_list_append (rtti_structures, current_rtti);
		}
	}
	r_list_free (vtables);
	return rtti_structures;
}

R_API void r_core_anal_print_rtti (void *core) {
	RList* rtti_structures = r_core_anal_parse_rtti (core, false);
	RListIter* RTTIIter;
	rtti_struct* curRTTI;
	if (rtti_structures) {
		r_list_foreach (rtti_structures, RTTIIter, curRTTI) {
			r_cons_printf ("Reached here\n");
		}
	}
}
