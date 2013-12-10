/* radare - LGPL - Copyright 2012 - pancake<nopcode.org>
			     2013 - condret		*/


/*
	this file was based on anal_i8080.c

	Todo(for Condret):	1. MOAR Meta-comments on Hardware-Access
				2. Implement all MBC's and detect Bankswitches
				3. Trace all Data copied to OAM and VRAM (and add a command for converting the OAM/VRAM to a pngfile,
					so that we can produce snapshots of the gb-screen for tracing sprites)
				4. Payloads for gameboy
*/


#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include "../../asm/arch/gb/gbdis.c"

void meta_gb_hardware_cmt(RMeta *m, const ut8 hw, ut64 addr) {
	switch(hw)
	{
		case 0:
			r_meta_set_string(m, R_META_TYPE_COMMENT, addr, "JOYPAD");
			break;
		case 1:
			r_meta_set_string(m, R_META_TYPE_COMMENT, addr, "Serial tranfer data");
			break;
		case 2:
			r_meta_set_string(m, R_META_TYPE_COMMENT, addr, "Serial tranfer data - Ctl");
			break;
		case 4:
			r_meta_set_string(m, R_META_TYPE_COMMENT, addr, "DIV");
			break;
		case 5:
			r_meta_set_string(m, R_META_TYPE_COMMENT, addr, "TIMA");
			break;
		case 6:
			r_meta_set_string(m, R_META_TYPE_COMMENT, addr, "TMA");
			break;
		case 7:
			r_meta_set_string(m, R_META_TYPE_COMMENT, addr, "TAC");
			break;
		case 0x0f:
			r_meta_set_string(m, R_META_TYPE_COMMENT, addr, "Interrupt Flag");			//TODO: save in sdb for halt
			break;
		case 0x10:
		case 0x11:
		case 0x12:
		case 0x13:
		case 0x14:
		case 0x16:
		case 0x17:
		case 0x18:
		case 0x19:
		case 0x1a:
		case 0x1b:
		case 0x1c:
		case 0x1d:
		case 0x1e:
		case 0x20:
		case 0x21:
		case 0x22:
		case 0x23:
		case 0x24:
		case 0x25:
		case 0x26:
			r_meta_set_string(m, R_META_TYPE_COMMENT, addr, "SOUND");
			break;
		case 0x30:
			r_meta_set_string(m, R_META_TYPE_COMMENT, addr, "Wave Pattern RAM/SOUND");
			break;
		case 0x40:
			r_meta_set_string(m, R_META_TYPE_COMMENT, addr, "LCDC");
			break;			//TODO: MOAR
	}
}

static int gb_anop(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	int ilen = gbOpLength(gb_op[data[0]].type);
	if(ilen>len)
		ilen=0;
	memset (op, '\0', sizeof (RAnalOp));
	op->addr = addr;
	op->type = R_ANAL_OP_TYPE_UNK;
	switch (data[0])
	{
		case 0x00:
		case 0x10:
			op->type = R_ANAL_OP_TYPE_NOP;
			break;
		case 0x01:
		case 0x06:
		case 0x0e:
		case 0x11:
		case 0x16:
		case 0x1e:
		case 0x21:
		case 0x26:
		case 0x2e:
		case 0x31:
		case 0x36:
		case 0x3e:
		case 0xf8:
		case 0xf9:
			op->type = R_ANAL_OP_TYPE_MOV;		// LD
			break;
		case 0x03:
		case 0x04:
		case 0x0c:
		case 0x13:
		case 0x14:
		case 0x1c:
		case 0x23:
		case 0x24:
		case 0x2c:
		case 0x33:
		case 0x34:
		case 0x3c:
			op->type = R_ANAL_OP_TYPE_ADD;		// INC
			break;
		case 0x02:
		case 0x08:
		case 0x12:
		case 0x22:
		case 0x32:
		case 0x40:
		case 0x41:
		case 0x42:
		case 0x43:
		case 0x44:
		case 0x45:
		case 0x47:
		case 0x48:
		case 0x49:
		case 0x4a:
		case 0x4b:
		case 0x4c:
		case 0x4d:
		case 0x4f:
		case 0x50:
		case 0x51:
		case 0x52:
		case 0x53:
		case 0x54:
		case 0x55:
		case 0x57:
		case 0x58:
		case 0x59:
		case 0x5a:
		case 0x5b:
		case 0x5c:
		case 0x5d:
		case 0x5f:
		case 0x60:
		case 0x61:
		case 0x62:
		case 0x63:
		case 0x64:
		case 0x65:
		case 0x67:
		case 0x68:
		case 0x69:
		case 0x6a:
		case 0x6b:
		case 0x6c:
		case 0x6d:
		case 0x6f:
		case 0x70:
		case 0x71:
		case 0x72:
		case 0x73:
		case 0x74:
		case 0x75:
		case 0x77:
		case 0xe2:
		case 0xea:
			op->type = R_ANAL_OP_TYPE_STORE;	//LD
			break;
		case 0xe0:
			meta_gb_hardware_cmt(anal->meta, data[1], addr);
			op->type = R_ANAL_OP_TYPE_STORE;
			break;
		case 0x78:
		case 0x79:
		case 0x7a:
		case 0x7b:
		case 0x7c:
		case 0x7d:
		case 0x7e:
		case 0x7f:
			op->type = R_ANAL_OP_TYPE_MOV;		// LD
			break;
		case 0x0a:
		case 0x1a:
		case 0x2a:
		case 0x3a:
		case 0x46:
		case 0x4e:
		case 0x56:
		case 0x5e:
		case 0x66:
		case 0x6e:
		case 0xf2:
		case 0xfa:
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case 0xf0:
			meta_gb_hardware_cmt(anal->meta, data[1], addr);
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case 0x09:
		case 0x19:
		case 0x29:
		case 0x39:
		case 0x80:
		case 0x81:
		case 0x82:
		case 0x83:
		case 0x84:
		case 0x85:
		case 0x86:
		case 0x87:
		case 0xc6:
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case 0x88:
		case 0x89:
		case 0x8a:
		case 0x8b:
		case 0x8c:
		case 0x8d:
		case 0x8f:
			op->type = R_ANAL_OP_TYPE_ADD;		// ADC
			break;
		case 0x90:
		case 0x91:
		case 0x92:
		case 0x93:
		case 0x94:
		case 0x95:
		case 0x96:
		case 0x97:
		case 0xd6:
			op->type = R_ANAL_OP_TYPE_SUB;
			break;
		case 0x98:
		case 0x99:
		case 0x9a:
		case 0x9b:
		case 0x9c:
		case 0x9d:
		case 0x9e:
		case 0x9f:
		case 0xde:
			op->type = R_ANAL_OP_TYPE_SUB;		// SBC
			break;
		case 0xa0:
		case 0xa1:
		case 0xa2:
		case 0xa3:
		case 0xa4:
		case 0xa5:
		case 0xa6:
		case 0xa7:
		case 0xe6:
			op->type = R_ANAL_OP_TYPE_AND;
			break;
		case 0x07:
		case 0x17:
			op->type = R_ANAL_OP_TYPE_ROL;
			break;
		case 0x0f:
		case 0x1f:
			op->type = R_ANAL_OP_TYPE_ROR;
			break;
		case 0x2f:					//cpl
		case 0xa8:
		case 0xa9:
		case 0xaa:
		case 0xab:
		case 0xac:
		case 0xad:
		case 0xae:
		case 0xaf:
		case 0xee:
			op->type = R_ANAL_OP_TYPE_XOR;
			break;
		case 0xb0:
		case 0xb1:
		case 0xb2:
		case 0xb3:
		case 0xb4:
		case 0xb5:
		case 0xb6:
		case 0xb7:
		case 0xf6:
			op->type = R_ANAL_OP_TYPE_OR;
			break;
		case 0xb8:
		case 0xb9:
		case 0xba:
		case 0xbb:
		case 0xbc:
		case 0xbd:
		case 0xbe:
		case 0xbf:
		case 0xfe:
			op->type = R_ANAL_OP_TYPE_CMP;
			break;
		case 0xc0:
		case 0xc8:
		case 0xd0:
		case 0xd8:
			op->eob = 1;
			op->type = R_ANAL_OP_TYPE_CRET;
			break;
		case 0xc9:
		case 0xd9:
			op->eob = 1;
			op->type = R_ANAL_OP_TYPE_RET;
			break;
		case 0x05:
		case 0x0b:
		case 0x0d:
		case 0x15:
		case 0x1b:
		case 0x1d:
		case 0x25:
		case 0x2b:
		case 0x2d:
		case 0x35:
		case 0x3b:
		case 0x3d:
			op->type = R_ANAL_OP_TYPE_SUB;		// DEC
			break;
		case 0xc5:
		case 0xd5:
		case 0xe5:
		case 0xf5:
			op->type = R_ANAL_OP_TYPE_PUSH;
			break;
		case 0xc1:
		case 0xd1:
		case 0xe1:
		case 0xf1:
			op->type = R_ANAL_OP_TYPE_POP;
			break;
		case 0xc3:
			op->jump = (data[2]*0x100)+data[1];
			op->fail = addr+ilen;
			op->type = R_ANAL_OP_TYPE_JMP;
			op->eob = 1;
			break;
		case 0x18:					// JR
			op->jump = addr+data[1]-0x80;		//is this wrong?
			op->fail = addr+ilen;
			op->type = R_ANAL_OP_TYPE_JMP;
			break;
		case 0x20:
		case 0x28:
		case 0x30:
		case 0x38:					//JR cond
			op->jump = addr+data[1]-0x80;		//is this wrong?
			op->fail = addr+ilen;
			op->type = R_ANAL_OP_TYPE_CJMP;
			break;
		case 0xc2:
		case 0xca:
		case 0xd2:
		case 0xda:
			op->jump = (data[2]*0x100)+data[1];
			op->fail = addr+ilen;
			op->type = R_ANAL_OP_TYPE_JMP;
			op->eob=1;
			break;
		case 0xe9:
		case 0x76:					/*
								DAH-FUCK: halts must be handled as jumps:
								http://marc.rawer.de/Gameboy/Docs/GBCPUman.pdf (page 20)
								*/
			op->type = R_ANAL_OP_TYPE_UJMP;
			break;
		case 0xc4:
		case 0xcc:
		case 0xcd:
		case 0xd4:
		case 0xdc:
			op->jump = (data[2]*0x100)+data[1];
			op->fail = addr+3;
			op->type = R_ANAL_OP_TYPE_CALL;
			op->eob = 1;
			break;
		case 0xc7:
		case 0xcf:
		case 0xd7:
		case 0xdf:
		case 0xe7:
		case 0xef:
		case 0xf7:
		case 0xff:
			op->type = R_ANAL_OP_TYPE_TRAP;
			op->eob = 1;
			break;					// RST
		case 0xd3:
		case 0xdb:
		case 0xdd:
		case 0xe3:
		case 0xe4:
		case 0xeb:
		case 0xec:
		case 0xed:
		case 0xfc:
		case 0xfd:
			op->type = R_ANAL_OP_TYPE_ILL;
			break;

		case 0xcb:
			switch(data[1]/8)
			{
				case 0:
				case 2:
				case 4:
				case 6:				//swap
					op->type = R_ANAL_OP_TYPE_ROL;
					break;
				case 1:
				case 3:
				case 5:
				case 7:
					op->type = R_ANAL_OP_TYPE_ROR;
					break;
			}
			break;
	}
	op->size = ilen;
	return op->size;
}

struct r_anal_plugin_t r_anal_plugin_gb = {
	.name = "gb",
	.desc = "Gameboy CPU code analysis plugin",
	.license = "LGPL3",
	.arch = R_SYS_ARCH_Z80,
	.bits = 16,
	.init = NULL,
	.fini = NULL,
	.op = &gb_anop,
	.set_reg_profile = NULL,				//TODO
	.fingerprint_bb = NULL,
	.fingerprint_fcn = NULL,
	.diff_bb = NULL,
	.diff_fcn = NULL,
	.diff_eval = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_gb
};
#endif
