#ifndef R2_H8300_DISAS_H
#define R2_H8300_DISAS_H

#include <stdint.h>

enum h8300_4bit_opcodes{
	H8300_MOV_4BIT_2	= 0x2,
	H8300_MOV_4BIT_3	= 0x3,
	H8300_ADD_4BIT		= 0x8,
	H8300_ADDX_4BIT		= 0x9,
	H8300_CMP_4BIT		= 0xA,
	H8300_SUBX_4BIT		= 0xB,
	H8300_OR_4BIT		= 0xC,
	H8300_XOR_4BIT		= 0xD,
	H8300_AND_4BIT		= 0xE,
	H8300_MOV_4BIT		= 0xF,
};

enum h8300_opcodes {
	H8300_NOP		= 0x00,
	H8300_SLEEP		= 0x01,
	H8300_STC		= 0x02,
	H8300_LDC		= 0x03,
	H8300_ORC		= 0x04,
	H8300_XORC		= 0x05,
	H8300_ANDC		= 0x06,
	H8300_LDC_2		= 0x07,
	H8300_ADDB_DIRECT	= 0x08,
	H8300_ADDW_DIRECT	= 0x09,
	H8300_INC		= 0x0A,
	H8300_ADDS		= 0x0B,
	H8300_MOV_1		= 0x0C,
	H8300_MOV_2		= 0x0D,
	H8300_ADDX		= 0x0E,
	H8300_DAA		= 0x0F,
	H8300_SHL		= 0x10,
	H8300_SHR		= 0x11,
	H8300_ROTL		= 0x12,
	H8300_ROTR		= 0x13,
	H8300_OR		= 0x14,
	H8300_XOR		= 0x15,
	H8300_AND		= 0x16,
	H8300_NOT_NEG		= 0x17,
	H8300_SUB_1		= 0x18,
	H8300_SUBW		= 0x19,
	H8300_DEC		= 0x1A,
	H8300_SUBS		= 0x1B,
	H8300_CMP_1		= 0x1C,
	H8300_CMP_2		= 0x1D,
	H8300_SUBX		= 0x1E,
	H8300_DAS		= 0x1F,
	H8300_BRA		= 0x40,
	H8300_BRN		= 0x41,
	H8300_BHI		= 0x42,
	H8300_BLS		= 0x43,
	H8300_BCC		= 0x44,
	H8300_BCS		= 0x45,
	H8300_BNE		= 0x46,
	H8300_BEQ		= 0x47,
	H8300_BVC		= 0x48,
	H8300_BVS		= 0x49,
	H8300_BPL		= 0x4A,
	H8300_BMI		= 0x4B,
	H8300_BGE		= 0x4C,
	H8300_BLT		= 0x4D,
	H8300_BGT		= 0x4E,
	H8300_BLE		= 0x4F,
	H8300_MULXU		= 0x50,
	H8300_DIVXU		= 0x51,
	H8300_RTS		= 0x54,
	H8300_BSR		= 0x55,
	H8300_RTE		= 0x56,
	H8300_JMP_1		= 0x59,
	H8300_JMP_2		= 0x5A,
	H8300_JMP_3		= 0x5B,
	H8300_JSR_1		= 0x5D,
	H8300_JSR_2		= 0x5E,
	H8300_JSR_3		= 0x5F,
	H8300_BSET_1		= 0x60,
	H8300_BNOT_1		= 0x61,
	H8300_BCLR_R2R8		= 0x62,
	H8300_BTST_R2R8		= 0x63,
	H8300_BST_BIST		= 0x67,
	H8300_MOV_R82IND16	= 0x68,
	H8300_MOV_IND162R16	= 0x69,
	H8300_MOV_R82ABS16	= 0x6a,
	H8300_MOV_ABS162R16	= 0x6B,
	H8300_MOV_R82RDEC16	= 0x6C,
	H8300_MOV_INDINC162R16	= 0x6D,
	H8300_MOV_R82DISPR16	= 0x6E,
	H8300_MOV_DISP162R16	= 0x6F,
	H8300_BSET_2		= 0x70,
	H8300_BNOT_2		= 0x71,
	H8300_BCLR_IMM2R8	= 0x72,
	H8300_BTST		= 0x73,
	H8300_BOR_BIOR		= 0x74,
	H8300_BXOR_BIXOR	= 0x75,
	H8300_BAND_BIAND	= 0x76,
	H8300_BILD_IMM2R8	= 0x77,
	H8300_MOV_IMM162R16	= 0x79,
	H8300_EEPMOV		= 0x7B,
	H8300_BIAND_IMM2IND16	= 0x7C,
	H8300_BCLR_R2IND16	= 0x7D,
	H8300_BIAND_IMM2ABS8	= 0x7E,
	H8300_BCLR_R2ABS8	= 0x7F,
};

#define H8300_INSTR_MAXLEN	20

enum h8300_opcodes_9bit {
	H8300_BST		= 0x6700 >> 7,
	H8300_BIST		= 0x6780 >> 7,
	H8300_BOR		= 0x7400 >> 7,
	H8300_BIOR		= 0x7480 >> 7,
	H8300_BXOR		= 0x7500 >> 7,
	H8300_BIXOR		= 0x7580 >> 7,
	H8300_BAND		= 0x7600 >> 7,
	H8300_BIAND		= 0x7680 >> 7,
	H8300_BLD		= 0x7700 >> 7,
	H8300_BILD		= 0x7780 >> 7,
};

struct h8300_cmd {
	char	instr[H8300_INSTR_MAXLEN];
	char	operands[H8300_INSTR_MAXLEN];
};

int h8300_decode_command(const ut8 *instr, struct h8300_cmd *cmd);

#endif /* H8300_DISAS_H */
