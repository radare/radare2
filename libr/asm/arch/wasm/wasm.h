#ifndef WASM_ASM_H
#define WASM_ASM_H
#include <r_util.h>

typedef enum {
	// Control flow operators
	WASM_OP_TRAP = 0x00,
	WASM_OP_NOP,
	WASM_OP_BLOCK,
	WASM_OP_LOOP,
	WASM_OP_IF,
	WASM_OP_ELSE,
	WASM_OP_END = 0x0b,
	WASM_OP_BR,
	WASM_OP_BRIF,
	WASM_OP_BRTABLE,
	WASM_OP_RETURN,

	// Call operators
	WASM_OP_CALL = 0x10,
	WASM_OP_CALLINDIRECT,

	// Parametric operators
	WASM_OP_DROP = 0x1a,
	WASM_OP_SELECT,

	// Variable access
	WASM_OP_GETLOCAL = 0x20,
	WASM_OP_SETLOCAL,
	WASM_OP_TEELOCAL,
	WASM_OP_GETGLOBAL,
	WASM_OP_SETGLOBAL,

	// Memory-related operators
	WASM_OP_I32LOAD = 0x28,
	WASM_OP_I64LOAD,
	WASM_OP_F32LOAD,
	WASM_OP_F64LOAD,
	WASM_OP_I32LOAD8S,
	WASM_OP_I32LOAD8U,
	WASM_OP_I32LOAD16S,
	WASM_OP_I32LOAD16U,
	WASM_OP_I64LOAD8S,
	WASM_OP_I64LOAD8U,
	WASM_OP_I64LOAD16S,
	WASM_OP_I64LOAD16U,
	WASM_OP_I64LOAD32S,
	WASM_OP_I64LOAD32U,
	WASM_OP_I32STORE,
	WASM_OP_I64STORE,
	WASM_OP_F32STORE,
	WASM_OP_F64STORE,
	WASM_OP_I32STORE8,
	WASM_OP_I32STORE16,
	WASM_OP_I64STORE8,
	WASM_OP_I64STORE16,
	WASM_OP_I64STORE32,
	WASM_OP_CURRENTMEMORY,
	WASM_OP_GROWMEMORY,

	// Constants
	WASM_OP_I32CONST,
	WASM_OP_I64CONST,
	WASM_OP_F32CONST,
	WASM_OP_F64CONST,

	// Comparison operators
	WASM_OP_I32EQZ,
	WASM_OP_I32EQ,
	WASM_OP_I32NE,
	WASM_OP_I32LTS,
	WASM_OP_I32LTU,
	WASM_OP_I32GTS,
	WASM_OP_I32GTU,
	WASM_OP_I32LES,
	WASM_OP_I32LEU,
	WASM_OP_I32GES,
	WASM_OP_I32GEU,
	WASM_OP_I64EQZ,
	WASM_OP_I64EQ,
	WASM_OP_I64NE,
	WASM_OP_I64LTS,
	WASM_OP_I64LTU,
	WASM_OP_I64GTS,
	WASM_OP_I64GTU,
	WASM_OP_I64LES,
	WASM_OP_I64LEU,
	WASM_OP_I64GES,
	WASM_OP_I64GEU,
	WASM_OP_F32EQ,
	WASM_OP_F32NE,
	WASM_OP_F32LT,
	WASM_OP_F32GT,
	WASM_OP_F32LE,
	WASM_OP_F32GE,
	WASM_OP_F64EQ,
	WASM_OP_F64NE,
	WASM_OP_F64LT,
	WASM_OP_F64GT,
	WASM_OP_F64LE,
	WASM_OP_F64GE,

	// Numeric operators
	WASM_OP_I32CLZ,
	WASM_OP_I32CTZ,
	WASM_OP_I32POPCNT,
	WASM_OP_I32ADD,
	WASM_OP_I32SUB,
	WASM_OP_I32MUL,
	WASM_OP_I32DIVS,
	WASM_OP_I32DIVU,
	WASM_OP_I32REMS,
	WASM_OP_I32REMU,
	WASM_OP_I32AND,
	WASM_OP_I32OR,
	WASM_OP_I32XOR,
	WASM_OP_I32SHL,
	WASM_OP_I32SHRS,
	WASM_OP_I32SHRU,
	WASM_OP_I32ROTL,
	WASM_OP_I32ROTR,
	WASM_OP_I64CLZ,
	WASM_OP_I64CTZ,
	WASM_OP_I64POPCNT,
	WASM_OP_I64ADD,
	WASM_OP_I64SUB,
	WASM_OP_I64MUL,
	WASM_OP_I64DIVS,
	WASM_OP_I64DIVU,
	WASM_OP_I64REMS,
	WASM_OP_I64REMU,
	WASM_OP_I64AND,
	WASM_OP_I64OR,
	WASM_OP_I64XOR,
	WASM_OP_I64SHL,
	WASM_OP_I64SHRS,
	WASM_OP_I64SHRU,
	WASM_OP_I64ROTL,
	WASM_OP_I64ROTR,
	WASM_OP_F32ABS,
	WASM_OP_F32NEG,
	WASM_OP_F32CEIL,
	WASM_OP_F32FLOOR,
	WASM_OP_F32TRUNC,
	WASM_OP_F32NEAREST,
	WASM_OP_F32SQRT,
	WASM_OP_F32ADD,
	WASM_OP_F32SUB,
	WASM_OP_F32MUL,
	WASM_OP_F32DIV,
	WASM_OP_F32MIN,
	WASM_OP_F32MAX,
	WASM_OP_F32COPYSIGN,
	WASM_OP_F64ABS,
	WASM_OP_F64NEG,
	WASM_OP_F64CEIL,
	WASM_OP_F64FLOOR,
	WASM_OP_F64TRUNC,
	WASM_OP_F64NEAREST,
	WASM_OP_F64SQRT,
	WASM_OP_F64ADD,
	WASM_OP_F64SUB,
	WASM_OP_F64MUL,
	WASM_OP_F64DIV,
	WASM_OP_F64MIN,
	WASM_OP_F64MAX,
	WASM_OP_F64COPYSIGN,

	// Conversions
	WASM_OP_I32WRAPI64,
	WASM_OP_I32TRUNCSF32,
	WASM_OP_I32TRUNCUF32,
	WASM_OP_I32TRUNCSF64,
	WASM_OP_I32TRUNCUF64,
	WASM_OP_I64EXTENDSI32,
	WASM_OP_I64EXTENDUI32,
	WASM_OP_I64TRUNCSF32,
	WASM_OP_I64TRUNCUF32,
	WASM_OP_I64TRUNCSF64,
	WASM_OP_I64TRUNCUF64,
	WASM_OP_F32CONVERTSI32,
	WASM_OP_F32CONVERTUI32,
	WASM_OP_F32CONVERTSI64,
	WASM_OP_F32CONVERTUI64,
	WASM_OP_F32DEMOTEF64,
	WASM_OP_F64CONVERTSI32,
	WASM_OP_F64CONVERTUI32,
	WASM_OP_F64CONVERTSI64,
	WASM_OP_F64CONVERTUI64,
	WASM_OP_F64PROMOTEF32,

	// Reinterpretations
	WASM_OP_I32REINTERPRETF32,
	WASM_OP_I64REINTERPRETF64,
	WASM_OP_F32REINTERPRETI32,
	WASM_OP_F64REINTERPRETI64,

	// Extensions
	// ...
} WasmOpCodes;

typedef struct {
	WasmOpCodes op;
	int len;
	char *txt;
} WasmOp;

typedef struct {
	const char *txt;
	size_t min, max;
} WasmOpDef;


R_IPI int wasm_asm(const char *str, unsigned char *buf, int buf_len);
R_IPI int wasm_dis(WasmOp *op, const unsigned char *buf, int buf_len);

#endif