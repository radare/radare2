OBJ_WASM=bin_wasm.o

STATIC_OBJ+=${OBJ_WASM}
TARGET_WASM=bin_wasm.${EXT_SO}

ALL_TARGETS+=${TARGET_WASM}

${TARGET_WASM}: ${OBJ_WASM}
	-${CC} $(call libname,bin_wasm) ${CFLAGS} ${OBJ_WASM}
