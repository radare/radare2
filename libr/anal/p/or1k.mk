OBJ_OR1K=anal_or1k.o

STATIC_OBJ+=${OBJ_OR1K}
TARGET_OR1K=anal_or1k.${EXT_SO}

ALL_TARGETS+=${TARGET_OR1K}

${TARGET_OR1K}: ${OBJ_OR1K}
	${CC} $(call libname,anal_nios2) ${LDFLAGS} ${CFLAGS} \
		-o anal_or1k.${EXT_SO} ${OBJ_OR1K}
