OBJ_MCORE=anal_mcore.o

STATIC_OBJ+=${OBJ_MCORE}

TARGET_MCORE=anal_mcore.${EXT_SO}

ALL_TARGETS+=${TARGET_MCORE}

${TARGET_MCORE}: ${OBJ_MCORE}
	${CC} ${CFLAGS} $(call libname,anal_sysz) $(CS_LDFLAGS) \
		-o anal_mcore.${EXT_SO} ${OBJ_MCORE}
