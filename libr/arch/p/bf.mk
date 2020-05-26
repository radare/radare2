OBJ_BF=arch_bf.o

TARGET_BF=arch_bf.${EXT_SO}
STATIC_OBJ+=${OBJ_BF}

ifeq ($(WITHPIC),1)
ALL_TARGETS+=${TARGET_BF}
${TARGET_BF}: ${OBJ_BF}
	${CC} $(call libname,arch_bf) ${LDFLAGS} ${CFLAGS} -o ${TARGET_BF} ${OBJ_BF}
endif
