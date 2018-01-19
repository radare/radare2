OBJ_PPC_CS=anal_ppc_cs.o

include $(CURDIR)capstone.mk

STATIC_OBJ+=${OBJ_PPC_CS}
TARGET_PPC_CS=anal_ppc_cs.${EXT_SO}

ifeq ($(WITHPIC),1)
OBJ_PPC_CS+=../../asm/arch/ppc/libvle/vle.o
endif

ALL_TARGETS+=${TARGET_PPC_CS}

${TARGET_PPC_CS}: ${OBJ_PPC_CS}
	${CC} ${CFLAGS} $(call libname,anal_ppc_cs) $(CS_CFLAGS) \
		-o anal_ppc_cs.${EXT_SO} ${OBJ_PPC_CS} $(CS_LDFLAGS)
