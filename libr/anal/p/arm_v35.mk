include ../config.mk
N=anal_arm_v35
V35ARM64_HOME=$(LIBR)/asm/arch/arm/v35arm64/

include ../asm/arch/arm/v35arm64/deps.mk

OBJ_ARM_V35=anal_arm_v35.o
# OBJ_ARM_V35+=${V35ARM64_LINK}
OBJ_ARM_V35+=../../asm/arch/arm/v35arm64/arch-arm64/disassembler/*.o

STATIC_OBJ+=${OBJ_ARM_V35}
CFLAGS+=$(V35ARM64_CFLAGS)
TARGET_ARM_V35=$(N).${LIBEXT}

ALL_TARGETS+=${TARGET_ARM_V35}

${TARGET_ARM_V35}: 
# $(STATIC_OBJ)
	${CC} $(V35ARM64_CFLAGS) ${CFLAGS} $(call libname,$(N)) \
		-lr_util -lr_search \
		-o $(TARGET_ARM_V35) ${OBJ_ARM_V35} $(V35ARM64_LDFLAGS)
