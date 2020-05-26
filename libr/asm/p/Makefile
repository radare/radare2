include ../../config.mk
include ../../../mk/platform.mk

CFLAGS+=-I$(TOP)/shlr -I../../include -I../arch/ -I../arch/include
CFLAGS+=-Wall -shared ${PIC_CFLAGS} ${LDFLAGS_LIB} ${LDFLAGS_LINKPATH}..
LDFLAGS+=-L../../util -L../../flag
ifeq ($(CC),cccl)
LDFLAGS+=${LINK} -llibr_flag -llibr_util
else
LDFLAGS+=${LINK} -lr_flag -lr_util
endif

CURDIR=

ifeq ($(WITHPIC),1)
all: ${ALL_TARGETS}

ALL_TARGETS=
# TODO: rename to enabled plugins
ARCHS=mips_gnu.mk x86_cs.mk sparc_cs.mk sparc_gnu.mk java.mk arm_gnu.mk dalvik.mk
ARCHS+=x86_as.mk x86_nz.mk cris_gnu.mk vax.mk
ARCHS+=ppc_gnu.mk ppc_cs.mk xap.mk x86_nasm.mk avr.mk
ARCHS+=sh.mk arm_winedbg.mk tms320.mk gb.mk snes.mk ebc.mk malbolge.mk ws.mk
ARCHS+=6502.mk h8300.mk cr16.mk v850.mk spc700.mk propeller.mk msp430.mk i4004.mk
ARCHS+=lh5801.mk v810.mk mcs96.mk lm32.mk
ARCHS+=riscv.mk rsp.mk mcore.mk
include $(ARCHS)

clean:
	-rm -f *.${EXT_SO} *.o ${STATIC_OBJ}

mrproper: clean
	-rm -f *.d ../arch/*/*/*.d

.PHONY: all clean mrproper
else
all clean mrproper:

.PHONY: all clean mrproper
endif
