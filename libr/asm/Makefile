include ../../global.mk

NAME=r_asm
R2DEPS=r_syscall r_lang r_util r_parse
R2DEPS+=r_flag r_cons r_reg
CFLAGS+=-DR2_PLUGIN_INCORE -Iarch/include -Iarch -I../../shlr
CURDIR=p/

include $(TOP)/libr/config.mk

include p/capstone.mk
LDFLAGS+=${CS_LDFLAGS}
include $(STOP)/java/deps.mk
include $(STOP)/capstone.mk

.PHONY: alle plugins

alle:
	$(MAKE) gperfs
	$(MAKE) -C arch/arm/v35arm64
	$(MAKE) plugins

SDB_PATH=../../../shlr/sdb
SDB=$(SDB_PATH)/sdb

gperfs:
	PATH=$(SDB_PATH):$$PATH $(MAKE) -C d all
ifeq ($(HAVE_GPERF),1)
	PATH=$(SDB_PATH):$$PATH cd d && for a in *.sdb ; do test $$a -nt `echo $$a.c|sed -e 's,.sdb,,'`; if [ $$? = 0 ]; then $(SDB) -t -C $$a ; fi ; done
else
	PATH=$(SDB_PATH):$$PATH cd d && for a in *.sdb ; do test $$a -nt `echo $$a.c|sed -e 's,.sdb,,'`; if [ $$? = 0 ]; then $(SDB) -t -C $$a ; fi ; done
endif

plugins: ${LIBSO} ${LIBAR}
	$(MAKE) -C d all
	$(MAKE) -C p all

alle2:
	${MAKE} -C d all
	${MAKE} -C p all
	${MAKE} $(LIBSO)
	${MAKE} $(LIBAR)

EXTRA_CLEAN=doclean
$(EXTRA_CLEAN):
	$(MAKE) -C d clean
	$(MAKE) -C p clean
	rm -f `find arch/| grep '\.o$$'`

include ${STATIC_ASM_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst asm_,p/asm_,$(STATIC_OBJ)))
OBJS=${STATIC_OBJS} asm.o acode.o aop.o binutils_as.o aplugs.o
OBJS+=${SHARED2_OBJ}

ifeq ($(HAVE_GPERF),1)
OBJS+=d/z80.o
OBJS+=d/6502.o
OBJS+=d/i4004.o
OBJS+=d/avr.o
OBJS+=d/chip8.o
OBJS+=d/i8080.o
OBJS+=d/java.o
OBJS+=d/lm32.o
OBJS+=d/m68k.o
OBJS+=d/malbolge.o
OBJS+=d/mips.o
OBJS+=d/ppc.o
OBJS+=d/riscv.o
OBJS+=d/sh.o
OBJS+=d/sparc.o
OBJS+=d/x86.o
OBJS+=d/v810.o
OBJS+=d/v850.o
OBJS+=d/8051.o
OBJS+=d/LH5801.o
OBJS+=d/arc.o
OBJS+=d/arm.o
OBJS+=d/msp430.o
OBJS+=d/propeller.o
OBJS+=d/pic18c.o
endif

include $(TOP)/libr/rules.mk
