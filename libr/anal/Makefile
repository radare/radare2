include ../config.mk

EXTRA_TARGETS+=do
EXTRA_CLEAN=doclean
CFLAGS+=-I..

NAME=r_anal
DEPS=r_util r_reg r_syscall r_search r_cons r_flag r_hash r_crypto r_parse r_arch
CFLAGS+=-DR2_PLUGIN_INCORE -Iarch -I$(TOP)/shlr
CFLAGS+=-I$(LTOP)/asm/arch/include

LDFLAGS+=${BN_LIBS}

CURDIR=p/

include p/capstone.mk
LDFLAGS+=$(CS_LDFLAGS)
include $(STOP)/java/deps.mk
LDFLAGS+=$(LINK)

.PHONY: all plugins libs ${EXTRA_CLEAN}

all: plugins

plugins: ${LIBSO} ${LIBAR}
	@${MAKE} -C p all

include ${STATIC_ANAL_PLUGINS}

STATIC_OBJS=$(addprefix $(LTOP)/anal/p/,$(STATIC_OBJ))
OBJLIBS=meta.o reflines.o op.o fcn.o bb.o var.o block.o
OBJLIBS+=cond.o value.o cc.o class.o diff.o type.o
OBJLIBS+=hint.o anal.o data.o xrefs.o esil.o sign.o
OBJLIBS+=switch.o cycles.o esil_dfg.o
OBJLIBS+=esil_sources.o esil_interrupt.o esil_cfg.o
OBJLIBS+=esil_stats.o esil_trace.o flirt.o labels.o
OBJLIBS+=esil2reil.o pin.o session.o vtable.o rtti.o
OBJLIBS+=rtti_msvc.o rtti_itanium.o jmptbl.o function.o
ASMOBJS+=$(LTOP)/asm/arch/xtensa/gnu/xtensa-modules.o
ASMOBJS+=$(LTOP)/asm/arch/xtensa/gnu/xtensa-isa.o
ASMOBJS+=$(LTOP)/asm/arch/xtensa/gnu/elf32-xtensa.o

OBJS=${STATIC_OBJS} ${OBJLIBS} ${ASMOBJS}

test tests: tests-esil

tests-esil:
	cd ../../test ; \
		sh run_tests.sh t.esil

.PHONY: do doclean

do:
	${MAKE} -C d

doclean:
	${MAKE} -C d clean

include $(LTOP)/rules.mk
