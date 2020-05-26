include ../../global.mk

NAME=r_asm
DEPS=r_syscall r_lang r_util r_parse
DEPS+=r_flag r_cons r_reg r_arch
CFLAGS+=-DR2_PLUGIN_INCORE -Iarch/include -Iarch -I../../shlr
CURDIR=p/

include $(TOP)/libr/config.mk

include p/capstone.mk
LDFLAGS+=${CS_LDFLAGS}
include $(STOP)/java/deps.mk
include $(STOP)/capstone.mk

.PHONY: all plugins

EXTRA_CLEAN=doclean

all: plugins

doclean:
	@cd d && ${MAKE} clean
	@cd p && ${MAKE} clean
	rm -f `find arch/| grep '\.o$$'`

plugins: ${LIBSO} ${LIBAR}
	${MAKE} -C d all
	${MAKE} -C p all

include ${STATIC_ASM_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst asm_,p/asm_,$(STATIC_OBJ)))
OBJS=${STATIC_OBJS} asm.o acode.o aop.o
# hack to b
OBJS+=${SHARED2_OBJ}

include $(TOP)/libr/rules.mk
