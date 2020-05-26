include ../../global.mk

NAME=r_arch
DEPS=r_util
CFLAGS+=-DR2_PLUGIN_INCORE -Iarch/include -Iarch -I../../shlr
CURDIR=p/

include $(TOP)/libr/config.mk

.PHONY: all plugins

EXTRA_CLEAN=doclean

all: plugins

doclean:
	# @cd d && ${MAKE} clean
	@cd p && ${MAKE} clean
	rm -f `find arch/| grep '\.o$$'`

plugins: ${LIBSO} ${LIBAR}
#	${MAKE} -C d all
	${MAKE} -C p all

include ${STATIC_ARCH_PLUGINS}
STATIC_OBJS=$(subst ..,p/..,$(subst arch_,p/arch_,$(STATIC_OBJ)))

OBJS=${STATIC_OBJS}
OBJS+=arch.o
OBJS+=arch_info.o
OBJS+=arch_instruction.o
OBJS+=arch_lazysession.o
OBJS+=arch_session.o
OBJS+=arch_session_pool.o

include $(TOP)/libr/rules.mk
