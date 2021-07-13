include ../config.mk

NAME=r_io
R2DEPS+=r_util
R2DEPS+=r_socket
R2DEPS+=r_hash
R2DEPS+=r_cons
R2DEPS+=r_crypto
STATIC_OBJS=$(subst ..,p/..,$(subst io_,p/io_,$(STATIC_OBJ)))
OBJS=${STATIC_OBJS}
OBJS+=io.o io_plugin.o io_map.o io_desc.o io_cache.o p_cache.o undo.o ioutils.o io_fd.o io_memory.o
OBJS+=io_bank.o io_submap.o

CFLAGS+=-Wall -DR2_PLUGIN_INCORE

include ../socket/deps.mk
include $(SHLR)/ar/deps.mk
include $(SHLR)/zip/deps.mk
include $(SHLR)/gdb/deps.mk
include $(SHLR)/qnx/deps.mk

ifeq ($(USE_PTRACE_WRAP),1)
OBJS+=ptrace_wrap.o
endif

## only for shm_open
#ifeq (${OSTYPE},gnulinux)
#  LDFLAGS+=-lrt
#endif

ifeq (${BUILD_OS},dragonfly)
  LDFLAGS+=-lkvm
endif

.PHONY: pre
pre: libr_io.${EXT_SO} libr_io.${EXT_AR}
	@${MAKE} -C p

include ${STATIC_IO_PLUGINS}
include $(LTOP)/rules.mk

