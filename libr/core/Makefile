include ../config.mk

NAME=r_core

DEPS=r_config r_cons r_io r_util r_flag r_asm r_arch
DEPS+=r_debug r_hash r_bin r_lang r_io r_anal r_parse r_bp r_egg
DEPS+=r_reg r_search r_syscall r_socket r_fs r_magic r_crypto

OBJS=core.o cmd.o cfile.o cconfig.o visual.o cio.o yank.o libs.o agraph.o
OBJS+=fortune.o hack.o vasm.o patch.o cbin.o corelog.o rtr.o cmd_api.o
OBJS+=carg.o canal.o project.o gdiff.o casm.o disasm.o cplugin.o
OBJS+=vmenus.o vmenus_graph.o vmenus_zigns.o zdiff.o citem.o
OBJS+=task.o panels.o pseudo.o vmarks.o anal_tp.o anal_objc.o blaze.o cundo.o

CFLAGS+=-I../../shlr/heap/include
CFLAGS+=-I../../shlr/tree-sitter/lib/include -I../../shlr/radare2-shell-parser/src/tree_parser
CFLAGS+=-DR2_PLUGIN_INCORE -I../../shlr
LDFLAGS+=${DL_LIBS}
LDFLAGS+=${CLOCK_LDFLAGS}

ifeq ($(shell uname),OpenBSD)
LDFLAGS+=-lpthread
endif

ifeq ($(USE_LIB_MAGIC),1)
#LDFLAGS+=-lmagic
LDFLAGS+=${LIBMAGIC}
endif

ifeq ($(HAVE_LIBUV),1)
CFLAGS+=${LIBUV_CFLAGS}
LDFLAGS+=${LIBUV_LDFLAGS}
endif

first:: all

include ${STATIC_CORE_PLUGINS}

STATIC_OBJS=$(addprefix $(LTOP)/core/p/,$(STATIC_OBJ))
OBJS+=$(STATIC_OBJS)

#STATIC_OBJS=$(subst ..,p/..,$(subst core_,p/core_,$(STATIC_OBJ)))

include $(TOP)/shlr/gdb/deps.mk
include $(TOP)/shlr/radare2-shell-parser-deps.mk
include $(LTOP)/rules.mk

# include plugins
#include ${STATIC_CORE_PLUGINS}

cmd.o: cmd_hash.c cmd_debug.c cmd_zign.c cmd_project.c \
	cmd_open.c cmd_meta.c cmd_macro.c cmd_magic.c cmd_mount.c cmd_eval.c \
	cmd_seek.c cmd_print.c cmd_help.c cmd_anal.c cmd_search.c cmd_log.c \
	cmd_cmp.c cmd_write.c cmd_egg.c cmd_info.c cmd_type.c cmd_flag.c \
	cmd_search_rop.c

rtr.o: rtr_http.c rtr_shell.c
