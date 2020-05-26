BIN=radiff2

BINDEPS=r_core r_config r_cons r_search r_anal
BINDEPS+=r_bin r_debug r_io r_asm r_hash r_fs r_crypto
BINDEPS+=r_socket r_flag r_lang r_reg r_bp r_parse r_arch
BINDEPS+=r_syscall r_magic r_util r_parse r_egg r_main

include ../rules.mk

ifeq ($(OSTYPE),android)
LDFLAGS+=${DL_LIBS} -lm
endif

include ../../libr/socket/deps.mk
include ../../libr/main/deps.mk
include ../../shlr/zip/deps.mk
include ../../shlr/gdb/deps.mk
include ../../shlr/bochs/deps.mk
include ../../shlr/qnx/deps.mk
include ../../shlr/ar/deps.mk

LDFLAGS+=$(LINK)
