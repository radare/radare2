BIN=ragg2
BINDEPS=r_egg r_syscall r_asm r_arch
BINDEPS+=r_core r_hash r_debug r_fs r_config r_bp r_crypto r_cons
BINDEPS+=r_lang r_parse r_anal r_reg r_flag r_crypto
BINDEPS+=r_bin r_search r_io r_socket
BINDEPS+=r_magic r_util r_main

include ../rules.mk
include ../../libr/main/deps.mk
include ../../shlr/ar/deps.mk
include ../../libr/socket/deps.mk
include ../../shlr/bochs/deps.mk
include ../../shlr/gdb/deps.mk
include ../../shlr/grub/deps.mk
include ../../shlr/java/deps.mk
include ../../shlr/capstone.mk
include ../../shlr/qnx/deps.mk

LDFLAGS+=$(LINK)
