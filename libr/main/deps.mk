MAIN_LINK_ALL=1

ifeq ($(MAIN_LINK_ALL),1)
DEPS=r_config r_cons r_io r_util r_flag r_asm r_core r_arch
DEPS+=r_debug r_hash r_bin r_lang r_io r_anal r_parse r_bp r_egg
DEPS+=r_reg r_search r_syscall r_socket r_fs r_magic r_crypto
else
# only works
WITH_LIBS=0
WITH_LIBR=1
endif
